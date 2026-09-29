package analysis

import (
	"fmt"
	"os"
	"path/filepath"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/naming"
	"aotopsy/internal/output"
	"aotopsy/internal/snapshot"
)

// GraphObject is one node in the named-object graph.
type GraphObject struct {
	Snapshot  string `json:"snapshot"`
	Ref       int    `json:"ref"`
	CID       int    `json:"cid"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	OwnerRef  int    `json:"owner_ref,omitempty"`
	OwnerName string `json:"owner_name,omitempty"`
}

// GraphEdge is one edge in the named-object graph.
type GraphEdge struct {
	Snapshot string `json:"snapshot"`
	FromRef  int    `json:"from_ref"`
	ToRef    int    `json:"to_ref"`
	Type     string `json:"type"`
}

// CodeMapEntry is one Code→Function mapping in the graph output.
type CodeMapEntry struct {
	Snapshot     string `json:"snapshot"`
	CodeRef      int    `json:"code_ref"`
	FunctionRef  int    `json:"function_ref"`
	FunctionName string `json:"function_name"`
	OwnerName    string `json:"owner_name,omitempty"`
}

// RunGraph parses a snapshot's named-object graph and writes objects.jsonl,
// edges.jsonl, and code_map.jsonl to outDir.
func RunGraph(libapp, outDir, which string, maxSteps int) error {
	if outDir == "" {
		return fmt.Errorf("graph: output directory is empty")
	}
	containsSource, err := output.ContainsPath(outDir, libapp)
	if err != nil {
		return fmt.Errorf("graph: compare output/input paths: %w", err)
	}
	if containsSource {
		return fmt.Errorf("graph: output directory must not contain source binary %s", libapp)
	}
	opts := dartfmt.Options{
		Mode:     dartfmt.ModeBestEffort,
		MaxSteps: maxSteps,
	}

	ef, info, err := LoadSnapshotRaw(libapp, opts)
	if err != nil {
		return err
	}
	defer func() { _ = ef.Close() }()

	if info.Version != nil && info.Version.DartVersion != "" {
		fmt.Fprintf(os.Stderr, "Dart SDK version: %s\n", info.Version.DartVersion)
	}
	if info.Version != nil && !info.Version.Supported {
		return fmt.Errorf("HALT_UNSUPPORTED_VERSION: Dart %s (hash %s)", info.Version.DartVersion, info.SnapshotHash())
	}

	type target struct {
		name         string
		data         []byte
		snapshotSize int64
		header       *snapshot.Header
	}
	var targets []target
	if info.UnifiedSnapshot {
		if which == "vm" {
			return fmt.Errorf("graph: Dart 3.13+ unified snapshot has no separate VM snapshot")
		}
		if which != "" && which != "both" && which != "isolate" {
			return fmt.Errorf("graph: unknown --which %q (want vm, isolate, or both)", which)
		}
		if info.IsolateHeader == nil {
			return fmt.Errorf("graph: unified snapshot header is missing")
		}
		targets = []target{{"Unified", info.IsolateData.Data, info.IsolateHeader.TotalSize, info.IsolateHeader}}
	} else {
		switch which {
		case "vm":
			if info.VmHeader == nil {
				return fmt.Errorf("graph: VM snapshot header is missing")
			}
			targets = []target{{"VM", info.VmData.Data, info.VmHeader.TotalSize, info.VmHeader}}
		case "isolate":
			if info.IsolateHeader == nil {
				return fmt.Errorf("graph: isolate snapshot header is missing")
			}
			targets = []target{{"Isolate", info.IsolateData.Data, info.IsolateHeader.TotalSize, info.IsolateHeader}}
		case "", "both":
			if info.VmHeader == nil || info.IsolateHeader == nil {
				return fmt.Errorf("graph: legacy snapshot headers are incomplete")
			}
			targets = []target{
				{"VM", info.VmData.Data, info.VmHeader.TotalSize, info.VmHeader},
				{"Isolate", info.IsolateData.Data, info.IsolateHeader.TotalSize, info.IsolateHeader},
			}
		default:
			return fmt.Errorf("graph: unknown --which %q (want vm, isolate, or both)", which)
		}
	}

	// Parse all targets.
	type parsedTarget struct {
		name               string
		result             *cluster.Result
		firstEntryWithCode int
		refToStr           map[int]string
		refToNamed         map[int]*cluster.NamedObject
	}
	var parsed []parsedTarget

	for _, t := range targets {
		if len(t.data) < 64 {
			return fmt.Errorf("graph %s: data too short (%d bytes)", t.name, len(t.data))
		}

		clusterStart, err := snapshot.FindClusterDataStart(t.data)
		if err != nil {
			return fmt.Errorf("graph %s cluster start: %w", t.name, err)
		}

		isVM := t.name == "VM"
		result, err := cluster.ScanClusters(t.data, clusterStart, info.Version, isVM, opts)
		if err != nil {
			return fmt.Errorf("graph %s scan: %w", t.name, err)
		}

		if err := cluster.ReadFill(t.data, result, info.Version, isVM, t.snapshotSize, opts); err != nil {
			return fmt.Errorf("graph %s fill: %w", t.name, err)
		}

		firstEntryWithCode := -1
		if info.Version.CodeIndexOneBased {
			table, err := cluster.ParseInstructionsTable(t.data, &result.Header, info.Version, t.header)
			if err != nil {
				return fmt.Errorf("graph %s instructions table: %w", t.name, err)
			}
			firstEntryWithCode = int(table.FirstEntryWithCode)
		}
		pt := parsedTarget{
			name:               t.name,
			result:             result,
			firstEntryWithCode: firstEntryWithCode,
			refToStr:           make(map[int]string, len(result.Strings)),
			refToNamed:         make(map[int]*cluster.NamedObject, len(result.Named)),
		}
		for _, ps := range result.Strings {
			pt.refToStr[ps.RefID] = ps.Value
		}
		for i := range result.Named {
			no := &result.Named[i]
			pt.refToNamed[no.RefID] = no
		}
		parsed = append(parsed, pt)
	}

	// Legacy isolate snapshots share the VM snapshot's base-object namespace:
	// refs below NumBaseObjects+1 deliberately point at VM objects/strings. Keep
	// each graph row tagged with its own snapshot, but seed only that valid base
	// range into the isolate lookup so name/owner resolution still follows the
	// snapshot format without allowing arbitrary VM/isolate RefID collisions.
	var vmTarget *parsedTarget
	for i := range parsed {
		if parsed[i].name == "VM" {
			vmTarget = &parsed[i]
			break
		}
	}
	if vmTarget != nil {
		for i := range parsed {
			pt := &parsed[i]
			if pt.name != "Isolate" {
				continue
			}
			baseLimit := int(pt.result.Header.NumBaseObjects) + 1
			for ref, s := range vmTarget.refToStr {
				if ref > 0 && ref < baseLimit {
					if _, local := pt.refToStr[ref]; !local {
						pt.refToStr[ref] = s
					}
				}
			}
			for ref, no := range vmTarget.refToNamed {
				if ref > 0 && ref < baseLimit {
					if _, local := pt.refToNamed[ref]; !local {
						pt.refToNamed[ref] = no
					}
				}
			}
		}
	}

	resolveName := func(pt *parsedTarget, no *cluster.NamedObject) string {
		if no != nil && no.NameRefID >= 0 {
			return pt.refToStr[no.NameRefID]
		}
		return ""
	}
	resolveOwnerName := func(pt *parsedTarget, no *cluster.NamedObject) string {
		if no == nil || no.OwnerRefID < 0 {
			return ""
		}
		return resolveName(pt, pt.refToNamed[no.OwnerRefID])
	}

	ct := info.Version.CIDs

	// The three graph files are one generation: never publish objects.jsonl from
	// the new parse next to edges/code_map from an older run.  This also removes
	// stale graph artifacts when a rerun legitimately produces fewer files.
	tx, err := output.BeginDirTransaction(outDir)
	if err != nil {
		return fmt.Errorf("begin graph output transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Abort()
		}
	}()
	stageDir := tx.StageDir()

	// Write objects.jsonl.
	objectsPath := filepath.Join(stageDir, "objects.jsonl")
	objectsWriter, err := jsonutil.NewJSONLWriter[GraphObject](objectsPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", objectsPath, err)
	}
	var objectCount int

	for pi := range parsed {
		pt := &parsed[pi]
		for _, no := range pt.result.Named {
			kind := cluster.CidNameV(no.CID, ct)
			if kind == "" {
				kind = fmt.Sprintf("CID_%d", no.CID)
			}
			obj := GraphObject{
				Snapshot:  pt.name,
				Ref:       no.RefID,
				CID:       no.CID,
				Kind:      kind,
				Name:      resolveName(pt, &no),
				OwnerRef:  no.OwnerRefID,
				OwnerName: resolveOwnerName(pt, &no),
			}
			if err := objectsWriter.Write(&obj); err != nil {
				_ = objectsWriter.Abort()
				return fmt.Errorf("write objects.jsonl: %w", err)
			}
			objectCount++
		}
	}
	if err := objectsWriter.Close(); err != nil {
		return fmt.Errorf("commit objects.jsonl: %w", err)
	}

	// Write edges.jsonl.
	edgesPath := filepath.Join(stageDir, "edges.jsonl")
	edgesWriter, err := jsonutil.NewJSONLWriter[GraphEdge](edgesPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", edgesPath, err)
	}
	var edgeCount int

	for pi := range parsed {
		pt := &parsed[pi]
		for _, no := range pt.result.Named {
			if no.OwnerRefID >= 0 {
				edge := GraphEdge{
					Snapshot: pt.name,
					FromRef:  no.RefID,
					ToRef:    no.OwnerRefID,
					Type:     "owner",
				}
				if err := edgesWriter.Write(&edge); err != nil {
					_ = edgesWriter.Abort()
					return fmt.Errorf("write edges.jsonl: %w", err)
				}
				edgeCount++
			}
			if no.NameRefID >= 0 {
				edge := GraphEdge{
					Snapshot: pt.name,
					FromRef:  no.RefID,
					ToRef:    no.NameRefID,
					Type:     "name",
				}
				if err := edgesWriter.Write(&edge); err != nil {
					_ = edgesWriter.Abort()
					return fmt.Errorf("write edges.jsonl: %w", err)
				}
				edgeCount++
			}
		}
		byCodeIndex := naming.CodeIndexToFunc(pt.result, ct, info.Version.CodeIndexOneBased, pt.firstEntryWithCode)
		for _, ce := range pt.result.Codes {
			if owner, ok := naming.ResolveCodeOwner(ce, pt.refToNamed, byCodeIndex, ct); ok {
				edge := GraphEdge{
					Snapshot: pt.name,
					FromRef:  ce.RefID,
					ToRef:    owner.RefID,
					Type:     "code_owner",
				}
				if err := edgesWriter.Write(&edge); err != nil {
					_ = edgesWriter.Abort()
					return fmt.Errorf("write edges.jsonl: %w", err)
				}
				edgeCount++
			}
		}
	}
	if err := edgesWriter.Close(); err != nil {
		return fmt.Errorf("commit edges.jsonl: %w", err)
	}

	// Write code_map.jsonl.
	codeMapPath := filepath.Join(stageDir, "code_map.jsonl")
	codeMapWriter, err := jsonutil.NewJSONLWriter[CodeMapEntry](codeMapPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", codeMapPath, err)
	}
	var codeMapCount int

	for pi := range parsed {
		pt := &parsed[pi]
		byCodeIndex := naming.CodeIndexToFunc(pt.result, ct, info.Version.CodeIndexOneBased, pt.firstEntryWithCode)
		for _, ce := range pt.result.Codes {
			owner, ok := naming.ResolveCodeOwner(ce, pt.refToNamed, byCodeIndex, ct)
			if !ok {
				continue
			}
			funcName := resolveName(pt, owner)
			ownerName := resolveOwnerName(pt, owner)
			entry := CodeMapEntry{
				Snapshot:     pt.name,
				CodeRef:      ce.RefID,
				FunctionRef:  owner.RefID,
				FunctionName: funcName,
				OwnerName:    ownerName,
			}
			if err := codeMapWriter.Write(&entry); err != nil {
				_ = codeMapWriter.Abort()
				return fmt.Errorf("write code_map.jsonl: %w", err)
			}
			codeMapCount++
		}
	}
	if err := codeMapWriter.Close(); err != nil {
		return fmt.Errorf("commit code_map.jsonl: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("publish graph generation: %w", err)
	}
	committed = true

	fmt.Fprintf(os.Stderr, "Wrote %d objects to %s\n", objectCount, filepath.Join(outDir, "objects.jsonl"))
	fmt.Fprintf(os.Stderr, "Wrote %d edges to %s\n", edgeCount, filepath.Join(outDir, "edges.jsonl"))
	fmt.Fprintf(os.Stderr, "Wrote %d code mappings to %s\n", codeMapCount, filepath.Join(outDir, "code_map.jsonl"))

	return nil
}
