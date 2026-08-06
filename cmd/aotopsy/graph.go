package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/pipeline"
	"aotopsy/internal/snapshot"
)

type graphObject struct {
	Ref       int    `json:"ref"`
	CID       int    `json:"cid"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	OwnerRef  int    `json:"owner_ref,omitempty"`
	OwnerName string `json:"owner_name,omitempty"`
}

type graphEdge struct {
	FromRef int    `json:"from_ref"`
	ToRef   int    `json:"to_ref"`
	Type    string `json:"type"`
}

type codeMapEntry struct {
	CodeRef      int    `json:"code_ref"`
	FunctionRef  int    `json:"function_ref"`
	FunctionName string `json:"function_name"`
	OwnerName    string `json:"owner_name,omitempty"`
}

func cmdGraph(args []string) error {
	fs := flag.NewFlagSet("graph", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	which := fs.String("which", "isolate", "which snapshot: vm, isolate, or both")
	outDir := fs.String("out", "", "output directory for JSONL files")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *libapp == "" {
		return fmt.Errorf("--lib is required")
	}
	if *outDir == "" {
		return fmt.Errorf("--out is required")
	}

	opts := dartfmt.Options{
		Mode:     dartfmt.ModeBestEffort,
		MaxSteps: *maxSteps,
	}

	ef, err := elfx.Open(*libapp)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = ef.Close() }()

	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}

	if info.Version != nil && info.Version.DartVersion != "" {
		fmt.Fprintf(os.Stderr, "Dart SDK version: %s\n", info.Version.DartVersion)
	}
	if info.Version != nil && !info.Version.Supported {
		return fmt.Errorf("HALT_UNSUPPORTED_VERSION: Dart %s (hash %s)", info.Version.DartVersion, info.VmHeader.SnapshotHash)
	}

	type target struct {
		name         string
		data         []byte
		snapshotSize int64
	}
	var targets []target
	switch *which {
	case "vm":
		targets = []target{{"VM", info.VmData.Data, info.VmHeader.TotalSize}}
	case "isolate":
		targets = []target{{"Isolate", info.IsolateData.Data, info.IsolateHeader.TotalSize}}
	default:
		targets = []target{
			{"VM", info.VmData.Data, info.VmHeader.TotalSize},
			{"Isolate", info.IsolateData.Data, info.IsolateHeader.TotalSize},
		}
	}

	// Parse all targets.
	type parsedTarget struct {
		name   string
		result *cluster.Result
	}
	var parsed []parsedTarget

	for _, t := range targets {
		if len(t.data) < 64 {
			fmt.Fprintf(os.Stderr, "%s: data too short (%d bytes)\n", t.name, len(t.data))
			continue
		}

		clusterStart, err := cluster.FindClusterDataStart(t.data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", t.name, err)
			continue
		}

		isVM := t.name == "VM"
		result, err := cluster.ScanClusters(t.data, clusterStart, info.Version, isVM, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: scan error: %v\n", t.name, err)
			continue
		}

		if err := cluster.ReadFill(t.data, result, info.Version, isVM, t.snapshotSize); err != nil {
			fmt.Fprintf(os.Stderr, "%s: fill error: %v\n", t.name, err)
			continue
		}

		parsed = append(parsed, parsedTarget{name: t.name, result: result})
	}

	// Build combined ref→string map.
	refToStr := make(map[int]string)
	for _, pt := range parsed {
		for _, ps := range pt.result.Strings {
			refToStr[ps.RefID] = ps.Value
		}
	}

	// Build ref→NamedObject lookup.
	refToNamed := make(map[int]*cluster.NamedObject)
	for _, pt := range parsed {
		for i := range pt.result.Named {
			no := &pt.result.Named[i]
			refToNamed[no.RefID] = no
		}
	}

	// Resolve names: for each named object, resolve its name string.
	resolveName := func(no *cluster.NamedObject) string {
		if no.NameRefID >= 0 {
			if s, ok := refToStr[no.NameRefID]; ok {
				return s
			}
		}
		return ""
	}

	// Resolve owner name through the chain.
	resolveOwnerName := func(no *cluster.NamedObject) string {
		if no.OwnerRefID < 0 {
			return ""
		}
		if owner, ok := refToNamed[no.OwnerRefID]; ok {
			return resolveName(owner)
		}
		return ""
	}

	ct := info.Version.CIDs

	// Create output directory.
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", *outDir, err)
	}

	// Write objects.jsonl.
	objectsPath := filepath.Join(*outDir, "objects.jsonl")
	objectsFile, err := os.Create(objectsPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", objectsPath, err)
	}
	defer func() { _ = objectsFile.Close() }()

	enc := json.NewEncoder(objectsFile)
	enc.SetEscapeHTML(false)
	var objectCount int

	for _, pt := range parsed {
		for _, no := range pt.result.Named {
			kind := cluster.CidNameV(no.CID, ct)
			if kind == "" {
				kind = fmt.Sprintf("CID_%d", no.CID)
			}
			obj := graphObject{
				Ref:       no.RefID,
				CID:       no.CID,
				Kind:      kind,
				Name:      resolveName(&no),
				OwnerRef:  no.OwnerRefID,
				OwnerName: resolveOwnerName(&no),
			}
			if err := enc.Encode(obj); err != nil {
				return fmt.Errorf("write objects.jsonl: %w", err)
			}
			objectCount++
		}
	}

	// Write edges.jsonl.
	edgesPath := filepath.Join(*outDir, "edges.jsonl")
	edgesFile, err := os.Create(edgesPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", edgesPath, err)
	}
	defer func() { _ = edgesFile.Close() }()

	edgeEnc := json.NewEncoder(edgesFile)
	edgeEnc.SetEscapeHTML(false)
	var edgeCount int

	for _, pt := range parsed {
		// Ownership edges from named objects.
		for _, no := range pt.result.Named {
			if no.OwnerRefID >= 0 {
				edge := graphEdge{
					FromRef: no.RefID,
					ToRef:   no.OwnerRefID,
					Type:    "owner",
				}
				if err := edgeEnc.Encode(edge); err != nil {
					return fmt.Errorf("write edges.jsonl: %w", err)
				}
				edgeCount++
			}
			// Name ref edge.
			if no.NameRefID >= 0 {
				edge := graphEdge{
					FromRef: no.RefID,
					ToRef:   no.NameRefID,
					Type:    "name",
				}
				if err := edgeEnc.Encode(edge); err != nil {
					return fmt.Errorf("write edges.jsonl: %w", err)
				}
				edgeCount++
			}
		}
		// Code→owner edges. Resolved via pipeline.ResolveCodeOwner rather
		// than trusting ce.OwnerRef directly -- Code.OwnerRef is confirmed
		// unreliable on some real snapshots (Dart 3.7.0 x86_64: ~5.4% of
		// functions get a bogus shared owner resolving to CID 61/Mint).
		byCodeIndex := pipeline.CodeIndexToFunc(pt.result, ct, info.Version.CodeIndexOneBased)
		for _, ce := range pt.result.Codes {
			if owner, ok := pipeline.ResolveCodeOwner(ce, refToNamed, byCodeIndex); ok {
				edge := graphEdge{
					FromRef: ce.RefID,
					ToRef:   owner.RefID,
					Type:    "code_owner",
				}
				if err := edgeEnc.Encode(edge); err != nil {
					return fmt.Errorf("write edges.jsonl: %w", err)
				}
				edgeCount++
			}
		}
	}

	// Write code_map.jsonl.
	codeMapPath := filepath.Join(*outDir, "code_map.jsonl")
	codeMapFile, err := os.Create(codeMapPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", codeMapPath, err)
	}
	defer func() { _ = codeMapFile.Close() }()

	codeEnc := json.NewEncoder(codeMapFile)
	codeEnc.SetEscapeHTML(false)
	var codeMapCount int

	for _, pt := range parsed {
		byCodeIndex := pipeline.CodeIndexToFunc(pt.result, ct, info.Version.CodeIndexOneBased)
		for _, ce := range pt.result.Codes {
			owner, ok := pipeline.ResolveCodeOwner(ce, refToNamed, byCodeIndex)
			if !ok {
				continue
			}
			funcName := resolveName(owner)
			ownerName := resolveOwnerName(owner)
			entry := codeMapEntry{
				CodeRef:      ce.RefID,
				FunctionRef:  owner.RefID,
				FunctionName: funcName,
				OwnerName:    ownerName,
			}
			if err := codeEnc.Encode(entry); err != nil {
				return fmt.Errorf("write code_map.jsonl: %w", err)
			}
			codeMapCount++
		}
	}

	fmt.Fprintf(os.Stderr, "Wrote %d objects to %s\n", objectCount, objectsPath)
	fmt.Fprintf(os.Stderr, "Wrote %d edges to %s\n", edgeCount, edgesPath)
	fmt.Fprintf(os.Stderr, "Wrote %d code mappings to %s\n", codeMapCount, codeMapPath)

	return nil
}
