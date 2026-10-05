package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"aotopsy/internal/cli"
	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/disasm"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/naming"
	"aotopsy/internal/output"
	"aotopsy/internal/render"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/strutil"
	"aotopsy/internal/thraudit"
)

// DisasmResult holds summary stats from the disassembly stage.
type DisasmResult struct {
	Written         int
	TotalEdges      int
	TotalBLR        int
	BLRAnnotated    int
	BLRUnannotated  int
	TotalUnresTHR   int
	TotalStringRefs int
	CFGCount        int
}

// RunDisasmStage executes the per-function disassembly loop.
func RunDisasmStage(
	opts *Opts,
	pl *naming.PoolLookups,
	poolDisplay map[int]string,
	clResult *cluster.Result,
	ranges []cluster.CodeRange,
	code []byte,
	codeOff uint64,
	codeVA uint64,
	thrFields map[int]string,
	info *snapshot.Info,
	table *cluster.InstructionsTable,
	fmtOpts dartfmt.Options,
	elfFuncSyms map[uint64]string,
) (*DisasmResult, error) {
	// Build symbol map for cross-references during disassembly. Shared with
	// LoadContext and RunDisasmStageX86 so a name recovered anywhere reaches
	// call_edges.jsonl, signal.dot and callgraph.dot too -- the signal graph's
	// IsInterestingCallee filter drops sub_*/0x.. names, so a stub named in
	// only one of the three builders silently vanished from the graph. (F-036)
	vaImage := cluster.CodeImage{CodeVA: codeVA, CodeOff: codeOff}
	symbolSet, err := BuildSymbolNames(ranges, vaImage, pl, clResult, info, table,
		fmtOpts, info.IsolateData.Data)
	if err != nil {
		return nil, err
	}
	symbols := symbolSet.Names
	lookup := disasm.PlaceholderLookup(symbols)

	ppAnn := disasm.PPAnnotator(poolDisplay)
	closureEntry := disasm.ClosureEntryFor(info.Version.DartVersion, info.Version.CompressedPointers)

	opts.stagef("disasm", "%s%d%s functions, pool %s%d%s entries (%d resolved)",
		cli.Gold, len(ranges), cli.Reset, cli.Gold, len(clResult.Pool), cli.Reset, len(poolDisplay))

	// Create output directories.
	asmDir := filepath.Join(opts.OutDir, "asm")
	if err := os.MkdirAll(asmDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir asm: %w", err)
	}
	cfgDir := filepath.Join(opts.OutDir, "cfg")
	if opts.Graph {
		if err := os.MkdirAll(cfgDir, 0755); err != nil {
			return nil, fmt.Errorf("mkdir cfg: %w", err)
		}
	}

	// Limit function count.
	n := len(ranges)
	if opts.Limit > 0 && opts.Limit < n {
		n = opts.Limit
	}

	// Open all shared JSONL outputs through the same pinned-root atomic stream
	// writer used everywhere else. They remain unpublished until each stream has
	// encoded, synced, and closed successfully; the outer directory transaction
	// then publishes the complete analysis generation as one unit.
	indexWriter, err := jsonutil.NewJSONLWriterUnder[strutil.DisasmIndexEntry](opts.OutDir, "index.jsonl")
	if err != nil {
		return nil, fmt.Errorf("create index: %w", err)
	}
	defer func() { _ = indexWriter.Abort() }()

	funcsWriter, err := jsonutil.NewJSONLWriterUnder[disasm.FuncRecord](opts.OutDir, "functions.jsonl")
	if err != nil {
		return nil, fmt.Errorf("create functions.jsonl: %w", err)
	}
	defer func() { _ = funcsWriter.Abort() }()

	edgesWriter, err := jsonutil.NewJSONLWriterUnder[disasm.CallEdgeRecord](opts.OutDir, "call_edges.jsonl")
	if err != nil {
		return nil, fmt.Errorf("create call_edges.jsonl: %w", err)
	}
	defer func() { _ = edgesWriter.Abort() }()

	unresTHRWriter, err := jsonutil.NewJSONLWriterUnder[disasm.UnresolvedTHRRecord](opts.OutDir, "unresolved_thr.jsonl")
	if err != nil {
		return nil, fmt.Errorf("create unresolved_thr.jsonl: %w", err)
	}
	defer func() { _ = unresTHRWriter.Abort() }()

	stringRefsWriter, err := jsonutil.NewJSONLWriterUnder[disasm.StringRefRecord](opts.OutDir, "string_refs.jsonl")
	if err != nil {
		return nil, fmt.Errorf("create string_refs.jsonl: %w", err)
	}
	defer func() { _ = stringRefsWriter.Abort() }()

	dr := &DisasmResult{}
	var funcRecs []disasm.FuncRecord
	var edgeRecs []disasm.CallEdgeRecord
	// Pre-InstructionsTable snapshots can contain many Code objects that share
	// one deduplicated instructions payload. When those aliases resolve to the
	// same semantic name they also intentionally share one canonical asm path
	// (DisasmArtifactFiles accepts exactly that case). Parallel workers must not
	// race to atomically replace that same .txt/.bin pair. Claim the path once;
	// every alias still emits its own functions/index metadata below.
	var artifactMu sync.Mutex
	writtenArtifacts := make(map[string]struct{})
	claimArtifact := func(name string) bool {
		artifactMu.Lock()
		defer artifactMu.Unlock()
		if _, exists := writtenArtifacts[name]; exists {
			return false
		}
		writtenArtifacts[name] = struct{}{}
		return true
	}

	// Disassembly runs in parallel (each function is independent: read-only
	// code slice, read-only lookup), but every SHARED output is written by
	// the main goroutine in input order.
	//
	// The first parallel version had each worker take a mutex and write
	// directly to the shared encoders. That made functions.jsonl,
	// call_edges.jsonl, string_refs.jsonl, index.jsonl and unresolved_thr.jsonl
	// come out in whatever order the workers happened to finish -- a different
	// order on every run of the same binary, which breaks report diffing and
	// funcdiff. It also read `disasmErr` outside the mutex, a data race.
	//
	// Instead the work is done in chunks: a chunk is computed in parallel,
	// then drained in order. The chunk bounds how many decoded functions are
	// live at once, which matters on the 6 GB host (AGENTS.md).
	workers := runtime.NumCPU()
	if workers > 4 {
		workers = 4
	}
	if workers < 1 {
		workers = 1
	}
	const chunkPerWorker = 8
	chunkSize := workers * chunkPerWorker

	// Per-function computed output, held only until its chunk is drained.
	type funcOutput struct {
		skip       bool
		filename   string
		entry      strutil.DisasmIndexEntry
		funcRec    disasm.FuncRecord
		name       string
		edgeRecs   []disasm.CallEdgeRecord
		edgeKinds  []string // parallel to edgeRecs: "bl"/"blr"/...
		edges      []disasm.CallEdge
		stringRefs []disasm.StringRefRecord
		thrRecs    []disasm.UnresolvedTHRRecord
		cfgDot     string
		cfgPath    string
		err        error
	}

	codeImage := NewCodeImage(code, codeVA, codeOff, pl, elfFuncSyms)
	compute := func(r *cluster.CodeRange, out *funcOutput) {
		fs, ok := codeImage.Slice(*r)
		if !ok {
			out.skip = true
			return
		}
		funcCode := fs.Code
		funcVA := fs.VA

		var funcName, ownerName, fallbackName string
		if r.RefID >= 0 {
			ci := pl.CodeNames[r.RefID]
			funcName = ci.FuncName
			ownerName = ci.OwnerName
			fallbackName = ci.Qualified(r.PCOffset)
			if funcName == "" {
				fallbackName = naming.ElfStubName(elfFuncSyms, funcVA, fallbackName)
			}
		} else {
			funcName = fmt.Sprintf("stub_%x", r.PCOffset)
			fallbackName = funcName
		}
		name, funcName := authoritativeDisasmName(symbols, funcVA, ownerName, funcName, fallbackName)
		out.name = name

		insts := disasm.Disassemble(funcCode, disasm.Options{
			BaseAddr: funcVA,
			Symbols:  lookup,
		})

		thrCtxAnn := disasm.THRContextAnnotator(insts, thrFields)
		ppCtxAnn := disasm.PPContextAnnotator(insts, poolDisplay)
		closureAnn := disasm.ClosureCallAnnotator(insts, closureEntry)
		annotators := []disasm.Annotator{ppAnn, thrCtxAnn, ppCtxAnn, closureAnn}

		filename := naming.FuncRelPath(ownerName, funcName, r.PCOffset)
		out.filename = filename

		if claimArtifact(filename) {
			if err := output.WriteASM(opts.OutDir, filename, insts, lookup, annotators...); err != nil {
				out.err = fmt.Errorf("write asm %s: %w", filename, err)
				return
			}
			if err := output.WriteBin(opts.OutDir, filename, funcCode); err != nil {
				out.err = fmt.Errorf("write bin %s: %w", filename, err)
				return
			}
		}

		out.entry = strutil.DisasmIndexEntry{
			Name:      funcName,
			OwnerName: ownerName,
			RefID:     r.RefID,
			OwnerRef:  r.OwnerRef,
			PCOffset:  r.PCOffset,
			Size:      r.Size,
			File:      filepath.ToSlash(filepath.Join("asm", filename+".txt")),
		}

		var paramCount int
		if r.RefID >= 0 {
			paramCount = pl.CodeNames[r.RefID].ParamCount
		}
		out.funcRec = disasm.FuncRecord{
			PC:         fmt.Sprintf("0x%x", funcVA),
			PCOffset:   r.PCOffset,
			RefID:      r.RefID,
			Size:       int(r.Size),
			Name:       name,
			Owner:      ownerName,
			ParamCount: paramCount,
		}

		edges := disasm.ExtractCallEdgesCFG(name, insts, lookup, annotators, poolDisplay)
		out.edges = edges
		for _, e := range edges {
			rec := disasm.CallEdgeRecord{
				FromFunc: name,
				FromPC:   fmt.Sprintf("0x%x", e.FromPC),
				Kind:     e.Kind,
				Reg:      e.Reg,
				Via:      e.Via,
			}
			if e.Kind == "bl" && e.TargetValid {
				rec.TargetAddress = fmt.Sprintf("0x%x", e.TargetPC)
				if e.TargetName != "" {
					rec.Target = e.TargetName
				}
			}
			out.edgeRecs = append(out.edgeRecs, rec)
			out.edgeKinds = append(out.edgeKinds, e.Kind)
		}

		if opts.Graph {
			dcfg := disasm.BuildCFG(name, insts)
			if len(dcfg.Blocks) > 1 {
				out.cfgDot = render.CFGDOT(dcfg, out.edgeRecs, render.NASA)
				out.cfgPath = "cfg/" + filename + ".dot"
			}
		}

		out.stringRefs = ExtractStringRefs(insts, poolDisplay, name)

		thrAccesses := disasm.ExtractTHRAccesses(insts, thrFields)
		thrAuditRecords := disasm.BuildAuditRecords(thrAccesses, insts, thraudit.Provenance{Arch: thraudit.ArchARM64}, name)
		for _, a := range thrAuditRecords {
			if a.Resolved {
				continue
			}
			out.thrRecs = append(out.thrRecs, disasm.UnresolvedRecordFromAudit(a))
		}
	}

	outputs := make([]funcOutput, chunkSize)

	for base := 0; base < n; base += chunkSize {
		end := base + chunkSize
		if end > n {
			end = n
		}
		for i := range outputs[:end-base] {
			outputs[i] = funcOutput{}
		}
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for i := base + w; i < end; i += workers {
					compute(&ranges[i], &outputs[i-base])
				}
			}(w)
		}
		wg.Wait()

		// Drain in input order -- this is what makes the JSONL outputs
		// reproducible.
		for i := base; i < end; i++ {
			o := &outputs[i-base]
			if o.err != nil {
				return nil, o.err
			}
			if o.skip {
				continue
			}
			if err := indexWriter.Write(&o.entry); err != nil {
				return nil, fmt.Errorf("write index: %w", err)
			}
			if err := funcsWriter.Write(&o.funcRec); err != nil {
				return nil, fmt.Errorf("write functions.jsonl: %w", err)
			}
			for ei, rec := range o.edgeRecs {
				if err := edgesWriter.Write(&rec); err != nil {
					return nil, fmt.Errorf("write call_edges.jsonl: %w", err)
				}
				dr.TotalEdges++
				if o.edgeKinds[ei] == "blr" {
					dr.TotalBLR++
					if rec.Via != "" {
						dr.BLRAnnotated++
					} else {
						dr.BLRUnannotated++
					}
				}
			}
			if opts.Graph {
				if o.cfgPath != "" {
					if err := output.WriteArtifactFile(opts.OutDir, o.cfgPath, []byte(o.cfgDot), 0o644); err != nil {
						return nil, fmt.Errorf("write cfg dot %s: %w", o.filename, err)
					}
					dr.CFGCount++
				}
				funcRecs = append(funcRecs, o.funcRec)
				edgeRecs = append(edgeRecs, o.edgeRecs...)
			}
			for _, sr := range o.stringRefs {
				if err := stringRefsWriter.Write(&sr); err != nil {
					return nil, fmt.Errorf("write string_refs.jsonl: %w", err)
				}
				dr.TotalStringRefs++
			}
			for _, rec := range o.thrRecs {
				if err := unresTHRWriter.Write(&rec); err != nil {
					return nil, fmt.Errorf("write unresolved_thr.jsonl: %w", err)
				}
				dr.TotalUnresTHR++
			}
			dr.Written++
		}
	}

	if err := indexWriter.Close(); err != nil {
		return nil, fmt.Errorf("commit index.jsonl: %w", err)
	}
	if err := funcsWriter.Close(); err != nil {
		return nil, fmt.Errorf("commit functions.jsonl: %w", err)
	}
	if err := edgesWriter.Close(); err != nil {
		return nil, fmt.Errorf("commit call_edges.jsonl: %w", err)
	}
	if err := unresTHRWriter.Close(); err != nil {
		return nil, fmt.Errorf("commit unresolved_thr.jsonl: %w", err)
	}
	if err := stringRefsWriter.Close(); err != nil {
		return nil, fmt.Errorf("commit string_refs.jsonl: %w", err)
	}

	opts.logf("  %sfunctions:%s %d -> %s%s%s\n", cli.Muted, cli.Reset, dr.Written, cli.Blue, asmDir, cli.Reset)
	opts.logf("  %scall edges:%s %d (%d BLR: %d annotated, %d unannotated)\n",
		cli.Muted, cli.Reset, dr.TotalEdges, dr.TotalBLR, dr.BLRAnnotated, dr.BLRUnannotated)
	opts.logf("  %sstring refs:%s %d\n", cli.Muted, cli.Reset, dr.TotalStringRefs)
	if dr.TotalBLR > 0 {
		pct := float64(dr.BLRAnnotated) / float64(dr.TotalBLR) * 100
		opts.logf("  %sBLR annotation:%s %.1f%%\n", cli.Muted, cli.Reset, pct)
	}

	// Build call graph.
	if opts.Graph && len(funcRecs) > 0 {
		cgDOT := render.CallgraphDOT(funcRecs, edgeRecs, "callgraph", render.NASA, 0)
		cgPath := filepath.Join(opts.OutDir, "callgraph.dot")
		if err := output.WriteFileAtomic(cgPath, []byte(cgDOT), 0o644); err != nil {
			return nil, fmt.Errorf("write callgraph.dot: %w", err)
		}
		opts.logf("  %scallgraph:%s %d funcs, %d edges -> %s%s%s\n",
			cli.Muted, cli.Reset, len(funcRecs), len(edgeRecs), cli.Blue, cgPath, cli.Reset)
		opts.logf("  %sCFG DOTs:%s %d -> %s%s%s\n", cli.Muted, cli.Reset, dr.CFGCount, cli.Blue, cfgDir, cli.Reset)
	}

	return dr, nil
}

func authoritativeDisasmName(symbols map[uint64]string, va uint64, ownerName, funcName, fallback string) (string, string) {
	name := symbols[va]
	if name == "" || (isGenericDisasmName(name) && !isGenericDisasmName(fallback)) {
		name = fallback
	}
	if ownerName != "" {
		prefix := ownerName + "."
		if strings.HasPrefix(name, prefix) {
			return name, strings.TrimPrefix(name, prefix)
		}
	}
	if funcName == "" || strings.HasPrefix(funcName, "stub_") || strings.HasPrefix(funcName, "sub_") {
		funcName = name
	}
	return name, funcName
}

func isGenericDisasmName(name string) bool {
	return strings.HasPrefix(name, "sub_") || strings.HasPrefix(name, "stub_") || strings.HasPrefix(name, "Stub_")
}

// ExtractStringRefs scans instructions for PP loads that resolve to string values.
func ExtractStringRefs(insts []disasm.Inst, poolDisplay map[int]string, funcName string) []disasm.StringRefRecord {
	var refs []disasm.StringRefRecord
	for _, access := range disasm.ExtractARM64PoolAccesses(insts, poolDisplay) {
		if access.Kind != disasm.ARM64PoolAccessLoad || access.RegClass != disasm.ARM64PoolRegGPR {
			continue
		}
		s, found := poolDisplay[access.PoolIndex]
		if !found || len(s) == 0 || s[0] != '"' {
			continue
		}
		val, err := strconv.Unquote(s)
		if err != nil {
			continue
		}
		kind := "PP_peep"
		if access.Direct {
			kind = "PP"
		}
		refs = append(refs, disasm.StringRefRecord{
			Func:    funcName,
			PC:      fmt.Sprintf("0x%x", access.PC),
			Kind:    kind,
			PoolIdx: access.PoolIndex,
			Value:   val,
		})
	}
	return refs
}
