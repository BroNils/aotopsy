package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"aotopsy/internal/callgraph"
	"aotopsy/internal/cli"
	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/disasm"
	"aotopsy/internal/output"
	"aotopsy/internal/snapshot"

	"aotopsy/internal/lattice"
	"aotopsy/internal/lattice/render"
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
	pl *PoolLookups,
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
) (*DisasmResult, error) {
	// Build symbol map for cross-references during disassembly.
	symbols := make(map[uint64]string)
	for _, r := range ranges {
		va := codeVA + uint64(r.PCOffset) - codeOff
		if r.RefID >= 0 {
			symbols[va] = QualifiedCodeName(r.RefID, pl, r.PCOffset)
		} else {
			symbols[va] = fmt.Sprintf("stub_%x", r.PCOffset)
		}
	}
	// Merge VM stub symbols and discarded function symbols so that
	// call_edges.jsonl, signal.dot, and callgraph.dot show real names
	// instead of stub_<hex>/sub_<hex>. This mirrors LoadContext's
	// pattern (context.go:170-175). Without this, the signal graph's
	// IsInterestingCallee filter excludes real signal functions because
	// it filters out sub_* and 0x.. names. (F-036)
	for va, name := range BuildVMStubSymbols(info, fmtOpts) {
		symbols[va] = name
	}
	for va, name := range BuildDiscardedFunctionSymbols(clResult.Named, info.Version.CIDs, table, pl, codeVA, codeOff, info.Version.CodeIndexOneBased) {
		symbols[va] = name
	}
	lookup := disasm.PlaceholderLookup(symbols)

	ppAnn := disasm.PPAnnotator(poolDisplay)

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

	// Open all output files.
	indexFile, err := os.Create(filepath.Join(opts.OutDir, "index.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("create index: %w", err)
	}
	defer func() { _ = indexFile.Close() }()
	enc := json.NewEncoder(indexFile)
	enc.SetEscapeHTML(false)

	funcsFile, err := os.Create(filepath.Join(opts.OutDir, "functions.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("create functions.jsonl: %w", err)
	}
	defer func() { _ = funcsFile.Close() }()
	funcsEnc := json.NewEncoder(funcsFile)
	funcsEnc.SetEscapeHTML(false)

	edgesFile, err := os.Create(filepath.Join(opts.OutDir, "call_edges.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("create call_edges.jsonl: %w", err)
	}
	defer func() { _ = edgesFile.Close() }()
	edgesEnc := json.NewEncoder(edgesFile)
	edgesEnc.SetEscapeHTML(false)

	unresTHRFile, err := os.Create(filepath.Join(opts.OutDir, "unresolved_thr.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("create unresolved_thr.jsonl: %w", err)
	}
	defer func() { _ = unresTHRFile.Close() }()
	unresTHREnc := json.NewEncoder(unresTHRFile)
	unresTHREnc.SetEscapeHTML(false)

	stringRefsFile, err := os.Create(filepath.Join(opts.OutDir, "string_refs.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("create string_refs.jsonl: %w", err)
	}
	defer func() { _ = stringRefsFile.Close() }()
	stringRefsEnc := json.NewEncoder(stringRefsFile)
	stringRefsEnc.SetEscapeHTML(false)

	dr := &DisasmResult{}
	var funcInfos []callgraph.FuncInfo

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
		entry      DisasmIndexEntry
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

	compute := func(r *cluster.CodeRange, out *funcOutput, peep *disasm.PeepholeState) {
		if r.Size == 0 {
			out.skip = true
			return
		}
		funcStart := uint64(r.PCOffset) - codeOff
		funcEnd := funcStart + uint64(r.Size)
		if funcEnd > uint64(len(code)) {
			funcEnd = uint64(len(code))
		}
		if funcStart >= funcEnd {
			out.skip = true
			return
		}
		funcCode := code[funcStart:funcEnd]
		funcVA := codeVA + funcStart

		var funcName, ownerName, name string
		if r.RefID >= 0 {
			ci := pl.CodeNames[r.RefID]
			funcName = ci.FuncName
			ownerName = ci.OwnerName
			name = QualifiedName(ownerName, funcName, r.PCOffset)
		} else {
			funcName = fmt.Sprintf("stub_%x", r.PCOffset)
			name = funcName
		}
		out.name = name

		peep.Reset()
		insts := disasm.Disassemble(funcCode, disasm.Options{
			BaseAddr: funcVA,
			Symbols:  lookup,
		})

		thrCtxAnn := disasm.THRContextAnnotator(insts, thrFields)
		annotators := []disasm.Annotator{ppAnn, thrCtxAnn, peep.Annotate}

		filename := FuncRelPath(ownerName, funcName, r.PCOffset)
		out.filename = filename

		// Per-function files live at unique paths, so they can be written
		// here: their content and location do not depend on ordering.
		if err := output.WriteASM(opts.OutDir, filename, insts, lookup, annotators...); err != nil {
			out.err = fmt.Errorf("write asm %s: %w", filename, err)
			return
		}
		if err := output.WriteBin(opts.OutDir, filename, funcCode); err != nil {
			out.err = fmt.Errorf("write bin %s: %w", filename, err)
			return
		}

		out.entry = DisasmIndexEntry{
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
			Size:       int(r.Size),
			Name:       name,
			Owner:      ownerName,
			ParamCount: paramCount,
		}

		edges := disasm.ExtractCallEdgesCFG(name, insts, lookup, annotators)
		out.edges = edges
		for _, e := range edges {
			rec := disasm.CallEdgeRecord{
				FromFunc: name,
				FromPC:   fmt.Sprintf("0x%x", e.FromPC),
				Kind:     e.Kind,
				Reg:      e.Reg,
				Via:      e.Via,
			}
			if e.Kind == "bl" {
				if e.TargetName != "" {
					rec.Target = e.TargetName
				} else {
					rec.Target = fmt.Sprintf("0x%x", e.TargetPC)
				}
			}
			out.edgeRecs = append(out.edgeRecs, rec)
			out.edgeKinds = append(out.edgeKinds, e.Kind)
		}

		if opts.Graph {
			lcfg, nblocks := callgraph.BuildFuncCFG(name, insts, edges)
			if nblocks > 1 {
				g := &lattice.CFGGraph{Funcs: []*lattice.FuncCFG{lcfg}}
				out.cfgDot = render.DOTCFG(g, name)
				out.cfgPath = filepath.Join(cfgDir, filename+".dot")
			}
		}

		out.stringRefs = ExtractStringRefs(insts, poolDisplay, name)

		for _, a := range disasm.ExtractTHRAccesses(insts, thrFields) {
			if a.Resolved {
				continue
			}
			rec := disasm.UnresolvedTHRRecord{
				FuncName:  name,
				PC:        fmt.Sprintf("0x%x", a.PC),
				THROffset: fmt.Sprintf("0x%x", a.THROffset),
				Width:     a.Width,
				IsStore:   a.IsStore,
				Class:     "UNKNOWN",
			}
			if ann := thrCtxAnn(disasm.Inst{Addr: a.PC, Raw: 0}); ann != "" {
				switch {
				case strings.Contains(ann, "RUNTIME_ENTRY"):
					rec.Class = "RUNTIME_ENTRY"
				case strings.Contains(ann, "OBJSTORE"):
					rec.Class = "OBJSTORE"
				case strings.Contains(ann, "ISO_GROUP"):
					rec.Class = "ISO_GROUP"
				case strings.HasPrefix(ann, "THR."):
					continue
				}
			}
			out.thrRecs = append(out.thrRecs, rec)
		}
	}

	// One peephole state per worker: it is stateful across the instructions
	// of a single function and must not be shared between goroutines.
	peepholes := make([]*disasm.PeepholeState, workers)
	for i := range peepholes {
		peepholes[i] = disasm.NewPeepholeState(poolDisplay)
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
					compute(&ranges[i], &outputs[i-base], peepholes[w])
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
			if err := enc.Encode(o.entry); err != nil {
				return nil, fmt.Errorf("write index: %w", err)
			}
			if err := funcsEnc.Encode(o.funcRec); err != nil {
				return nil, fmt.Errorf("write functions.jsonl: %w", err)
			}
			for ei, rec := range o.edgeRecs {
				if err := edgesEnc.Encode(rec); err != nil {
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
					if err := os.MkdirAll(filepath.Dir(o.cfgPath), 0755); err != nil {
						return nil, fmt.Errorf("mkdir cfg: %w", err)
					}
					if err := os.WriteFile(o.cfgPath, []byte(o.cfgDot), 0644); err != nil {
						return nil, fmt.Errorf("write cfg dot %s: %w", o.filename, err)
					}
					dr.CFGCount++
				}
				funcInfos = append(funcInfos, callgraph.FuncInfo{
					Name:      o.name,
					CallEdges: o.edges,
				})
			}
			for _, sr := range o.stringRefs {
				if err := stringRefsEnc.Encode(sr); err != nil {
					return nil, fmt.Errorf("write string_refs.jsonl: %w", err)
				}
				dr.TotalStringRefs++
			}
			for _, rec := range o.thrRecs {
				if err := unresTHREnc.Encode(rec); err != nil {
					return nil, fmt.Errorf("write unresolved_thr.jsonl: %w", err)
				}
				dr.TotalUnresTHR++
			}
			dr.Written++
		}
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
	if opts.Graph && len(funcInfos) > 0 {
		cg := callgraph.BuildCallGraph(funcInfos)
		cgDOT := render.DOT(cg, "callgraph")
		cgPath := filepath.Join(opts.OutDir, "callgraph.dot")
		if err := os.WriteFile(cgPath, []byte(cgDOT), 0644); err != nil {
			return nil, fmt.Errorf("write callgraph.dot: %w", err)
		}
		opts.logf("  %scallgraph:%s %d nodes, %d edges -> %s%s%s\n",
			cli.Muted, cli.Reset, len(cg.Nodes), len(cg.Edges), cli.Blue, cgPath, cli.Reset)
		opts.logf("  %sCFG DOTs:%s %d -> %s%s%s\n", cli.Muted, cli.Reset, dr.CFGCount, cli.Blue, cfgDir, cli.Reset)
	}

	return dr, nil
}

// ExtractStringRefs scans instructions for PP loads that resolve to string values.
func ExtractStringRefs(insts []disasm.Inst, poolDisplay map[int]string, funcName string) []disasm.StringRefRecord {
	var refs []disasm.StringRefRecord
	peep := disasm.NewPeepholeState(poolDisplay)

	for _, inst := range insts {
		// Check single-instruction PP load: LDR Xt, [X27, #imm]. X27 = ARM64
		// object-pool pointer -- this whole function is only ever reached
		// for ARM64 input (pipeline.Run rejects x86_64 before this stage
		// runs), so 27 is not a magic number that needs to vary by arch.
		if baseReg, byteOff, ok := disasm.IsLDR64UnsignedOffsetExported(inst.Raw); ok && baseReg == 27 {
			idx, idxOK := disasm.ARM64PoolIndex(byteOff)
			if s, found := poolDisplay[idx]; idxOK && found && len(s) > 0 && s[0] == '"' {
				val, err := strconv.Unquote(s)
				if err == nil {
					refs = append(refs, disasm.StringRefRecord{
						Func:    funcName,
						PC:      fmt.Sprintf("0x%x", inst.Addr),
						Kind:    "PP",
						PoolIdx: idx,
						Value:   val,
					})
				}
			}
		}

		// Check two-instruction peephole: ADD Xd, X27, #upper + LDR Xt, [Xd, #lower]
		ann := peep.Annotate(inst)
		if ann != "" && strings.HasPrefix(ann, "PP[") {
			closeBracket := strings.IndexByte(ann, ']')
			if closeBracket > 3 {
				idxStr := ann[3:closeBracket]
				idx, err := strconv.Atoi(idxStr)
				if err == nil {
					rest := strings.TrimSpace(ann[closeBracket+1:])
					if len(rest) > 0 && rest[0] == '"' {
						val, err := strconv.Unquote(rest)
						if err == nil {
							refs = append(refs, disasm.StringRefRecord{
								Func:    funcName,
								PC:      fmt.Sprintf("0x%x", inst.Addr),
								Kind:    "PP_peep",
								PoolIdx: idx,
								Value:   val,
							})
						}
					}
				}
			}
		}
	}
	return refs
}
