package analysis

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"aotopsy/internal/callgraph"
	"aotopsy/internal/cli"
	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
	"aotopsy/internal/naming"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/strutil"

	"aotopsy/internal/lattice"
	"aotopsy/internal/lattice/render"
)

// RunDisasmStageX86 is RunDisasmStage's x86_64 counterpart: same output
// contract (functions.jsonl, call_edges.jsonl, string_refs.jsonl,
// index.jsonl, an empty unresolved_thr.jsonl, asm/*.txt, and, with
// --graph, cfg/*.dot + callgraph.dot), built on internal/disasm's
// x86.go/dataflow_x86.go (ScanX86FunctionCFG) and internal/callgraph's
// cfg_x86.go (BuildX86FuncCFG, itself built on internal/decompiler's x86
// CFG lifter) instead of the ARM64-only Disassemble/ExtractCallEdgesCFG/
// BuildCFG chain.
func RunDisasmStageX86(
	opts *Opts,
	pl *naming.PoolLookups,
	poolDisplay map[int]string,
	clResult *cluster.Result,
	ranges []cluster.CodeRange,
	code []byte,
	codeOff uint64,
	codeVA uint64,
	info *snapshot.Info,
	table *cluster.InstructionsTable,
	fmtOpts dartfmt.Options,
	thrFields map[int]string, // H-3 fix: pass THR fields for annotation
	elfFuncSyms map[uint64]string,
) (*DisasmResult, error) {
	symbols := make(map[uint64]string)
	for _, r := range ranges {
		va := codeVA + uint64(r.PCOffset) - codeOff
		if r.RefID >= 0 {
		symbols[va] = naming.QualifiedCodeName(r.RefID, pl, r.PCOffset)
		} else {
			symbols[va] = fmt.Sprintf("stub_%x", r.PCOffset)
		}
	}
	// Merge VM stub symbols and discarded function symbols (F-036).
	// Same pattern as RunDisasmStage and LoadContext (context.go:170-175).
	for va, name := range naming.BuildVMStubSymbols(info, fmtOpts) {
		symbols[va] = name
	}
	for va, name := range naming.BuildDiscardedFunctionSymbols(clResult.Named, info.Version.CIDs, table, pl, codeVA, codeOff, info.Version.CodeIndexOneBased) {
		symbols[va] = name
	}
	lookup := disasm.PlaceholderLookup(symbols)

	opts.stagef("disasm", "%s%d%s functions (x86_64), pool %s%d%s entries (%d resolved)",
		cli.Gold, len(ranges), cli.Reset, cli.Gold, len(clResult.Pool), cli.Reset, len(poolDisplay))

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

	n := len(ranges)
	if opts.Limit > 0 && opts.Limit < n {
		n = opts.Limit
	}

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

	// unresolved_thr.jsonl: always created (downstream tooling/tests may
	// expect the file to exist) but left empty -- see doc comment above.
	unresTHRFile, err := os.Create(filepath.Join(opts.OutDir, "unresolved_thr.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("create unresolved_thr.jsonl: %w", err)
	}
	_ = unresTHRFile.Close()

	stringRefsFile, err := os.Create(filepath.Join(opts.OutDir, "string_refs.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("create string_refs.jsonl: %w", err)
	}
	defer func() { _ = stringRefsFile.Close() }()
	stringRefsEnc := json.NewEncoder(stringRefsFile)
	stringRefsEnc.SetEscapeHTML(false)

	dr := &DisasmResult{}
	var funcInfos []callgraph.FuncInfo

	for i := 0; i < n; i++ {
		r := &ranges[i]
		if r.Size == 0 {
			continue
		}

		funcStart := uint64(r.PCOffset) - codeOff
		funcEnd := funcStart + uint64(r.Size)
		if funcEnd > uint64(len(code)) {
			funcEnd = uint64(len(code))
		}
		if funcStart >= funcEnd {
			continue
		}
		funcCode := code[funcStart:funcEnd]
		funcVA := codeVA + funcStart

		var funcName, ownerName, name string
		if r.RefID >= 0 {
			ci := pl.CodeNames[r.RefID]
			funcName = ci.FuncName
			ownerName = ci.OwnerName
			name = ci.Qualified(r.PCOffset)
			if funcName == "" {
			name = naming.ElfStubName(elfFuncSyms, funcVA, name)
			}
		} else {
			funcName = fmt.Sprintf("stub_%x", r.PCOffset)
			name = funcName
		}

		if err := writeX86ASM(asmDir, naming.FuncRelPath(ownerName, funcName, r.PCOffset), funcCode, funcVA, lookup); err != nil {
			return nil, fmt.Errorf("write asm %s: %w", name, err)
		}

		entry := strutil.DisasmIndexEntry{
			Name:      funcName,
			OwnerName: ownerName,
			RefID:     r.RefID,
			OwnerRef:  r.OwnerRef,
			PCOffset:  r.PCOffset,
			Size:      r.Size,
			File:      filepath.ToSlash(filepath.Join("asm", naming.FuncRelPath(ownerName, funcName, r.PCOffset)+".txt")),
		}
		if err := enc.Encode(entry); err != nil {
			return nil, fmt.Errorf("write index: %w", err)
		}

		var paramCount int
		if r.RefID >= 0 {
			paramCount = pl.CodeNames[r.RefID].ParamCount
		}
		if err := funcsEnc.Encode(disasm.FuncRecord{
			PC: fmt.Sprintf("0x%x", funcVA), Size: int(r.Size),
			Name: name, Owner: ownerName, ParamCount: paramCount,
		}); err != nil {
			return nil, fmt.Errorf("write functions.jsonl: %w", err)
		}

		scan := disasm.ScanX86FunctionCFG(funcCode, funcVA, lookup, poolDisplay, name, thrFields)
		for _, e := range scan.Edges {
			rec := disasm.CallEdgeRecord{
				FromFunc: name, FromPC: fmt.Sprintf("0x%x", e.FromPC),
				Kind: e.Kind, Reg: e.Reg, Via: e.Via,
			}
			if e.Kind == "call" {
				if e.TargetName != "" {
					rec.Target = e.TargetName
				} else {
					rec.Target = fmt.Sprintf("0x%x", e.TargetPC)
				}
			}
			if err := edgesEnc.Encode(rec); err != nil {
				return nil, fmt.Errorf("write call_edges.jsonl: %w", err)
			}
			dr.TotalEdges++
			if e.Kind == "call_indirect" {
				dr.TotalBLR++
				if e.Via != "" {
					dr.BLRAnnotated++
				} else {
					dr.BLRUnannotated++
				}
			}
		}
		for _, sr := range scan.StringRefs {
			if err := stringRefsEnc.Encode(sr); err != nil {
				return nil, fmt.Errorf("write string_refs.jsonl: %w", err)
			}
			dr.TotalStringRefs++
		}

		if opts.Graph {
			lcfg, nblocks := callgraph.BuildX86FuncCFG(name, funcCode, funcVA, scan.Edges)
			if nblocks > 1 {
				g := &lattice.CFGGraph{Funcs: []*lattice.FuncCFG{lcfg}}
				dot := render.DOTCFG(g, name)
				dotPath := filepath.Join(cfgDir, naming.FuncRelPath(ownerName, funcName, r.PCOffset)+".dot")
				if err := os.MkdirAll(filepath.Dir(dotPath), 0755); err != nil {
					return nil, fmt.Errorf("mkdir cfg: %w", err)
				}
				if err := os.WriteFile(dotPath, []byte(dot), 0o600); err != nil {
					return nil, fmt.Errorf("write cfg dot %s: %w", name, err)
				}
				dr.CFGCount++
			}
			funcInfos = append(funcInfos, callgraph.FuncInfo{Name: name, CallEdges: scan.Edges})
		}

		dr.Written++
	}

	if opts.Graph && len(funcInfos) > 0 {
		cg := callgraph.BuildCallGraph(funcInfos)
		cgDOT := render.DOT(cg, "callgraph")
		cgPath := filepath.Join(opts.OutDir, "callgraph.dot")
		if err := os.WriteFile(cgPath, []byte(cgDOT), 0o600); err != nil {
			return nil, fmt.Errorf("write callgraph.dot: %w", err)
		}
		opts.logf("  %scallgraph:%s %d nodes, %d edges -> %s%s%s\n",
			cli.Muted, cli.Reset, len(cg.Nodes), len(cg.Edges), cli.Blue, cgPath, cli.Reset)
		opts.logf("  %sCFG DOTs:%s %d -> %s%s%s\n", cli.Muted, cli.Reset, dr.CFGCount, cli.Blue, cfgDir, cli.Reset)
	}

	return dr, nil
}

// writeX86ASM writes a simple annotated disassembly listing -- a lighter
// equivalent of output.WriteASM (which is built around the ARM64 Inst
// type). Kept minimal: this is read opportunistically by the signal
// stage for code-snippet context and gracefully skipped if absent, not a
// hard dependency.
func writeX86ASM(asmDir, relName string, funcCode []byte, funcVA uint64, symbols disasm.SymbolLookup) error {
	path := filepath.Join(asmDir, relName+".txt")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path) //nolint:gosec // path is built from this run's own --out directory, not untrusted input
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	sdk.WalkX86(funcCode, funcVA, func(d sdk.X86Decoded) bool {
		if d.Bad {
			_, _ = fmt.Fprintf(f, "0x%x: <bad>\n", d.VA)
			return true
		}
		line := d.Inst.String()
		if target, ok := sdk.X86RelTarget(d.Inst, d.VA, d.Len); ok {
			if name, ok := symbols(target); ok {
				line += fmt.Sprintf("  ; -> %s", name)
			} else {
				line += fmt.Sprintf("  ; -> 0x%x", target)
			}
		}
		_, _ = fmt.Fprintf(f, "0x%x: %s\n", d.VA, line)
		return true
	})
	return nil
}
