package analysis

import (
	"aotopsy/internal/arch/x86"
	"fmt"
	"io"
	"os"
	"path/filepath"

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
)

// RunDisasmStageX86 is RunDisasmStage's x86_64 counterpart: same output
// contract (functions.jsonl, call_edges.jsonl, string_refs.jsonl,
// index.jsonl, an empty unresolved_thr.jsonl, asm/*.txt, and, with
// --graph, cfg/*.dot + callgraph.dot), built on internal/disasm's
// x86.go/dataflowx86.go (ScanX86FunctionCFG) and internal/callgraph's
// cfgx86.go (BuildX86FuncCFG, itself built on internal/decompiler's x86
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
	// See RunDisasmStage: one shared builder for all three call sites. (F-036)
	vaImage := cluster.CodeImage{CodeVA: codeVA, CodeOff: codeOff}
	symbolSet, err := BuildSymbolNames(ranges, vaImage, pl, clResult, info, table,
		fmtOpts, info.IsolateData.Data)
	if err != nil {
		return nil, err
	}
	symbols := symbolSet.Names
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

	dr := &DisasmResult{}
	indexRecs := make([]strutil.DisasmIndexEntry, 0, n)
	funcRecs := make([]disasm.FuncRecord, 0, n)
	edgeRecs := make([]disasm.CallEdgeRecord, 0)
	unresTHRRecs := make([]disasm.UnresolvedTHRRecord, 0)
	stringRefRecs := make([]disasm.StringRefRecord, 0)

	codeImage := NewCodeImage(code, codeVA, codeOff, pl, elfFuncSyms)
	for i := 0; i < n; i++ {
		r := &ranges[i]
		fs, ok := codeImage.Slice(*r)
		if !ok {
			continue
		}
		funcCode := fs.Code
		funcVA := fs.VA

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

		relName := naming.FuncRelPath(ownerName, funcName, r.PCOffset)
		if err := writeX86ASM(asmDir, relName, funcCode, funcVA, lookup); err != nil {
			return nil, fmt.Errorf("write asm %s: %w", name, err)
		}
		// The raw bytes are what BuildSignalContent re-decodes for its
		// per-function snippets, and what `_debug graph` rebuilds CFGs
		// from. Only the ARM64 stage used to write them, so on x86_64
		// every consumer silently found nothing and skipped.
		if err := output.WriteBin(opts.OutDir, relName, funcCode); err != nil {
			return nil, fmt.Errorf("write bin %s: %w", name, err)
		}

		entry := strutil.DisasmIndexEntry{
			Name:      funcName,
			OwnerName: ownerName,
			RefID:     r.RefID,
			OwnerRef:  r.OwnerRef,
			PCOffset:  r.PCOffset,
			Size:      r.Size,
			File:      filepath.ToSlash(filepath.Join("asm", relName+".txt")),
		}
		indexRecs = append(indexRecs, entry)

		var paramCount int
		if r.RefID >= 0 {
			paramCount = pl.CodeNames[r.RefID].ParamCount
		}
		fRec := disasm.FuncRecord{
			PC: fmt.Sprintf("0x%x", funcVA), PCOffset: r.PCOffset, RefID: r.RefID, Size: int(r.Size),
			Name: name, Owner: ownerName, ParamCount: paramCount,
		}
		funcRecs = append(funcRecs, fRec)

		var fnEdgeRecs []disasm.CallEdgeRecord
		scan := disasm.ScanX86FunctionCFG(funcCode, funcVA, lookup, poolDisplay, name, thrFields)
		for _, e := range scan.Edges {
			rec := disasm.CallEdgeRecord{
				FromFunc: name, FromPC: fmt.Sprintf("0x%x", e.FromPC),
				Kind: e.Kind, Reg: e.Reg, Via: e.Via,
			}
			if e.Kind == "call" && e.TargetValid {
				if e.TargetName != "" {
					rec.Target = e.TargetName
				} else {
					rec.Target = fmt.Sprintf("0x%x", e.TargetPC)
				}
			}
			edgeRecs = append(edgeRecs, rec)
			dr.TotalEdges++
			if opts.Graph {
				fnEdgeRecs = append(fnEdgeRecs, rec)
			}
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
			stringRefRecs = append(stringRefRecs, sr)
			dr.TotalStringRefs++
		}

		thrAccs := disasm.ExtractX86THRAccesses(funcCode, funcVA, thrFields)
		for _, acc := range thrAccs {
			if !acc.Resolved {
				rec := disasm.UnresolvedTHRRecord{
					FuncName:  name,
					PC:        fmt.Sprintf("0x%x", acc.PC),
					THROffset: fmt.Sprintf("0x%x", acc.THROffset),
					Width:     acc.Width,
					IsStore:   acc.IsStore,
					Class:     "UNKNOWN",
				}
				unresTHRRecs = append(unresTHRRecs, rec)
			}
		}

		if opts.Graph {
			dcfg := disasm.BuildX86CFG(name, funcCode, funcVA)
			if len(dcfg.Blocks) > 1 {
				dot := render.CFGDOT(dcfg, fnEdgeRecs, render.NASA)
				dotPath := filepath.Join(cfgDir, relName+".dot")
				if err := os.MkdirAll(filepath.Dir(dotPath), 0755); err != nil {
					return nil, fmt.Errorf("mkdir cfg: %w", err)
				}
				if err := output.WriteFileAtomic(dotPath, []byte(dot), 0o600); err != nil {
					return nil, fmt.Errorf("write cfg dot %s: %w", name, err)
				}
				dr.CFGCount++
			}
		}

		dr.Written++
	}

	for _, item := range []struct {
		name  string
		write func() error
	}{
		{"index.jsonl", func() error {
			_, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "index.jsonl"), indexRecs)
			return err
		}},
		{"functions.jsonl", func() error {
			_, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "functions.jsonl"), funcRecs)
			return err
		}},
		{"call_edges.jsonl", func() error {
			_, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "call_edges.jsonl"), edgeRecs)
			return err
		}},
		{"unresolved_thr.jsonl", func() error {
			_, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "unresolved_thr.jsonl"), unresTHRRecs)
			return err
		}},
		{"string_refs.jsonl", func() error {
			_, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "string_refs.jsonl"), stringRefRecs)
			return err
		}},
	} {
		if err := item.write(); err != nil {
			return nil, fmt.Errorf("write %s: %w", item.name, err)
		}
	}

	if opts.Graph && len(funcRecs) > 0 {
		cgDOT := render.CallgraphDOT(funcRecs, edgeRecs, "callgraph", render.NASA, 0)
		cgPath := filepath.Join(opts.OutDir, "callgraph.dot")
		if err := output.WriteFileAtomic(cgPath, []byte(cgDOT), 0o600); err != nil {
			return nil, fmt.Errorf("write callgraph.dot: %w", err)
		}
		opts.logf("  %scallgraph:%s %d funcs, %d edges -> %s%s%s\n",
			cli.Muted, cli.Reset, len(funcRecs), len(edgeRecs), cli.Blue, cgPath, cli.Reset)
		opts.logf("  %sCFG DOTs:%s %d -> %s%s%s\n", cli.Muted, cli.Reset, dr.CFGCount, cli.Blue, cfgDir, cli.Reset)
	}

	return dr, nil
}

// writeX86ASM writes a simple annotated disassembly listing -- a lighter
// equivalent of output.WriteASM (which is built around the ARM64 Inst
// type). Kept minimal: it is the human-readable listing only. Consumers
// that need to re-decode instructions read the .bin written alongside it.
func writeX86ASM(asmDir, relName string, funcCode []byte, funcVA uint64, symbols disasm.SymbolLookup) error {
	path := filepath.Join(asmDir, relName+".txt")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return output.WriteAtomic(path, 0o644, func(w io.Writer) error {
		var writeErr error
		x86.Walk(funcCode, funcVA, func(d x86.Decoded) bool {
			if d.Bad {
				_, writeErr = fmt.Fprintf(w, "0x%x: <bad>\n", d.VA)
				return writeErr == nil
			}
			line := x86.InstText(d.Inst)
			if target, ok := x86.RelTarget(d.Inst, d.VA, d.Len); ok {
				if name, ok := symbols(target); ok {
					line += fmt.Sprintf("  ; -> %s", name)
				} else {
					line += fmt.Sprintf("  ; -> 0x%x", target)
				}
			}
			_, writeErr = fmt.Fprintf(w, "0x%x: %s\n", d.VA, line)
			return writeErr == nil
		})
		return writeErr
	})
}
