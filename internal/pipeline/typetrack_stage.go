package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/arch/x86/x86asm"

	"aotopsy/internal/cluster"
	"aotopsy/internal/disasm"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/typetrack"
)

// RunTypeInferenceStage runs the whole-program type inference engine
// to resolve dispatch-table BLR call sites. It is called after the
// disassembly stage (which writes call_edges.jsonl with unresolved BLR
// edges) and before the signal stage (which reads call_edges.jsonl).
//
// This stage:
//  1. Parses the dispatch table from the snapshot roots section.
//  2. Builds a TypeContext from cluster fill data.
//  3. Re-disassembles all functions and runs type inference.
//  4. Rewrites call_edges.jsonl with resolved BLR targets.
//
// Non-fatal: if anything fails, BLR edges remain unresolved (as before).
func RunTypeInferenceStage(
	opts *Opts,
	isARM64 bool,
	pl *PoolLookups,
	clResult *cluster.Result,
	ranges []cluster.CodeRange,
	code []byte,
	codeOff uint64,
	codeVA uint64,
	info *snapshot.Info,
	table *cluster.InstructionsTable,
	thrFields map[int]string,
) error {
	if info == nil || info.Version == nil {
		return nil
	}
	if info.Version.ObjectStoreAOTFieldCount <= 0 {
		return nil
	}
	// TARGET 3: For Dart 2.x (no InstructionsTable), still run typetrack
	// using dispatch table entries from TextOffset fallback.
	if table == nil && !info.Version.CodeTextOffsetDelta {
		return nil
	}

	opts.logf("  type inference: starting...\n")

	resolved, total, tctx, err := runTypeInference(opts.OutDir, clResult, pl, ranges, code, codeOff, codeVA, info, table, isARM64, thrFields)
	if err != nil {
		opts.logf("  type inference: %v (BLR edges remain unresolved)\n", err)
		return nil // non-fatal
	}

	opts.logf("  type inference: resolved %d/%d BLR call sites\n", resolved, total)
	if tctx != nil && len(tctx.InstanceFieldTypes) > 0 {
		opts.logf("  observed field types: %d classes, %d field loads typed from const instances\n",
			len(tctx.InstanceFieldTypes), tctx.InstanceFieldHits)
	}

	if err := typetrack.WriteTypeInferenceReport(opts.OutDir, resolved, total, tctx); err != nil {
		return fmt.Errorf("write typetrack report: %w", err)
	}

	return nil
}

// runTypeInference is the core logic, separated from RunTypeInferenceStage
// for testability.
func runTypeInference(
	outDir string,
	clResult *cluster.Result,
	pl *PoolLookups,
	ranges []cluster.CodeRange,
	code []byte,
	codeOff uint64,
	codeVA uint64,
	info *snapshot.Info,
	table *cluster.InstructionsTable,
	isARM64 bool,
	thrFields map[int]string,
) (int, int, *typetrack.TypeContext, error) {
	// 1. Parse dispatch table.
	// ParseDispatchTable reads from the roots section, which is in the
	// snapshot DATA region (info.IsolateData.Data), not the instructions
	// region. result.FillEnd is the byte offset within this data.
	dispatchEntries, err := cluster.ParseDispatchTable(info.IsolateData.Data, clResult, info.Version, table)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("parse dispatch table: %w", err)
	}
	if len(dispatchEntries) == 0 {
		return 0, 0, nil, nil
	}

	// 2. Build TypeContext.
	byCodeIndex := CodeIndexToFunc(clResult, info.Version.CIDs, info.Version.CodeIndexOneBased)

	// Build CodeRefToName map from CodeNames.
	codeRefToName := make(map[int]string, len(pl.CodeNames))
	for ref, ci := range pl.CodeNames {
		codeRefToName[ref] = ci.FuncName
	}

	// Build PP index → function name map for PP-loaded Code objects.
	// For each PP entry that is a Code object (CID == ct.Code):
	//   1. Try RefToNamed (app isolate Function name)
	//   2. Try VmRefToNamed (VM isolate Function name)
	//   3. Try matching Code's TextOffset to a function VA
	poolCodeNames := make(map[int]string)
	// Build refID → function name from CodeNames (already have codeRefToName)
	// Build refID → TextOffset from clResult.Codes
	codeByRef := make(map[int]*cluster.CodeEntry, len(clResult.Codes))
	for i := range clResult.Codes {
		codeByRef[clResult.Codes[i].RefID] = &clResult.Codes[i]
	}
	// Build VA → function name from ranges
	vaToName := make(map[uint64]string)
	for _, r := range ranges {
		if r.RefID >= 0 {
			if ci, ok := pl.CodeNames[r.RefID]; ok {
				funcStart := uint64(r.PCOffset) - codeOff
				vaToName[codeVA+funcStart] = ci.FuncName
			}
		}
	}
	for _, pe := range clResult.Pool {
		if pe.Kind != cluster.PoolTagged {
			continue
		}
		if pl.CT != nil && pl.RefCID != nil {
			if cid, ok := pl.RefCID[pe.RefID]; ok && cid == pl.CT.Code {
				// Try app isolate NamedObject
				if no, ok2 := pl.RefToNamed[pe.RefID]; ok2 {
					if no.NameRefID >= 0 {
						if name, ok3 := pl.RefToStr[no.NameRefID]; ok3 && name != "" {
							poolCodeNames[pe.Index] = name
						}
					}
				}
				// Try VM isolate NamedObject
				if _, exists := poolCodeNames[pe.Index]; !exists && pl.VmRefToNamed != nil {
					if no, ok2 := pl.VmRefToNamed[pe.RefID]; ok2 {
						if no.NameRefID >= 0 {
							if name, ok3 := pl.VmRefToStr[no.NameRefID]; ok3 && name != "" {
								poolCodeNames[pe.Index] = name
							}
						}
					}
				}
				// Try matching by TextOffset → VA → function name
				if _, exists := poolCodeNames[pe.Index]; !exists {
					if ce, ok2 := codeByRef[pe.RefID]; ok2 && ce.TextOffset > 0 {
						va := codeVA + uint64(ce.TextOffset) - codeOff
						// Find function whose range contains this VA
						for funcVA, name := range vaToName {
							if funcVA <= va && va < funcVA+0x10000 { // within 64KB
								poolCodeNames[pe.Index] = name
								break
							}
						}
					}
				}
			}
		}
	}

	poolData := &typetrack.PoolLookupData{
		RefToStr:       pl.RefToStr,
		RefToNamed:     pl.RefToNamed,
		RefCID:         pl.RefCID,
		CT:             pl.CT,
		CodeRefToName:  codeRefToName,
		VmRefToStr:     pl.VmRefToStr,
		VmRefToNamed:   pl.VmRefToNamed,
		PoolCodeNames:  poolCodeNames,
	}

	// Compute kOriginElement: ARM64=4096, x86_64=16.
	// These are compile-time constants in the Dart SDK (dispatch_table.h).
	kOriginElement := 4096
	if !isARM64 {
		kOriginElement = 16
	}

	// Get allocation stub offsets from ThreadStubOffsets (arch-independent).
	allocStubOffsets := disasm.ThreadStubOffsets(info.Version.DartVersion, isARM64)

	ctx := typetrack.BuildTypeContext(clResult, poolData, dispatchEntries, byCodeIndex, info.Version, kOriginElement, thrFields, allocStubOffsets)

	// Build class name → class ID lookup from ClassIDToName.
	// ClassIDToName is built from ClassInfo.ClassID (Dart runtime CID).
	classNameToID := make(map[string]int, len(ctx.ClassIDToName))
	for cid, name := range ctx.ClassIDToName {
		if name != "" {
			classNameToID[name] = cid
		}
	}

	// Write dispatch table for debugging.
	_ = typetrack.WriteDispatchTable(outDir, dispatchEntries, ctx)

	// 3. Re-disassemble all functions and collect instruction lists.
	var funcInstsARM64 typetrack.FuncInstsARM64
	var funcInstsX86 typetrack.FuncInstsX86
	if isARM64 {
		funcInstsARM64 = make(map[string][]disasm.Inst, len(ranges))
	} else {
		funcInstsX86 = make(map[string][]typetrack.X86DecodedInst, len(ranges))
	}
	blEdges := make(map[string][]typetrack.BLEdge)

	// Build address → function name lookup for BL/CALL target resolution.
	type funcRange struct {
		start, end uint64
		name       string
	}
	var funcRanges []funcRange

	for i := range ranges {
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
		funcVA := codeVA + funcStart

		var name string
		var ownerName string
		if r.RefID >= 0 {
			ci := pl.CodeNames[r.RefID]
			name = QualifiedName(ci.OwnerName, ci.FuncName, r.PCOffset)
			ownerName = ci.OwnerName
		} else {
			name = fmt.Sprintf("stub_%x", r.PCOffset)
		}

		// Map function name → owner class ID for instance method receiver init.
		if ownerName != "" {
			if cid, ok := classNameToID[ownerName]; ok && cid >= 0 {
				ctx.FuncOwnerClass[name] = cid
			}
		}

		funcRanges = append(funcRanges, funcRange{start: funcVA, end: funcVA + uint64(r.Size), name: name})

		funcCode := code[funcStart:funcEnd]

		if isARM64 {
			insts := disasm.Disassemble(funcCode, disasm.Options{
				BaseAddr: funcVA,
			})
			funcInstsARM64[name] = insts

			// Collect BL edges for inter-procedural propagation.
			for _, inst := range insts {
				if target, ok := isBLRaw(inst.Raw, inst.Addr); ok {
					calleeName := ""
					for _, fr := range funcRanges {
						if target >= fr.start && target < fr.end {
							calleeName = fr.name
							break
						}
					}
					if calleeName != "" {
						blEdges[name] = append(blEdges[name], typetrack.BLEdge{
							Callee: calleeName,
							CallPC: inst.Addr,
						})
					}
				}
			}
		} else {
			insts := typetrack.DecodeX86Function(funcCode, funcVA)
			funcInstsX86[name] = insts

			// Collect CALL rel32 edges for inter-procedural propagation.
			for _, inst := range insts {
				if inst.Inst.Op == x86asm.CALL {
					if target, ok := x86CallRelTarget(inst); ok {
						calleeName := ""
						for _, fr := range funcRanges {
							if target >= fr.start && target < fr.end {
								calleeName = fr.name
								break
							}
						}
						if calleeName != "" {
							blEdges[name] = append(blEdges[name], typetrack.BLEdge{
								Callee: calleeName,
								CallPC: inst.Addr,
							})
						}
					}
				}
			}
		}
	}

	// 4. Run inter-procedural analysis.
	// Fase 7 PART A: build BL target → callee name map for call-return tracking.
	blTargetToName := make(map[uint64]string)
	for _, fr := range funcRanges {
		blTargetToName[fr.start] = fr.name
	}
	// Fase 7 PHASE 3: increased from 3 to 10 iterations for better convergence.
	// More iterations allow type info to propagate deeper across function call chains.
	// Q7: RunInterprocedural already has early convergence detection (breaks when
	// no types change in an iteration), so 10 is a safe upper bound — it won't
	// do unnecessary work if the fixed-point is reached earlier.
	// Override via AOTOPSY_TYPETRACK_ITERATIONS env var for tuning.
	maxIter := 10 // M-9 fix: was 5, comment says 10, code now matches comment
	if v := os.Getenv("AOTOPSY_TYPETRACK_ITERATIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxIter = n
		}
	}
	interResult := typetrack.RunInterprocedural(ctx, funcInstsARM64, funcInstsX86, blEdges, maxIter, isARM64, blTargetToName)

	// 5. Rewrite call_edges.jsonl with resolved BLR targets.
	resolved, total, err := rewriteCallEdges(outDir, interResult)
	if err != nil {
		return 0, 0, ctx, fmt.Errorf("rewrite call_edges: %w", err)
	}

	// ctx is returned so the caller can report per-source hit counters.
	return resolved, total, ctx, nil
}

// rewriteCallEdges reads call_edges.jsonl, updates BLR edges with resolved
// targets from the inter-procedural analysis, and writes it back.
func rewriteCallEdges(outDir string, interResult *typetrack.InterResult) (int, int, error) {
	edgesPath := filepath.Join(outDir, "call_edges.jsonl")
	edges, err := ReadJSONL[disasm.CallEdgeRecord](edgesPath)
	if err != nil {
		return 0, 0, fmt.Errorf("read call_edges.jsonl: %w", err)
	}

	// Build PC → resolution map for each function.
	type resKey struct {
		funcName string
		pc       string
	}
	resolutionMap := make(map[resKey]string)
	for _, fa := range interResult.Functions {
		for _, res := range fa.Intra.BLRResolutions {
			if res.Resolved && res.TargetName != "" {
				key := resKey{
					funcName: fa.Name,
					pc:       fmt.Sprintf("0x%x", res.PC),
				}
				resolutionMap[key] = res.TargetName
			}
		}
	}

	// Update edges.
	resolved := 0
	total := 0
	for i := range edges {
		e := &edges[i]
		if e.Kind != "blr" && e.Kind != "call_indirect" {
			continue
		}
		total++
		key := resKey{funcName: e.FromFunc, pc: e.FromPC}
		if target, ok := resolutionMap[key]; ok {
			e.Target = target
			resolved++
		}
	}

	// Write back.
	f, err := os.Create(edgesPath)
	if err != nil {
		return 0, 0, fmt.Errorf("create call_edges.jsonl: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, e := range edges {
		if err := enc.Encode(e); err != nil {
			return 0, 0, fmt.Errorf("encode call_edge: %w", err)
		}
	}

	return resolved, total, nil
}

// isBLRaw detects ARM64 BL instruction. Returns target address.
// This is a local copy of the pattern in typetrack/intraproc.go to avoid
// exporting it from the typetrack package.
func isBLRaw(raw uint32, pc uint64) (uint64, bool) {
	if raw&0xFC000000 != 0x94000000 {
		return 0, false
	}
	imm26 := int32(raw & 0x03FFFFFF)
	if imm26&(1<<25) != 0 {
		imm26 |= ^int32(0x03FFFFFF)
	}
	return uint64(int64(pc) + int64(imm26)*4), true
}

// x86CallRelTarget returns the absolute target of a CALL rel32 instruction.
func x86CallRelTarget(d typetrack.X86DecodedInst) (uint64, bool) {
	for _, arg := range d.Inst.Args {
		if arg == nil {
			continue
		}
		if rel, ok := arg.(x86asm.Rel); ok {
			return d.Addr + uint64(d.Len) + uint64(int64(rel)), true
		}
	}
	return 0, false
}
