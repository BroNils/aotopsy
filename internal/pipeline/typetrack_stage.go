package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

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
	vmResult *cluster.Result,
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

	bd, tctx, err := runTypeInference(opts.OutDir, clResult, pl, ranges, code, codeOff, codeVA, info, table, isARM64, thrFields, vmResult)
	if err != nil {
		opts.logf("  type inference: %v (BLR edges remain unresolved)\n", err)
		return nil // non-fatal
	}

	// Report the three claims separately. "resolved N/M" alone hid the
	// difference between a call site with one known callee and one with 43
	// possible ones -- both used to count as resolved.
	opts.logf("  type inference: %d/%d indirect call sites with a single callee (%d VM stub)\n",
		bd.Resolved(), bd.Total, bd.Stub)
	if bd.Polymorphic > 0 {
		opts.logf("  polymorphic: %d site(s), %d candidate callees total (avg %.1f per site)\n",
			bd.Polymorphic, bd.PolymorphicCandidates,
			float64(bd.PolymorphicCandidates)/float64(bd.Polymorphic))
	}
	opts.logf("  unresolved: %d site(s)\n", bd.Unresolved)
	if tctx != nil && len(tctx.InstanceFieldTypes) > 0 {
		opts.logf("  observed field types: %d classes, %d field loads typed from const instances\n",
			len(tctx.InstanceFieldTypes), tctx.InstanceFieldHits)
	}

	if err := typetrack.WriteTypeInferenceReport(opts.OutDir, bd, tctx); err != nil {
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
	vmResult *cluster.Result,
) (BLRBreakdown, *typetrack.TypeContext, error) {
	// 1. Parse dispatch table.
	// ParseDispatchTable reads from the roots section, which is in the
	// snapshot DATA region (info.IsolateData.Data), not the instructions
	// region. result.FillEnd is the byte offset within this data.
	dispatchEntries, err := cluster.ParseDispatchTable(info.IsolateData.Data, clResult, info.Version, table)
	if err != nil {
		return BLRBreakdown{}, nil, fmt.Errorf("parse dispatch table: %w", err)
	}
	if len(dispatchEntries) == 0 {
		return BLRBreakdown{}, nil, nil
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
	// Build a sorted [start,end) → function name index from ranges, so a VA
	// can be mapped to the function that actually CONTAINS it.
	//
	// This replaces a `for funcVA, name := range vaToName { if funcVA <= va &&
	// va < funcVA+0x10000 }` scan: iterating a map returns entries in random
	// order, so that loop picked an arbitrary function starting within 64 KB
	// below the address -- a different, and usually wrong, one on each run.
	type funcSpan struct {
		start, end uint64
		name       string
	}
	spans := make([]funcSpan, 0, len(ranges))
	for _, r := range ranges {
		if r.RefID < 0 || r.Size == 0 {
			continue
		}
		ci, ok := pl.CodeNames[r.RefID]
		if !ok || ci.FuncName == "" {
			continue
		}
		start := codeVA + uint64(r.PCOffset) - codeOff
		spans = append(spans, funcSpan{start: start, end: start + uint64(r.Size), name: ci.FuncName})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	funcNameAt := func(va uint64) (string, bool) {
		i := sort.Search(len(spans), func(i int) bool { return spans[i].start > va })
		if i == 0 {
			return "", false
		}
		s := spans[i-1]
		if va < s.start || va >= s.end {
			return "", false
		}
		return s.name, true
	}
	for _, pe := range clResult.Pool {
		if pe.Kind != cluster.PoolTagged {
			continue
		}
		// Check both app isolate RefCID and VM VmRefCID for Code objects.
		// VM Code objects (ref < BaseObjLimit) have cid in VmRefCID, not RefCID.
		isCode := false
		if pl.CT != nil && pl.RefCID != nil {
			if cid, ok := pl.RefCID[pe.RefID]; ok && cid == pl.CT.Code {
				isCode = true
			}
		}
		if !isCode && pl.CT != nil && pl.VmRefCID != nil {
			if cid, ok := pl.VmRefCID[pe.RefID]; ok && cid == pl.CT.Code {
				isCode = true
			}
		}
		// Also check CodeRefDisplay for any ref that has a display string
		// (covers VM Code objects that don't have CID in either map).
		if !isCode && pl.CodeRefDisplay != nil {
			if _, ok := pl.CodeRefDisplay[pe.RefID]; ok {
				isCode = true
			}
		}
		if !isCode {
			continue
		}
		{
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
					if name, ok3 := funcNameAt(va); ok3 {
						poolCodeNames[pe.Index] = name
					}
				}
			}
			// Try CodeRefDisplay (covers VM Code objects with display strings
			// like "dyn:call", "Native", function names from CodeNames)
			if _, exists := poolCodeNames[pe.Index]; !exists {
				if name, ok2 := pl.CodeRefDisplay[pe.RefID]; ok2 && name != "" {
					poolCodeNames[pe.Index] = name
				}
			}
			// Try CodeNames directly (covers VM Code objects whose names
			// were resolved via VM Function owner chain in BuildPoolLookups).
			if _, exists := poolCodeNames[pe.Index]; !exists {
				if ci, ok2 := pl.CodeNames[pe.RefID]; ok2 && ci.FuncName != "" {
					poolCodeNames[pe.Index] = ci.FuncName
				}
			}
		}
	}

	// Build PP index → type testing stub name map.
	// When a Type object is loaded from the pool and its
	// type_test_stub_entry_point_ (offset 7 from tagged) is called via BLR,
	// the type tracker needs the stub name to resolve the call.
	poolTTSNames := make(map[int]string)
	if len(pl.TypeTestingStubNames) > 0 {
		for _, pe := range clResult.Pool {
			if pe.Kind != cluster.PoolTagged {
				continue
			}
			if name, ok := pl.TypeTestingStubNames[pe.RefID]; ok && name != "" {
				poolTTSNames[pe.Index] = name
			}
		}
	}

	poolData := &typetrack.PoolLookupData{
		RefToStr:      pl.RefToStr,
		RefToNamed:    pl.RefToNamed,
		RefCID:        pl.RefCID,
		CT:            pl.CT,
		CodeRefToName: codeRefToName,
		VmRefToStr:    pl.VmRefToStr,
		VmRefToNamed:  pl.VmRefToNamed,
		VmRefCID:      pl.VmRefCID,
		PoolCodeNames:       poolCodeNames,
		TypeTestingStubNames: poolTTSNames,
	}
	if vmResult != nil {
		poolData.VmFields = vmResult.Fields
		poolData.VmTypes = vmResult.Types
		poolData.VmClasses = vmResult.Classes
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
	//
	// Class names are NOT unique -- a Flutter build has many same-named
	// classes across libraries (State, Node, Entry, _Sink...). Iterating the
	// map and letting the last writer win therefore picked a random CID for
	// those names on every run. That CID becomes the receiver type
	// (ctx.FuncOwnerClass) seeded into the intra-procedural analysis, so a
	// dispatch-table BLR in e.g. TextStyle.compareTo resolved to a target in
	// one run and stayed unresolved in the next.
	//
	// Ambiguous names are dropped instead: no receiver type at all is
	// correct-but-weaker, whereas a coin-flip between two classes is wrong
	// half the time and unreproducible either way.
	nameCount := make(map[string]int, len(ctx.ClassIDToName))
	for _, name := range ctx.ClassIDToName {
		if name != "" {
			nameCount[name]++
		}
	}
	classNameToID := make(map[string]int, len(ctx.ClassIDToName))
	for cid, name := range ctx.ClassIDToName {
		if name == "" || nameCount[name] > 1 {
			continue
		}
		classNameToID[name] = cid
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
			name = ci.Qualified(r.PCOffset)
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
	bd, err := rewriteCallEdges(outDir, interResult, buildTTSCallTargets(clResult.Pool, pl))
	if err != nil {
		return bd, ctx, fmt.Errorf("rewrite call_edges: %w", err)
	}

	// 6. field_accessor_xref.jsonl — (class, field) → the functions that read
	// and write it, from the per-function field accesses the type analysis
	// recorded.
	if err := writeFieldAccessorXref(outDir, ctx, interResult, clResult, pl, info.Version.CompressedPointers); err != nil {
		return bd, ctx, fmt.Errorf("write field_accessor_xref.jsonl: %w", err)
	}

	// ctx is returned so the caller can report per-source hit counters.
	return bd, ctx, nil
}

// writeFieldAccessorXref writes field_accessor_xref.jsonl: for every instance
// field the analysis saw touched, the functions that read it and the functions
// that write it.
//
// The accesses come from typetrack.IntraResult.FieldAccesses, recorded at each
// LDUR/STUR/STR whose receiver register held a resolved class. A previous
// version of this file emitted the class→offset table with EMPTY readers and
// writers and a comment saying per-function field access records did not
// exist; they do now, so the file is an actual cross-reference.
//
// Offsets: the instruction displacement is relative to the TAGGED receiver
// pointer, so the field at layout byte offset N is addressed as N-1
// (kHeapObjectTag). Layout offsets are reported, and the tag is removed here.
func writeFieldAccessorXref(
	outDir string,
	ctx *typetrack.TypeContext,
	interResult *typetrack.InterResult,
	clResult *cluster.Result,
	pl *PoolLookups,
	compressedPtrs bool,
) error {
	if interResult == nil || ctx == nil {
		return nil
	}

	// class ID → (layout byte offset → field name)
	fieldNames := map[int]map[int32]string{}
	for _, layout := range BuildClassLayouts(clResult, pl, compressedPtrs) {
		m := make(map[int32]string, len(layout.Fields))
		for _, f := range layout.Fields {
			m[f.ByteOffset] = f.Name
		}
		fieldNames[int(layout.ClassID)] = m
	}

	type key struct {
		classID int
		offset  int32
	}
	readers := map[key]map[string]bool{}
	writers := map[key]map[string]bool{}
	for name, fa := range interResult.Functions {
		if fa == nil {
			continue
		}
		for _, acc := range fa.Intra.FieldAccesses {
			k := key{classID: acc.ClassID, offset: acc.ByteOffset + 1}
			target := readers
			if acc.IsStore {
				target = writers
			}
			if target[k] == nil {
				target[k] = map[string]bool{}
			}
			target[k][name] = true
		}
	}

	keys := map[key]bool{}
	for k := range readers {
		keys[k] = true
	}
	for k := range writers {
		keys[k] = true
	}
	if len(keys) == 0 {
		return nil
	}

	sortedNames := func(set map[string]bool) []string {
		out := make([]string, 0, len(set))
		for n := range set {
			out = append(out, n)
		}
		sort.Strings(out)
		return out
	}

	entries := make([]interface{}, 0, len(keys))
	for k := range keys {
		e := FieldAccessorXref{
			ClassName:  ctx.ClassIDToName[k.classID],
			ClassID:    k.classID,
			ByteOffset: int(k.offset),
			Readers:    sortedNames(readers[k]),
			Writers:    sortedNames(writers[k]),
		}
		if e.ClassName == "" {
			e.ClassName = fmt.Sprintf("class_%d", k.classID)
		}
		if names, ok := fieldNames[k.classID]; ok {
			e.FieldName = names[k.offset]
		}
		entries = append(entries, e)
	}
	// Sort by (name, class ID, offset). Class ID is what makes this a TOTAL
	// order: without it, two distinct classes sharing a name produced ties,
	// sort.Slice is not stable, and the file came out in a different order on
	// every run.
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i].(FieldAccessorXref), entries[j].(FieldAccessorXref)
		if a.ClassName != b.ClassName {
			return a.ClassName < b.ClassName
		}
		if a.ClassID != b.ClassID {
			return a.ClassID < b.ClassID
		}
		return a.ByteOffset < b.ByteOffset
	})
	return writeJSONL(filepath.Join(outDir, "field_accessor_xref.jsonl"), entries)
}

// BLRBreakdown is typetrack.BLRBreakdown; aliased so this file reads
// naturally.
type BLRBreakdown = typetrack.BLRBreakdown

// rewriteCallEdges reads call_edges.jsonl, fills in what the
// inter-procedural analysis recovered for each indirect call site, writes it
// back, and returns the breakdown.
func rewriteCallEdges(outDir string, interResult *typetrack.InterResult, ttsByPoolIndex map[int]string) (BLRBreakdown, error) {
	var bd BLRBreakdown
	edgesPath := filepath.Join(outDir, "call_edges.jsonl")
	edges, err := ReadJSONL[disasm.CallEdgeRecord](edgesPath)
	if err != nil {
		return bd, fmt.Errorf("read call_edges.jsonl: %w", err)
	}

	// Build PC → resolution map for each function.
	type resKey struct {
		funcName string
		pc       string
	}
	resolutionMap := make(map[resKey]typetrack.BlrResolution)
	for _, fa := range interResult.Functions {
		for _, res := range fa.Intra.BLRResolutions {
			if !res.Resolved {
				continue
			}
			if res.TargetName == "" && len(res.TargetNames) == 0 {
				continue
			}
			key := resKey{
				funcName: fa.Name,
				pc:       fmt.Sprintf("0x%x", res.PC),
			}
			resolutionMap[key] = res
		}
	}

	// Update edges.
	for i := range edges {
		e := &edges[i]
		if e.Kind != "blr" && e.Kind != "call_indirect" {
			continue
		}
		bd.Total++
		key := resKey{funcName: e.FromFunc, pc: e.FromPC}
		if res, ok := resolutionMap[key]; ok {
			if res.Polymorphic {
				e.Targets = res.TargetNames
				e.Candidates = res.Candidates
				bd.Polymorphic++
				bd.PolymorphicCandidates += res.Candidates
			} else {
				e.Target = res.TargetName
				e.Candidates = res.Candidates
				bd.Monomorphic++
			}
		} else if name := ttsCallTarget(e.Via, ttsByPoolIndex); name != "" {
			// A call through a pool slot holding a Type invokes that type's
			// testing stub -- GenerateIndirectTTSCall, see ttscall.go. One
			// known callee, so it counts as a stub rather than a Dart-level
			// monomorphic call.
			e.Target = name
			bd.Stub++
		} else if strings.HasPrefix(e.Via, "THR.") {
			// Fallback: resolve THR stub calls from via annotation.
			// via format: "THR.stub_name" or "THR.stub_name_ep"
			stubName := strings.TrimPrefix(e.Via, "THR.")
			// Remove _ep suffix if present
			stubName = strings.TrimSuffix(stubName, "_ep")
			// Remove _entry_point suffix if present
			stubName = strings.TrimSuffix(stubName, "_entry_point")
			if stubName != "" {
				e.Target = stubName
				bd.Stub++
			} else {
				bd.Unresolved++
			}
		} else {
			// Item 14: Directed symbolic execution fallback.
			// For unresolved BLR edges, try resolving via the pool
			// display string in the Via annotation. This catches
			// pool-loaded Code objects that the type tracker missed.
			if resolved := resolveViaPoolDisplay(e.Via); resolved != "" {
				e.Target = resolved
				bd.Stub++
			} else {
				bd.Unresolved++
			}
		}
		// NOTE: there used to be a third branch here that matched
		// `via = "THR+0xNNN LDR[RUNTIME_ENTRY]"` and set Target =
		// "RuntimeEntry", counting it as resolved. That annotation is emitted
		// precisely for THR offsets whose field name is NOT known
		// (thrAnnotationLabel's classTag path in disasm/annotate.go), so no
		// callee identity was recovered: "RuntimeEntry" is a category, not a
		// target. It named no function, duplicated information already in
		// Via, and inflated the resolved-BLR count. Removed.
	}

	// Write back.
	f, err := os.Create(edgesPath)
	if err != nil {
		return bd, fmt.Errorf("create call_edges.jsonl: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, e := range edges {
		if err := enc.Encode(e); err != nil {
			return bd, fmt.Errorf("encode call_edge: %w", err)
		}
	}

	return bd, nil
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

// resolveViaPoolDisplay attempts to resolve an unresolved BLR edge
// via the pool display string in the Via annotation.
// Item 14: Directed symbolic execution fallback.
//
// Via annotations for pool-loaded Code objects look like:
//   "PP[123] foo" or "pp[123] foo"
// The pool display string after the PP index is the function name.
func resolveViaPoolDisplay(via string) string {
	// Check for PP[NNN] pattern — pool-loaded Code object.
	if via == "" {
		return ""
	}
	// Look for "PP[" or "pp[" prefix.
	viaLower := strings.ToLower(via)
	if !strings.HasPrefix(viaLower, "pp[") {
		return ""
	}
	// Extract the display string after the bracket.
	closeBracket := strings.IndexByte(via, ']')
	if closeBracket < 0 {
		return ""
	}
	rest := strings.TrimSpace(via[closeBracket+1:])
	if rest == "" {
		return ""
	}
	// The rest is the pool display string — a function name.
	// Skip placeholder values like "<vm:NNN>" or "<ref:NNN>".
	if strings.HasPrefix(rest, "<") {
		return ""
	}
	return rest
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
