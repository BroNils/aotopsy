package analysis

import (
	"aotopsy/internal/arch/x86"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/arch/x86/x86asm"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/disasm"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/naming"
	"aotopsy/internal/sdk"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/typetrack"
	"aotopsy/internal/vmtables"
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
// A failure is fatal to the staged generation. Publishing the disassembly
// while silently leaving BLR edges unresolved makes every downstream xref,
// signal, and evidence artifact look complete while carrying degraded call
// semantics.
func RunTypeInferenceStage(
	opts *Opts,
	isARM64 bool,
	pl *naming.PoolLookups,
	clResult *cluster.Result,
	ranges []cluster.CodeRange,
	code []byte,
	codeOff uint64,
	codeVA uint64,
	info *snapshot.Info,
	table *cluster.InstructionsTable,
	thrFields map[int]string,
	vmResult *cluster.Result,
) (*TypeInferenceOutput, error) {
	if opts == nil {
		return nil, fmt.Errorf("type inference options unavailable")
	}
	if info == nil {
		return nil, fmt.Errorf("snapshot info unavailable")
	}
	if info.Version == nil {
		return nil, fmt.Errorf("snapshot version profile unavailable")
	}
	if clResult == nil {
		return nil, fmt.Errorf("cluster result unavailable")
	}
	if pl == nil {
		return nil, fmt.Errorf("pool lookups unavailable")
	}
	if info.Version.CIDs == nil {
		return nil, fmt.Errorf("dart %s has no CID profile", info.Version.DartVersion)
	}
	if info.Version.ObjectStoreAOTFieldCount <= 0 {
		return nil, fmt.Errorf("dart %s has no verified Full AOT ObjectStore field count", info.Version.DartVersion)
	}
	// TARGET 3: For Dart 2.x (no InstructionsTable), still run typetrack
	// using dispatch table entries from TextOffset fallback.
	if table == nil && !info.Version.CodeTextOffsetDelta {
		return nil, fmt.Errorf("dart %s has neither InstructionsTable nor verified text-offset code locator", info.Version.DartVersion)
	}

	opts.logf("  type inference: starting...\n")

	bd, tctx, interResult, err := runTypeInference(opts.OutDir, clResult, pl, ranges, code, codeOff, codeVA, info, table, isARM64, thrFields, vmResult)
	if err != nil {
		return nil, fmt.Errorf("run type inference: %w", err)
	}
	if interResult != nil && !interResult.Converged {
		opts.logf("  type inference: interprocedural budget exhausted after %d iteration(s); using conservative fallback\n", interResult.Iterations)
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
	out := &TypeInferenceOutput{Inter: interResult}
	if tctx != nil {
		out.ClassIDToName = tctx.ClassIDToName
		out.SelectorTargets = buildSelectorTargets(tctx)
	}

	if err := typetrack.WriteTypeInferenceReport(opts.OutDir, bd, tctx); err != nil {
		return out, fmt.Errorf("write typetrack report: %w", err)
	}

	return out, nil
}

// TypeInferenceOutput is what the type-inference stage hands back for
// reuse downstream.
//
// Inter carries the per-function analyses with the confidence and slot
// index the analysis produced; those are lossy once they have been through
// call_edges.jsonl, which is where the evidence collector used to read
// them from. ClassIDToName is the same resolver field_accessor_xref uses,
// so a field access reports the same class name in both artifacts.
type TypeInferenceOutput struct {
	Inter         *typetrack.InterResult
	ClassIDToName map[int]string
	// SelectorTargets is keyed by the actual selector immediate used by
	// EmitDispatchTableCall, not by an absolute dispatch-table entry index.
	SelectorTargets map[int][]string
}

func buildSelectorTargets(ctx *typetrack.TypeContext) map[int][]string {
	if ctx == nil {
		return nil
	}
	sets := make(map[int]map[string]struct{})
	for name, imms := range ctx.MethodNameToSelectorImms {
		if name == "" {
			continue
		}
		for _, imm := range imms {
			if sets[imm] == nil {
				sets[imm] = make(map[string]struct{})
			}
			sets[imm][name] = struct{}{}
		}
	}
	out := make(map[int][]string, len(sets))
	for imm, names := range sets {
		targets := make([]string, 0, len(names))
		for name := range names {
			targets = append(targets, name)
		}
		sort.Strings(targets)
		out[imm] = targets
	}
	return out
}

// runTypeInference is the core logic, separated from RunTypeInferenceStage
// for testability.
// buildAllocationStubCIDs maps each per-class allocation stub's entry VA to
// the class id it allocates.
//
// The join is entirely structural: PoolLookups already marks a Code whose
// owner is a Class (naming/pool.go, IsAllocationStub, named "new X"), and
// ClassInfo carries that Class object's ref alongside the class id it
// describes. Nothing here is inferred from instructions.
//
// It exists because IsAllocationStub had no reader at all -- the flag was set
// and dropped, while typetrack answered the same question by reading RDI, a
// register AllocateObjectABI does not use.
func buildAllocationStubCIDs(
	clResult *cluster.Result,
	pl *naming.PoolLookups,
	ranges []cluster.CodeRange,
	codeVA, codeOff uint64,
) map[uint64]int {
	if clResult == nil || pl == nil {
		return nil
	}
	// Class object ref → the class id instances of it carry.
	cidByClassRef := make(map[int]int32, len(clResult.Classes))
	for _, ci := range clResult.Classes {
		cidByClassRef[ci.RefID] = ci.ClassID
	}

	// Code ref → allocated class id, for the Codes marked IsAllocationStub.
	// The owner ref lives on the CodeEntry (Code.owner_), not on a
	// NamedObject: a Code is not itself a named object, which is why
	// ResolveCodeOwner takes ce.OwnerRef rather than looking the Code up.
	cidByCodeRef := make(map[int]int32)
	for _, ce := range clResult.Codes {
		ci, ok := pl.CodeNames[ce.RefID]
		if !ok || !ci.IsAllocationStub {
			continue
		}
		if cid, ok := cidByClassRef[ce.OwnerRef]; ok && cid > 0 {
			cidByCodeRef[ce.RefID] = cid
		}
	}

	im := cluster.CodeImage{CodeVA: codeVA, CodeOff: codeOff}
	out := make(map[uint64]int, len(cidByCodeRef))
	for _, r := range ranges {
		cid, ok := cidByCodeRef[r.RefID]
		if !ok {
			continue
		}
		va, ok := im.FuncVA(r)
		if !ok {
			continue
		}
		out[va] = int(cid)
	}
	return out
}

func runTypeInference(
	outDir string,
	clResult *cluster.Result,
	pl *naming.PoolLookups,
	ranges []cluster.CodeRange,
	code []byte,
	codeOff uint64,
	codeVA uint64,
	info *snapshot.Info,
	table *cluster.InstructionsTable,
	isARM64 bool,
	thrFields map[int]string,
	vmResult *cluster.Result,
) (BLRBreakdown, *typetrack.TypeContext, *typetrack.InterResult, error) {
	// 1. Parse dispatch table.
	// ParseDispatchTable reads from the roots section, which is in the
	// snapshot DATA region (info.IsolateData.Data), not the instructions
	// region. result.FillEnd is the byte offset within this data.
	dispatchEntries, err := cluster.ParseDispatchTable(info.IsolateData.Data, clResult, info.Version, table, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
	if err != nil {
		return BLRBreakdown{}, nil, nil, fmt.Errorf("parse dispatch table: %w", err)
	}

	// 2. Build TypeContext.
	firstEntryWithCode := -1
	if table != nil {
		firstEntryWithCode = int(table.FirstEntryWithCode)
	}
	byCodeIndex := naming.CodeIndexToFunc(clResult, info.Version.CIDs, info.Version.CodeIndexOneBased, firstEntryWithCode)

	// Build CodeRefToName map from CodeNames.
	codeRefToName := make(map[int]string, len(pl.CodeNames))
	for ref, ci := range pl.CodeNames {
		if name := ci.DisplayName(); name != "" {
			codeRefToName[ref] = name
		}
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
		start, size uint64
		name        string
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
		start, ok := cluster.CodeImage{CodeVA: codeVA, CodeOff: codeOff}.FuncVA(r)
		if !ok {
			continue
		}
		spans = append(spans, funcSpan{start: start, size: uint64(r.Size), name: ci.DisplayName()})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	funcNameAt := func(va uint64) (string, bool) {
		i := sort.Search(len(spans), func(i int) bool { return spans[i].start > va })
		if i == 0 {
			return "", false
		}
		s := spans[i-1]
		if va < s.start || va-s.start >= s.size {
			return "", false
		}
		return s.name, true
	}
	for _, pe := range clResult.Pool {
		if pe.Kind != cluster.PoolTagged {
			continue
		}
		cid, cidKnown := pl.CIDForRef(pe.RefID)
		isCode := pl.CT != nil && cidKnown && cid == pl.CT.Code
		if !isCode {
			continue
		}
		{
			if name := pl.ResolveObjectName(pe.RefID); name != "" {
				poolCodeNames[pe.Index] = name
			}
			// Try matching by TextOffset → VA → function name
			if _, exists := poolCodeNames[pe.Index]; !exists {
				if ce, ok2 := codeByRef[pe.RefID]; ok2 && ce.TextOffset > 0 {
					textOff := uint64(ce.TextOffset)
					if textOff < codeOff {
						continue
					}
					delta := textOff - codeOff
					if delta > ^uint64(0)-codeVA {
						continue
					}
					va := codeVA + delta
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
					poolCodeNames[pe.Index] = ci.DisplayName()
				}
			}
		}
	}

	// Build PP index → type testing stub name map.
	// When a Type object is loaded from the pool and its
	// type_test_stub_entry_point_ (offset 7 from tagged) is called via BLR,
	// the type tracker needs the stub name to resolve the call.
	poolTTSNames := naming.BuildTTSCallTargets(clResult.Pool, pl)

	poolData := &typetrack.PoolLookupData{
		RefToNamed:            pl.RefToNamed,
		RefCID:                pl.RefCID,
		CT:                    pl.CT,
		BaseObjLimit:          pl.BaseObjLimit,
		CodeRefToName:         codeRefToName,
		VmRefCID:              pl.VmRefCID,
		PoolCodeNames:         poolCodeNames,
		TypeTestingStubNames:  poolTTSNames,
		FunctionRefToName:     make(map[int]string),
		FunctionRefToLeafName: make(map[int]string),
		ObjectRefToName:       make(map[int]string),
		ClassIDToName:         make(map[int]string),
	}
	for i := range clResult.Named {
		no := &clResult.Named[i]
		if name := pl.ResolveObjectName(no.RefID); name != "" {
			poolData.ObjectRefToName[no.RefID] = name
		}
		if pl.CT != nil && no.CID == pl.CT.Function {
			if name := pl.FunctionDisplayName(no.RefID); name != "" {
				poolData.FunctionRefToName[no.RefID] = name
			}
			if name := pl.ResolveIsolateName(no); name != "" {
				poolData.FunctionRefToLeafName[no.RefID] = name
			}
		}
	}
	for i := range clResult.Classes {
		ci := &clResult.Classes[i]
		if name, ok := pl.StringForRef(ci.NameRefID); ok && name != "" {
			poolData.ClassIDToName[int(ci.ClassID)] = name
		}
	}
	if vmResult != nil {
		poolData.VmFields = vmResult.Fields
		poolData.VmTypes = vmResult.Types
		poolData.VmClasses = vmResult.Classes
		for i := range vmResult.Classes {
			ci := &vmResult.Classes[i]
			if name := pl.ResolveVMObjectName(ci.RefID); name != "" {
				if _, exists := poolData.ClassIDToName[int(ci.ClassID)]; !exists {
					poolData.ClassIDToName[int(ci.ClassID)] = name
				}
			}
		}
	}

	// The dispatch origin is stable across supported releases, but its source
	// spelling changes: OriginElement() through 2.18 and kOriginElement from
	// 2.19. A populated table without a verified exact-version fact is still a
	// profile inconsistency rather than a reason to guess.
	kOriginElement, hasDispatchOrigin := sdk.DispatchTableOriginElement(info.Version.DartVersion, isARM64)
	if len(dispatchEntries) > 0 && !hasDispatchOrigin {
		return BLRBreakdown{}, nil, nil, fmt.Errorf("dart %s has dispatch entries but no verified dispatch-table origin", info.Version.DartVersion)
	}

	// Get allocation stub offsets from the exact snapshot profile. Pointer
	// compression changes the Thread layout on supported 64-bit targets.
	var allocStubOffsets map[int64]string
	if target, ok := vmtables.TargetProfileFromVersion(info.Version, isARM64); ok {
		allocStubOffsets = vmtables.ThreadStubOffsets(target)
	}

	ctx := typetrack.BuildTypeContext(clResult, poolData, dispatchEntries, byCodeIndex, info.Version, kOriginElement, thrFields, allocStubOffsets,
		buildAllocationStubCIDs(clResult, pl, ranges, codeVA, codeOff))
	// extends + implements: bounds a selector scan to the receiver's subtypes.
	ctx.SetHierarchy(cluster.NewClassHierarchy(clResult, vmResult))
	registerCC, hasRegisterCC := sdk.DartRegisterCallingConvention(info.Version.DartVersion, isARM64)

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
	if err := typetrack.WriteDispatchTable(outDir, dispatchEntries, ctx); err != nil {
		return BLRBreakdown{}, nil, nil, fmt.Errorf("write dispatch table: %w", err)
	}

	// 3. Re-disassemble all functions and collect instruction lists.
	var funcInstsARM64 typetrack.FuncInstsARM64
	var funcInstsX86 typetrack.FuncInstsX86
	if isARM64 {
		funcInstsARM64 = make(map[string][]disasm.Inst, len(ranges))
	} else {
		funcInstsX86 = make(map[string][]x86.Decoded, len(ranges))
	}
	// One source for the ClassIdTag layout: snapshot.ClassIdTagLayout, which
	// is also what fill_strings.go reads and what the SDK drift gate checks.
	classIDPos, classIDSize, ok := snapshot.ClassIdTagLayout(info.Version.DartVersion)
	if !ok {
		return BLRBreakdown{}, nil, nil, fmt.Errorf("unsupported class-id tag layout for Dart %s", info.Version.DartVersion)
	}
	ctx.SetClassIDTagLayout(classIDPos, classIDSize)
	blEdges := make(map[string][]typetrack.BLEdge)

	// Build address → function name lookup for BL/CALL target resolution.
	type funcRange struct {
		start, size uint64
		name        string
	}
	containsFuncVA := func(fr funcRange, va uint64) bool {
		return va >= fr.start && va-fr.start < fr.size
	}
	codeImage := NewCodeImage(code, codeVA, codeOff, pl, nil)
	// Build the complete target-address index BEFORE extracting any call edges.
	// The old single pass appended each range immediately before disassembling it,
	// so a direct call could resolve only to the current or an EARLIER function.
	// Forward calls were silently absent from blEdges. That was already an
	// interprocedural blind spot; once register-CC evidence was attached to those
	// edges it also starved later callees of argument-location evidence and caused
	// a large BLR-resolution regression.
	funcRanges := make([]funcRange, 0, len(ranges))
	for i := range ranges {
		fs, ok := codeImage.Slice(ranges[i])
		if !ok {
			continue
		}
		funcRanges = append(funcRanges, funcRange{
			start: fs.VA,
			size:  uint64(ranges[i].Size),
			name:  fs.Name,
		})
	}

	for i := range ranges {
		r := &ranges[i]
		fs, ok := codeImage.Slice(*r)
		if !ok {
			continue
		}
		funcVA := fs.VA
		name := fs.Name
		ownerName := fs.Owner
		var codeName naming.CodeNameInfo
		if r.RefID >= 0 {
			codeName = pl.CodeNames[r.RefID]
			ctx.FuncMayUseRegisterCC[name] = codeName.MayUseRegisterCC
		}
		// For 3.4.3+ an SDK register table exists globally but a specific
		// Function may still be forced to the stack. Only the definitive
		// snapshot-negative cases use stack recovery here. Ordinary eligible
		// functions are left unseeded until RunInterprocedural sees independent
		// multi-call-site register-setup evidence.
		receiverDefinitelyOnStack := codeName.MustUseStackCC
		legacyStaticReceiverSlot := receiverDefinitelyOnStack &&
			!sdk.HasDartRegisterCallingConvention(info.Version.DartVersion)

		// Map INSTANCE function name → owner class ID for receiver init. A static
		// method is class-owned too, so OwnerName alone is not receiver evidence.
		if ownerName != "" && codeName.ReceiverKnown && codeName.HasImplicitReceiver {
			if cid, ok := classNameToID[ownerName]; ok && cid >= 0 {
				ctx.FuncOwnerClass[name] = cid
				// Before the register calling convention (SDK 3.4.0, first
				// supported profile 3.4.3) there is none:
				// the receiver comes in on the caller's stack and the prologue
				// loads it out. WHERE depends on whether the function copies
				// its parameters -- see cluster.ReceiverFrameSlot, which
				// carries the SDK derivation and all three cases.
				//
				// This used to be a single unconditional
				// `(1 + FixedParamsWithReceiver) * 8`, which is the no-copy
				// case only. A function with optional parameters addresses
				// them off ArgumentsDescriptor.count at runtime, so it has no
				// static slot and the old formula recorded one no load could
				// match -- a dead seed rather than a wrong one, but still a
				// claim with nothing behind it.
				if legacyStaticReceiverSlot && r.RefID >= 0 {
					ci := codeName
					if slot, ok := cluster.ReceiverFrameSlot(
						ci.FixedParamsWithReceiver, ci.OptionalParams,
						ci.IsSuspendable, 8,
					); ok {
						ctx.FuncReceiverStackSlot[name] = int(slot)
					}
				}
			}
		}

		// Stack-passed parameters with a declared class. Same frame formula as the
		// receiver (cluster.ParamFrameSlot) and the same preconditions: the function
		// passes its arguments on the stack (every function before the register
		// calling convention, the snapshot-proven stack-CC ones after it) with a
		// constant-index prologue, and the declared signature agrees on the arity.
		if r.RefID >= 0 && (legacyStaticReceiverSlot || !sdk.HasDartRegisterCallingConvention(info.Version.DartVersion) || codeName.MustUseStackCC) &&
			codeName.ParamCountKnown && codeName.FixedParamsWithReceiver > 0 {
			if classes, ok := ctx.DeclaredParamClasses(name); ok && len(classes) == codeName.FixedParamsWithReceiver {
				_, hasReceiver := ctx.FuncOwnerClass[name]
				for i, cls := range classes {
					if cls < 0 || (i == 0 && hasReceiver) {
						continue // no class to bound, or the receiver (owner class)
					}
					if slot, ok := cluster.ParamFrameSlot(codeName.FixedParamsWithReceiver, codeName.OptionalParams, codeName.IsSuspendable, i, 8); ok {
						ctx.FuncStackParams[name] = append(ctx.FuncStackParams[name], typetrack.StackParam{Slot: int(slot), Class: cls})
					}
				}
			}
		}

		funcCode := fs.Code

		if isARM64 {
			insts := disasm.Disassemble(funcCode, disasm.Options{
				BaseAddr: funcVA,
			})
			funcInstsARM64[name] = insts
			if _, isInstance := ctx.FuncOwnerClass[name]; hasRegisterCC && codeName.MayUseRegisterCC && isInstance {
				fir := decompiler.BuildARM64IR(name, info.Version.DartVersion, info.Version.CompressedPointers, insts, registerCC)
				for _, pos := range decompiler.LiveInArgIndices(fir) {
					if pos == 0 {
						ctx.FuncReceiverInRegister[name] = true
						break
					}
				}
			}

			// Recover an actual stack receiver not only for metadata-proven stack
			// functions, but also for modern MAY-register functions whose receiver
			// register is not live-in. This catches the precompiler-only
			// must_use_stack_calling_convention bit that full AOT snapshots omit;
			// the recovery itself is a positive machine-code proof (FP load plus
			// owner-field use), not a guess from the missing metadata.
			_, isInstance := ctx.FuncOwnerClass[name]
			recoverStackReceiver := receiverDefinitelyOnStack ||
				(hasRegisterCC && codeName.MayUseRegisterCC && isInstance && !ctx.FuncReceiverInRegister[name])
			if recoverStackReceiver {
				if ownerCID, ok := ctx.FuncOwnerClass[name]; ok && ownerCID >= 0 {
					if _, set := ctx.FuncReceiverStackSlot[name]; !set {
						if slot, ok := typetrack.RecoverReceiverStackSlotARM64(insts, ownerCID, ctx); ok {
							ctx.FuncReceiverStackSlot[name] = slot
						}
					}
					// Functions that address parameters through the
					// ArgumentsDescriptor have no static slot for the scan
					// above to find; their receiver is typed at the load.
					if pc, rl, ok := typetrack.RecoverArgsDescReceiverARM64(insts, ownerCID, ctx); ok {
						ctx.ReceiverLoadAtPC[pc] = rl
					}
				}
			}

			argMasks := disasm.DirectCallArgMasksARM64(insts)
			// Collect BL edges for inter-procedural propagation.
			for _, inst := range insts {
				if target, ok := arm64.BL(inst.Raw, inst.Addr); ok {
					calleeName := ""
					for _, fr := range funcRanges {
						if containsFuncVA(fr, target) {
							calleeName = fr.name
							break
						}
					}
					if calleeName != "" {
						blEdges[name] = append(blEdges[name], typetrack.BLEdge{
							Callee:  calleeName,
							CallPC:  inst.Addr,
							ArgMask: argMasks[inst.Addr],
						})
					}
				}
			}
		} else {
			insts := typetrack.DecodeX86Function(funcCode, funcVA)
			funcInstsX86[name] = insts
			if _, isInstance := ctx.FuncOwnerClass[name]; hasRegisterCC && codeName.MayUseRegisterCC && isInstance {
				fir := decompiler.BuildX86IR(name, info.Version.DartVersion, insts, registerCC)
				for _, pos := range decompiler.LiveInArgIndices(fir) {
					if pos == 0 {
						ctx.FuncReceiverInRegister[name] = true
						break
					}
				}
			}

			// Same positive stack-receiver recovery on x86_64.
			_, isInstance := ctx.FuncOwnerClass[name]
			recoverStackReceiver := receiverDefinitelyOnStack ||
				(hasRegisterCC && codeName.MayUseRegisterCC && isInstance && !ctx.FuncReceiverInRegister[name])
			if recoverStackReceiver {
				if ownerCID, ok := ctx.FuncOwnerClass[name]; ok && ownerCID >= 0 {
					if _, set := ctx.FuncReceiverStackSlot[name]; !set {
						if slot, ok := typetrack.RecoverReceiverStackSlotX86(insts, ownerCID, ctx); ok {
							ctx.FuncReceiverStackSlot[name] = slot
						}
					}
					if pc, rl, ok := typetrack.RecoverArgsDescReceiverX86(insts, ownerCID, ctx); ok {
						ctx.ReceiverLoadAtPC[pc] = rl
					}
				}
			}

			argMasks := disasm.DirectCallArgMasksX86(insts)
			// Collect CALL rel32 edges for inter-procedural propagation.
			for _, inst := range insts {
				if inst.Inst.Op == x86asm.CALL {
					if target, ok := x86.RelTarget(inst.Inst, inst.VA, inst.Len); ok {
						calleeName := ""
						for _, fr := range funcRanges {
							if containsFuncVA(fr, target) {
								calleeName = fr.name
								break
							}
						}
						if calleeName != "" {
							blEdges[name] = append(blEdges[name], typetrack.BLEdge{
								Callee:  calleeName,
								CallPC:  inst.VA,
								ArgMask: argMasks[inst.VA],
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
	// Interprocedural propagation stops early at a fixed point. Ten rounds is a
	// resource budget, not a correctness assumption: if it is exhausted,
	// RunInterprocedural discards partial propagated facts and performs one
	// conservative declared-types-only pass. Override the budget via
	// AOTOPSY_TYPETRACK_ITERATIONS for diagnostics/tuning.
	maxIter := 10 // M-9 fix: was 5, comment says 10, code now matches comment
	if v := os.Getenv("AOTOPSY_TYPETRACK_ITERATIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxIter = n
		}
	}
	interResult := typetrack.RunInterprocedural(ctx, funcInstsARM64, funcInstsX86, blEdges, maxIter, isARM64, blTargetToName)

	// 5. Rewrite call_edges.jsonl with resolved BLR targets.
	bd, err := rewriteCallEdges(
		outDir,
		interResult,
		naming.BuildTTSCallTargets(clResult.Pool, pl),
		poolCodeNames,
		buildThreadCallableTargets(thrFields, allocStubOffsets),
	)
	if err != nil {
		return bd, ctx, interResult, fmt.Errorf("rewrite call_edges: %w", err)
	}

	// 6. field_accessor_xref.jsonl — (class, field) → the functions that read
	// and write it, from the per-function field accesses the type analysis
	// recorded.
	if err := writeFieldAccessorXref(outDir, ctx, interResult, clResult, pl, info.Version.CompressedPointers); err != nil {
		return bd, ctx, interResult, fmt.Errorf("write field_accessor_xref.jsonl: %w", err)
	}

	// ctx is returned so the caller can report per-source hit counters;
	// interResult so the evidence collector can record the BLR
	// resolutions and field accesses with the confidence and slot index
	// the analysis actually produced, rather than the lossy versions that
	// survive a round trip through call_edges.jsonl.
	return bd, ctx, interResult, nil
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
	pl *naming.PoolLookups,
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
func rewriteCallEdges(
	outDir string,
	interResult *typetrack.InterResult,
	ttsByPoolIndex map[int]string,
	codeByPoolIndex map[int]string,
	thrStubTargets map[string]string,
) (BLRBreakdown, error) {
	var bd BLRBreakdown
	edgesPath := filepath.Join(outDir, "call_edges.jsonl")
	edges, err := jsonutil.ReadJSONL[disasm.CallEdgeRecord](edgesPath, jsonutil.StandardLimits)
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
		if e.Runtime != nil {
			return bd, fmt.Errorf("call edge %s/%s contains runtime enrichment; static type inference requires a static generation", e.FromFunc, e.FromPC)
		}
		// Resolution is current fixed-point state, not historical enrichment.
		// Clear any result from a previous typetrack pass before applying this
		// run so a formerly-polymorphic/monomorphic site can become unresolved
		// without retaining stale callees.
		e.Target = ""
		e.Targets = nil
		e.Candidates = 0
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
		} else if name := naming.TtsCallTarget(e.Via, ttsByPoolIndex); name != "" {
			// A call through a pool slot holding a Type invokes that type's
			// testing stub -- GenerateIndirectTTSCall, see ttscall.go. One
			// known callee, so it counts as a stub rather than a Dart-level
			// monomorphic call.
			e.Target = name
			bd.Stub++
		} else if name := naming.PoolCallTarget(e.Via, codeByPoolIndex); name != "" {
			// The pool index was independently proven to hold a Code object.
			// Ignore Via's display suffix completely: it is provenance text, not
			// callee identity. A Code slot denotes one exact callable.
			e.Target = name
			bd.Monomorphic++
		} else if strings.HasPrefix(e.Via, "THR.") {
			// A Thread-relative provenance names a FIELD, not necessarily a
			// callable. The same SDK table contains data such as
			// dispatch_table_array and field_table_values alongside cached VM stub
			// entry points. Resolve only the exact field names whose offsets are in
			// the independently-derived ThreadStubOffsets table; treating every
			// THR field as a stub fabricates call targets from data pointers.
			fieldName := strings.TrimPrefix(e.Via, "THR.")
			if stubName := thrStubTargets[fieldName]; stubName != "" {
				e.Target = stubName
				bd.Stub++
			} else {
				bd.Unresolved++
			}
		} else {
			bd.Unresolved++
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

	// Publish transactionally. A direct os.Create + encoder loop can truncate
	// the previous generation before an encode/write failure is known.
	if _, err := jsonutil.WriteJSONLFile(edgesPath, edges); err != nil {
		return bd, fmt.Errorf("write call_edges.jsonl: %w", err)
	}

	return bd, nil
}

// buildThreadCallableTargets joins the SDK-derived Thread field table with the
// subset of Thread fields that are callable targets.
//
// ThreadStubOffsets supplies canonical names for cached VM-stub entry points.
// THRFields itself also carries runtime/leaf-runtime entry points and cached
// function entry points as literal "*_entry_point" fields: extract_thr writes
// those names from runtime_offsets_extracted.h plus the SDK runtime-entry lists
// and drift-gates them against the exact SDK source.  A few cached CodePtr
// stubs are stored as "*_stub" rather than an entry-point scalar; keep only the
// exact callable fields proven by CACHED_VM_STUBS_LIST.  Write-barrier wrapper
// slots are likewise callable entry points and are named explicitly by the
// extracted write_barrier_wrappers_thread_offset range.
//
// Crucially, ordinary Thread data fields such as dispatch_table_array and
// field_table_values never enter this map. Treating every named THR load as a
// callee previously fabricated thousands of resolved indirect calls to data.
// The result is keyed by the raw Thread field name because that is what
// disassembly provenance stores in CallEdge.Via.
func buildThreadCallableTargets(thrFields map[int]string, stubOffsets map[int64]string) map[string]string {
	if len(thrFields) == 0 {
		return nil
	}
	out := make(map[string]string, len(stubOffsets)+32)
	for off, stubName := range stubOffsets {
		if stubName == "" {
			continue
		}
		if fieldName := thrFields[int(off)]; fieldName != "" {
			out[fieldName] = stubName
		}
	}
	for _, fieldName := range thrFields {
		if fieldName == "" {
			continue
		}
		// Prefer the canonical VM-stub name supplied above when the same field
		// is represented in ThreadStubOffsets.
		if _, exists := out[fieldName]; exists {
			continue
		}
		if target, ok := strings.CutSuffix(fieldName, "_entry_point"); ok && target != "" {
			out[fieldName] = target
			continue
		}
		switch fieldName {
		case "enter_safepoint_stub":
			out[fieldName] = "EnterSafepoint"
		case "exit_safepoint_stub":
			out[fieldName] = "ExitSafepoint"
		default:
			if strings.HasPrefix(fieldName, "wb_wrapper_R") {
				out[fieldName] = fieldName
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
