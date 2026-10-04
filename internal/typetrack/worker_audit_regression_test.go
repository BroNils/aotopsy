package typetrack

import (
	"testing"

	"aotopsy/internal/arch/arm64"
	archx86 "aotopsy/internal/arch/x86"
	"aotopsy/internal/cluster"
	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
	"aotopsy/internal/snapshot"
	"golang.org/x/arch/x86/x86asm"
)

func minimalTypeContext() *TypeContext {
	return &TypeContext{
		DartVersion:              "3.12.2",
		FieldTypes:               map[int]int{},
		FieldByOwnerOffset:       map[int]map[int32]int{},
		SuperClass:               map[int]int{},
		CalleeExitTypes:          map[uint64]TypeLattice{},
		CalleeAllExitTypes:       map[uint64][31]TypeLattice{},
		MethodNameToSelectorImms: map[string][]int{},
		PoolClosureFunctionNames: map[int]string{},
		DispatchBySlot:           map[int]cluster.DispatchTableEntry{},
		DispatchCodeIndexToName:  map[int]string{},
		SelectorOffsets:          map[uint64]int{},
		SelectorCache:            map[int][]string{},
		SelectorMonomorphic:      map[int]string{},
	}
}

func TestSelectorCandidatesUsesOriginRelativeSelectorImmediateWithoutRTAElimination(t *testing.T) {
	ctx := minimalTypeContext()
	origin, ok := sdk.DispatchTableOriginElement("3.12.2", sdk.ArchARM64)
	if !ok {
		t.Fatal("supported ARM64 dispatch origin unavailable")
	}
	ctx.KOriginElement = origin
	const (
		classID    = 42
		imm        = 100
		clusterIdx = 7
	)
	ctx.DispatchBySlot[classID+imm] = cluster.DispatchTableEntry{Kind: cluster.DispatchCode, ClusterIndex: clusterIdx}
	ctx.DispatchCodeIndexToName[clusterIdx] = "foo"
	ctx.SuperClass[classID] = -1
	ctx.InstantiatedClasses = map[int]bool{999: true} // deliberately excludes classID

	targets := ctx.selectorCandidates(imm)
	if len(targets) != 1 || targets[0] != "foo" {
		t.Fatalf("selectorCandidates(%d) = %v, want [foo]", imm, targets)
	}
}

func TestBuildDispatchTablesDerivesSelectorImmFromFunctionOwner(t *testing.T) {
	origin, ok := sdk.DispatchTableOriginElement("3.12.2", sdk.ArchARM64)
	if !ok {
		t.Fatal("supported ARM64 dispatch origin unavailable")
	}
	const (
		classRef     = 300
		functionRef  = 100
		functionName = 200
		clusterIdx   = 7
		classID      = 42
		selectorImm  = 100
	)
	ct := &snapshot.CIDTable{Class: 10, Function: 11, PatchClass: 12}
	classObj := &cluster.NamedObject{CID: ct.Class, RefID: classRef, NameRefID: -1, OwnerRefID: -1}
	fn := &cluster.NamedObject{CID: ct.Function, RefID: functionRef, NameRefID: functionName, OwnerRefID: classRef}
	pl := &PoolLookupData{
		CT:                    ct,
		RefToNamed:            map[int]*cluster.NamedObject{classRef: classObj, functionRef: fn},
		CodeRefToName:         map[int]string{},
		FunctionRefToName:     map[int]string{functionRef: "Widget.foo"},
		FunctionRefToLeafName: map[int]string{functionRef: "foo"},
	}
	result := &cluster.Result{
		Classes: []cluster.ClassInfo{{RefID: classRef, ClassID: classID}},
		Codes:   []cluster.CodeEntry{{ClusterIndex: clusterIdx, OwnerRef: 999}}, // deliberately bogus OwnerRef
	}
	entry := cluster.DispatchTableEntry{
		Index:        origin + classID + selectorImm,
		Kind:         cluster.DispatchCode,
		ClusterIndex: clusterIdx,
	}
	ctx := minimalTypeContext()
	buildDispatchTables(ctx, []cluster.DispatchTableEntry{entry}, map[int]*cluster.NamedObject{clusterIdx: fn}, result, pl, origin)

	imms := ctx.MethodNameToSelectorImms["foo"]
	if len(imms) != 1 || imms[0] != selectorImm {
		t.Fatalf("selector immediates = %v, want [%d]", imms, selectorImm)
	}
	if got := ctx.DispatchCodeIndexToName[clusterIdx]; got != "Widget.foo" {
		t.Fatalf("dispatch semantic name = %q, want Widget.foo", got)
	}
}

func TestMethodNameIndexKeepsSemanticAndLeafIdentitiesSeparate(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 11}
	const functionRef = 100
	fn := &cluster.NamedObject{CID: ct.Function, RefID: functionRef, NameRefID: 200}
	pl := &PoolLookupData{
		CT:                    ct,
		RefToNamed:            map[int]*cluster.NamedObject{functionRef: fn},
		FunctionRefToName:     map[int]string{functionRef: "Owner.parent.<anonymous closure>"},
		FunctionRefToLeafName: map[int]string{functionRef: "<anonymous closure>"},
	}

	got := buildMethodNameToRefIDs(pl)
	for _, key := range []string{"Owner.parent.<anonymous closure>", "<anonymous closure>"} {
		refs := got[key]
		if len(refs) != 1 || refs[0] != functionRef {
			t.Fatalf("method index[%q] = %v, want [%d]", key, refs, functionRef)
		}
	}
	if _, exists := got["Owner.<anonymous closure>"]; exists {
		t.Fatalf("method index rebuilt a class-qualified closure instead of using naming identity: %v", got)
	}
}

func TestARMFieldLoadFormsRecordReadsWithoutFabricatingType(t *testing.T) {
	cases := []struct {
		name string
		raw  uint32
		off  int32
	}{
		{"LDUR64", 0xF8407020, 7},
		{"LDUR32", 0xB8407020, 7},
		{"LDURH", 0x78407020, 7},
		{"LDR64", 0xF9400420, 8},
		{"LDR32", 0xB9400420, 4},
	}
	for i, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := minimalTypeContext()
			ctx.FieldByOwnerOffset[100] = map[int32]int{tt.off + 1: 900}
			var state [31]TypeLattice
			state[1] = ClassBound(100)
			result := &IntraResult{}
			tc := &transferCtx{
				state:      &state,
				inst:       disasm.Inst{Addr: uint64(0x1000 + i*4), Raw: tt.raw, Size: 4},
				ctx:        ctx,
				result:     result,
				stackTypes: map[int]TypeLattice{},
			}
			if !handleFieldLoad(tc) {
				t.Fatalf("%s was not consumed as a field load", tt.name)
			}
			if state[0].Kind != LatticeTop {
				t.Fatalf("%s fabricated loaded type %+v from receiver class", tt.name, state[0])
			}
			if len(result.FieldAccesses) != 1 {
				t.Fatalf("%s recorded %d field reads, want 1", tt.name, len(result.FieldAccesses))
			}
			got := result.FieldAccesses[0]
			if got.ClassID != 100 || got.ByteOffset != tt.off || got.IsStore {
				t.Fatalf("%s field access = %+v, want class=100 off=%d read", tt.name, got, tt.off)
			}
		})
	}
}

func TestARMUnsignedFieldStoresRecordXrefWithoutClassWideValueFact(t *testing.T) {
	cases := []struct {
		name string
		raw  uint32
		off  int32
	}{
		{"STR64", 0xF9000422, 8},
		{"STR32", 0xB9000422, 4},
	}
	for i, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := minimalTypeContext()
			ctx.FieldByOwnerOffset[100] = map[int32]int{tt.off + 1: 900}
			var state [31]TypeLattice
			state[1] = ExactClass(100)
			state[2] = ExactClass(200)
			result := &IntraResult{}
			stack := map[int]TypeLattice{}
			tc := &transferCtx{
				state:      &state,
				inst:       disasm.Inst{Addr: uint64(0x2000 + i*4), Raw: tt.raw, Size: 4},
				ctx:        ctx,
				result:     result,
				stackTypes: stack,
			}
			handleStackStore(tc)
			if len(result.FieldAccesses) != 1 || !result.FieldAccesses[0].IsStore {
				t.Fatalf("%s did not emit one store xref: %+v", tt.name, result.FieldAccesses)
			}
			if len(stack) != 0 {
				t.Fatalf("%s created class-wide pseudo-memory facts: %v", tt.name, stack)
			}
		})
	}
}

func TestSuperclassCyclesDegradeWithoutLooping(t *testing.T) {
	hierarchy := map[int]int{3: 4, 4: 3, 5: -1}
	if got := LCA(5, 3, hierarchy); got != -1 {
		t.Fatalf("LCA across cyclic malformed hierarchy = %d, want -1", got)
	}
	ctx := minimalTypeContext()
	ctx.SuperClass = hierarchy
	if _, ok := ctx.FieldValueType(3, 7, 0); ok {
		t.Fatal("cyclic hierarchy fabricated a field type")
	}
	if ctx.OwnerHasFieldAt(3, 7) {
		t.Fatal("cyclic hierarchy fabricated an owner field")
	}
}

func TestARMRetIsTerminalCFG(t *testing.T) {
	insts := []disasm.Inst{
		{Addr: 0x3000, Raw: 0xD65F03C0, Size: 4},
		{Addr: 0x3004, Raw: 0xD503201F, Size: 4},
	}
	blocks := buildBlocks(insts)
	if len(blocks) != 2 || len(blocks[0].successors) != 0 {
		t.Fatalf("RET CFG = %+v, want two blocks and no fallthrough", blocks)
	}
}

func TestReceiverRecoveryRejectsUseBeforeDefinitionAndClobber(t *testing.T) {
	ctx := newCtxWithOwnerField(100, 11)
	if _, ok := RecoverReceiverStackSlotARM64([]disasm.Inst{
		{Raw: rawLDUR_W1_X0_11},
		{Raw: rawLDR_X0_X29_16},
	}, 100, ctx); ok {
		t.Fatal("receiver recovery accepted field use before candidate load")
	}
	if _, ok := RecoverReceiverStackSlotARM64([]disasm.Inst{
		{Raw: rawLDR_X0_X29_16},
		{Raw: 0xAA0103E0}, // MOV X0, X1: clobber candidate
		{Raw: rawLDUR_W1_X0_11},
	}, 100, ctx); ok {
		t.Fatal("receiver recovery accepted owner-field use after clobber")
	}
}

func TestKnownStubBLRProducesExactlyOneResolution(t *testing.T) {
	ctx := minimalTypeContext()
	var state [31]TypeLattice
	state[1] = KnownStub("PPCode:targetFn", 17)
	result := &IntraResult{}
	tc := &transferCtx{
		state:      &state,
		inst:       disasm.Inst{Addr: 0x4000, Raw: 0xD63F0020, Size: 4}, // BLR X1
		ctx:        ctx,
		result:     result,
		stackTypes: map[int]TypeLattice{},
	}
	if !handleBLR(tc) {
		t.Fatal("BLR X1 was not handled")
	}
	if len(result.BLRResolutions) != 1 || !result.BLRResolutions[0].Resolved || result.BLRResolutions[0].TargetName != "targetFn" {
		t.Fatalf("BLR resolutions = %+v, want one resolved targetFn", result.BLRResolutions)
	}
}

func TestGenericAllocationBLRDoesNotTreatPreCallR0AsAllocatedClass(t *testing.T) {
	ctx := minimalTypeContext()
	ctx.InstantiatedClasses = map[int]bool{}
	var state [31]TypeLattice
	state[0] = ExactClass(777) // stale/pre-call value; not an AllocateObject input
	state[1] = KnownStub("AllocateObject", 0x220)
	result := &IntraResult{}
	tc := &transferCtx{
		state:      &state,
		inst:       disasm.Inst{Addr: 0x4100, Raw: 0xD63F0020, Size: 4}, // BLR X1
		ctx:        ctx,
		result:     result,
		stackTypes: map[int]TypeLattice{},
	}
	if !handleBLR(tc) {
		t.Fatal("generic allocation BLR was not handled")
	}
	if state[0].Kind != LatticeTop {
		t.Fatalf("post-allocation R0 = %+v, want Top when class is unknown", state[0])
	}
	if len(ctx.InstantiatedClasses) != 0 {
		t.Fatalf("generic allocation fabricated observed class evidence: instantiated=%v", ctx.InstantiatedClasses)
	}
}

func TestFixedPointEvidenceReplacesEarlierVisitAtSamePC(t *testing.T) {
	ctx := minimalTypeContext()
	ctx.FieldByOwnerOffset[100] = map[int32]int{9: 900}
	result := &IntraResult{}
	const pc = uint64(0x4200)

	// First visit has a concrete receiver and records a field access.
	var first [31]TypeLattice
	first[1] = ClassBound(100)
	transferInstruction(&first, disasm.Inst{Addr: pc, Raw: 0xF9400420, Size: 4}, 0, ctx, result, nil, map[int]TypeLattice{}, nil) // LDR X0,[X1,#8]
	if len(result.FieldAccesses) != 1 || result.FieldAccesses[0].ClassID != 100 {
		t.Fatalf("first visit field evidence = %+v", result.FieldAccesses)
	}

	// Final visit reaches the same instruction with unknown receiver state. The
	// earlier concrete claim must disappear instead of surviving forever.
	var final [31]TypeLattice
	for i := range final {
		final[i] = Top()
	}
	transferInstruction(&final, disasm.Inst{Addr: pc, Raw: 0xF9400420, Size: 4}, 0, ctx, result, nil, map[int]TypeLattice{}, nil)
	if len(result.FieldAccesses) != 0 {
		t.Fatalf("stale first-visit field evidence survived final visit: %+v", result.FieldAccesses)
	}

	recordBLRResolution(result, BlrResolution{PC: pc, Resolved: true, TargetName: "old", Confidence: ResolutionStub, Derivation: DerivationStub})
	recordBLRResolution(result, BlrResolution{PC: pc, Resolved: false, Confidence: ResolutionUnknown, Derivation: DerivationUnknown})
	if len(result.BLRResolutions) != 1 || result.BLRResolutions[0].Resolved || result.BLRResolutions[0].TargetName != "" {
		t.Fatalf("BLR final-state replacement failed: %+v", result.BLRResolutions)
	}
}

func TestX86UnknownFullExitUsesDeclaredReturnSeed(t *testing.T) {
	call := archx86.Decoded{
		VA:   0x5000,
		Len:  5,
		Inst: x86asm.Inst{Op: x86asm.CALL, Args: [4]x86asm.Arg{x86asm.Rel(0x10fb)}},
	}
	target := call.VA + uint64(call.Len) + uint64(int64(x86asm.Rel(0x10fb)))
	ctx := minimalTypeContext()
	ctx.CalleeAllExitTypes[target] = [31]TypeLattice{}
	ctx.CalleeExitTypes[target] = ClassBound(42)
	var state [31]TypeLattice
	state[x86RegRAX] = ExactClass(7)
	tc := &transferCtxX86{state: &state, inst: call, ctx: ctx, result: &IntraResult{}, stackTypes: map[int]TypeLattice{}}
	if !handleX86Call(tc) {
		t.Fatal("direct x86 CALL was not handled")
	}
	if !state[x86RegRAX].Equal(ClassBound(42)) {
		t.Fatalf("RAX after call = %+v, want declared return Class(42)", state[x86RegRAX])
	}
}

func TestARMUnknownFullExitUsesDeclaredReturnSeed(t *testing.T) {
	pc := uint64(0x6000)
	raw := uint32(0x94000001)
	target, ok := arm64.BL(raw, pc)
	if !ok {
		t.Fatal("test BL encoding did not decode")
	}
	ctx := minimalTypeContext()
	ctx.CalleeAllExitTypes[target] = [31]TypeLattice{}
	ctx.CalleeExitTypes[target] = ClassBound(42)
	var state [31]TypeLattice
	state[0] = ExactClass(7)
	tc := &transferCtx{state: &state, inst: disasm.Inst{Addr: pc, Raw: raw, Size: 4}, ctx: ctx, result: &IntraResult{}, stackTypes: map[int]TypeLattice{}}
	if !handleBL(tc) {
		t.Fatal("ARM BL was not handled")
	}
	if !state[0].Equal(ClassBound(42)) {
		t.Fatalf("X0 after BL = %+v, want declared return Class(42)", state[0])
	}
}

func TestARMCallDoesNotImportCalleeLocalRegisters(t *testing.T) {
	pc := uint64(0x6100)
	raw := uint32(0x94000001)
	target, ok := arm64.BL(raw, pc)
	if !ok {
		t.Fatal("test BL encoding did not decode")
	}
	ctx := minimalTypeContext()
	var exit [31]TypeLattice
	exit[0] = ExactClass(42)
	exit[1] = ExactClass(99) // local callee state, never an ABI output
	ctx.CalleeAllExitTypes[target] = exit
	var state [31]TypeLattice
	state[1] = ExactClass(7)
	tc := &transferCtx{state: &state, inst: disasm.Inst{Addr: pc, Raw: raw, Size: 4}, ctx: ctx, result: &IntraResult{}, stackTypes: map[int]TypeLattice{}}
	if !handleBL(tc) {
		t.Fatal("ARM BL was not handled")
	}
	if !state[0].Equal(ExactClass(42)) {
		t.Fatalf("X0 after BL = %+v, want return Class(42)", state[0])
	}
	if state[1].Kind != LatticeTop {
		t.Fatalf("X1 after BL = %+v, want Top; callee local register leaked across call", state[1])
	}
}

func TestX86CallDoesNotImportCalleeLocalRegisters(t *testing.T) {
	call := archx86.Decoded{VA: 0x6200, Len: 5, Inst: x86asm.Inst{Op: x86asm.CALL, Args: [4]x86asm.Arg{x86asm.Rel(0x20)}}}
	target := call.VA + uint64(call.Len) + uint64(int64(x86asm.Rel(0x20)))
	ctx := minimalTypeContext()
	var exit [31]TypeLattice
	exit[x86RegRAX] = ExactClass(42)
	exit[13] = ExactClass(99) // callee local R13 state
	ctx.CalleeAllExitTypes[target] = exit
	var state [31]TypeLattice
	state[13] = ExactClass(7)
	tc := &transferCtxX86{state: &state, inst: call, ctx: ctx, result: &IntraResult{}, stackTypes: map[int]TypeLattice{}}
	if !handleX86Call(tc) {
		t.Fatal("x86 CALL was not handled")
	}
	if !state[x86RegRAX].Equal(ExactClass(42)) {
		t.Fatalf("RAX after CALL = %+v, want return Class(42)", state[x86RegRAX])
	}
	if state[13].Kind != LatticeTop {
		t.Fatalf("R13 after CALL = %+v, want Top; Dart calls clobber every allocatable register", state[13])
	}
}

func TestX86FlagClobberInvalidatesClassNarrowing(t *testing.T) {
	insts := []archx86.Decoded{
		x86Inst(0x7000, x86asm.MOV, x86asm.R9L, x86asm.Mem{Base: x86asm.RAX, Disp: -1}),
		x86Inst(0x7004, x86asm.SHR, x86asm.R9L, x86asm.Imm(12)),
		x86Inst(0x7008, x86asm.CMP, x86asm.R9, x86asm.Imm(42)),
		x86Inst(0x700c, x86asm.TEST, x86asm.RAX, x86asm.RAX),
		x86Inst(0x7010, x86asm.JE, x86asm.Rel(4)),
		x86Inst(0x7014, x86asm.NOP),
		x86Inst(0x7018, x86asm.RET),
	}
	ctx := minimalTypeContext()
	ctx.SetClassIDTagLayout(12, 20)
	var entry [31]TypeLattice
	AnalyzeFunctionX86(insts, ctx, entry, nil)
	if ctx.NarrowHits != 0 {
		t.Fatalf("CMP; TEST; JE produced %d stale class narrowing hit(s)", ctx.NarrowHits)
	}
}

func TestSelectorCacheIsIndependentOfObservedInstantiationSet(t *testing.T) {
	ctx := minimalTypeContext()
	ctx.DispatchBySlot[12] = cluster.DispatchTableEntry{Kind: cluster.DispatchCode, ClusterIndex: 1}
	ctx.DispatchCodeIndexToName[1] = "only"
	ctx.SuperClass[5] = -1 // 5 + selector 7 = slot 12
	first := ctx.selectorCandidates(7)
	ctx.InstantiatedClasses = map[int]bool{999: true}
	second := ctx.selectorCandidates(7)
	if len(first) != 1 || first[0] != "only" || len(second) != 1 || second[0] != "only" {
		t.Fatalf("observed instantiation set changed selector candidates: first=%v second=%v", first, second)
	}
}

func TestInterproceduralBudgetExhaustionFallsBackWithoutPropagatedParameterFact(t *testing.T) {
	ctx := minimalTypeContext()
	ctx.FuncOwnerClass = map[string]int{"callerA": 100, "callerB": 100}
	ctx.FuncReceiverInRegister = map[string]bool{"callerA": true, "callerB": true}
	ctx.FuncMayUseRegisterCC = map[string]bool{"callee": true}
	ctx.MethodNameToRefIDs = map[string][]int{}
	ctx.FuncParamTypes = map[int][]int{}
	ctx.FuncIsInstance = map[int]bool{}
	ctx.FuncReturnType = map[int]int{}

	caller := func(pc uint64) []disasm.Inst {
		return []disasm.Inst{
			{Addr: pc, Raw: 0x94000000, Size: 4}, // BL; target is irrelevant to explicit BLEdge below.
			{Addr: pc + 4, Raw: 0xD65F03C0, Size: 4},
		}
	}
	funcs := FuncInstsARM64{
		"callerA": caller(0x8000),
		"callerB": caller(0x9000),
		"callee":  {{Addr: 0xA000, Raw: 0xD65F03C0, Size: 4}},
	}
	edges := map[string][]BLEdge{
		"callerA": {{Callee: "callee", CallPC: 0x8000, ArgMask: 1}},
		"callerB": {{Callee: "callee", CallPC: 0x9000, ArgMask: 1}},
	}

	result := RunInterprocedural(ctx, funcs, nil, edges, 1, true, nil)
	if result.Converged || result.Iterations != 1 || ctx.InterConverged || ctx.InterIterations != 1 {
		t.Fatalf("budget telemetry = result(converged=%v iter=%d) ctx(converged=%v iter=%d), want exhausted after one round",
			result.Converged, result.Iterations, ctx.InterConverged, ctx.InterIterations)
	}
	callee := result.Functions["callee"]
	if callee == nil || callee.Intra == nil {
		t.Fatal("callee analysis missing after conservative fallback")
	}
	cc, ok := sdk.DartRegisterCallingConvention(ctx.DartVersion, sdk.ArchARM64)
	if !ok || len(cc.GPR) == 0 {
		t.Fatal("test SDK register convention unavailable")
	}
	if got := callee.Intra.EntryTypes[cc.GPR[0]]; got.Kind != LatticeTop {
		t.Fatalf("callee retained partially propagated receiver fact after budget exhaustion: %+v", got)
	}
}

func TestInterproceduralArgMaskConsensusIncludesZeroEvidence(t *testing.T) {
	ctx := minimalTypeContext()
	ctx.FuncMayUseRegisterCC = map[string]bool{"callee": true}
	ctx.FuncReceiverInRegister = map[string]bool{"callerA": true, "callerB": true, "callerC": true}
	ctx.FuncReceiverStackSlot = map[string]int{}
	ctx.FuncOwnerClass = map[string]int{"callerA": 100, "callerB": 100, "callerC": 100}
	ctx.MethodNameToRefIDs = map[string][]int{}
	ctx.FuncParamTypes = map[int][]int{}
	ctx.FuncIsInstance = map[int]bool{}
	ctx.FuncReturnType = map[int]int{}

	caller := func(pc uint64) []disasm.Inst {
		return []disasm.Inst{
			{Addr: pc, Raw: 0x94000000, Size: 4},
			{Addr: pc + 4, Raw: 0xD65F03C0, Size: 4},
		}
	}
	funcs := FuncInstsARM64{
		"callerA": caller(0xB000),
		"callerB": caller(0xC000),
		"callerC": caller(0xD000),
		"callee":  {{Addr: 0xE000, Raw: 0xD65F03C0, Size: 4}},
	}
	edges := map[string][]BLEdge{
		"callerA": {{Callee: "callee", CallPC: 0xB000, ArgMask: 1}},
		"callerB": {{Callee: "callee", CallPC: 0xC000, ArgMask: 1}},
		// This is an observed direct call site with no register setup in the
		// local evidence window. It must veto position 0 rather than disappear.
		"callerC": {{Callee: "callee", CallPC: 0xD000, ArgMask: 0}},
	}

	result := RunInterprocedural(ctx, funcs, nil, edges, 3, true, nil)
	callee := result.Functions["callee"]
	if callee == nil || callee.Intra == nil {
		t.Fatal("callee analysis missing")
	}
	cc, ok := sdk.DartRegisterCallingConvention(ctx.DartVersion, sdk.ArchARM64)
	if !ok || len(cc.GPR) == 0 {
		t.Fatal("test SDK register convention unavailable")
	}
	if got := callee.Intra.EntryTypes[cc.GPR[0]]; got.Kind != LatticeTop {
		t.Fatalf("zero-mask call site was ignored and false arg-register consensus leaked into callee: %+v", got)
	}
}
