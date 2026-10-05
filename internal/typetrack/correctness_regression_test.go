package typetrack

import (
	"math"
	"testing"

	"aotopsy/internal/arch/arm64"
	archx86 "aotopsy/internal/arch/x86"
	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
	"golang.org/x/arch/x86/x86asm"
)

// TestBALDoesNotCreatePhantomFallthrough verifies that B.AL (cond=14) and
// B.NV (cond=15) are treated as unconditional by isCondBranch — they must
// NOT create a phantom fall-through successor in the type tracker's CFG.
//
// Before the fix, isCondBranch returned true for ALL B.cond encodings,
// including AL/NV. This created phantom fall-through edges that corrupted
// type propagation (28148 occurrences in the 2.12 sample).
func TestBALDoesNotCreatePhantomFallthrough(t *testing.T) {
	// B.AL: 01010100 | imm19=0 | 0 | cond=14 (0xE)
	// Encoding: 0x54000000 | (0 << 5) | 14 = 0x5400000E
	rawBAL := uint32(0x5400000E)
	targets, ok := isCondBranch(rawBAL, 0x1000)
	if ok {
		t.Errorf("B.AL (cond=14) should be unconditional, isCondBranch returned %v targets=%v", ok, targets)
	}

	// B.NV: 01010100 | imm19=0 | 0 | cond=15 (0xF)
	// Encoding: 0x54000000 | (0 << 5) | 15 = 0x5400000F
	rawBNV := uint32(0x5400000F)
	targets, ok = isCondBranch(rawBNV, 0x1000)
	if ok {
		t.Errorf("B.NV (cond=15) should be unconditional, isCondBranch returned %v targets=%v", ok, targets)
	}

	// B.EQ: 01010100 | imm19=0 | 0 | cond=0 (EQ)
	// This IS conditional and should return true.
	rawBEQ := uint32(0x54000000)
	targets, ok = isCondBranch(rawBEQ, 0x1000)
	if !ok || len(targets) != 1 || targets[0] != 0x1000 {
		t.Errorf("B.EQ (cond=0) should be conditional with target 0x1000, got ok=%v targets=%v", ok, targets)
	}

	// B.NE: 01010100 | imm19=1 | 0 | cond=1 (NE)
	// Target = 0x1000 + 1*4 = 0x1004
	rawBNE := uint32(0x54000000) | (1 << 5) | 1
	targets, ok = isCondBranch(rawBNE, 0x1000)
	if !ok || len(targets) != 1 || targets[0] != 0x1004 {
		t.Errorf("B.NE (cond=1) should be conditional with target 0x1004, got ok=%v targets=%v", ok, targets)
	}
}

func TestBALTerminatesBlockAndRejectsWrappedTarget(t *testing.T) {
	// B.AL +8 must terminate its block even though the next instruction is
	// unreachable. Without a leader at the instruction after B.AL, that NOP was
	// incorrectly kept inside the branch block and the branch ceased to be its
	// terminator.
	insts := []disasm.Inst{
		{Addr: 0x1000, Raw: 0x5400004E, Size: 4}, // B.AL 0x1008
		{Addr: 0x1004, Raw: 0xD503201F, Size: 4}, // unreachable NOP
		{Addr: 0x1008, Raw: 0xD65F03C0, Size: 4}, // target RET
	}
	blocks := buildBlocks(insts)
	if len(blocks) != 3 || len(blocks[0].insts) != 1 {
		t.Fatalf("B.AL block partition = %#v, want three one-terminator blocks", blocks)
	}
	if len(blocks[0].successors) != 1 || blocks[0].successors[0] != 2 {
		t.Fatalf("B.AL successors = %v, want target block 2 only", blocks[0].successors)
	}

	// A malicious/high ELF VA must not wrap PC+4 to address zero and create a
	// fabricated CFG edge to a real low-address block.
	high := uint64(math.MaxUint64 - 3)
	wrapped := buildBlocks([]disasm.Inst{
		{Addr: high, Raw: 0x5400002E, Size: 4}, // B.AL +4 would overflow
		{Addr: 0, Raw: 0xD65F03C0, Size: 4},
	})
	if len(wrapped) != 2 {
		t.Fatalf("overflow B.AL blocks = %d, want 2", len(wrapped))
	}
	if len(wrapped[0].successors) != 0 {
		t.Fatalf("overflow B.AL fabricated successor(s): %v", wrapped[0].successors)
	}
}

func TestShadowStackPrePostIndexUsesStableFrameRelativeSlots(t *testing.T) {
	var state [31]TypeLattice
	for i := range state {
		state[i] = Top()
	}
	state[1] = ExactClass(42)
	stack := make(map[int]TypeLattice)
	shadow := shadowSPState{}
	ctx := &TypeContext{}
	result := &IntraResult{}

	// MOV X29,X15 establishes frame-relative coordinate 0.
	transferInstruction(&state, disasm.Inst{Addr: 0x1000, Raw: 0xAA0F03FD, Size: 4}, 0, ctx, result, nil, stack, &shadow)
	if !shadow.Known || shadow.RelFP != 0 {
		t.Fatalf("MOV FP,SP relation = %+v, want known zero", shadow)
	}

	// Real Dart Push shape: STR X1,[X15,#-8]!. The access is at -8 and X15
	// remains at -8 afterwards.
	transferInstruction(&state, disasm.Inst{Addr: 0x1004, Raw: 0xF81F8DE1, Size: 4}, 0, ctx, result, nil, stack, &shadow)
	if !shadow.Known || shadow.RelFP != -8 {
		t.Fatalf("after push shadow relation = %+v, want -8", shadow)
	}
	if got := stack[shadowStackKey(-8)]; !got.Equal(ExactClass(42)) {
		t.Fatalf("pushed slot = %+v, want ExactClass(42)", got)
	}

	state[1] = Top()
	// Real Dart Pop shape: LDR X1,[X15],#8. It reads the SAME canonical slot
	// before restoring X15 to frame-relative zero.
	transferInstruction(&state, disasm.Inst{Addr: 0x1008, Raw: 0xF84085E1, Size: 4}, 0, ctx, result, nil, stack, &shadow)
	if !state[1].Equal(ExactClass(42)) {
		t.Fatalf("post-index pop recovered %+v, want ExactClass(42)", state[1])
	}
	if !shadow.Known || shadow.RelFP != 0 {
		t.Fatalf("after pop shadow relation = %+v, want zero", shadow)
	}
}

func TestShadowStackPairPrePostIndexAndNonTemporalModes(t *testing.T) {
	var state [31]TypeLattice
	for i := range state {
		state[i] = Top()
	}
	state[2] = ExactClass(7)
	state[3] = ExactClass(8)
	stack := make(map[int]TypeLattice)
	shadow := shadowSPState{Known: true, RelFP: 0}
	ctx := &TypeContext{}
	result := &IntraResult{}

	// STP X2,X3,[X15,#-16]!
	pushPair := uint32(0xA9BF0DE2)
	transferInstruction(&state, disasm.Inst{Addr: 0x2000, Raw: pushPair, Size: 4}, 0, ctx, result, nil, stack, &shadow)
	if shadow.RelFP != -16 || !stack[shadowStackKey(-16)].Equal(ExactClass(7)) || !stack[shadowStackKey(-8)].Equal(ExactClass(8)) {
		t.Fatalf("pair push relation=%+v slots=%v", shadow, stack)
	}

	state[2], state[3] = Top(), Top()
	// LDP X2,X3,[X15],#16
	popPair := uint32(0xA8C10DE2)
	transferInstruction(&state, disasm.Inst{Addr: 0x2004, Raw: popPair, Size: 4}, 0, ctx, result, nil, stack, &shadow)
	if !state[2].Equal(ExactClass(7)) || !state[3].Equal(ExactClass(8)) || shadow.RelFP != 0 {
		t.Fatalf("pair pop state2=%+v state3=%+v shadow=%+v", state[2], state[3], shadow)
	}

	// STNP is no-writeback: the old hand mask mistook this family for post-index.
	shadow.RelFP = 24
	state[0], state[1] = ExactClass(1), ExactClass(2)
	transferInstruction(&state, disasm.Inst{Addr: 0x2008, Raw: 0xA80005E0, Size: 4}, 0, ctx, result, nil, stack, &shadow) // STNP X0,X1,[X15]
	if shadow.RelFP != 24 {
		t.Fatalf("STNP changed shadow SP: %+v", shadow)
	}
}

// TestBLCallSiteTypesKeyIsCallSitePC verifies that BLCallSiteTypes is keyed
// by the BL instruction's address (call-site PC), NOT the callee's target
// address. The interprocedural pass reads BLCallSiteTypes[edge.CallPC] where
// edge.CallPC is the BL instruction address — so the write must use the same key.
//
// Before the fix, the write used the callee target VA as key, so the lookup
// always missed and fell back to ExitTypes (which is Top for arg registers
// because BL kills them). This made inter-procedural parameter type
// propagation completely dead.
func TestBLCallSiteTypesKeyIsCallSitePC(t *testing.T) {
	// BL with imm26=1 → target = PC + 4 = 0x1004
	// Encoding: 0x94000001
	rawBL := uint32(0x94000001)
	pc := uint64(0x1000)

	target, ok := arm64.BL(rawBL, pc)
	if !ok || target != 0x1004 {
		t.Fatalf("BL target = 0x%x, want 0x1004", target)
	}

	// Simulate handleBL: the key must be the instruction's PC (0x1000),
	// not the target (0x1004).
	ctx := &TypeContext{
		CalleeExitTypes:    map[uint64]TypeLattice{},
		CalleeAllExitTypes: map[uint64][31]TypeLattice{},
	}
	result := &IntraResult{
		BLCallSiteTypes: make(map[uint64][31]TypeLattice),
	}
	var state [31]TypeLattice
	state[1] = ExactClass(42) // arg0 = exact runtime class 42
	tc := &transferCtx{
		inst:   disasm.Inst{Addr: pc, Raw: rawBL},
		state:  &state,
		ctx:    ctx,
		result: result,
	}

	handleBL(tc)

	// The key MUST be the call-site PC (0x1000), not the target (0x1004).
	if _, ok := result.BLCallSiteTypes[pc]; !ok {
		t.Errorf("BLCallSiteTypes must be keyed by call-site PC 0x%x, but key not found", pc)
	}
	if _, ok := result.BLCallSiteTypes[target]; ok {
		t.Errorf("BLCallSiteTypes must NOT be keyed by target 0x%x (old bug)", target)
	}
}

func TestOpenWorldEntryFactsDemoteDirectCallerExactness(t *testing.T) {
	if got := openWorldEntryFact(ExactClass(100)); !got.Equal(ClassBound(100)) {
		t.Fatalf("ExactClass direct-call observation stayed exact for open-world callee: %+v", got)
	}
	if got := openWorldEntryFact(ClassBound(100)); !got.Equal(ClassBound(100)) {
		t.Fatalf("ClassBound was unnecessarily weakened: %+v", got)
	}
	if got := openWorldEntryFact(KnownStub("AllocateFoo", 7)); got.Kind != LatticeTop {
		t.Fatalf("value-specific stub fact survived open-world entry: %+v", got)
	}
}

func TestUBFXTypePropagationRequiresClassIDBitfield(t *testing.T) {
	ctx := &TypeContext{}
	ctx.SetClassIDTagLayout(12, 20)
	var state [31]TypeLattice
	state[1] = ExactHeaderTags(42)

	// UBFX X2,X1,#12,#20 is exactly the Dart 3.x ClassIdTag extraction.
	tc := &transferCtx{
		state: &state,
		inst:  disasm.Inst{Raw: 0xD34C7C22},
		ctx:   ctx,
	}
	if !handleUBFX(tc) || !state[2].Equal(ExactClassID(42)) {
		t.Fatalf("class-id UBFX did not produce exact CID scalar: got %+v", state[2])
	}

	// LSR X4,X1,#12 is the same UBFM family but extracts 52 bits, not the
	// 20-bit class-id field. It must not be consumed as type propagation.
	state[4] = ExactClass(99)
	tc.inst = disasm.Inst{Raw: 0xD34CFC24}
	if handleUBFX(tc) {
		t.Fatal("generic UBFM/LSR was consumed as class-id extraction")
	}
}

func TestBadDecodeIsHardDataflowBarrier(t *testing.T) {
	arm := []disasm.Inst{
		{Addr: 0x1000, Raw: 0xD503201F, Size: 4},
		{Addr: 0x1004, Raw: 0xFFFFFFFF, Size: 4, Bad: true},
		{Addr: 0x1008, Raw: 0xD503201F, Size: 4},
	}
	armBlocks := buildBlocks(arm)
	if len(armBlocks) != 2 || len(armBlocks[0].successors) != 0 {
		t.Fatalf("ARM bad-byte CFG = %#v, want two blocks and no edge across bad decode", armBlocks)
	}
	var armState [31]TypeLattice
	armState[0] = ExactClass(42)
	armStack := map[int]TypeLattice{8: ExactClass(7)}
	transferInstruction(&armState, arm[1], 0, nil, nil, nil, armStack, nil)
	if armState[0].Kind != LatticeTop || len(armStack) != 0 {
		t.Fatalf("ARM bad decode retained facts: r0=%+v stack=%v", armState[0], armStack)
	}

	x86insts := []archx86.Decoded{
		{VA: 0x2000, Inst: x86asm.Inst{Op: x86asm.NOP}, Len: 1},
		{VA: 0x2001, Len: 1, Bad: true},
		{VA: 0x2002, Inst: x86asm.Inst{Op: x86asm.RET}, Len: 1},
	}
	x86Blocks := buildBlocksX86(x86insts)
	if len(x86Blocks) != 2 || len(x86Blocks[0].successors) != 0 {
		t.Fatalf("x86 bad-byte CFG has edge across failed decode: %+v", x86Blocks)
	}
	var x86State [31]TypeLattice
	x86State[0] = ExactClass(42)
	x86Stack := map[int]TypeLattice{8: ExactClass(7)}
	transferInstructionX86(&x86State, x86insts[1], nil, nil, nil, nil, x86Stack)
	if x86State[0].Kind != LatticeTop || len(x86Stack) != 0 {
		t.Fatalf("x86 bad decode retained facts: rax=%+v stack=%v", x86State[0], x86Stack)
	}
}

func TestArchitecturalTrapIsHardDataflowBarrier(t *testing.T) {
	arm := []disasm.Inst{
		{Addr: 0x3000, Raw: 0xD503201F, Size: 4, Mnemonic: "NOP"},
		{Addr: 0x3004, Raw: 0xD4200000, Size: 4, Mnemonic: "BRK"},
		{Addr: 0x3008, Raw: 0xD503201F, Size: 4, Mnemonic: "NOP"},
	}
	armBlocks := buildBlocks(arm)
	if len(armBlocks) != 2 || len(armBlocks[0].successors) != 0 {
		t.Fatalf("ARM trap CFG = %#v, want two blocks and no edge across BRK", armBlocks)
	}
	var armState [31]TypeLattice
	armState[0] = ExactClass(42)
	armStack := map[int]TypeLattice{8: ExactClass(7)}
	transferInstruction(&armState, arm[1], 0, nil, nil, nil, armStack, nil)
	if armState[0].Kind != LatticeTop || len(armStack) != 0 {
		t.Fatalf("ARM trap retained facts: r0=%+v stack=%v", armState[0], armStack)
	}

	x86insts := []archx86.Decoded{
		{VA: 0x4000, Inst: x86asm.Inst{Op: x86asm.NOP}, Len: 1},
		{VA: 0x4001, Inst: x86asm.Inst{Op: x86asm.UD2}, Len: 2},
		{VA: 0x4003, Inst: x86asm.Inst{Op: x86asm.NOP}, Len: 1},
	}
	x86Blocks := buildBlocksX86(x86insts)
	if len(x86Blocks) != 2 || len(x86Blocks[0].successors) != 0 {
		t.Fatalf("x86 trap CFG = %+v, want two blocks and no edge across UD2", x86Blocks)
	}
	var x86State [31]TypeLattice
	x86State[0] = ExactClass(42)
	x86Stack := map[int]TypeLattice{8: ExactClass(7)}
	transferInstructionX86(&x86State, x86insts[1], nil, nil, nil, nil, x86Stack)
	if x86State[0].Kind != LatticeTop || len(x86Stack) != 0 {
		t.Fatalf("x86 trap retained facts: rax=%+v stack=%v", x86State[0], x86Stack)
	}
}

func TestX86DirectCallTargetOverflowCannotResolveMetadata(t *testing.T) {
	inst := archx86.Decoded{
		VA:  ^uint64(0) - 2,
		Len: 5,
		Inst: x86asm.Inst{
			Op:   x86asm.CALL,
			Len:  5,
			Args: [4]x86asm.Arg{x86asm.Rel(16)},
		},
	}
	ctx := &TypeContext{AllocationStubCID: map[uint64]int{18: 42}}
	var state [31]TypeLattice
	state[x86RegRAX] = ExactClass(7)
	tc := &transferCtxX86{
		state:      &state,
		inst:       inst,
		ctx:        ctx,
		result:     &IntraResult{},
		stackTypes: map[int]TypeLattice{},
	}
	if !handleX86Call(tc) {
		t.Fatal("overflowing direct CALL was not consumed")
	}
	if state[x86RegRAX].Kind != LatticeTop {
		t.Fatalf("overflowing CALL resolved wrapped metadata into RAX: %+v", state[x86RegRAX])
	}
	if ctx.AllocStubHits != 0 {
		t.Fatalf("overflowing CALL produced %d allocation-stub hit(s)", ctx.AllocStubHits)
	}
}

func TestShiftedADDOnlyDecompressesExactHeapBitsShape(t *testing.T) {
	ctx := &TypeContext{DartVersion: "3.12.2"}
	result := &IntraResult{}

	// ADD X0,X1,X28,LSR #7 must not be mistaken for HEAP_BITS decompression.
	var state [31]TypeLattice
	state[1] = ExactClass(42)
	badShape := uint32(0x8B000000 | (1 << 22) | (28 << 16) | (7 << 10) | (1 << 5))
	transferInstruction(&state, disasm.Inst{Raw: badShape}, 0, ctx, result, nil, map[int]TypeLattice{}, nil)
	if state[0].Kind != LatticeTop {
		t.Fatalf("LSR HEAP_BITS ADD produced authoritative type %+v", state[0])
	}

	state = [31]TypeLattice{}
	state[1] = ExactClass(42)
	goodShape := uint32(0x8B000000 | (sdk.ARM64HeapBits << 16) | (32 << 10) | (1 << 5))
	transferInstruction(&state, disasm.Inst{Raw: goodShape}, 0, ctx, result, nil, map[int]TypeLattice{}, nil)
	if !state[0].Equal(ExactClass(42)) {
		t.Fatalf("exact LSL #32 decompression lost type: %+v", state[0])
	}

	// Dart 2.13 uses the dedicated HEAP_BASE register R23 with no shift.
	legacyCtx := &TypeContext{DartVersion: "2.13.0"}
	state = [31]TypeLattice{}
	state[1] = ExactClass(77)
	legacyShape := uint32(0x8B000000 | (sdk.ARM64HeapBaseLegacy << 16) | (1 << 5))
	transferInstruction(&state, disasm.Inst{Raw: legacyShape}, 0, legacyCtx, result, nil, map[int]TypeLattice{}, nil)
	if !state[0].Equal(ExactClass(77)) {
		t.Fatalf("Dart 2.13 HEAP_BASE decompression lost type: %+v", state[0])
	}

	state = [31]TypeLattice{}
	state[1] = ExactClass(77)
	lateShapeOnLegacy := uint32(0x8B000000 | (sdk.ARM64HeapBits << 16) | (32 << 10) | (1 << 5))
	transferInstruction(&state, disasm.Inst{Raw: lateShapeOnLegacy}, 0, legacyCtx, result, nil, map[int]TypeLattice{}, nil)
	if state[0].Kind != LatticeTop {
		t.Fatalf("Dart 2.13 accepted the later HEAP_BITS decompression shape: %+v", state[0])
	}
}

func TestX86ClassIDPropagationRequiresExactHeaderShift(t *testing.T) {
	ctx := &TypeContext{}
	ctx.SetClassIDTagLayout(12, 20)

	header := archx86.Decoded{
		VA:   0x1000,
		Len:  4,
		Inst: x86asm.Inst{Op: x86asm.MOV, Args: [4]x86asm.Arg{x86asm.R9L, x86asm.Mem{Base: x86asm.RAX, Disp: -1}}},
	}

	for _, tc := range []struct {
		name string
		op   x86asm.Op
		imm  x86asm.Imm
		prev *archx86.Decoded
		want TypeLatticeKind
	}{
		{"exact SDK SHR", x86asm.SHR, 12, &header, LatticeUnknownClassID},
		{"wrong shift", x86asm.SHR, 7, &header, LatticeTop},
		{"missing header producer", x86asm.SHR, 12, nil, LatticeTop},
		{"generic AND", x86asm.AND, 0xfffff, &header, LatticeTop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var state [31]TypeLattice
			state[9] = UnknownHeaderTags()
			inst := archx86.Decoded{
				VA:   0x1004,
				Len:  4,
				Inst: x86asm.Inst{Op: tc.op, Args: [4]x86asm.Arg{x86asm.R9L, tc.imm}},
			}
			transferInstructionX86(&state, inst, tc.prev, ctx, &IntraResult{}, nil, map[int]TypeLattice{})
			if state[9].Kind != tc.want {
				t.Fatalf("state kind = %v, want %v", state[9].Kind, tc.want)
			}
		})
	}
}

func TestDartCallClobberedGPRsARM64HeapBaseBoundary(t *testing.T) {
	contains := func(regs []int, want int) bool {
		for _, r := range regs {
			if r == want {
				return true
			}
		}
		return false
	}

	for _, tc := range []struct {
		version string
		wantR23 bool
	}{
		{"2.12.0", true},
		{"2.13.0", false}, // R23 is reserved HEAP_BASE only on this supported line.
		{"3.12.2", true},
	} {
		regs, ok := sdk.DartCallClobberedGPRs(tc.version, sdk.ArchARM64)
		if !ok {
			t.Fatalf("DartCallClobberedGPRs(%s) unavailable", tc.version)
		}
		if got := contains(regs, 23); got != tc.wantR23 {
			t.Fatalf("DartCallClobberedGPRs(%s) contains R23=%v, want %v; regs=%v", tc.version, got, tc.wantR23, regs)
		}
	}
}
