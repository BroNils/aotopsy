package typetrack

import (
	"testing"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/disasm"
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
	state[1] = KnownClass(42) // arg0 = class 42
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
