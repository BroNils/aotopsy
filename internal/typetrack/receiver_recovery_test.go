package typetrack

import (
	"testing"

	"aotopsy/internal/disasm"
)

// Real encodings from a 3.3.0 arm64 instance method (AntiInlineTools.processItems):
//
//	0x1a3590  a0 0b 40 f9  LDR  X0, [X29,#16]   -- receiver load from FP+16
//	0x1a3594  01 b0 40 b8  LDUR W1, [X0,#11]    -- field read off the receiver
const (
	rawLDR_X0_X29_16  = 0xf9400ba0
	rawLDUR_W1_X0_11  = 0xb840b001
	rawLDR_X3_X29_8   = 0xf94007a3 // a decoy: lower FP offset (should not win)
)

func newCtxWithOwnerField(ownerCID int, rawFieldOff int32) *TypeContext {
	ctx := &TypeContext{
		FieldByOwnerOffset: map[int]map[int32]int{
			// FieldValueClass/OwnerHasFieldAt look up rawOff+1.
			ownerCID: {rawFieldOff + 1: 999},
		},
		SuperClass: map[int]int{},
	}
	return ctx
}

func TestRecoverReceiverStackSlotARM64(t *testing.T) {
	ctx := newCtxWithOwnerField(100, 11)
	insts := []disasm.Inst{
		{Raw: rawLDR_X3_X29_8},  // FP+8, lower -- decoy
		{Raw: rawLDR_X0_X29_16}, // FP+16, receiver
		{Raw: rawLDUR_W1_X0_11}, // field access off X0 at offset 11 -> validates
	}
	slot, ok := RecoverReceiverStackSlotARM64(insts, 100, ctx)
	if !ok {
		t.Fatal("expected receiver slot to be recovered")
	}
	if slot != 16 {
		t.Errorf("slot = %d, want 16 (highest validated FP load)", slot)
	}
}

// Without a validating owner-field access, no slot is recovered -- this is the
// gate that stops a static method's parameter 0 being seeded as the owner class.
func TestRecoverReceiverStackSlotARM64NoFieldUseRejected(t *testing.T) {
	ctx := newCtxWithOwnerField(100, 99) // owner has a field at 99, not 11
	insts := []disasm.Inst{
		{Raw: rawLDR_X0_X29_16},
		{Raw: rawLDUR_W1_X0_11}, // accesses offset 11, which owner does NOT declare
	}
	if _, ok := RecoverReceiverStackSlotARM64(insts, 100, ctx); ok {
		t.Error("must not recover a slot when the loaded register is not an owner-field base")
	}
}

func TestOwnerHasFieldAt(t *testing.T) {
	ctx := &TypeContext{
		FieldByOwnerOffset: map[int]map[int32]int{
			5: {12: 1}, // field at lookup offset 12 (raw 11)
			9: {8: 2},
		},
		SuperClass: map[int]int{5: 9}, // 5 extends 9
	}
	if !ctx.OwnerHasFieldAt(5, 11) {
		t.Error("own field at raw 11 (lookup 12) should be found")
	}
	if !ctx.OwnerHasFieldAt(5, 7) {
		t.Error("inherited field at raw 7 (lookup 8, on super 9) should be found")
	}
	if ctx.OwnerHasFieldAt(5, 40) {
		t.Error("no field at raw 40 -- must not report one")
	}
}
