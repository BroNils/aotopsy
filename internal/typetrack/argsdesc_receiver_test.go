package typetrack

import (
	"testing"

	"aotopsy/internal/disasm"
)

// Real encodings from the Dart 2.12.0 arm64 sample, RangeError.range -- a
// constructor with optional parameters, so its prologue addresses arguments
// through ArgumentsDescriptor.count rather than at a static frame slot.
//
//	0xaa0403e1  MOV  X1, X4               ; ARGS_DESC_REG
//	0xf841f022  LDUR X2, [X1,#31]         ; ArgumentsDescriptor.count
//	0xd1002041  SUB  X1, X2, #0x8         ; count - min_num_pos_args
//	0x8b010ba2  ADD  X2, X29, X1, LSL #2
//	0xf9401442  LDR  X2, [X2,#40]         ; parameter 0 -- the receiver
//	0x8b010ba3  ADD  X3, X29, X1, LSL #2
//	0xf9401063  LDR  X3, [X3,#32]         ; parameter 1
//	0x8b010ba0  ADD  X0, X29, X1, LSL #2
//	0xf9400c00  LDR  X0, [X0,#24]         ; parameter 2
const (
	rawMOV_X1_X4     = 0xaa0403e1
	rawLDUR_X2_X1_31 = 0xf841f022
	rawSUB_X1_X2_8   = 0xd1002041
	rawADD_X2_X29_X1 = 0x8b010ba2
	rawLDR_X2_X2_40  = 0xf9401442
	rawADD_X3_X29_X1 = 0x8b010ba3
	rawLDR_X3_X3_32  = 0xf9401063
	rawLDUR_W1_X2_11 = 0xb840b041 // field read off X2 -- validates the receiver
	rawLDUR_W1_X3_11 = 0xb840b061 // same read off X3 -- validates the decoy
)

func argsDescInsts() []disasm.Inst {
	return []disasm.Inst{
		{Addr: 0x1000, Raw: rawMOV_X1_X4},
		{Addr: 0x1004, Raw: rawLDUR_X2_X1_31},
		{Addr: 0x1008, Raw: rawSUB_X1_X2_8},
		{Addr: 0x100c, Raw: rawADD_X2_X29_X1},
		{Addr: 0x1010, Raw: rawLDR_X2_X2_40},
		{Addr: 0x1014, Raw: rawADD_X3_X29_X1},
		{Addr: 0x1018, Raw: rawLDR_X3_X3_32},
	}
}

func TestRecoverArgsDescReceiverARM64(t *testing.T) {
	ctx := newCtxWithOwnerField(100, 11)
	insts := append(argsDescInsts(), disasm.Inst{Addr: 0x101c, Raw: rawLDUR_W1_X2_11})

	pc, rl, ok := RecoverArgsDescReceiverARM64(insts, 100, ctx)
	if !ok {
		t.Fatal("expected the receiver load to be recovered")
	}
	if pc != 0x1010 {
		t.Errorf("pc = %#x, want 0x1010 (the largest displacement)", pc)
	}
	if rl.Reg != 2 {
		t.Errorf("reg = X%d, want X2", rl.Reg)
	}
	if rl.ClassCID != 100 {
		t.Errorf("cid = %d, want 100", rl.ClassCID)
	}
}

// The displacement, not the instruction order, picks parameter 0. Validating
// the decoy instead must not move the answer to it -- a lower displacement is
// a different parameter, however it is used afterwards.
func TestRecoverArgsDescReceiverPicksLargestDisplacement(t *testing.T) {
	ctx := newCtxWithOwnerField(100, 11)
	insts := append(argsDescInsts(), disasm.Inst{Addr: 0x101c, Raw: rawLDUR_W1_X3_11})

	if _, _, ok := RecoverArgsDescReceiverARM64(insts, 100, ctx); ok {
		t.Error("X3 holds parameter 1, not the receiver; recovery must not accept it")
	}
}

// The owner-field-base gate is what keeps a static method -- whose parameter 0
// is an ordinary argument -- from being given the owner's field names.
func TestRecoverArgsDescReceiverRequiresOwnerFieldUse(t *testing.T) {
	ctx := newCtxWithOwnerField(100, 11)
	if _, _, ok := RecoverArgsDescReceiverARM64(argsDescInsts(), 100, ctx); ok {
		t.Error("no field access off the loaded value; recovery must decline")
	}
}

// Without the ArgumentsDescriptor chain a plain FP-relative load is an
// ordinary access, not a dynamically addressed parameter.
func TestRecoverArgsDescReceiverIgnoresStaticFrameLoads(t *testing.T) {
	ctx := newCtxWithOwnerField(100, 11)
	insts := []disasm.Inst{
		{Addr: 0x1000, Raw: rawLDR_X0_X29_16},
		{Addr: 0x1004, Raw: rawLDUR_W1_X0_11},
	}
	if _, _, ok := RecoverArgsDescReceiverARM64(insts, 100, ctx); ok {
		t.Error("static FP load must not be treated as an ArgumentsDescriptor parameter")
	}
}
