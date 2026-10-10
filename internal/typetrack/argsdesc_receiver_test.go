package typetrack

import (
	"testing"

	archx86 "aotopsy/internal/arch/x86"
	"aotopsy/internal/disasm"
	"golang.org/x/arch/x86/x86asm"
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

func withLDURImm9(raw uint32, imm int) uint32 {
	return raw&^(0x1ff<<12) | (uint32(imm)&0x1ff)<<12
}

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

func TestRecoverArgsDescReceiverARM64CompressedUsesCountOffset14(t *testing.T) {
	ctx := newCtxWithOwnerField(100, 11)
	ctx.DartVersion = "3.4.3"
	ctx.WordSize = 4
	ctx.CompressedPointers = true
	insts := argsDescInsts()
	insts[1].Raw = withLDURImm9(rawLDUR_X2_X1_31, 19) // 0x14 - kHeapObjectTag
	insts = append(insts, disasm.Inst{Addr: 0x101c, Raw: rawLDUR_W1_X2_11})
	if pc, rl, ok := RecoverArgsDescReceiverARM64(insts, 100, ctx); !ok || pc != 0x1010 || rl.Reg != 2 {
		t.Fatalf("compressed receiver recovery = pc=%#x load=%+v ok=%v, want pc=0x1010 X2", pc, rl, ok)
	}

	// The old 0x10 slot is type_args_len on compressed 64-bit targets and must
	// not be accepted as ArgumentsDescriptor.count.
	insts = argsDescInsts()
	insts[1].Raw = withLDURImm9(rawLDUR_X2_X1_31, 15)
	insts = append(insts, disasm.Inst{Addr: 0x101c, Raw: rawLDUR_W1_X2_11})
	if _, _, ok := RecoverArgsDescReceiverARM64(insts, 100, ctx); ok {
		t.Fatal("compressed recovery accepted type_args_len displacement 15 as count")
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

func TestRecoverArgsDescReceiverX86(t *testing.T) {
	ctx := newCtxWithOwnerField(100, 11)
	ctx.WordSize = 8
	insts := []archx86.Decoded{
		x86Inst(0x2000, x86asm.MOV, x86asm.RAX, x86asm.R10),
		x86Inst(0x2004, x86asm.MOV, x86asm.RCX, x86asm.Mem{Base: x86asm.RAX, Disp: 31}),
		x86Inst(0x2008, x86asm.MOV, x86asm.RDX, x86asm.RCX),
		x86Inst(0x200c, x86asm.SUB, x86asm.RDX, x86asm.Imm(8)),
		x86Inst(0x2010, x86asm.MOV, x86asm.RBX, x86asm.Mem{Base: x86asm.RBP, Index: x86asm.RDX, Scale: 4, Disp: 40}),
		x86Inst(0x2014, x86asm.MOV, x86asm.R8, x86asm.Mem{Base: x86asm.RBX, Disp: 11}),
	}

	pc, rl, ok := RecoverArgsDescReceiverX86(insts, 100, ctx)
	if !ok {
		t.Fatal("expected x86 ArgumentsDescriptor receiver load to be recovered")
	}
	if pc != 0x2010 || rl.Reg != 3 || rl.ClassCID != 100 {
		t.Fatalf("recovered x86 receiver = pc=%#x reg=%d cid=%d, want pc=0x2010 RBX(3) cid=100", pc, rl.Reg, rl.ClassCID)
	}

	ctx.ReceiverLoadAtPC = map[uint64]ReceiverLoad{pc: rl}
	var state [31]TypeLattice
	transferInstructionX86(&state, insts[4], nil, ctx, &IntraResult{}, nil, map[int]TypeLattice{})
	if !state[3].Equal(ClassBound(100)) {
		t.Fatalf("x86 receiver load state = %+v, want ClassBound(100)", state[3])
	}
}

func TestRecoverArgsDescReceiverX86CompressedUsesCountOffset14(t *testing.T) {
	ctx := newCtxWithOwnerField(100, 11)
	ctx.DartVersion = "3.4.3"
	ctx.WordSize = 4
	ctx.CompressedPointers = true
	insts := []archx86.Decoded{
		x86Inst(0x2200, x86asm.MOV, x86asm.RAX, x86asm.R10),
		x86Inst(0x2204, x86asm.MOV, x86asm.RCX, x86asm.Mem{Base: x86asm.RAX, Disp: 19}),
		x86Inst(0x2208, x86asm.MOV, x86asm.RDX, x86asm.RCX),
		x86Inst(0x220c, x86asm.SUB, x86asm.RDX, x86asm.Imm(8)),
		x86Inst(0x2210, x86asm.MOV, x86asm.RBX, x86asm.Mem{Base: x86asm.RBP, Index: x86asm.RDX, Scale: 4, Disp: 40}),
		x86Inst(0x2214, x86asm.MOV, x86asm.R8, x86asm.Mem{Base: x86asm.RBX, Disp: 11}),
	}
	if pc, rl, ok := RecoverArgsDescReceiverX86(insts, 100, ctx); !ok || pc != 0x2210 || rl.Reg != 3 {
		t.Fatalf("compressed x86 receiver recovery = pc=%#x load=%+v ok=%v", pc, rl, ok)
	}
	insts[1] = x86Inst(0x2204, x86asm.MOV, x86asm.RCX, x86asm.Mem{Base: x86asm.RAX, Disp: 15})
	if _, _, ok := RecoverArgsDescReceiverX86(insts, 100, ctx); ok {
		t.Fatal("compressed x86 recovery accepted type_args_len displacement 15 as count")
	}
}

func TestRecoverArgsDescReceiverX86RequiresExactDescriptorChain(t *testing.T) {
	ctx := newCtxWithOwnerField(100, 11)
	ctx.WordSize = 8
	insts := []archx86.Decoded{
		// Looks like LoadIndexedUnsafe but has no proven ArgumentsDescriptor.count
		// producer. This must not be accepted from shape alone.
		x86Inst(0x2100, x86asm.MOV, x86asm.RBX, x86asm.Mem{Base: x86asm.RBP, Index: x86asm.RDX, Scale: 4, Disp: 40}),
		x86Inst(0x2104, x86asm.MOV, x86asm.R8, x86asm.Mem{Base: x86asm.RBX, Disp: 11}),
	}
	if _, _, ok := RecoverArgsDescReceiverX86(insts, 100, ctx); ok {
		t.Fatal("x86 recovery accepted indexed FP load without ArgumentsDescriptor provenance")
	}
}
