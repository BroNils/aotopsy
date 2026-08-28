package typetrack

import (
	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"

	"golang.org/x/arch/x86/x86asm"
)

// Receiver-stack-slot recovery for the pre-3.4.3 calling convention.
//
// Before Dart 3.4.3 the receiver (`this`) is passed on the caller's stack, not
// in a register, so seeding its class requires knowing its frame slot: parameter
// i of a function with N fixed parameters is at
//
//	FP + (kParamEndSlotFromFp + N - i) * wordSize
//
// with kParamEndSlotFromFp == 1 on both architectures, so the receiver
// (parameter 0) sits at the HIGHEST positive frame-pointer offset. The snapshot
// used to carry N in UntaggedFunction.packed_fields_, but 2.14 moved it onto
// FunctionType, reachable only through a WeakSerializationReference the AOT
// serializer drops -- so from 2.14 through 3.3.0, N is gone and the receiver
// could not be located. That is the measured cause of the field-type "cliff":
// field_type_declared_hits collapses across 2.14..3.3.0 and jumps back at 3.4.3
// (register convention, no slot needed).
//
// These functions recover the slot directly from the CODE: the receiver is the
// highest positive frame-pointer load offset the prologue performs, AND the
// register it loads into is used as the base of a field access that genuinely
// belongs to the owner class. The second condition is the safety gate -- it
// confirms the value behaves as an owner instance, so a static method (whose
// parameter 0 is not `this`) is not mistaken for an instance method and owner
// field names are never fabricated for a non-receiver value.
//
// Verified against a real 3.3.0 arm64 instance method
// (AntiInlineTools.processItems): `LDR X0, [X29,#16]` feeds `LDUR W1, [X0,#11]`
// -- the receiver loaded from FP+16 and immediately read as a field base at an
// offset the owner class declares.
const receiverSlotFloor = 16 // 2 * 8: first parameter slot above saved FP/LR

// RecoverReceiverStackSlotARM64 returns the receiver's frame slot, validated by
// a field access off the loaded register that the owner class declares.
func RecoverReceiverStackSlotARM64(insts []disasm.Inst, ownerCID int, ctx *TypeContext) (int, bool) {
	bestSlot, bestReg := -1, -1
	for i := range insts {
		if baseReg, byteOff, ok := arm64.LDR64UnsignedOffset(insts[i].Raw); ok && baseReg == 29 {
			if byteOff >= receiverSlotFloor && byteOff > bestSlot {
				bestSlot = byteOff
				bestReg = int(insts[i].Raw & 0x1F) // Rt
			}
		}
	}
	if bestSlot < 0 || bestReg < 0 {
		return 0, false
	}
	if !arm64RegUsedAsOwnerFieldBase(insts, bestReg, ownerCID, ctx) {
		return 0, false
	}
	return bestSlot, true
}

// arm64RegUsedAsOwnerFieldBase reports whether reg is used as the base of a
// field load `[reg, #off]` at an offset the owner class declares. Covers the
// 64-bit, 32-bit and 16-bit (character) load forms the field-load handlers use.
func arm64RegUsedAsOwnerFieldBase(insts []disasm.Inst, reg, ownerCID int, ctx *TypeContext) bool {
	for i := range insts {
		raw := insts[i].Raw
		if base, off, ok := arm64.LDR64UnsignedOffset(raw); ok && base == reg && ctx.OwnerHasFieldAt(ownerCID, int32(off)) {
			return true
		}
		if base, off, _, ok := arm64.LDR32UnsignedOffset(raw); ok && base == reg && ctx.OwnerHasFieldAt(ownerCID, int32(off)) {
			return true
		}
		if base, _, imm9, ok := arm64.LDUR32(raw); ok && base == reg && ctx.OwnerHasFieldAt(ownerCID, int32(imm9)) {
			return true
		}
		if base, _, imm9, ok := arm64.LDURH(raw); ok && base == reg && ctx.OwnerHasFieldAt(ownerCID, int32(imm9)) {
			return true
		}
	}
	return false
}

// RecoverReceiverStackSlotX86 is the x86_64 counterpart: the highest positive
// [RBP+disp] load, validated by an owner-field access off the loaded register.
func RecoverReceiverStackSlotX86(insts []sdk.X86Decoded, ownerCID int, ctx *TypeContext) (int, bool) {
	bestSlot := -1
	var bestReg x86asm.Reg
	for i := range insts {
		in := insts[i].Inst
		if in.Op != x86asm.MOV || len(in.Args) < 2 {
			continue
		}
		dst, dok := in.Args[0].(x86asm.Reg)
		mem, mok := in.Args[1].(x86asm.Mem)
		if !dok || !mok || sdk.X86CanonReg(mem.Base) != 5 || mem.Index != 0 {
			continue
		}
		if off := int(mem.Disp); off >= receiverSlotFloor && off > bestSlot {
			bestSlot = off
			bestReg = dst
		}
	}
	if bestSlot < 0 {
		return 0, false
	}
	if !x86RegUsedAsOwnerFieldBase(insts, bestReg, ownerCID, ctx) {
		return 0, false
	}
	return bestSlot, true
}

func x86RegUsedAsOwnerFieldBase(insts []sdk.X86Decoded, reg x86asm.Reg, ownerCID int, ctx *TypeContext) bool {
	rc := sdk.X86CanonReg(reg)
	for i := range insts {
		in := insts[i].Inst
		if in.Op != x86asm.MOV || len(in.Args) < 2 {
			continue
		}
		mem, ok := in.Args[1].(x86asm.Mem)
		if !ok || mem.Index != 0 {
			continue
		}
		if sdk.X86CanonReg(mem.Base) != rc {
			continue
		}
		if ctx.OwnerHasFieldAt(ownerCID, int32(mem.Disp)) {
			return true
		}
	}
	return false
}
