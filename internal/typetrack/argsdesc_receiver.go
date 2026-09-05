package typetrack

import (
	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
)

// Receiver recovery for functions that address their parameters through the
// ArgumentsDescriptor, i.e. every function with optional parameters compiled
// before Dart 3.4.3.
//
// PrologueBuilder::BuildParameterHandling (prologue_builder.cc) emits a
// constant index when the arity is fixed and a RUNTIME index when it is not:
//
//	copy_args_prologue += LoadArgDescriptor();
//	copy_args_prologue += LoadNativeField(Slot::ArgumentsDescriptor_count());
//	count_var = MakeTemporary();
//	copy_args_prologue += LoadLocal(count_var);
//	copy_args_prologue += IntConstant(min_num_pos_args);
//	copy_args_prologue += SmiBinaryOp(Token::kSUB, /* truncate= */ true);
//	optional_count_var = MakeTemporary();
//	...
//	copy_args_prologue += LoadLocal(optional_count_var);   // dynamic index
//	copy_args_prologue += LoadFpRelativeSlot(/* static displacement */ ...);
//
// with LoadFpRelativeSlot = LoadIndexedUnsafeInstr(Pop(), offset, ...). On
// ARM64 that is:
//
//	MOV  X1, X4                 ; ARGS_DESC_REG
//	LDUR X2, [X1,#31]           ; ArgumentsDescriptor.count
//	SUB  X1, X2, #0x8           ; count - min_num_pos_args
//	ADD  X2, X29, X1, LSL #2    ; FP + optional_count * wordSize
//	LDR  X2, [X2,#40]           ; + static displacement -> parameter 0
//	ADD  X3, X29, X1, LSL #2
//	LDR  X3, [X3,#32]           ; parameter 1
//
// The displacements DESCEND with the parameter index, because the static part
// is `param_end_from_fp + fixed_params_size - param_offset` and param_offset
// counts up. So the receiver -- parameter 0 -- is the load with the LARGEST
// displacement.
//
// This is worth having beyond the copy-parameters case it was written for: it
// needs no arity at all. From Dart 2.14 the arity moved onto FunctionType
// behind a WeakSerializationReference that the AOT serializer does not write
// (app_snapshot.cc: "No WSRs are serialized"), so roughly 80% of functions on
// 2.14..3.3.0 have no arity in the snapshot and no other way to place a
// receiver.

// ReceiverLoad records that the instruction at a PC produces the receiver of
// an instance method, so the type tracker can type its destination register
// where the value is actually created rather than at function entry (an entry
// seed would be killed by the load itself).
type ReceiverLoad struct {
	Reg      int
	ClassCID int
}

// RecoverArgsDescReceiverARM64 finds the ArgumentsDescriptor-relative load of
// parameter 0 and returns its PC and destination register.
//
// The owner-field-base gate is the same one RecoverReceiverStackSlotARM64
// uses, and it carries the same weight: it confirms the loaded value behaves
// like an instance of the owner class, so a static method -- whose parameter 0
// is an ordinary argument, not `this` -- cannot be mistaken for an instance
// method and have owner field names fabricated onto it.
func RecoverArgsDescReceiverARM64(insts []disasm.Inst, ownerCID int, ctx *TypeContext) (uint64, ReceiverLoad, bool) {
	// Registers currently holding a copy of ARGS_DESC_REG. R4 itself counts.
	argsDesc := map[int]bool{sdk.ARM64ArgsDesc: true}
	// Registers holding ArgumentsDescriptor.count.
	countRegs := map[int]bool{}
	// Registers holding the derived runtime index.
	indexRegs := map[int]bool{}
	// Registers holding FP + index*scale.
	addrRegs := map[int]bool{}

	bestDisp, bestReg := -1, -1
	var bestPC uint64

	kill := func(rd int) {
		delete(argsDesc, rd)
		delete(countRegs, rd)
		delete(indexRegs, rd)
		delete(addrRegs, rd)
	}

	for i := range insts {
		raw := insts[i].Raw

		// LDR Xr, [Xt, #disp] where Xt = FP + index*scale -- a parameter.
		if base, disp, ok := arm64.LDR64UnsignedOffset(raw); ok && addrRegs[base] {
			rt := int(raw & 0x1F)
			if disp > bestDisp {
				bestDisp, bestReg, bestPC = disp, rt, insts[i].Addr
			}
			kill(rt)
			continue
		}
		// ADD Xt, X29, Xi{, LSL #n}
		if rd, rn, rm, ok := arm64.ADD64Register(raw); ok {
			kill(rd)
			if rn == sdk.ARM64FrameReg && indexRegs[rm] {
				addrRegs[rd] = true
			}
			continue
		}
		// SUB Xi, Xcount, #imm
		if rd, rn, _, ok := arm64.SUB64Immediate(raw); ok {
			kill(rd)
			if countRegs[rn] {
				indexRegs[rd] = true
			}
			continue
		}
		// LDUR Xc, [Xargsdesc, #off]
		if base, rt, _, ok := arm64.LDUR64(raw); ok {
			kill(rt)
			if argsDesc[base] {
				countRegs[rt] = true
			}
			continue
		}
		// MOV Xd, Xs -- propagate an ARGS_DESC_REG copy.
		if rd, ok := arm64.MOVOrr(raw); ok {
			rs := int((raw >> 16) & 0x1F)
			wasArgsDesc := argsDesc[rs]
			kill(rd)
			if wasArgsDesc {
				argsDesc[rd] = true
			}
			continue
		}
		for _, rd := range arm64.DstRegsOfInst(raw) {
			if rd >= 0 && rd < 31 {
				kill(rd)
			}
		}
	}

	if bestReg < 0 {
		return 0, ReceiverLoad{}, false
	}
	if !arm64RegUsedAsOwnerFieldBase(insts, bestReg, ownerCID, ctx) {
		return 0, ReceiverLoad{}, false
	}
	return bestPC, ReceiverLoad{Reg: bestReg, ClassCID: ownerCID}, true
}

// handleArgsDescReceiver types the destination of a parameter-0 load that the
// prepass identified as producing `this`.
func handleArgsDescReceiver(tc *transferCtx) bool {
	if len(tc.ctx.ReceiverLoadAtPC) == 0 {
		return false
	}
	rl, ok := tc.ctx.ReceiverLoadAtPC[tc.inst.Addr]
	if !ok || rl.Reg < 0 || rl.Reg >= 31 || rl.ClassCID < 0 {
		return false
	}
	tc.state[rl.Reg] = KnownClass(rl.ClassCID)
	tc.ctx.ArgsDescReceiverHits++
	return true
}
