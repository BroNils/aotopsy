package typetrack

import (
	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/arch/x86"
	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
	"aotopsy/internal/snapshot"

	"golang.org/x/arch/x86/x86asm"
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
	if ctx == nil || (ctx.WordSize != 4 && ctx.WordSize != 8) {
		return 0, ReceiverLoad{}, false
	}
	countDisp, ok := argumentsDescriptorCountDisp(ctx)
	if !ok {
		return 0, ReceiverLoad{}, false
	}

	// Registers currently holding a copy of ARGS_DESC_REG. R4 itself counts.
	argsDesc := map[int]bool{sdk.ARM64ArgsDesc: true}
	// Registers holding ArgumentsDescriptor.count.
	countRegs := map[int]bool{}
	// Registers holding the derived runtime index.
	indexRegs := map[int]bool{}
	// Registers holding FP + index*scale.
	addrRegs := map[int]bool{}

	bestDisp, bestReg, bestAt := -1, -1, -1
	var bestPC uint64

	kill := func(rd int) {
		delete(argsDesc, rd)
		delete(countRegs, rd)
		delete(indexRegs, rd)
		delete(addrRegs, rd)
	}

	for i := range insts {
		raw := insts[i].Raw
		if insts[i].Bad {
			break
		}

		// Calls clobber ARGS_DESC_REG under the Dart ABI, so no post-call value
		// can be connected to the entry descriptor without fresh proof. This
		// recovery is deliberately straight-line only: after a branch, re-seeding
		// the architectural ARGS_DESC_REG would be unsound if an earlier
		// instruction on the path had overwritten it.
		if arm64.IsRet(raw) {
			break
		}
		if arm64.IsBLEncoding(raw) {
			break
		}
		if _, ok := arm64.BLR(raw); ok {
			break
		}
		if arm64.IsBEncoding(raw) || arm64.IsConditionalBranchEncoding(raw) {
			break
		}

		// LDR Xr, [Xt, #disp] where Xt = FP + index*scale -- a parameter.
		if base, disp, ok := arm64.LDR64UnsignedOffset(raw); ok && addrRegs[base] {
			rt := int(raw & 0x1F)
			if disp > bestDisp {
				bestDisp, bestReg, bestAt, bestPC = disp, rt, i, insts[i].Addr
			}
			kill(rt)
			continue
		}
		// ADD Xt, X29, Xi{, LSL #n}
		if rd, rn, rm, shift, _, ok := arm64.ADD64Register(raw); ok {
			kill(rd)
			if shift == arm64.ShiftLSL && rn == sdk.ARM64FrameReg && indexRegs[rm] {
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
		// Load the exact ArgumentsDescriptor.count slot. Accept both X and W
		// unscaled forms because compressed-pointer builds materialize tagged
		// array elements through the 32-bit load family.
		if base, rt, off, ok := arm64.LDUR64(raw); ok {
			kill(rt)
			if argsDesc[base] && off == countDisp {
				countRegs[rt] = true
			}
			continue
		}
		if base, rt, off, ok := arm64.LDUR32(raw); ok {
			kill(rt)
			if argsDesc[base] && off == countDisp {
				countRegs[rt] = true
			}
			continue
		}
		// MOV Xd, Xs -- propagate an ARGS_DESC_REG copy.
		if rd, rs, ok := arm64.MOVOrr(raw); ok {
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
	if !arm64RegUsedAsOwnerFieldBaseAfter(insts, bestAt+1, bestReg, ownerCID, ctx) {
		return 0, ReceiverLoad{}, false
	}
	return bestPC, ReceiverLoad{Reg: bestReg, ClassCID: ownerCID}, true
}

// RecoverArgsDescReceiverX86 is the x86_64 counterpart. The exact SDK lowering
// of LoadFpRelativeSlot is `movq(out, [FP + smi_index*4 + offset])`; the Smi
// scale of four yields an eight-byte stack-slot stride. Compressed builds may
// insert MOVSXD on the index first. We require the complete provenance chain
// ARGS_DESC_REG -> ArgumentsDescriptor.count -> subtract fixed-parameter count
// -> indexed FP load, then the same owner-field use gate as static stack-slot
// recovery. A bare `[RBP + reg*4 + disp]` is not enough.
func RecoverArgsDescReceiverX86(insts []x86.Decoded, ownerCID int, ctx *TypeContext) (uint64, ReceiverLoad, bool) {
	if ctx == nil || (ctx.WordSize != 4 && ctx.WordSize != 8) {
		return 0, ReceiverLoad{}, false
	}
	countDispInt, ok := argumentsDescriptorCountDisp(ctx)
	if !ok {
		return 0, ReceiverLoad{}, false
	}
	countDisp := int64(countDispInt)

	argsDesc := map[int]bool{sdk.X86ArgsDesc: true}
	countRegs := map[int]bool{}
	indexRegs := map[int]bool{}

	bestDisp := int64(-1)
	bestReg, bestAt := -1, -1
	var bestPC uint64

	kill := func(reg int) {
		delete(argsDesc, reg)
		delete(countRegs, reg)
		delete(indexRegs, reg)
	}
	for i := range insts {
		if insts[i].Bad {
			break
		}
		in := insts[i].Inst
		if in.Op == x86asm.RET || in.Op == x86asm.CALL {
			break
		}
		if in.Op == x86asm.JMP || x86.IsCondJump(in.Op) {
			break
		}

		// The parameter load produced by LoadIndexedUnsafeInstr.
		if in.Op == x86asm.MOV && len(in.Args) >= 2 {
			if dst, ok := in.Args[0].(x86asm.Reg); ok {
				dstIdx := x86.CanonReg(dst)
				if mem, ok := in.Args[1].(x86asm.Mem); ok &&
					x86.CanonReg(mem.Base) == sdk.X86FrameReg &&
					mem.Scale == 4 && indexRegs[x86.CanonReg(mem.Index)] {
					if mem.Disp > bestDisp {
						bestDisp, bestReg, bestAt, bestPC = mem.Disp, dstIdx, i, insts[i].VA
					}
					kill(dstIdx)
					continue
				}
			}
		}

		// Exact ArgumentsDescriptor.count load from the tagged descriptor.
		if in.Op == x86asm.MOV && len(in.Args) >= 2 {
			dst, dstOK := in.Args[0].(x86asm.Reg)
			mem, memOK := in.Args[1].(x86asm.Mem)
			if dstOK && memOK && mem.Index == 0 {
				dstIdx := x86.CanonReg(dst)
				baseIdx := x86.CanonReg(mem.Base)
				if dstIdx >= 0 && argsDesc[baseIdx] && mem.Disp == countDisp {
					kill(dstIdx)
					countRegs[dstIdx] = true
					continue
				}
			}
		}

		// MOV copies descriptor/count/index provenance. MOVSXD is emitted on
		// compressed x64 before the indexed FP load and preserves the Smi index.
		if (in.Op == x86asm.MOV || in.Op == x86asm.MOVSXD) && len(in.Args) >= 2 {
			dst, dstOK := in.Args[0].(x86asm.Reg)
			src, srcOK := in.Args[1].(x86asm.Reg)
			if dstOK && srcOK {
				dstIdx, srcIdx := x86.CanonReg(dst), x86.CanonReg(src)
				wasArgsDesc := argsDesc[srcIdx]
				wasCount := countRegs[srcIdx]
				wasIndex := indexRegs[srcIdx]
				kill(dstIdx)
				if in.Op == x86asm.MOV && wasArgsDesc {
					argsDesc[dstIdx] = true
				}
				if in.Op == x86asm.MOV && wasCount {
					countRegs[dstIdx] = true
				}
				if wasIndex {
					indexRegs[dstIdx] = true
				}
				continue
			}
		}

		// SmiBinaryOp(SUB) is a two-address x64 SUB. Only a register already
		// proven to contain ArgumentsDescriptor.count may become the runtime index.
		if in.Op == x86asm.SUB && len(in.Args) >= 2 {
			if dst, ok := in.Args[0].(x86asm.Reg); ok {
				dstIdx := x86.CanonReg(dst)
				wasCount := countRegs[dstIdx]
				kill(dstIdx)
				if _, immOK := in.Args[1].(x86asm.Imm); wasCount && immOK {
					indexRegs[dstIdx] = true
				}
				continue
			}
		}

		for _, dst := range x86.DstRegsOfInst(in) {
			if dst >= 0 {
				kill(dst)
			}
		}
	}

	if bestReg < 0 || !x86RegUsedAsOwnerFieldBaseAfter(insts, bestAt+1, bestReg, ownerCID, ctx) {
		return 0, ReceiverLoad{}, false
	}
	return bestPC, ReceiverLoad{Reg: bestReg, ClassCID: ownerCID}, true
}

func argumentsDescriptorCountDisp(ctx *TypeContext) (int, bool) {
	if ctx == nil {
		return 0, false
	}
	// SDK runtime/vm/compiler/runtime_offsets_extracted.h AOT blocks:
	//   64-bit uncompressed: ArgumentsDescriptor_count_offset = 0x20
	//   64-bit compressed:   ArgumentsDescriptor_count_offset = 0x14
	//   32-bit uncompressed: ArgumentsDescriptor_count_offset = 0x10
	// The generated load uses FieldAddress and therefore subtracts
	// kHeapObjectTag. WordSize==4 alone is not enough to choose the last row:
	// ARM64/x86_64 compressed snapshots also have four-byte heap slots.
	var offset int
	switch {
	case ctx.CompressedPointers && snapshot.VersionAtLeast(ctx.DartVersion, "2.14.0"):
		offset = 0x14
	case ctx.CompressedPointers:
		// SDK @2.13.0 AOT runtime_offsets_extracted.h still keeps the
		// 64-bit ArgumentsDescriptor count slot at 0x20 even when the build
		// advertises compressed pointers. The compact 0x14 layout starts at
		// 2.14.0 (verified by the SDK-derived gate below).
		offset = 0x20
	case ctx.WordSize == 8:
		offset = 0x20
	case ctx.WordSize == 4:
		offset = 0x10
	default:
		return 0, false
	}
	return offset - sdk.HeapObjectTag, true
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
	// The declaring owner is a safe upper bound only: an inherited instance
	// method can run with a subclass receiver.
	tc.state[rl.Reg] = ClassBound(rl.ClassCID)
	tc.ctx.hitMetric(metricArgsDescReceiver, tc.inst.Addr, &tc.ctx.ArgsDescReceiverHits)
	return true
}

func handleArgsDescReceiverX86(tc *transferCtxX86) bool {
	if tc.ctx == nil || len(tc.ctx.ReceiverLoadAtPC) == 0 {
		return false
	}
	rl, ok := tc.ctx.ReceiverLoadAtPC[tc.inst.VA]
	if !ok || rl.Reg < 0 || rl.Reg >= 31 || rl.ClassCID < 0 {
		return false
	}
	tc.state[rl.Reg] = ClassBound(rl.ClassCID)
	tc.ctx.hitMetric(metricArgsDescReceiver, tc.inst.VA, &tc.ctx.ArgsDescReceiverHits)
	return true
}
