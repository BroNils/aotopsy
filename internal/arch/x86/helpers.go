// Package x86 holds x86_64 instruction decode primitives — register
// canonicalization, relative-branch resolution, conditional-jump
// classification, and the linear decode sweep.
//
// These were previously in internal/sdk (x86_helpers.go, x86_decode.go),
// mixed with SDK-verified facts (register roles, calling conventions).
// They are instruction-decode helpers, not SDK facts, so they belong here
// alongside internal/arch/arm64/decoders.go for symmetry.
//
// Three helpers below existed in three, three and two copies respectively --
// in internal/disasm, internal/decompiler, internal/typetrack and
// cmd/aotopsy. They were byte-identical in logic and differed only in name
// (`canonX86Reg` / `canonX86RegLocal` / `canon64`) or in the wrapper struct
// they unpacked. That is exactly the shape that produced the
// `call [r14+rcx*8+disp]` mistake elsewhere in this project: an
// architecture fact written down several times, so a correction to one copy
// leaves the others wrong.
package x86

import (
	"aotopsy/internal/sdk"
	"math"

	"golang.org/x/arch/x86/x86asm"
)

// CanonReg maps any width of an x86_64 general-purpose register to its
// canonical number 0..15 (RAX=0 .. R15=15), or -1 for anything else.
//
// Analysis code has to fold widths together because Dart AOT freely mixes
// them for the same value -- `MOV ECX, [RAX-1]` then `SHR ECX, 0xc` then
// `CMP RCX, 0x8ca` is one class-id check on one register, written three
// widths.
func CanonReg(r x86asm.Reg) int {
	switch r {
	case x86asm.RAX, x86asm.EAX, x86asm.AX, x86asm.AL:
		return 0
	case x86asm.RCX, x86asm.ECX, x86asm.CX, x86asm.CL:
		return 1
	case x86asm.RDX, x86asm.EDX, x86asm.DX, x86asm.DL:
		return 2
	case x86asm.RBX, x86asm.EBX, x86asm.BX, x86asm.BL:
		return 3
	case x86asm.RSP, x86asm.ESP, x86asm.SP, x86asm.SPB:
		return 4
	case x86asm.RBP, x86asm.EBP, x86asm.BP, x86asm.BPB:
		return 5
	case x86asm.RSI, x86asm.ESI, x86asm.SI, x86asm.SIB:
		return 6
	case x86asm.RDI, x86asm.EDI, x86asm.DI, x86asm.DIB:
		return 7
	case x86asm.R8, x86asm.R8L, x86asm.R8W, x86asm.R8B:
		return 8
	case x86asm.R9, x86asm.R9L, x86asm.R9W, x86asm.R9B:
		return 9
	case x86asm.R10, x86asm.R10L, x86asm.R10W, x86asm.R10B:
		return 10
	case x86asm.R11, x86asm.R11L, x86asm.R11W, x86asm.R11B:
		return 11
	case x86asm.R12, x86asm.R12L, x86asm.R12W, x86asm.R12B:
		return 12
	case x86asm.R13, x86asm.R13L, x86asm.R13W, x86asm.R13B:
		return 13
	case x86asm.R14, x86asm.R14L, x86asm.R14W, x86asm.R14B:
		return 14
	case x86asm.R15, x86asm.R15L, x86asm.R15W, x86asm.R15B:
		return 15
	}
	return -1
}

// RelTarget resolves a PC-relative branch or call to its absolute target.
// addr is the instruction's address and length its encoded size; an x86 Rel
// displacement is measured from the END of the instruction.
//
// Takes the three primitives rather than a decoded-instruction struct,
// because each caller wraps x86asm.Inst in its own type and the previous
// copies differed only in which wrapper they unpacked.
//
// Arithmetic is checked. Malformed ELF inputs can place executable sections
// near MaxUint64; letting a rel32 wrap there turns an invalid target into a
// plausible small address and can create a false exact symbol match.
func RelTarget(inst x86asm.Inst, addr uint64, length int) (uint64, bool) {
	if length < 0 || addr > math.MaxUint64-uint64(length) {
		return 0, false
	}
	base := addr + uint64(length)
	for _, arg := range inst.Args {
		if arg == nil {
			continue
		}
		if rel, ok := arg.(x86asm.Rel); ok {
			v := int64(rel)
			if v >= 0 {
				uv := uint64(v)
				if base > math.MaxUint64-uv {
					return 0, false
				}
				return base + uv, true
			}
			mag := uint64(-(v + 1)) + 1
			if mag > base {
				return 0, false
			}
			return base - mag, true
		}
	}
	return 0, false
}

// IsCondJump reports whether op is a conditional branch.
//
// JCXZ/JECXZ/JRCXZ are included: they are conditional control flow even
// though they test a register rather than the flags. Callers that care about
// what a preceding CMP proves must check the specific opcode -- see
// EqualitySuccessor -- rather than treating every conditional jump as
// flag-driven.
func IsCondJump(op x86asm.Op) bool {
	switch op {
	case x86asm.JA, x86asm.JAE, x86asm.JB, x86asm.JBE, x86asm.JCXZ, x86asm.JECXZ, x86asm.JRCXZ,
		x86asm.JE, x86asm.JG, x86asm.JGE, x86asm.JL, x86asm.JLE, x86asm.JNE, x86asm.JNO, x86asm.JNP,
		x86asm.JNS, x86asm.JO, x86asm.JP, x86asm.JS, x86asm.LOOP, x86asm.LOOPE, x86asm.LOOPNE:
		return true
	}
	return false
}

// IsSemanticBarrier reports architectural traps after which ordinary static
// fallthrough is not valid. Decoder failures live on Decoded.Bad and remain the
// caller's responsibility.
func IsSemanticBarrier(inst x86asm.Inst) bool {
	switch inst.Op {
	case x86asm.UD2, x86asm.HLT:
		return true
	case x86asm.INT:
		// x86asm does not expose a distinct INT3 opcode. 0xCC decodes as
		// INT $0x3, while Dart's x86 constants define int3 as exactly 0xCC.
		// Other software interrupts are not Dart AOT break fillers, so keep the
		// barrier classification specific to vector 3.
		imm, ok := inst.Args[0].(x86asm.Imm)
		return ok && imm == 3
	default:
		return false
	}
}

// EqualitySuccessor returns which successor edge of a two-way branch
// proves the operands of the preceding comparison were equal, or
// sdk.SuccUnknown.
//
// Successor convention constants (SuccEqual, SuccNotEqual, SuccUnknown)
// live in internal/sdk because they are shared with ARM64's
// equalitySuccessor in typetrack/intraproc.go.
// The constants used to be written out as bare 0/1/-1 with the sdk name
// in a trailing comment. A comment does not track a rename, and the two
// architectures disagreeing about which edge means "equal" is a bug that
// fails silently -- it produces confidently wrong types, not an error.
func EqualitySuccessor(op x86asm.Op, numSuccs int) int {
	if numSuccs != 2 {
		return sdk.SuccUnknown
	}
	switch op {
	case x86asm.JE:
		return sdk.SuccEqual
	case x86asm.JNE:
		return sdk.SuccNotEqual
	}
	return sdk.SuccUnknown
}

// DstRegsOfInst returns the canonical register indices (0..15) modified by inst,
// including implicit GPR effects such as RSP updates by PUSH/POP/CALL/RET.
// Returns nil only when no GPR family is modified (e.g. CMP, TEST, jumps).
func DstRegsOfInst(inst x86asm.Inst) []int {
	switch inst.Op {
	case x86asm.CMP, x86asm.TEST, x86asm.BT, x86asm.JMP:
		return nil
	case x86asm.PUSH, x86asm.CALL, x86asm.RET:
		return []int{4} // implicit RSP update
	case x86asm.POP:
		return appendUniqueReg(writtenRegisterArgs(inst, 0), 4)
	case x86asm.DIV, x86asm.IDIV, x86asm.MUL:
		// The byte forms use AX as the entire implicit result/dividend and
		// therefore modify only the RAX family. Wider forms use RDX:RAX.
		// The explicit operand is a source, not a destination.
		return implicitMulDivWrites(inst)
	case x86asm.IMUL:
		// x86 has both one-operand IMUL (implicit RDX:RAX destination) and
		// two/three-operand forms whose first operand is the explicit dest.
		if inst.Args[1] == nil {
			return implicitMulDivWrites(inst)
		}
	case x86asm.LOOP, x86asm.LOOPE, x86asm.LOOPNE:
		// LOOP-family branches decrement the address-size count register. All
		// widths canonicalize to RCX=1 for our provenance/type state.
		return []int{1}
	case x86asm.MOVSB, x86asm.MOVSW, x86asm.MOVSD, x86asm.MOVSQ:
		// String moves implicitly advance/retreat RSI and RDI. A live REP/REPN
		// prefix also decrements RCX as the repetition counter. x86asm keeps
		// ignored/overridden prefixes in the Prefix array, so only an effective
		// low-byte F2/F3 counts here.
		regs := []int{6, 7}
		for _, p := range inst.Prefix {
			if p&x86asm.PrefixIgnored != 0 {
				continue
			}
			low := p & 0xFF
			if low == x86asm.PrefixREP || low == x86asm.PrefixREPN {
				regs = append(regs, 1)
				break
			}
		}
		return regs
	case x86asm.CWD, x86asm.CDQ, x86asm.CQO:
		// Sign-extension into the implicit high half of the dividend.
		return []int{2}
	case x86asm.XCHG, x86asm.XADD:
		return writtenRegisterArgs(inst, 0, 1)
	case x86asm.BTC, x86asm.BTR, x86asm.BTS:
		return writtenRegisterArgs(inst, 0)
	case x86asm.CMPXCHG:
		// CMPXCHG may define the destination and always may replace RAX with
		// the observed value on the compare-fail path.
		return appendUniqueReg(writtenRegisterArgs(inst, 0), 0)
	case x86asm.CMPXCHG8B, x86asm.CMPXCHG16B:
		// On failure the loaded memory value is returned in EDX:EAX/RDX:RAX.
		return []int{0, 2}
	}
	if IsCondJump(inst.Op) {
		return nil
	}
	if len(inst.Args) >= 1 {
		if r, ok := inst.Args[0].(x86asm.Reg); ok {
			canon := writtenRegFamily(r)
			if canon >= 0 {
				return []int{canon}
			}
		}
	}
	return nil
}

func implicitMulDivWrites(inst x86asm.Inst) []int {
	if implicitMulDivByteOperand(inst) {
		return []int{0}
	}
	return []int{0, 2}
}

func implicitMulDivByteOperand(inst x86asm.Inst) bool {
	if _, ok := inst.Args[0].(x86asm.Mem); ok {
		return inst.MemBytes == 1
	}
	r, ok := inst.Args[0].(x86asm.Reg)
	if !ok {
		return false
	}
	switch r {
	case x86asm.AL, x86asm.CL, x86asm.DL, x86asm.BL,
		x86asm.AH, x86asm.CH, x86asm.DH, x86asm.BH,
		x86asm.SPB, x86asm.BPB, x86asm.SIB, x86asm.DIB,
		x86asm.R8B, x86asm.R9B, x86asm.R10B, x86asm.R11B,
		x86asm.R12B, x86asm.R13B, x86asm.R14B, x86asm.R15B:
		return true
	}
	return false
}

func writtenRegisterArgs(inst x86asm.Inst, positions ...int) []int {
	var out []int
	for _, pos := range positions {
		if pos < 0 || pos >= len(inst.Args) {
			continue
		}
		r, ok := inst.Args[pos].(x86asm.Reg)
		if !ok {
			continue
		}
		if idx := writtenRegFamily(r); idx >= 0 {
			out = appendUniqueReg(out, idx)
		}
	}
	return out
}

// writtenRegFamily maps a register write to the 64-bit GPR state slot that it
// invalidates. Unlike CanonReg, it deliberately accepts AH/CH/DH/BH: those
// high-byte writes do not carry a whole-register value that can be propagated,
// but they do mutate the corresponding parent register and therefore must kill
// any stale type/provenance fact for it.
func writtenRegFamily(r x86asm.Reg) int {
	switch r {
	case x86asm.AH:
		return 0
	case x86asm.CH:
		return 1
	case x86asm.DH:
		return 2
	case x86asm.BH:
		return 3
	default:
		return CanonReg(r)
	}
}

func appendUniqueReg(regs []int, reg int) []int {
	if reg < 0 {
		return regs
	}
	for _, existing := range regs {
		if existing == reg {
			return regs
		}
	}
	return append(regs, reg)
}
