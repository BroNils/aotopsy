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

import "golang.org/x/arch/x86/x86asm"

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
// The arithmetic is deliberately signed. The copies split between
// `uint64(int64(addr)+int64(length)+int64(rel))` and
// `addr + uint64(length) + uint64(int64(rel))`; those agree for negative rel
// only because two's-complement addition wraps, which is true but is not
// something a reader should have to re-derive.
func RelTarget(inst x86asm.Inst, addr uint64, length int) (uint64, bool) {
	for _, arg := range inst.Args {
		if arg == nil {
			continue
		}
		if rel, ok := arg.(x86asm.Rel); ok {
			//nolint:gosec // rel is a decoded rel8/rel32; the sum is an address by construction
			return uint64(int64(addr) + int64(length) + int64(rel)), true
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
		x86asm.JNS, x86asm.JO, x86asm.JP, x86asm.JS:
		return true
	}
	return false
}

// EqualitySuccessor returns which successor edge of a two-way branch
// proves the operands of the preceding comparison were equal, or
// sdk.SuccUnknown.
//
// Successor convention constants (SuccEqual, SuccNotEqual, SuccUnknown)
// live in internal/sdk because they are shared with ARM64's
// equalitySuccessor in typetrack/intraproc.go.
func EqualitySuccessor(op x86asm.Op, numSuccs int) int {
	if numSuccs != 2 {
		return -1 // sdk.SuccUnknown
	}
	switch op {
	case x86asm.JE:
		return 0 // sdk.SuccEqual
	case x86asm.JNE:
		return 1 // sdk.SuccNotEqual
	}
	return -1 // sdk.SuccUnknown
}

// DstRegsOfInst returns the canonical register indices (0..15) modified by inst.
// Returns nil for instructions that do not modify GP registers (e.g. CMP, TEST, PUSH, jumps).
func DstRegsOfInst(inst x86asm.Inst) []int {
	switch inst.Op {
	case x86asm.CMP, x86asm.TEST, x86asm.PUSH, x86asm.JMP:
		return nil
	case x86asm.DIV, x86asm.IDIV:
		// DIV/IDIV implicitly modifies RAX (0) and RDX (2)
		return []int{0, 2}
	}
	if IsCondJump(inst.Op) {
		return nil
	}
	if len(inst.Args) >= 1 {
		if r, ok := inst.Args[0].(x86asm.Reg); ok {
			canon := CanonReg(r)
			if canon >= 0 {
				return []int{canon}
			}
		}
	}
	return nil
}
