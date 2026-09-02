package x86

import (
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// Every width of a register must fold to the same index. Dart AOT writes one
// value three widths in a single class-id check -- `MOV ECX, [RAX-1]`,
// `SHR ECX, 0xc`, `CMP RCX, 0x8ca` -- so a table that misses one width breaks
// the dataflow silently rather than loudly.
func TestCanonRegFoldsAllWidths(t *testing.T) {
	groups := [][]x86asm.Reg{
		{x86asm.RAX, x86asm.EAX, x86asm.AX, x86asm.AL},
		{x86asm.RCX, x86asm.ECX, x86asm.CX, x86asm.CL},
		{x86asm.RDX, x86asm.EDX, x86asm.DX, x86asm.DL},
		{x86asm.RBX, x86asm.EBX, x86asm.BX, x86asm.BL},
		{x86asm.RSP, x86asm.ESP, x86asm.SP, x86asm.SPB},
		{x86asm.RBP, x86asm.EBP, x86asm.BP, x86asm.BPB},
		{x86asm.RSI, x86asm.ESI, x86asm.SI, x86asm.SIB},
		{x86asm.RDI, x86asm.EDI, x86asm.DI, x86asm.DIB},
		{x86asm.R8, x86asm.R8L, x86asm.R8W, x86asm.R8B},
		{x86asm.R9, x86asm.R9L, x86asm.R9W, x86asm.R9B},
		{x86asm.R10, x86asm.R10L, x86asm.R10W, x86asm.R10B},
		{x86asm.R11, x86asm.R11L, x86asm.R11W, x86asm.R11B},
		{x86asm.R12, x86asm.R12L, x86asm.R12W, x86asm.R12B},
		{x86asm.R13, x86asm.R13L, x86asm.R13W, x86asm.R13B},
		{x86asm.R14, x86asm.R14L, x86asm.R14W, x86asm.R14B},
		{x86asm.R15, x86asm.R15L, x86asm.R15W, x86asm.R15B},
	}
	for want, group := range groups {
		for _, r := range group {
			if got := CanonReg(r); got != want {
				t.Errorf("CanonReg(%v) = %d, want %d", r, got, want)
			}
		}
	}
	// The two registers Dart reserves must land where the analysis expects:
	// constants_x64.h has `const Register PP = R15;` and `THR = R14;`.
	if got := CanonReg(x86asm.R15); got != 15 {
		t.Errorf("PP (R15) = %d, want 15", got)
	}
	if got := CanonReg(x86asm.R14); got != 14 {
		t.Errorf("THR (R14) = %d, want 14", got)
	}
}

// Anything that is not a plain 64-bit GP register must be rejected rather
// than aliased onto one -- high-byte registers especially, since AH is not
// the low byte of RAX.
func TestCanonRegRejectsNonGP(t *testing.T) {
	for _, r := range []x86asm.Reg{
		x86asm.AH, x86asm.CH, x86asm.DH, x86asm.BH,
		x86asm.X0, x86asm.X1,
		x86asm.CS, x86asm.DS, x86asm.ES, x86asm.FS, x86asm.GS, x86asm.SS,
		x86asm.Reg(0),
	} {
		if got := CanonReg(r); got != -1 {
			t.Errorf("CanonReg(%v) = %d, want -1", r, got)
		}
	}
}

// A rel displacement is measured from the END of the instruction, and it is
// signed. The copies this replaced disagreed in form -- one computed in
// int64, the others added a wrapped uint64 -- so a backward branch is the
// case worth pinning.
func TestRelTargetIsSignedAndEndRelative(t *testing.T) {
	// jmp .+0x10 : E9 10 00 00 00 at 0x1000, length 5 -> 0x1015
	fwd, err := x86asm.Decode([]byte{0xe9, 0x10, 0x00, 0x00, 0x00}, 64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, ok := RelTarget(fwd, 0x1000, fwd.Len); !ok || got != 0x1015 {
		t.Errorf("forward: got 0x%x ok=%v, want 0x1015", got, ok)
	}

	// jmp .-0x10 : E9 F0 FF FF FF at 0x1000, length 5 -> 0xFF5
	back, err := x86asm.Decode([]byte{0xe9, 0xf0, 0xff, 0xff, 0xff}, 64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, ok := RelTarget(back, 0x1000, back.Len); !ok || got != 0xff5 {
		t.Errorf("backward: got 0x%x ok=%v, want 0xff5", got, ok)
	}

	// An instruction with no Rel operand resolves nothing.
	noRel, err := x86asm.Decode([]byte{0x48, 0x89, 0xc8}, 64) // mov rax, rcx
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := RelTarget(noRel, 0x1000, noRel.Len); ok {
		t.Error("mov rax, rcx has no relative target")
	}
}

func TestIsCondJump(t *testing.T) {
	for _, op := range []x86asm.Op{x86asm.JE, x86asm.JNE, x86asm.JA, x86asm.JBE, x86asm.JRCXZ} {
		if !IsCondJump(op) {
			t.Errorf("%v should be a conditional jump", op)
		}
	}
	for _, op := range []x86asm.Op{x86asm.JMP, x86asm.CALL, x86asm.RET, x86asm.MOV, x86asm.CMP} {
		if IsCondJump(op) {
			t.Errorf("%v is not a conditional jump", op)
		}
	}
}

// JE proves equality on the taken edge; JNE proves it on the fall-through.
// Getting this backwards types a register on the wrong edge, which nothing
// downstream can detect.
func TestEqualitySuccessor(t *testing.T) {
	if got := EqualitySuccessor(x86asm.JE, 2); got != 0 { // SuccEqual
		t.Errorf("JE = %d, want SuccEqual (0)", got)
	}
	if got := EqualitySuccessor(x86asm.JNE, 2); got != 1 { // SuccNotEqual
		t.Errorf("JNE = %d, want SuccNotEqual (1)", got)
	}
	// Magnitude tests learn nothing from a CMP about equality.
	for _, op := range []x86asm.Op{x86asm.JA, x86asm.JB, x86asm.JG, x86asm.JL, x86asm.JMP} {
		if got := EqualitySuccessor(op, 2); got != -1 { // SuccUnknown
			t.Errorf("%v = %d, want SuccUnknown (-1)", op, got)
		}
	}
	// Only a fully resolved two-way branch is usable.
	for _, n := range []int{0, 1, 3} {
		if got := EqualitySuccessor(x86asm.JE, n); got != -1 { // SuccUnknown
			t.Errorf("JE with %d successors = %d, want SuccUnknown (-1)", n, got)
		}
	}
}

func TestDstRegsOfInstX86(t *testing.T) {
	// MOV RAX, RBX -> [0]
	movInst := x86asm.Inst{Op: x86asm.MOV, Args: [4]x86asm.Arg{x86asm.RAX, x86asm.RBX, nil, nil}}
	if dsts := DstRegsOfInst(movInst); len(dsts) != 1 || dsts[0] != 0 {
		t.Errorf("MOV RAX, RBX dsts = %v, want [0]", dsts)
	}

	// CMP RAX, 10 -> nil
	cmpInst := x86asm.Inst{Op: x86asm.CMP, Args: [4]x86asm.Arg{x86asm.RAX, x86asm.Imm(10), nil, nil}}
	if dsts := DstRegsOfInst(cmpInst); len(dsts) != 0 {
		t.Errorf("CMP RAX, 10 dsts = %v, want nil", dsts)
	}

	// IDIV RCX -> [0, 2] (RAX, RDX)
	idivInst := x86asm.Inst{Op: x86asm.IDIV, Args: [4]x86asm.Arg{x86asm.RCX, nil, nil, nil}}
	if dsts := DstRegsOfInst(idivInst); len(dsts) != 2 || dsts[0] != 0 || dsts[1] != 2 {
		t.Errorf("IDIV RCX dsts = %v, want [0, 2]", dsts)
	}
}
