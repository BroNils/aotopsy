package decompiler

import (
	"strconv"
	"testing"
)

func TestCanonReg(t *testing.T) {
	cases := map[string]string{
		// ARM64 width views collapse onto x<n>.
		"w0": "x0", "x0": "x0", "w16": "x16", "x16": "x16", "W3": "x3",
		// x86-64 extended registers r8..r15 with width suffixes.
		"r8": "r8", "r8d": "r8", "r8w": "r8", "r8b": "r8",
		"r15": "r15", "r15d": "r15",
		// x86-64 legacy registers collapse every width onto the 64-bit name.
		"rax": "rax", "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
		"rsi": "rsi", "esi": "rsi", "sil": "rsi",
		"rdi": "rdi", "edi": "rdi",
		"rbp": "rbp", "ebp": "rbp",
		"rsp": "rsp", "esp": "rsp",
		// Non-register / pass-through tokens.
		"THR": "thr", "pp": "pp", "sp": "sp", "null": "null", "": "",
	}
	for in, want := range cases {
		if got := canonReg(in); got != want {
			t.Errorf("canonReg(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanonRegViewsPreserveArchitecturalWidthSemantics(t *testing.T) {
	// Aliases share one physical slot, but the value observed through a view is
	// not necessarily identical. ARM64 W writes/read select 32 bits and writes
	// zero-extend into X.
	s := &LiftState{Regs: map[string]string{}}
	s.setReg("w16", "-1")
	if got := s.lookupReg("x16"); got != "4294967295" {
		t.Fatalf("x16 after w16=-1 = %q, want zero-extended 4294967295", got)
	}
	s.setReg("x16", "-1")
	if got := s.lookupReg("w16"); got != "4294967295" {
		t.Fatalf("w16 read of x16=-1 = %q, want low 32 bits", got)
	}

	// x86 E writes clear the upper half; byte/word writes do not. The SDK says so
	// itself ("Clear upper part of the out register. We are going to use setcc on
	// it which is a byte move") and copes in three ways, all in il_x64.cc: clear
	// the register BEFORE the compare (IfThenElseInstr, ClearRegister(RDX) then
	// setcc(.., DL)); clear it, setcc, then negl (Int32x4FromBools); or follow
	// setcc with movzxb (EmitToBoolean). SDK @3.12.2 il_x64.cc:548-597 and
	// 4453-4481, read in full; the same sites exist at 2.12.0 and 3.9.2 by grep
	// only (not read).
	s.setReg("rax", "0x1122334455667788")
	s.setReg("al", "0xaa")
	want := strconv.FormatUint(0x11223344556677aa, 10)
	if got := s.lookupReg("rax"); got != want {
		t.Fatalf("rax after al write = %q, want %s", got, want)
	}
	s.setReg("ah", "0xbb")
	want = strconv.FormatUint(0x112233445566bbaa, 10)
	if got := s.lookupReg("rax"); got != want {
		t.Fatalf("rax after ah write = %q, want %s", got, want)
	}
	s.setReg("ax", "0xccdd")
	want = strconv.FormatUint(0x112233445566ccdd, 10)
	if got := s.lookupReg("rax"); got != want {
		t.Fatalf("rax after ax write = %q, want %s", got, want)
	}
	s.setReg("eax", "-1")
	if got := s.lookupReg("rax"); got != "4294967295" {
		t.Fatalf("rax after eax=-1 = %q, want zero-extended 4294967295", got)
	}
}

func TestStackComputedSlot(t *testing.T) {
	cases := []struct {
		in  string
		out string
		ok  bool
	}{
		{"SP", "stack_sp", true},
		{"(SP - 8)", "stack_m8", true},
		{"(SP + 16)", "stack_p16", true},
		{"(SP - 128)", "stack_m128", true},
		{"(x15 - 8)", "", false},
		{"(SP * 8)", "", false},
		{"arg1.f39", "", false},
		{"(SP - )", "", false},
	}
	for _, c := range cases {
		got, ok := stackComputedSlot(c.in)
		if ok != c.ok || (ok && got != c.out) {
			t.Errorf("stackComputedSlot(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.out, c.ok)
		}
	}
}
