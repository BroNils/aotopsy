package decompiler

import "testing"

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

func TestCanonRegAliasingIsSymmetric(t *testing.T) {
	// A write through one width view must be observable through every other:
	// this is the single-slot invariant the value-graph relies on.
	s := &LiftState{Regs: map[string]string{}}
	s.setReg("w16", "pool[64]")
	if got := s.lookupReg("x16"); got != "pool[64]" {
		t.Fatalf("x16 after w16 write = %q, want pool[64]", got)
	}
	s.setReg("x16", "THR.stack_limit")
	if got := s.lookupReg("w16"); got != "THR.stack_limit" {
		t.Fatalf("w16 after x16 write = %q, want THR.stack_limit", got)
	}
}

func TestStackComputedSlot(t *testing.T) {
	cases := []struct {
		in    string
		out   string
		ok    bool
	}{
		{"SP", "[SP]", true},
		{"(SP - 8)", "[SP-8]", true},
		{"(SP + 16)", "[SP+16]", true},
		{"(SP - 128)", "[SP-128]", true},
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
