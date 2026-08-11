package decompiler

import (
	"strings"
	"testing"
)

// buildTestIR lifts a hand-written ARM64 instruction sequence.
func liftARM64Ops(t *testing.T, srcs []string) *LiftState {
	t.Helper()
	fir := &FuncIR{FrameReg: arm64FrameReg, PoolReg: arm64PoolReg, ThreadReg: arm64ThreadReg, NullReg: arm64NullReg}
	s := newLiftState(fir.NullReg)
	for _, src := range srcs {
		ApplyOther(fir, s, Instr{Src: src})
	}
	return s
}

// ARM64 reserves R22 to cache Object::null() -- dart-lang/sdk's
// constants_arm64.h, `const Register NULL_REG = R22;`, unchanged from 2.12.0
// through 3.9.2. Reading it as x22 told the reader nothing.
func TestNullRegReadsAsNull(t *testing.T) {
	s := liftARM64Ops(t, []string{"mov x0, x22"})
	if got := s.lookupReg("x0"); got != "null" {
		t.Errorf("a copy of NULL_REG should read as null, got %q", got)
	}
	if got := s.lookupReg("x22"); got != "null" {
		t.Errorf("NULL_REG itself should read as null, got %q", got)
	}
}

// `true` and `false` live at fixed offsets from null, and the SDK's own
// disassembler decodes ADD Xd, NULL_REG, #32/#48 as those objects
// (instructions_arm64.cc + pointer_tagging.h). Without this the pseudocode
// said `null + 32`, which reads as arithmetic on null.
func TestBoolsMaterialiseFromNullOffsets(t *testing.T) {
	cases := []struct {
		imm  string
		want string
	}{
		{"#32", "true"},
		{"#48", "false"},
	}
	for _, tc := range cases {
		s := liftARM64Ops(t, []string{"add x0, x22, " + tc.imm})
		if got := s.lookupReg("x0"); got != tc.want {
			t.Errorf("add x0, x22, %s = %q, want %q", tc.imm, got, tc.want)
		}
	}
	// Recognised through a register copy too, because the check is on the
	// resolved value rather than the register token.
	s := liftARM64Ops(t, []string{"mov x1, x22", "add x0, x1, #32"})
	if got := s.lookupReg("x0"); got != "true" {
		t.Errorf("bool through a copy of NULL_REG = %q, want true", got)
	}
}

// Any other offset is NOT a bool and must keep its arithmetic form.
func TestOtherNullOffsetsAreNotBools(t *testing.T) {
	for _, imm := range []string{"#8", "#16", "#24", "#64"} {
		s := liftARM64Ops(t, []string{"add x0, x22, " + imm})
		got := s.lookupReg("x0")
		if got == "true" || got == "false" {
			t.Errorf("add x0, x22, %s must not be a bool, got %q", imm, got)
		}
		if !strings.Contains(got, "null") {
			t.Errorf("add x0, x22, %s = %q, expected it to mention null", imm, got)
		}
	}
}

// x86_64 has no NULL_REG -- constants_x64.h defines none, and null is loaded
// from the object pool -- so nothing may be seeded there.
func TestX86HasNoNullReg(t *testing.T) {
	s := newLiftState("")
	if len(s.Regs) != 0 {
		t.Errorf("no register should be seeded without a NullReg, got %v", s.Regs)
	}
}
