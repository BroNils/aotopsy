package typetrack

import "testing"

// Dart AOT declares its OWN calling convention; it is not the platform C ABI.
// Verified against dart-lang/sdk at tag 3.12.2 (and 3.9.2 for x64):
//
//	constants_arm64.h  kCpuRegistersForArgs[] = {R1, R2, R3, R5, R6, R7}
//	constants_x64.h    kCpuRegistersForArgs[] = {RDI, RSI, RDX, RBX, R8, R9}
//
// The x86_64 list was previously the ARM64 one, with a comment describing
// RDI as "the SysV ABI first arg". Only that first register coincides. The
// rest typed parameters into registers holding something else -- parameter 3
// went to RBP, the frame pointer -- so this was not a missing feature but a
// source of confident wrong types.
func TestDartCallingConventionRegisters(t *testing.T) {
	arm := dartArgRegisters(true)
	x64 := dartArgRegisters(false)

	// ARM64: R1, R2, R3, R5, R6, R7.
	if want := []int{1, 2, 3, 5, 6, 7}; !equalInts(arm, want) {
		t.Errorf("ARM64 arg registers = %v, want %v", arm, want)
	}
	// x86_64 canonical indices: RDI=7, RSI=6, RDX=2, RBX=3, R8=8, R9=9.
	if want := []int{7, 6, 2, 3, 8, 9}; !equalInts(x64, want) {
		t.Errorf("x86_64 arg registers = %v, want %v", x64, want)
	}

	// The receiver is parameter 0 on both, so it must be the head of the
	// list rather than a separately-maintained constant -- keeping the two
	// in step by hand is what produced a right receiver and five wrong
	// parameters on x86_64.
	if arm[0] != 1 {
		t.Errorf("ARM64 receiver = R%d, want R1", arm[0])
	}
	if x64[0] != 7 {
		t.Errorf("x86_64 receiver = reg %d, want 7 (RDI)", x64[0])
	}

	// RBP is the frame pointer on x86_64 and must never be an argument
	// register: typing it claims the frame pointer holds a Dart object.
	for i, r := range x64 {
		if r == 5 {
			t.Errorf("x86_64 parameter %d maps to RBP, the frame pointer", i)
		}
	}
	// The two architectures must not accidentally share a list again.
	if equalInts(arm, x64) {
		t.Error("ARM64 and x86_64 have the same argument registers; one of them is wrong")
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
