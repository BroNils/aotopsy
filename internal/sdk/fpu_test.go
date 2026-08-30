package sdk

import "testing"

// TestFpuCallingConvention verifies the FPU argument and return register
// names against the Dart SDK's DartCallingConvention.
//
// Source: constants_arm64.h @3.12.2:
//   kFpuRegistersForArgs[] = {V0, V1, V2, V3, V4, V5}
//   kReturnFpuReg = V0
// Source: constants_x64.h @3.12.2:
//   kFpuRegistersForArgs[] = {XMM1, XMM2, XMM3, XMM4, XMM5, XMM6}
//   kReturnFpuReg = XMM0
func TestFpuCallingConvention(t *testing.T) {
	// ARM64 FPU args.
	armFpu := ARM64FpuArgRegNames()
	if len(armFpu) != 6 {
		t.Fatalf("ARM64: want 6 FPU arg registers, got %d", len(armFpu))
	}
	wantArm := []string{"v0", "v1", "v2", "v3", "v4", "v5"}
	for i, w := range wantArm {
		if armFpu[i] != w {
			t.Errorf("ARM64 FPU arg[%d] = %s, want %s", i, armFpu[i], w)
		}
	}
	if ARM64FpuReturnRegName != "v0" {
		t.Errorf("ARM64 FPU return = %s, want v0", ARM64FpuReturnRegName)
	}

	// x86_64 FPU args.
	x64Fpu := X86FpuArgRegNames()
	if len(x64Fpu) != 6 {
		t.Fatalf("x86_64: want 6 FPU arg registers, got %d", len(x64Fpu))
	}
	wantX64 := []string{"xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6"}
	for i, w := range wantX64 {
		if x64Fpu[i] != w {
			t.Errorf("x86_64 FPU arg[%d] = %s, want %s", i, x64Fpu[i], w)
		}
	}
	if X86FpuReturnRegName != "xmm0" {
		t.Errorf("x86_64 FPU return = %s, want xmm0", X86FpuReturnRegName)
	}

	// DartFpuArgRegNames dispatch.
	if got := DartFpuArgRegNames(ArchARM64); len(got) != 6 || got[0] != "v0" {
		t.Errorf("DartFpuArgRegNames(ARM64) = %v, want v0..v5", got)
	}
	if got := DartFpuArgRegNames(ArchX86); len(got) != 6 || got[0] != "xmm1" {
		t.Errorf("DartFpuArgRegNames(x86) = %v, want xmm1..xmm6", got)
	}

	// FpuReturnRegName dispatch.
	if FpuReturnRegName(ArchARM64) != "v0" {
		t.Errorf("FpuReturnRegName(ARM64) = %s, want v0", FpuReturnRegName(ArchARM64))
	}
	if FpuReturnRegName(ArchX86) != "xmm0" {
		t.Errorf("FpuReturnRegName(x86) = %s, want xmm0", FpuReturnRegName(ArchX86))
	}
}
