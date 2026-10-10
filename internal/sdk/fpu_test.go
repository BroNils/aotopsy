package sdk

import "testing"

// TestFpuCallingConvention verifies the FPU argument and return register
// names against the Dart SDK's DartCallingConvention.
//
// Source: constants_arm64.h @3.12.2:
//
//	kFpuRegistersForArgs[] = {V0, V1, V2, V3, V4, V5}
//	kReturnFpuReg = V0
//
// Source: constants_x64.h @3.12.2:
//
//	kFpuRegistersForArgs[] = {XMM1, XMM2, XMM3, XMM4, XMM5, XMM6}
//	kReturnFpuReg = XMM0
func TestFpuCallingConvention(t *testing.T) {
	armCC, ok := DartRegisterCallingConvention("3.12.2", ArchARM64)
	if !ok {
		t.Fatal("3.12.2 ARM64 register calling convention unavailable")
	}
	// ARM64 FPU args.
	armFpu := armCC.FPUName
	if len(armFpu) != 6 {
		t.Fatalf("ARM64: want 6 FPU arg registers, got %d", len(armFpu))
	}
	wantArm := []string{"v0", "v1", "v2", "v3", "v4", "v5"}
	for i, w := range wantArm {
		if armFpu[i] != w {
			t.Errorf("ARM64 FPU arg[%d] = %s, want %s", i, armFpu[i], w)
		}
	}
	if armCC.FPUReturn != "v0" {
		t.Errorf("ARM64 FPU return = %s, want v0", armCC.FPUReturn)
	}

	x64CC, ok := DartRegisterCallingConvention("3.12.2", ArchX86)
	if !ok {
		t.Fatal("3.12.2 x86_64 register calling convention unavailable")
	}
	// x86_64 FPU args.
	x64Fpu := x64CC.FPUName
	if len(x64Fpu) != 6 {
		t.Fatalf("x86_64: want 6 FPU arg registers, got %d", len(x64Fpu))
	}
	wantX64 := []string{"xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6"}
	for i, w := range wantX64 {
		if x64Fpu[i] != w {
			t.Errorf("x86_64 FPU arg[%d] = %s, want %s", i, x64Fpu[i], w)
		}
	}
	if x64CC.FPUReturn != "xmm0" {
		t.Errorf("x86_64 FPU return = %s, want xmm0", x64CC.FPUReturn)
	}

	if _, ok := DartRegisterCallingConvention("3.3.0", ArchX86); ok {
		t.Error("3.3.0 must not expose FPU argument registers: Dart register CC does not exist yet")
	}
}
