package sdk

import "testing"

func TestDartArgRegisters(t *testing.T) {
	arm := DartArgRegisters(ArchARM64)
	if len(arm) != 6 {
		t.Fatalf("ARM64: want 6 arg registers, got %d", len(arm))
	}
	if arm[0] != 1 {
		t.Errorf("ARM64 arg0 = %d, want 1 (R1, NOT R0=kClassIdReg)", arm[0])
	}
	// R4 = ARGS_DESC_REG must NOT be in the arg list.
	for _, r := range arm {
		if r == 0 || r == 4 {
			t.Errorf("ARM64: R%d is not an argument register (R0=kClassIdReg, R4=ARGS_DESC_REG)", r)
		}
	}

	x64 := DartArgRegisters(ArchX86)
	if len(x64) != 6 {
		t.Fatalf("x86_64: want 6 arg registers, got %d", len(x64))
	}
	// RCX (canonical 1) is kClassIdReg, NOT an argument register.
	for _, r := range x64 {
		if r == 1 {
			t.Errorf("x86_64: RCX (canonical %d) is kClassIdReg, not an argument register", r)
		}
	}
}

func TestDartArgRegNames(t *testing.T) {
	arm := DartArgRegNames(ArchARM64)
	if arm[0] != "x1" {
		t.Errorf("ARM64 arg0 name = %q, want x1", arm[0])
	}
	x64 := DartArgRegNames(ArchX86)
	if x64[0] != "rdi" {
		t.Errorf("x86_64 arg0 name = %q, want rdi", x64[0])
	}
	if x64[3] != "rbx" {
		t.Errorf("x86_64 arg3 name = %q, want rbx (NOT rcx=kClassIdReg)", x64[3])
	}
}

func TestIsWriteBarrierCond(t *testing.T) {
	cases := map[string]bool{
		"(x17 & HEAP_BITS >> 32) == 0":      true,
		"(v & THR.write_barrier_mask) == 0": true,
		"x8 != null":                        false,
		"THR.stack_limit < SP":              false,
		"":                                  false,
	}
	for cond, want := range cases {
		if got := IsWriteBarrierCond(cond); got != want {
			t.Errorf("IsWriteBarrierCond(%q) = %v, want %v", cond, got, want)
		}
	}
}

func TestIsStackOverflowCond(t *testing.T) {
	if !IsStackOverflowCond("CMP SP, THR.stack_limit") {
		t.Error("prologue stack check should be recognized")
	}
	if IsStackOverflowCond("x0 < THR.stack_limit") {
		t.Error("stack_limit without stack pointer must NOT be elided")
	}
	if IsStackOverflowCond("(x17 & HEAP_BITS >> 32) == 0") {
		t.Error("write-barrier condition must not be a stack-overflow check")
	}
}

func TestCachedVMObjectValue(t *testing.T) {
	if v, ok := CachedVMObjectValue("object_null"); !ok || v != "null" {
		t.Errorf("object_null = %q ok=%v, want null true", v, ok)
	}
	if v, ok := CachedVMObjectValue("bool_true"); !ok || v != "true" {
		t.Errorf("bool_true = %q ok=%v, want true true", v, ok)
	}
	if _, ok := CachedVMObjectValue("stack_limit"); ok {
		t.Error("stack_limit is not a cached VM object")
	}
}

func TestStackSlotName(t *testing.T) {
	if got := StackSlotName(0); got != "stack_sp" {
		t.Errorf("StackSlotName(0) = %q, want stack_sp", got)
	}
	if got := StackSlotName(8); got != "stack_p8" {
		t.Errorf("StackSlotName(8) = %q, want stack_p8", got)
	}
	if got := StackSlotName(-16); got != "stack_m16" {
		t.Errorf("StackSlotName(-16) = %q, want stack_m16", got)
	}
}

func TestARM64RegName(t *testing.T) {
	if got := ARM64RegName(27); got != "x27" {
		t.Errorf("ARM64RegName(27) = %q, want x27", got)
	}
	if got := ARM64RegName(28); got != "x28" {
		t.Errorf("ARM64RegName(28) = %q, want x28", got)
	}
	if got := ARM64RegName(-1); got != "" {
		t.Errorf("ARM64RegName(-1) = %q, want empty", got)
	}
}

func TestIsARM64PointerDecompression(t *testing.T) {
	if !IsARM64PointerDecompression("x28", "lsl #32") {
		t.Error("x28 lsl #32 should be decompression")
	}
	if IsARM64PointerDecompression("x28", "lsl #16") {
		t.Error("x28 lsl #16 is NOT decompression")
	}
	if IsARM64PointerDecompression("x27", "lsl #32") {
		t.Error("x27 is not HEAP_BITS")
	}
}

func TestIsX86PointerDecompression(t *testing.T) {
	fields := map[int64]string{0x58: "heap_base", 0x60: "stack_limit"}
	if !IsX86PointerDecompression("r14", 0x58, fields) {
		t.Error("r14+heap_base should be decompression")
	}
	if IsX86PointerDecompression("r14", 0x60, fields) {
		t.Error("r14+stack_limit is NOT decompression")
	}
	if IsX86PointerDecompression("r15", 0x58, fields) {
		t.Error("r15 is not THR")
	}
}

func TestBoolFromNullOffset(t *testing.T) {
	if v, ok := BoolFromNullOffset(32); !ok || v != "true" {
		t.Errorf("offset 32 = %q ok=%v, want true true", v, ok)
	}
	if v, ok := BoolFromNullOffset(48); !ok || v != "false" {
		t.Errorf("offset 48 = %q ok=%v, want false true", v, ok)
	}
	if _, ok := BoolFromNullOffset(16); ok {
		t.Error("offset 16 is not a bool")
	}
}
