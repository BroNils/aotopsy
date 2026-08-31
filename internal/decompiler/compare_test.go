package decompiler

import (
	"testing"

	"aotopsy/internal/sdk"
)

// The three flag-setting compares, checked against how dart-lang/sdk's own
// ARM64 assembler defines them (assembler_arm64.h at 3.9.2):
//
//	cmp(rn, o) -> subs(ZR, rn, o)   flags from rn - o
//	cmn(rn, o) -> adds(ZR, rn, o)   flags from rn + o
//	tst(rn, o) -> ands(ZR, rn, o)   flags from rn & o
func lastCmpOf(t *testing.T, srcs ...string) ([2]string, bool) {
	t.Helper()
	fir := &FuncIR{FrameReg: sdk.ARM64FrameRegStr, PoolReg: sdk.ARM64PoolRegStr, ThreadReg: sdk.ARM64ThreadRegStr}
	s := newLiftState("")
	for _, src := range srcs {
		ApplyOther(fir, s, Instr{Src: src})
	}
	return s.LastCmp, s.HasCmp
}

// Regression: TST computes `a & b`. Storing [a, "0"] is only correct for the
// self-test idiom, and on this corpus that idiom is the rare case -- 878 of
// 878 ARM64 TST instructions have distinct operands. The second operand was
// dropped almost everywhere.
func TestTstUsesBothOperands(t *testing.T) {
	got, ok := lastCmpOf(t, "tst x16, x28")
	if !ok {
		t.Fatal("HasCmp = false for a plain tst")
	}
	if got[0] != "(x16 & x28)" || got[1] != "0" {
		t.Errorf("tst x16, x28 -> %q == %q, want %q == %q", got[0], got[1], "(x16 & x28)", "0")
	}
}

// The self-test idiom stays readable: `x & x` is zero exactly when x is.
func TestTstSelfTestStaysSimple(t *testing.T) {
	got, _ := lastCmpOf(t, "tst x3, x3")
	if got[0] != "x3" || got[1] != "0" {
		t.Errorf("tst x3, x3 -> %q == %q, want %q == %q", got[0], got[1], "x3", "0")
	}
}

// The shifted-register operand form, which is the majority of TST on this
// corpus (468 of 878). `TST X16, X28, LSR #32` is the write-barrier check:
// HEAP_BITS >> 32 is the write_barrier_mask.
func TestTstAppliesShiftedOperand(t *testing.T) {
	got, ok := lastCmpOf(t, "tst x16, x28, lsr #32")
	if !ok {
		t.Fatal("HasCmp = false for a shifted tst")
	}
	if got[0] != "(x16 & (x28 >> 32))" {
		t.Errorf("tst x16, x28, lsr #32 -> %q, want %q", got[0], "(x16 & (x28 >> 32))")
	}
}

// CMP's shifted operand was dropped too -- 152 occurrences in the 3.x sample.
func TestCmpAppliesShiftedOperand(t *testing.T) {
	got, ok := lastCmpOf(t, "cmp x0, x1, asr #2")
	if !ok {
		t.Fatal("HasCmp = false for a shifted cmp")
	}
	if got[0] != "x0" || got[1] != "(x1 >> 2)" {
		t.Errorf("cmp x0, x1, asr #2 -> %q == %q, want %q == %q", got[0], got[1], "x0", "(x1 >> 2)")
	}
}

// CMN takes its flags from rn + o, so equality means rn == -o. Sharing the
// cmp path reported the wrong sign.
func TestCmnNegatesItsOperand(t *testing.T) {
	got, _ := lastCmpOf(t, "cmn x0, x1")
	if got[1] != "-x1" {
		t.Errorf("cmn x0, x1 -> %q == %q, want rhs %q", got[0], got[1], "-x1")
	}
	lit, _ := lastCmpOf(t, "cmn x0, #8")
	if lit[1] != "-8" {
		t.Errorf("cmn x0, #8 -> rhs %q, want %q", lit[1], "-8")
	}
}

// An operand suffix that is not a renderable shift must clear HasCmp, so the
// emitter prints its placeholder rather than a condition missing a term.
func TestUnrenderableOperandSuffixSuppressesCondition(t *testing.T) {
	for _, src := range []string{"tst x0, x1, ror #4", "cmp x0, x1, uxtb"} {
		if _, ok := lastCmpOf(t, src); ok {
			t.Errorf("%q should not produce a usable condition", src)
		}
	}
}

// The x86_64 two-operand forms go through the same code.
func TestX86TestUsesBothOperands(t *testing.T) {
	got, ok := lastCmpOf(t, "test rax, rbx")
	if !ok {
		t.Fatal("HasCmp = false for test rax, rbx")
	}
	if got[0] != "(rax & rbx)" {
		t.Errorf("test rax, rbx -> %q, want %q", got[0], "(rax & rbx)")
	}
	self, _ := lastCmpOf(t, "test rax, rax")
	if self[0] != "rax" || self[1] != "0" {
		t.Errorf("test rax, rax -> %q == %q, want %q == %q", self[0], self[1], "rax", "0")
	}
}

// Compressed-pointer decompression is a mechanical artifact with no source
// counterpart, and it was the single largest source of noise in either
// architecture's output: 33264 `+ (x28 << 32)` on 3.x ARM64 and 47041
// `+ THR.heap_base` on x86_64.
//
// dart-lang/sdk emits both from inside `#if defined(DART_COMPRESSED_POINTERS)`:
//
//	assembler_arm64.h  add(dst, dst, Operand(HEAP_BITS, LSL, 32))
//	assembler_x64.cc   movl(dest, slot); addq(dest, Address(THR, heap_base_offset()))
func TestPointerDecompressionIsElided(t *testing.T) {
	arm := &FuncIR{FrameReg: sdk.ARM64FrameRegStr, PoolReg: sdk.ARM64PoolRegStr, ThreadReg: sdk.ARM64ThreadRegStr,
		NullReg: sdk.ARM64NullRegStr, HeapBitsReg: sdk.ARM64HeapBitsStr}
	s := newLiftState(arm.NullReg)
	ApplyOther(arm, s, Instr{Src: "add x0, x1, x28, lsl #32"})
	if got := s.lookupReg("x0"); got != "x1" {
		t.Errorf("ARM64 decompression should render as the operand alone, got %q", got)
	}

	x64 := &FuncIR{FrameReg: sdk.X86FrameRegStr, PoolReg: sdk.X86PoolRegStr, ThreadReg: sdk.X86ThreadRegStr,
		ThreadFieldNames: map[int64]string{0x68: "heap_base"}}
	sx := newLiftState("")
	sx.Regs["rax"] = "obj"
	ApplyOther(x64, sx, Instr{Src: "add rax, [r14+0x68]"})
	if got := sx.lookupReg("rax"); got != "obj" {
		t.Errorf("x86_64 decompression should leave the operand alone, got %q", got)
	}
}

// A shift that is not by 32, or a Thread field that is not heap_base, is
// ordinary arithmetic and must survive.
func TestNonDecompressionAddsSurvive(t *testing.T) {
	arm := &FuncIR{FrameReg: sdk.ARM64FrameRegStr, PoolReg: sdk.ARM64PoolRegStr, ThreadReg: sdk.ARM64ThreadRegStr,
		NullReg: sdk.ARM64NullRegStr, HeapBitsReg: sdk.ARM64HeapBitsStr}
	s := newLiftState(arm.NullReg)
	ApplyOther(arm, s, Instr{Src: "add x0, x1, x28, lsl #16"})
	if got := s.lookupReg("x0"); got == "x1" {
		t.Errorf("a shift by 16 is not decompression, got %q", got)
	}
	ApplyOther(arm, s, Instr{Src: "add x2, x1, x3, lsl #32"})
	if got := s.lookupReg("x2"); got == "x1" {
		t.Errorf("only the heap-bits register marks decompression, got %q", got)
	}

	x64 := &FuncIR{FrameReg: sdk.X86FrameRegStr, PoolReg: sdk.X86PoolRegStr, ThreadReg: sdk.X86ThreadRegStr,
		ThreadFieldNames: map[int64]string{0x68: "heap_base", 0x70: "stack_limit"}}
	sx := newLiftState("")
	sx.Regs["rax"] = "obj"
	ApplyOther(x64, sx, Instr{Src: "add rax, [r14+0x70]"})
	if got := sx.lookupReg("rax"); got == "obj" {
		t.Errorf("adding a non-heap_base Thread field is real arithmetic, got %q", got)
	}
}

// A displacement off the Dart stack pointer addresses a STACK SLOT, not a
// field. The SDK names the register SPREG -- R15 on ARM64 ("SP in Dart code"
// in constants_arm64.h), RSP on x86_64 -- and the output was claiming field
// stores on it: `x15.m16 = framePointer`, `rsp.f8`, and even `rsp._tag`,
// which asserts an object header the stack pointer does not have. 4588 such
// renderings on the 3.x ARM64 sample and 5150 on x86_64.
func TestStackSlotsAreNotFields(t *testing.T) {
	arm := &FuncIR{FrameReg: sdk.ARM64FrameRegStr, PoolReg: sdk.ARM64PoolRegStr, ThreadReg: sdk.ARM64ThreadRegStr,
		NullReg: sdk.ARM64NullRegStr, HeapBitsReg: sdk.ARM64HeapBitsStr, StackReg: sdk.ARM64StackRegStr}
	s := newLiftState(arm.NullReg)
	ApplyOther(arm, s, Instr{Src: "ldr x0, [x15, #8]"})
	if got := s.lookupReg("x0"); got != "stack_p8" {
		t.Errorf("ARM64 stack load = %q, want %q", got, "stack_p8")
	}
	line, ok := ApplyOther(arm, s, Instr{Src: "str x1, [x15, #-16]"})
	if !ok || line != "stack_m16 = x1;" {
		t.Errorf("ARM64 stack store = %q (ok=%v), want %q", line, ok, "stack_m16 = x1;")
	}

	x64 := &FuncIR{FrameReg: sdk.X86FrameRegStr, PoolReg: sdk.X86PoolRegStr, ThreadReg: sdk.X86ThreadRegStr, StackReg: sdk.X86StackRegStr}
	sx := newLiftState("")
	ApplyOther(x64, sx, Instr{Src: "mov rax, [rsp+0x8]"})
	if got := sx.lookupReg("rax"); got != "stack_p8" {
		t.Errorf("x86_64 stack load = %q, want %q", got, "stack_p8")
	}
	// -1 is the object-header offset for real objects; the stack pointer has
	// no header, so it must not render as ._tag.
	ApplyOther(x64, sx, Instr{Src: "mov rcx, [rsp-0x1]"})
	if got := sx.lookupReg("rcx"); got != "stack_m1" {
		t.Errorf("x86_64 [rsp-1] = %q, want %q -- never ._tag", got, "stack_m1")
	}
}
