package decompiler

import "testing"

// The three flag-setting compares, checked against how dart-lang/sdk's own
// ARM64 assembler defines them (assembler_arm64.h at 3.9.2):
//
//	cmp(rn, o) -> subs(ZR, rn, o)   flags from rn - o
//	cmn(rn, o) -> adds(ZR, rn, o)   flags from rn + o
//	tst(rn, o) -> ands(ZR, rn, o)   flags from rn & o
func lastCmpOf(t *testing.T, srcs ...string) ([2]string, bool) {
	t.Helper()
	fir := &FuncIR{FrameReg: arm64FrameReg, PoolReg: arm64PoolReg, ThreadReg: arm64ThreadReg}
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
