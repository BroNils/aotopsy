package decompiler

import (
	"strings"
	"testing"

	"aotopsy/internal/sdk"
)

// Write-barrier detection must distinguish the high-half HEAP_BITS mask from
// the low-half heap-base arithmetic used for pointer decompression.
func TestIsWriteBarrierCond(t *testing.T) {
	barrier := []string{
		// ARM64: HEAP_BITS (R28) mask test.
		"(x17 & THR.stack_limit & HEAP_BITS >> 32) == 0",
		"(x17 & sentinel & HEAP_BITS >> 32) == 0",
		"(x17 & x16 & HEAP_BITS >> 32) <= 0",
		"(false & local_m40 & HEAP_BITS >> 32) >= 0",
		// Dart <=2.13: R28 is the dedicated BARRIER_MASK register.
		"(x17 & BARRIER_MASK) == 0",
		// x86_64: THR.write_barrier_mask, when the scratch is forwarded into the
		// condition rather than materialized.
		"(value._tag & r11l >> 2 & THR.write_barrier_mask) == 0",
	}
	for _, c := range barrier {
		if !sdk.IsWriteBarrierCond(c) {
			t.Errorf("isWriteBarrierCond(%q) = false, want true", c)
		}
	}
	notBarrier := []string{
		"(obj + (HEAP_BITS << 32)) != null",
		"HEAP_BITS != 0",
		"x8 != null",
		"(x17 & arg1.f7.f11 - 1) <= arg2",
		"THR.stack_limit < SP",
		"",
	}
	for _, c := range notBarrier {
		if sdk.IsWriteBarrierCond(c) {
			t.Errorf("isWriteBarrierCond(%q) = true, want false", c)
		}
	}
}

// The x86_64 barrier materializes its scratch into a statement carrying the
// barrier-only THR.write_barrier_mask field; that statement is dropped.
func TestIsWriteBarrierStmt(t *testing.T) {
	drop := []string{
		"accumulator.f47 = r11l >> 2 & THR.write_barrier_mask;",
		"local_m40 = (r11l >> 2 & THR.write_barrier_mask) >> 2 & THR.write_barrier_mask;",
		"x16 = x17 & HEAP_BITS >> 32;",
		"x16 = x17 & BARRIER_MASK;",
	}
	for _, l := range drop {
		if !sdk.IsWriteBarrierStmt(l) {
			t.Errorf("isWriteBarrierStmt(%q) = false, want true", l)
		}
	}
	keep := []string{
		"x0 = x1 + (HEAP_BITS << 32);",
		"x0 = HEAP_BITS;",
		"accumulator.f47 = r11l >> 2;",
		"local_m8.f23 = bitField(arg2, 0, 32);",
		"return null;",
	}
	for _, l := range keep {
		if sdk.IsWriteBarrierStmt(l) {
			t.Errorf("isWriteBarrierStmt(%q) = true, want false", l)
		}
	}
}

func TestHeapBitsLeftShiftBranchIsNotElidedAsWriteBarrier(t *testing.T) {
	fir := newFuncIR("not_barrier", 0x1000)
	fir.DartVersion = "3.12.2"
	fir.ThreadReg = sdk.ARM64ThreadRegStr
	fir.PoolReg = sdk.ARM64PoolRegStr
	fir.ReturnReg = sdk.ARM64ReturnRegStr
	fir.HeapBitsReg = sdk.ARM64HeapBitsStr
	fir.addBlock(Block{ID: 0, StartVA: 0x1000, Instrs: []Instr{
		{Addr: 0x1000, Op: OpOther, Src: "sub x2, x1, x28, lsl #32"},
		{Addr: 0x1004, Op: OpOther, Src: "cmp x2, #0"},
		{Addr: 0x1008, Op: OpBranch, CondKind: "cmp", CondOp: "!="},
	}, Succs: []Succ{{BlockID: 1, Cond: "T"}, {BlockID: 2, Cond: "F"}}})
	fir.addBlock(Block{ID: 1, StartVA: 0x1010, Instrs: []Instr{
		{Addr: 0x1010, Op: OpOther, Src: "mov x0, #1"},
		{Addr: 0x1014, Op: OpReturn, Src: "ret"},
	}})
	fir.addBlock(Block{ID: 2, StartVA: 0x1020, Instrs: []Instr{
		{Addr: 0x1020, Op: OpOther, Src: "mov x0, #0"},
		{Addr: 0x1024, Op: OpReturn, Src: "ret"},
	}})

	src := EmitPseudocode(fir, nil, nil).Source
	if !strings.Contains(src, "if (") || !strings.Contains(src, "return 1;") || !strings.Contains(src, "return 0;") {
		t.Fatalf("HEAP_BITS left-shift branch was elided as GC bookkeeping:\n%s", src)
	}
}

// The stack-overflow recognizer must still require both the stack_limit field
// AND the stack pointer, so an ordinary THR-field compare is never elided.
func TestIsStackOverflowCond(t *testing.T) {
	if !sdk.IsStackOverflowCond("CMP SP, THR.stack_limit") {
		t.Error("prologue stack check should be recognized")
	}
	if sdk.IsStackOverflowCond("x0 < THR.stack_limit") {
		t.Error("a stack_limit compare without the stack pointer must NOT be elided")
	}
	if sdk.IsStackOverflowCond("x8 != null") {
		t.Error("ordinary condition must not be a stack check")
	}
}
