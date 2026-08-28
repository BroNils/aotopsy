package decompiler

import (
	"testing"

	"aotopsy/internal/sdk"
)

// isWriteBarrierCond keys on HEAP_BITS (R28), which only ever holds the
// write-barrier mask -- so any branch condition mentioning it is the barrier
// check, regardless of the stale THR tokens the lifter folds in alongside.
func TestIsWriteBarrierCond(t *testing.T) {
	barrier := []string{
		// ARM64: HEAP_BITS (R28) mask test.
		"(x17 & THR.stack_limit & HEAP_BITS >> 32) == 0",
		"(x17 & sentinel & HEAP_BITS >> 32) == 0",
		"(x17 & x16 & HEAP_BITS >> 32) <= 0",
		"(false & local_m40 & HEAP_BITS >> 32) >= 0",
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
	}
	for _, l := range drop {
		if !sdk.IsWriteBarrierStmt(l) {
			t.Errorf("isWriteBarrierStmt(%q) = false, want true", l)
		}
	}
	keep := []string{
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
