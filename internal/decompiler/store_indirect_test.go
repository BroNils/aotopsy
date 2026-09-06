package decompiler

import (
	"strings"
	"testing"

	"aotopsy/internal/sdk"
)

// TestNoDisplacementStoreIsADereference pins the rendering of `str src, [base]`.
//
// `str x1, [x0]` is exactly `str x1, [x0, #0]`: it writes to the memory at the
// address in x0. It does NOT rebind whatever variable holds that address. The
// displaced form already went through fieldExpr and rendered as `base.f0`,
// while the undisplaced form fell through to `lhs = baseExpr` and rendered as
// `base = value;` -- one machine operation, two renderings, one of them stating
// a different operation.
//
// The full-corpus sweep found it as `assign-to-final`, but only because the
// pointer often lives in a call temp (`final t35 = f();`). Where it lived in an
// ordinary register the output was equally wrong and said nothing, which is why
// this test checks the rendering rather than the validity.
func TestNoDisplacementStoreIsADereference(t *testing.T) {
	fir := &FuncIR{
		FrameReg:  sdk.ARM64FrameRegStr,
		PoolReg:   sdk.ARM64PoolRegStr,
		ThreadReg: sdk.ARM64ThreadRegStr,
		NullReg:   sdk.ARM64NullRegStr,
		StackReg:  sdk.ARM64StackRegStr,
	}
	s := newLiftState(fir.NullReg)
	// x0 holds a value the emitter would have named -- a call temp is the case
	// that produced invalid Dart.
	s.setReg("x0", "t35")
	s.setReg("x1", "7")

	line, ok := ApplyOther(fir, s, Instr{Src: "str x1, [x0]"})
	if !ok {
		t.Fatal("store emitted no line")
	}
	if strings.HasPrefix(strings.TrimSpace(line), "t35 =") {
		t.Errorf("store through a pointer rendered as a rebinding: %q", line)
	}
	if !strings.HasPrefix(strings.TrimSpace(line), "t35.") {
		t.Errorf("store through a pointer should address the pointee, got %q", line)
	}
}

// TestNoDisplacementMatchesExplicitZero is the invariant behind the fix: the
// assembler writing `#0` or omitting it cannot change what the store means, so
// it must not change how it reads.
func TestNoDisplacementMatchesExplicitZero(t *testing.T) {
	build := func() (*FuncIR, *LiftState) {
		fir := &FuncIR{
			FrameReg:  sdk.ARM64FrameRegStr,
			PoolReg:   sdk.ARM64PoolRegStr,
			ThreadReg: sdk.ARM64ThreadRegStr,
			NullReg:   sdk.ARM64NullRegStr,
			StackReg:  sdk.ARM64StackRegStr,
		}
		s := newLiftState(fir.NullReg)
		s.setReg("x0", "obj")
		s.setReg("x1", "7")
		return fir, s
	}

	fir, s := build()
	bare, okBare := ApplyOther(fir, s, Instr{Src: "str x1, [x0]"})
	fir, s = build()
	zero, okZero := ApplyOther(fir, s, Instr{Src: "str x1, [x0, #0]"})

	if !okBare || !okZero {
		t.Fatalf("stores emitted no line (bare=%v zero=%v)", okBare, okZero)
	}
	if bare != zero {
		t.Errorf("[x0] and [x0, #0] render differently:\n  [x0]     = %q\n  [x0, #0] = %q", bare, zero)
	}
}
