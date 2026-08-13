package decompiler

import (
	"fmt"
	"testing"

	"aotopsy/internal/disasm"
)

// stubPool stands in for the deserialized object pool. Index 6 is `sentinel`
// in every sample checked -- confirmed against the tool's own `_debug
// objects` dump on the Dart 3.10.7 x86_64 build, which prints
// `[pp+0x40] sentinel`. That dump uses UNTAGGED offsets (element 0 at 0x10),
// which is exactly the one-byte difference this test is about.
func stubPool(idx int) (string, bool) {
	switch idx {
	case 6:
		return `"sentinel"`, true
	case 708:
		return `"<Instance_2066>"`, true
	}
	return "", false
}

// x86_64 can compare directly against memory, so a pool entry is read
// without ever being loaded:
//
//	cmp eax, [r15+0x3f]
//
// That is not OpLoadPool, so it used to fall through operandExpr and render
// as the literal `pool[?]`, discarding an index the displacement already
// carried. 571 lines on a 400-function slice of the Dart 3.10.7 x86_64
// build; 229 of the 311 distinct sites are this one displacement, because
// comparing against the sentinel is how Dart checks a lazily-initialized
// static or a `late` field.
func TestPoolOperandResolvesWithoutALoad(t *testing.T) {
	x64 := &FuncIR{FrameReg: "rbp", PoolReg: x86PoolReg, ThreadReg: "r14",
		PoolIndexOf: disasm.X64PoolIndex}
	s := newLiftState("")
	s.Pool = stubPool
	s.Regs["eax"] = "eax"

	ApplyOther(x64, s, Instr{Src: "cmp eax, [r15+0x3f]"})
	if !s.HasCmp {
		t.Fatal("compare against a pool operand was not recorded")
	}
	if got := s.LastCmp[1]; got != `"sentinel"` {
		t.Errorf("pool operand should resolve to its contents, got %q", got)
	}
}

// The pool register is tagged on x86_64 and untagged on ARM64, so the same
// element sits at displacements one byte apart. Getting this wrong shifts
// every pool-derived fact by a constant number of slots -- invisible in
// aggregate, wrong in every individual line -- which is why each
// architecture supplies its own arithmetic rather than sharing a constant.
func TestPoolOperandTaggingDiffersPerArch(t *testing.T) {
	const wantIndex = 6
	if got, ok := disasm.X64PoolIndex(0x3f); !ok || got != wantIndex {
		t.Errorf("x86_64 (tagged PP): disp 0x3f should be index %d, got %d ok=%v", wantIndex, got, ok)
	}
	if got, ok := disasm.ARM64PoolIndex(0x40); !ok || got != wantIndex {
		t.Errorf("ARM64 (untagged PP): disp 0x40 should be index %d, got %d ok=%v", wantIndex, got, ok)
	}
	// And each must REJECT the other's displacement, or a mis-wired lifter
	// would silently read the neighbouring slot instead of failing.
	if _, ok := disasm.X64PoolIndex(0x40); ok {
		t.Error("x86_64 accepted an untagged displacement; it is not element-aligned there")
	}
	if _, ok := disasm.ARM64PoolIndex(0x3f); ok {
		t.Error("ARM64 accepted a tagged displacement; it is not element-aligned there")
	}
}

// Reporting a wrong index is worse than reporting none, so a displacement
// that cannot name an element must stay a placeholder rather than round to
// a neighbour.
func TestPoolOperandRefusesToGuess(t *testing.T) {
	x64 := &FuncIR{FrameReg: "rbp", PoolReg: x86PoolReg, PoolIndexOf: disasm.X64PoolIndex}
	cases := []struct{ name, src string }{
		{"not element-aligned", "cmp eax, [r15+0x3e]"},
		{"below the first element", "cmp eax, [r15+0x4]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newLiftState("")
			s.Pool = stubPool
			s.Regs["eax"] = "eax"
			ApplyOther(x64, s, Instr{Src: tc.src})
			if got := s.LastCmp[1]; got != "pool[?]" {
				t.Errorf("want the placeholder, got %q", got)
			}
		})
	}
}

// Without a pool -- unit tests, or an entry the deserializer could not
// resolve -- the index is still worth printing. It is a real fact about the
// instruction, and `pool[708]` can be looked up by hand where `pool[?]`
// cannot.
func TestPoolOperandKeepsIndexWhenContentsAreUnknown(t *testing.T) {
	x64 := &FuncIR{FrameReg: "rbp", PoolReg: x86PoolReg, PoolIndexOf: disasm.X64PoolIndex}
	// 0x1637 -> index 709, which stubPool does not know.
	s := newLiftState("")
	s.Pool = stubPool
	s.Regs["eax"] = "eax"
	ApplyOther(x64, s, Instr{Src: "cmp eax, [r15+0x1637]"})
	if got, want := s.LastCmp[1], fmt.Sprintf("pool[%d]", 709); got != want {
		t.Errorf("want %q, got %q", want, got)
	}

	// And with no pool at all.
	s2 := newLiftState("")
	s2.Regs["eax"] = "eax"
	ApplyOther(x64, s2, Instr{Src: "cmp eax, [r15+0x1637]"})
	if got, want := s2.LastCmp[1], "pool[709]"; got != want {
		t.Errorf("no pool: want %q, got %q", want, got)
	}
}

// ARM64 reaches pool entries only through a load, which is already
// OpLoadPool, so wiring PoolIndexOf there must not change any output. Both
// ARM64 samples were byte-identical across this change; this pins the
// reason rather than the observation.
func TestARM64PoolOperandUnaffected(t *testing.T) {
	arm := &FuncIR{FrameReg: arm64FrameReg, PoolReg: arm64PoolReg, ThreadReg: arm64ThreadReg,
		NullReg: arm64NullReg,
		PoolIndexOf: func(disp int64) (int, bool) {
			return disasm.ARM64PoolIndex(int(disp))
		}}
	s := newLiftState(arm.NullReg)
	s.Pool = stubPool
	s.Regs["x0"] = "x0"
	// A compare on ARM64 takes registers, never memory -- there is no shape
	// here that reads the pool inline.
	ApplyOther(arm, s, Instr{Src: "cmp x0, x1"})
	if s.LastCmp[1] == `"sentinel"` {
		t.Error("an ARM64 register compare must not resolve through the pool")
	}
}
