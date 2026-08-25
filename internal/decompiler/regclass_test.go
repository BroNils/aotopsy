package decompiler

import (
	"strings"
	"testing"
)

// TestRegClassAllocationFieldTyping verifies that a field access on a freshly
// allocated object resolves to the object's real field name via the tracked
// register class (RegClass), and that a stale class never leaks: after the
// register is overwritten by an unrelated (non-allocation) call, the field name
// is NOT resolved from the old class.
func TestRegClassAllocationFieldTyping(t *testing.T) {
	fir := newFuncIR("build_thing", 0x1000)
	fir.ArgRegs = arm64ArgRegs
	fir.ReturnReg = arm64ReturnReg
	fir.FrameReg = arm64FrameReg
	fir.ClassNameToID = map[string]int{"Foo": 42}
	fir.FieldNameResolver = func(classID int, off int64) string {
		if classID == 42 && off == 8 {
			return "label"
		}
		return ""
	}

	fir.addBlock(Block{
		ID:      0,
		StartVA: 0x1000,
		Instrs: []Instr{
			{Addr: 0x1000, Op: OpCall, Src: "bl 0x9000", Target: "0x9000"}, // x0 = new Foo()
			{Addr: 0x1004, Op: OpOther, Src: "str x1, [x0, #8]"},           // x0.label = x1
			{Addr: 0x1008, Op: OpCall, Src: "bl 0x9100", Target: "0x9100"}, // x0 = other() -> class cleared
			{Addr: 0x100c, Op: OpOther, Src: "str x2, [x0, #8]"},           // x0.f8 (NOT label)
			{Addr: 0x1010, Op: OpReturn, Src: "ret"},
		},
	})

	symbols := func(va uint64) (string, bool) {
		switch va {
		case 0x9000:
			return "new Foo", true
		case 0x9100:
			return "makeBar", true
		}
		return "", false
	}

	art := EmitPseudocode(fir, symbols, nil)
	src := art.Source
	// The first offset-8 access resolves to the real field name via RegClass.
	if !strings.Contains(src, ".label = ") {
		t.Errorf("expected allocated-object field to resolve to .label, got:\n%s", src)
	}
	// It must appear exactly once: the SECOND offset-8 access (after x0 was
	// overwritten by a non-allocation call) must NOT reuse the stale class.
	if n := strings.Count(src, ".label"); n != 1 {
		t.Errorf("expected exactly one .label (no stale-class leak), got %d:\n%s", n, src)
	}
	// After the class is cleared, the offset-8 access stays the raw .f8 form.
	if !strings.Contains(src, ".f8 = ") {
		t.Errorf("expected unresolved .f8 after class cleared, got:\n%s", src)
	}
}
