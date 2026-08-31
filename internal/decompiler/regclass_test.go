package decompiler

import (
	"strings"
	"testing"

	"aotopsy/internal/sdk"
)

// TestRegClassAllocationFieldTyping verifies that a field access on a freshly
// allocated object resolves to the object's real field name via the tracked
// register class (RegClass), and that a stale class never leaks: after the
// register is overwritten by an unrelated (non-allocation) call, the field name
// is NOT resolved from the old class.
func TestRegClassAllocationFieldTyping(t *testing.T) {
	fir := newFuncIR("build_thing", 0x1000)
	fir.ArgRegs = arm64ArgRegs
	fir.ReturnReg = sdk.ARM64ReturnRegStr
	fir.FrameReg = sdk.ARM64FrameRegStr
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
			{Addr: 0x1004, Op: OpOther, Src: "str x1, [x0, #7]"},           // x0.label = x1
			{Addr: 0x1008, Op: OpCall, Src: "bl 0x9100", Target: "0x9100"}, // x0 = other() -> class cleared
			{Addr: 0x100c, Op: OpOther, Src: "str x2, [x0, #7]"},           // x0.f8 (NOT label)
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
	if !strings.Contains(src, ".f7 = ") {
		t.Errorf("expected unresolved .f7 after class cleared, got:\n%s", src)
	}
}

// TestRegClassFieldTypeChain verifies field-load chain typing: a field of the
// receiver whose declared type is another class lets the next field access on
// the loaded object resolve too (this.child.inner).
func TestRegClassFieldTypeChain(t *testing.T) {
	fir := newFuncIR("walk_chain", 0x2000)
	fir.ArgRegs = arm64ArgRegs
	fir.ReturnReg = sdk.ARM64ReturnRegStr
	fir.FrameReg = sdk.ARM64FrameRegStr
	fir.ReceiverClassID = 10
	fir.FieldNameResolver = func(classID int, off int64) string {
		switch {
		case classID == 10 && off == 8:
			return "child"
		case classID == 20 && off == 16:
			return "inner"
		}
		return ""
	}
	fir.FieldTypeResolver = func(classID int, off int64) int {
		if classID == 10 && off == 8 {
			return 20 // this.child is of class 20
		}
		return 0
	}

	fir.addBlock(Block{
		ID:      0,
		StartVA: 0x2000,
		Instrs: []Instr{
			{Addr: 0x2000, Op: OpOther, Src: "ldr x3, [x1, #7]"},  // x3 = this.child (class 20)
			{Addr: 0x2004, Op: OpOther, Src: "str x2, [x3, #15]"}, // x3.inner = x2
			{Addr: 0x2008, Op: OpReturn, Src: "ret"},
		},
	})

	art := EmitPseudocode(fir, nil, nil)
	src := art.Source
	if !strings.Contains(src, ".child") {
		t.Errorf("expected receiver field .child, got:\n%s", src)
	}
	if !strings.Contains(src, ".inner = ") {
		t.Errorf("expected chained field .inner resolved via field type, got:\n%s", src)
	}
}
