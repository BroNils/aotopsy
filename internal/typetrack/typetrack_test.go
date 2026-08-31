package typetrack

import (
	"testing"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/cluster"
)

func TestLatticeTop(t *testing.T) {
	x := Top()
	if x.Kind != LatticeTop {
		t.Fatalf("Top() kind = %d, want %d", x.Kind, LatticeTop)
	}
}

func TestLatticeBottom(t *testing.T) {
	x := Bottom()
	if x.Kind != LatticeBottom {
		t.Fatalf("Bottom() kind = %d, want %d", x.Kind, LatticeBottom)
	}
}

func TestLatticeKnownClass(t *testing.T) {
	x := KnownClass(42)
	if x.Kind != LatticeKnownClass || x.ClassID != 42 {
		t.Fatalf("KnownClass(42) = %+v", x)
	}
}

func TestLatticeKnownDispatch(t *testing.T) {
	x := KnownDispatch(7)
	if x.Kind != LatticeKnownDispatchIndex || x.DispatchIndex != 7 {
		t.Fatalf("KnownDispatch(7) = %+v", x)
	}
}

func TestLatticeKnownStub(t *testing.T) {
	x := KnownStub("AllocateObject", 0x220)
	if x.Kind != LatticeKnownStub || x.StubName != "AllocateObject" || x.StubOff != 0x220 {
		t.Fatalf("KnownStub(AllocateObject, 0x220) = %+v", x)
	}
}

func TestLatticeEqual(t *testing.T) {
	tests := []struct {
		a, b TypeLattice
		want bool
	}{
		{Top(), Top(), true},
		{Bottom(), Bottom(), true},
		{KnownClass(1), KnownClass(1), true},
		{KnownClass(1), KnownClass(2), false},
		{KnownDispatch(3), KnownDispatch(3), true},
		{KnownDispatch(3), KnownDispatch(4), false},
		{KnownStub("A", 0x220), KnownStub("A", 0x220), true},
		{KnownStub("A", 0x220), KnownStub("B", 0x228), false},
		{Top(), Bottom(), false},
		{KnownClass(1), KnownDispatch(1), false},
		{KnownClass(1), KnownStub("A", 0x220), false},
	}
	for _, tc := range tests {
		got := tc.a.Equal(tc.b)
		if got != tc.want {
			t.Errorf("%+v.Equal(%+v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestMeetTypeTop(t *testing.T) {
	// Top ∧ x = x
	x := KnownClass(5)
	got := meetType(Top(), x, nil)
	if !got.Equal(x) {
		t.Fatalf("Top ∧ KnownClass(5) = %+v, want %+v", got, x)
	}
	got = meetType(x, Top(), nil)
	if !got.Equal(x) {
		t.Fatalf("KnownClass(5) ∧ Top = %+v, want %+v", got, x)
	}
}

func TestMeetTypeBottom(t *testing.T) {
	// Bottom ∧ x = Bottom
	got := meetType(Bottom(), KnownClass(5), nil)
	if got.Kind != LatticeBottom {
		t.Fatalf("Bottom ∧ KnownClass(5) = %+v, want Bottom", got)
	}
}

func TestMeetTypeSameClass(t *testing.T) {
	// KnownClass(a) ∧ KnownClass(a) = KnownClass(a)
	got := meetType(KnownClass(3), KnownClass(3), nil)
	if !got.Equal(KnownClass(3)) {
		t.Fatalf("KnownClass(3) ∧ KnownClass(3) = %+v, want KnownClass(3)", got)
	}
}

func TestMeetTypeDifferentClassWithLCA(t *testing.T) {
	// KnownClass(2) ∧ KnownClass(3) with LCA(2,3)=1 → KnownClass(1)
	hierarchy := map[int]int{2: 1, 3: 1, 1: -1}
	lca := func(a, b int) int { return LCA(a, b, hierarchy) }
	got := meetType(KnownClass(2), KnownClass(3), lca)
	if !got.Equal(KnownClass(1)) {
		t.Fatalf("KnownClass(2) ∧ KnownClass(3) with LCA=1 = %+v, want KnownClass(1)", got)
	}
}

func TestMeetTypeDifferentClassNoLCA(t *testing.T) {
	// KnownClass(2) ∧ KnownClass(3) with no LCA → Bottom
	hierarchy := map[int]int{2: -1, 3: -1}
	lca := func(a, b int) int { return LCA(a, b, hierarchy) }
	got := meetType(KnownClass(2), KnownClass(3), lca)
	if got.Kind != LatticeBottom {
		t.Fatalf("KnownClass(2) ∧ KnownClass(3) with no LCA = %+v, want Bottom", got)
	}
}

func TestMeetTypeSameDispatch(t *testing.T) {
	got := meetType(KnownDispatch(5), KnownDispatch(5), nil)
	if !got.Equal(KnownDispatch(5)) {
		t.Fatalf("KnownDispatch(5) ∧ KnownDispatch(5) = %+v, want KnownDispatch(5)", got)
	}
}

func TestMeetTypeDifferentDispatch(t *testing.T) {
	got := meetType(KnownDispatch(5), KnownDispatch(6), nil)
	if got.Kind != LatticeBottom {
		t.Fatalf("KnownDispatch(5) ∧ KnownDispatch(6) = %+v, want Bottom", got)
	}
}

func TestMeetTypeMixedClassDispatch(t *testing.T) {
	got := meetType(KnownClass(1), KnownDispatch(1), nil)
	if got.Kind != LatticeBottom {
		t.Fatalf("KnownClass(1) ∧ KnownDispatch(1) = %+v, want Bottom", got)
	}
}

func TestMeetTypeKnownStub(t *testing.T) {
	// KnownStub ∧ KnownClass = Bottom
	got := meetType(KnownStub("AllocateObject", 0x220), KnownClass(5), nil)
	if got.Kind != LatticeBottom {
		t.Fatalf("KnownStub ∧ KnownClass(5) = %+v, want Bottom", got)
	}
	// H-1 fix: KnownStub ∧ KnownStub with SAME StubOff = KnownStub (not Bottom)
	got = meetType(KnownStub("AllocateObject", 0x220), KnownStub("AllocateObject", 0x220), nil)
	if got.Kind != LatticeKnownStub {
		t.Fatalf("KnownStub ∧ KnownStub (same) = %+v, want KnownStub", got)
	}
	// KnownStub ∧ KnownStub with DIFFERENT StubOff = Bottom
	got = meetType(KnownStub("AllocateObject", 0x220), KnownStub("AllocateArray", 0x2d8), nil)
	if got.Kind != LatticeBottom {
		t.Fatalf("KnownStub ∧ KnownStub (diff) = %+v, want Bottom", got)
	}
	got = meetType(Top(), KnownStub("AllocateObject", 0x220), nil)
	if !got.Equal(KnownStub("AllocateObject", 0x220)) {
		t.Fatalf("Top ∧ KnownStub = %+v, want KnownStub", got)
	}
}

func TestLCA(t *testing.T) {
	// Hierarchy: 4→3→2→1, 5→3→2→1
	hierarchy := map[int]int{4: 3, 5: 3, 3: 2, 2: 1, 1: -1}

	// LCA(4, 5) = 3
	if got := LCA(4, 5, hierarchy); got != 3 {
		t.Errorf("LCA(4,5) = %d, want 3", got)
	}
	// LCA(4, 3) = 3
	if got := LCA(4, 3, hierarchy); got != 3 {
		t.Errorf("LCA(4,3) = %d, want 3", got)
	}
	// LCA(4, 1) = 1
	if got := LCA(4, 1, hierarchy); got != 1 {
		t.Errorf("LCA(4,1) = %d, want 1", got)
	}
	// LCA(4, 4) = 4
	if got := LCA(4, 4, hierarchy); got != 4 {
		t.Errorf("LCA(4,4) = %d, want 4", got)
	}
}

func TestBuildClassHierarchy(t *testing.T) {
	classes := []cluster.ClassInfo{
		{RefID: 100, ClassID: 1, SuperTypeRefID: -1},
		{RefID: 101, ClassID: 2, SuperTypeRefID: 200}, // Type ref 200 → ClassID 1
		{RefID: 102, ClassID: 3, SuperTypeRefID: 201}, // Type ref 201 → ClassID 2
	}
	types := []cluster.TypeInfo{
		{RefID: 200, ClassID: 1},
		{RefID: 201, ClassID: 2},
	}

	hierarchy := BuildClassHierarchy(classes, types, nil)

	if hierarchy[1] != -1 {
		t.Errorf("hierarchy[1] = %d, want -1", hierarchy[1])
	}
	if hierarchy[2] != 1 {
		t.Errorf("hierarchy[2] = %d, want 1", hierarchy[2])
	}
	if hierarchy[3] != 2 {
		t.Errorf("hierarchy[3] = %d, want 2", hierarchy[3])
	}
}

func TestIsBLR(t *testing.T) {
	// BLR X16: 0xD63F0200
	// Encoding: 1101011|0|0|01|11111|0000|0|0|10000|00000
	// Rn = 16 (bits 5-9)
	raw := uint32(0xD63F0200)
	rn, ok := arm64.BLR(raw)
	if !ok || rn != 16 {
		t.Fatalf("isBLR(0x%x) = (%d, %v), want (16, true)", raw, rn, ok)
	}

	// Not a BLR
	raw = uint32(0x94000000) // BL
	_, ok = arm64.BLR(raw)
	if ok {
		t.Fatalf("isBLR(BL) should be false")
	}
}

func TestIsBL(t *testing.T) {
	// BL with imm26=1 → target = PC + 4
	raw := uint32(0x94000001)
	pc := uint64(0x1000)
	target, ok := arm64.BL(raw, pc)
	if !ok || target != 0x1004 {
		t.Fatalf("isBL(0x%x, 0x%x) = (0x%x, %v), want (0x1004, true)", raw, pc, target, ok)
	}
}

func TestIsLDR64UnsignedOffset(t *testing.T) {
	// LDR X0, [X27, #0] → pool index 0
	// Encoding: 11|111|0|01|01|000000000000|11011|00000
	// = 0xF9400000 | (27 << 5) = 0xF9400360
	raw := uint32(0xF9400360)
	baseReg, byteOff, ok := arm64.LDR64UnsignedOffset(raw)
	if !ok || baseReg != 27 || byteOff != 0 {
		t.Fatalf("isLDR64UnsignedOffset(0x%x) = (%d, %d, %v), want (27, 0, true)", raw, baseReg, byteOff, ok)
	}

	// LDR X1, [X27, #8] → pool index 1
	// imm12 = 1, so raw = 0xF9400000 | (1 << 10) | (27 << 5) | 1
	raw = uint32(0xF9400361) | (1 << 10)
	baseReg, byteOff, ok = arm64.LDR64UnsignedOffset(raw)
	if !ok || baseReg != 27 || byteOff != 8 {
		t.Fatalf("isLDR64UnsignedOffset(0x%x) = (%d, %d, %v), want (27, 8, true)", raw, baseReg, byteOff, ok)
	}
}

func TestIsADD64Immediate(t *testing.T) {
	// ADD X0, X21, #16 → slot 2 (16/8=2)
	// Encoding: sf=1|0|0|100010|00|000000010000|10101|00000
	// = 0x91000000 | (16 << 10) | (21 << 5) | 0
	raw := uint32(0x91000000) | (16 << 10) | (21 << 5)
	rd, rn, imm, ok := arm64.ADD64Immediate(raw)
	if !ok || rd != 0 || rn != 21 || imm != 16 {
		t.Fatalf("isADD64Immediate(0x%x) = (%d, %d, %d, %v), want (0, 21, 16, true)", raw, rd, rn, imm, ok)
	}
}

func TestIsLDUR64(t *testing.T) {
	// LDUR X0, [X1, #0]
	// Encoding: 11|111|0|00|01|000000000|00|00001|00000
	// = 0xF8400000 | (1 << 5)
	raw := uint32(0xF8400020)
	base, rt, _, ok := arm64.LDUR64(raw)
	if !ok || base != 1 || rt != 0 {
		t.Fatalf("isLDUR64(0x%x) = (%d, %d, %v), want (1, 0, true)", raw, base, rt, ok)
	}
}

func TestTypesEqual(t *testing.T) {
	a := [31]TypeLattice{}
	b := [31]TypeLattice{}
	for i := range a {
		a[i] = Top()
		b[i] = Top()
	}
	if !typesEqual(a, b) {
		t.Fatal("typesEqual(all-Top, all-Top) = false, want true")
	}

	b[0] = KnownClass(1)
	if typesEqual(a, b) {
		t.Fatal("typesEqual(all-Top, X0=KnownClass(1)) = true, want false")
	}
}

func TestAllTop(t *testing.T) {
	a := [31]TypeLattice{}
	for i := range a {
		a[i] = Top()
	}
	if !allTop(a) {
		t.Fatal("allTop(all-Top) = false, want true")
	}

	a[5] = KnownClass(1)
	if allTop(a) {
		t.Fatal("allTop(X5=KnownClass(1)) = true, want false")
	}
}
