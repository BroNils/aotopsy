package typetrack

import (
	"testing"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/cluster"
)

func TestLatticeConstructors(t *testing.T) {
	tests := []struct {
		name string
		got  TypeLattice
		kind TypeLatticeKind
		cid  int
	}{
		{"top", Top(), LatticeTop, 0},
		{"bottom", Bottom(), LatticeBottom, 0},
		{"exact object", ExactClass(42), LatticeExactClass, 42},
		{"class bound", ClassBound(42), LatticeClassBound, 42},
		{"exact header", ExactHeaderTags(42), LatticeExactHeaderTags, 42},
		{"unknown header", UnknownHeaderTags(), LatticeUnknownHeaderTags, 0},
		{"exact cid", ExactClassID(42), LatticeExactClassID, 42},
		{"unknown cid", UnknownClassID(), LatticeUnknownClassID, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got.Kind != tc.kind || tc.got.ClassID != tc.cid {
				t.Fatalf("constructor = %+v, want kind=%v cid=%d", tc.got, tc.kind, tc.cid)
			}
		})
	}

	d := KnownDispatch(7)
	if d.Kind != LatticeKnownDispatchIndex || d.DispatchIndex != 7 || d.SelectorOnly {
		t.Fatalf("KnownDispatch(7) = %+v", d)
	}
	s := SelectorDispatch(-11, 0)
	if s.Kind != LatticeKnownDispatchIndex || !s.SelectorOnly || s.SelectorImm != -11 {
		t.Fatalf("SelectorDispatch(-11) = %+v", s)
	}
	stub := KnownStub("AllocateObject", 0x220)
	if stub.Kind != LatticeKnownStub || stub.StubName != "AllocateObject" || stub.StubOff != 0x220 {
		t.Fatalf("KnownStub = %+v", stub)
	}
}

func TestLatticeEqualDistinguishesSemanticKinds(t *testing.T) {
	tests := []struct {
		a, b TypeLattice
		want bool
	}{
		{Top(), Top(), true},
		{Bottom(), Bottom(), true},
		{ExactClass(1), ExactClass(1), true},
		{ExactClass(1), ExactClass(2), false},
		{ExactClass(1), ClassBound(1), false},
		{ExactClassID(1), ExactClassID(1), true},
		{ExactClassID(1), ExactClass(1), false},
		{UnknownClassID(), UnknownClassID(), true},
		{KnownDispatch(3), KnownDispatch(3), true},
		{KnownDispatch(3), SelectorDispatch(3, 0), false},
		{KnownStub("A", 0x220), KnownStub("A", 0x220), true},
		{KnownStub("A", 0x220), KnownStub("B", 0x228), false},
		{TypeLattice{Kind: LatticePPBase, PPBaseOffset: 16}, TypeLattice{Kind: LatticePPBase, PPBaseOffset: 16}, true},
		{TypeLattice{Kind: LatticePPBase, PPBaseOffset: 16}, TypeLattice{Kind: LatticePPBase, PPBaseOffset: 24}, false},
	}
	for _, tc := range tests {
		if got := tc.a.Equal(tc.b); got != tc.want {
			t.Errorf("%+v.Equal(%+v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestParamTypeMapsCompareAcrossIterations(t *testing.T) {
	var a [31]TypeLattice
	var b [31]TypeLattice
	a[1] = ExactClass(42)
	b[1] = ExactClass(42)
	one := map[string][31]TypeLattice{"callee": a}
	two := map[string][31]TypeLattice{"callee": b}
	if !paramTypeMapsEqual(one, two) {
		t.Fatal("identical propagated parameter maps must converge")
	}
	b[1] = ClassBound(42)
	two["callee"] = b
	if paramTypeMapsEqual(one, two) {
		t.Fatal("semantic kind change was treated as converged")
	}
	if clone := cloneParamTypeMap(one); !paramTypeMapsEqual(one, clone) {
		t.Fatal("cloned parameter map changed value")
	}
}

func TestJoinBottomIsUnreachableIdentity(t *testing.T) {
	x := ExactClass(5)
	if got := joinType(Bottom(), x, nil); !got.Equal(x) {
		t.Fatalf("Bottom join exact object = %+v, want %+v", got, x)
	}
	if got := joinType(x, Bottom(), nil); !got.Equal(x) {
		t.Fatalf("exact object join Bottom = %+v, want %+v", got, x)
	}
}

func TestJoinTopIsReachableUnknown(t *testing.T) {
	if got := joinType(Top(), ExactClass(5), nil); got.Kind != LatticeTop {
		t.Fatalf("Top join exact object = %+v, want Top", got)
	}
	if got := joinType(KnownStub("A", 1), Top(), nil); got.Kind != LatticeTop {
		t.Fatalf("stub join Top = %+v, want Top", got)
	}
}

func TestJoinObjectFactsUseBoundsAndLCA(t *testing.T) {
	hierarchy := map[int]int{4: 3, 5: 3, 3: 2, 2: 1, 1: -1}
	lca := func(a, b int) int { return LCA(a, b, hierarchy) }

	if got := joinType(ExactClass(4), ExactClass(4), lca); !got.Equal(ExactClass(4)) {
		t.Fatalf("same exact object join = %+v", got)
	}
	if got := joinType(ExactClass(4), ExactClass(5), lca); !got.Equal(ClassBound(3)) {
		t.Fatalf("sibling exact objects join = %+v, want Bound(3)", got)
	}
	if got := joinType(ExactClass(4), ClassBound(3), lca); !got.Equal(ClassBound(3)) {
		t.Fatalf("exact subclass + bound join = %+v, want Bound(3)", got)
	}
	noCommon := func(int, int) int { return -1 }
	if got := joinType(ExactClass(4), ExactClass(5), noCommon); got.Kind != LatticeTop {
		t.Fatalf("objects with no representable common bound = %+v, want Top", got)
	}
}

func TestJoinClassIDFactsNeverBecomeObjectFacts(t *testing.T) {
	if got := joinType(ExactClassID(7), ExactClassID(7), nil); !got.Equal(ExactClassID(7)) {
		t.Fatalf("same exact CID join = %+v", got)
	}
	if got := joinType(ExactClassID(7), ExactClassID(8), nil); got.Kind != LatticeUnknownClassID {
		t.Fatalf("different exact CIDs join = %+v, want UnknownClassID", got)
	}
	if got := joinType(ExactClassID(7), ExactClass(7), nil); got.Kind != LatticeTop {
		t.Fatalf("CID scalar + heap object join = %+v, want Top", got)
	}
}

func TestJoinNonClassFactsConflictToTop(t *testing.T) {
	if got := joinType(KnownDispatch(5), KnownDispatch(6), nil); got.Kind != LatticeTop {
		t.Fatalf("different dispatch facts = %+v, want Top", got)
	}
	if got := joinType(KnownStub("A", 1), KnownStub("B", 2), nil); got.Kind != LatticeTop {
		t.Fatalf("different stubs = %+v, want Top", got)
	}
	if got := joinType(KnownStub("A", 1), KnownStub("A", 1), nil); !got.Equal(KnownStub("A", 1)) {
		t.Fatalf("same stub join = %+v", got)
	}
}

func TestLCA(t *testing.T) {
	hierarchy := map[int]int{4: 3, 5: 3, 3: 2, 2: 1, 1: -1}
	for _, tc := range []struct{ a, b, want int }{{4, 5, 3}, {4, 3, 3}, {4, 1, 1}, {4, 4, 4}} {
		if got := LCA(tc.a, tc.b, hierarchy); got != tc.want {
			t.Errorf("LCA(%d,%d) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestBuildClassHierarchy(t *testing.T) {
	classes := []cluster.ClassInfo{
		{RefID: 100, ClassID: 1, SuperTypeRefID: -1},
		{RefID: 101, ClassID: 2, SuperTypeRefID: 200},
		{RefID: 102, ClassID: 3, SuperTypeRefID: 201},
	}
	types := []cluster.TypeInfo{{RefID: 200, ClassID: 1}, {RefID: 201, ClassID: 2}}
	hierarchy := BuildClassHierarchy(classes, types)
	if hierarchy[1] != -1 || hierarchy[2] != 1 || hierarchy[3] != 2 {
		t.Fatalf("hierarchy = %v", hierarchy)
	}
}

func TestARM64DecoderPrimitives(t *testing.T) {
	rn, ok := arm64.BLR(0xD63F0200)
	if !ok || rn != 16 {
		t.Fatalf("BLR decode = (%d,%v), want (16,true)", rn, ok)
	}
	if _, ok := arm64.BLR(0x94000000); ok {
		t.Fatal("BL decoded as BLR")
	}
	target, ok := arm64.BL(0x94000001, 0x1000)
	if !ok || target != 0x1004 {
		t.Fatalf("BL target = %#x,%v", target, ok)
	}
	base, off, ok := arm64.LDR64UnsignedOffset(0xF9400360)
	if !ok || base != 27 || off != 0 {
		t.Fatalf("LDR decode = base=%d off=%d ok=%v", base, off, ok)
	}
	raw := uint32(0x91000000) | (16 << 10) | (21 << 5)
	rd, rn2, imm, ok := arm64.ADD64Immediate(raw)
	if !ok || rd != 0 || rn2 != 21 || imm != 16 {
		t.Fatalf("ADD decode = rd=%d rn=%d imm=%d ok=%v", rd, rn2, imm, ok)
	}
}

func TestTypesEqual(t *testing.T) {
	a := [31]TypeLattice{}
	b := [31]TypeLattice{}
	for i := range a {
		a[i], b[i] = Top(), Top()
	}
	if !typesEqual(a, b) {
		t.Fatal("identical arrays compare unequal")
	}
	b[0] = ExactClass(1)
	if typesEqual(a, b) {
		t.Fatal("different arrays compare equal")
	}
}
