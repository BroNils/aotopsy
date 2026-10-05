package typetrack

import (
	"reflect"
	"testing"

	"aotopsy/internal/cluster"
)

// TestSelectorCandidatesRejectsSlotsOfOtherSelectorRows pins the dispatch-table
// row semantics of dispatch_table_generator.cc (SelectorRow::FillTable +
// RowFitter row displacement): slot imm+cid of a cid the row does not implement
// is usually another selector's entry and must not become a candidate.
func TestSelectorCandidatesRejectsSlotsOfOtherSelectorRows(t *testing.T) {
	ctx := minimalTypeContext()
	ctx.DispatchSlotMeta = map[int]DispatchSlotMeta{}
	// 1 = Object, 10 = A, 11 = B extends A, 12 = C extends Object (unrelated to A/B).
	ctx.SuperClass = map[int]int{1: -1, 10: 1, 11: 10, 12: 1}
	const imm = 100
	slot := func(cid, codeIdx int, name string, owner int, leaf string) {
		key := cid + imm
		ctx.DispatchBySlot[key] = cluster.DispatchTableEntry{Kind: cluster.DispatchCode, ClusterIndex: codeIdx}
		ctx.DispatchCodeIndexToName[codeIdx] = name
		ctx.DispatchSlotMeta[key] = DispatchSlotMeta{Owner: owner, Leaf: leaf}
	}
	// The real row: A.foo is inherited by B (no override), B.foo overrides for B.
	slot(10, 1, "A.foo", 10, "foo")
	slot(11, 2, "B.foo", 11, "foo")
	// Foreign slot, owner unrelated to the cid that would imply it (12): rejected by (1).
	slot(12, 3, "B.bar", 11, "bar")
	// Foreign slot whose owner is a legal ancestor (Object) but whose leaf is not
	// the row's: rejected by (2).
	slot(1, 4, "Object.baz", 1, "baz")

	got := ctx.selectorCandidates(imm)
	want := []string{"A.foo", "B.foo"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selectorCandidates(%d) = %v, want %v", imm, got, want)
	}
	if _, mono := ctx.SelectorMonomorphic[imm]; mono {
		t.Fatal("two implementations must not be recorded as monomorphic")
	}
}

// A row with one distinct implementation stays monomorphic even when the table
// holds other rows' slots around it.
func TestSelectorCandidatesSingleImplementationRowIsMonomorphic(t *testing.T) {
	ctx := minimalTypeContext()
	ctx.DispatchSlotMeta = map[int]DispatchSlotMeta{}
	ctx.SuperClass = map[int]int{1: -1, 10: 1, 11: 10, 12: 1}
	const imm = 50
	for _, cid := range []int{10, 11} {
		key := cid + imm
		ctx.DispatchBySlot[key] = cluster.DispatchTableEntry{Kind: cluster.DispatchCode, ClusterIndex: 7}
		ctx.DispatchSlotMeta[key] = DispatchSlotMeta{Owner: 10, Leaf: "only"}
	}
	ctx.DispatchCodeIndexToName[7] = "A.only"
	// Foreign slot at cid 12.
	ctx.DispatchBySlot[12+imm] = cluster.DispatchTableEntry{Kind: cluster.DispatchCode, ClusterIndex: 8}
	ctx.DispatchSlotMeta[12+imm] = DispatchSlotMeta{Owner: 10, Leaf: "other"}
	ctx.DispatchCodeIndexToName[8] = "A.other"

	got := ctx.selectorCandidates(imm)
	if !reflect.DeepEqual(got, []string{"A.only"}) {
		t.Fatalf("candidates = %v, want [A.only]", got)
	}
	if ctx.SelectorMonomorphic[imm] != "A.only" {
		t.Fatalf("SelectorMonomorphic = %v", ctx.SelectorMonomorphic)
	}
}
