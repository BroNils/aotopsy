package typetrack

import (
	"reflect"
	"testing"

	"aotopsy/internal/cluster"
)

// Row displacement packs selector rows into each other's holes, so the slots at
// `imm + cid` over ALL cids mix several selectors. Electing the row leaf over
// every cid lets the selector with the most slots win; the receiver's own slot
// belongs to its selector by construction. Measured on the 3.9.2 sample: a
// String receiver's call came back as `PointerEvent.get:pointer`.
func boundContext() *TypeContext {
	ctx := minimalTypeContext()
	ctx.DispatchSlotMeta = map[int]DispatchSlotMeta{}
	// 1 Object; 20 Str (concrete, the receiver's class); 30 Ptr, 31 Ptr2 extends Ptr;
	// 40 Impl implements the interface Iface (50) without extending it; 171 Null.
	ctx.SuperClass = map[int]int{1: -1, 20: 1, 30: 1, 31: 30, 40: 1, 50: 1, 171: 1}
	ctx.ClassIDToName = map[int]string{171: "Null"}
	return ctx
}

func addSlot(ctx *TypeContext, imm, cid, codeIdx int, name string, owner int, leaf string) {
	key := cid + imm
	ctx.DispatchBySlot[key] = cluster.DispatchTableEntry{Kind: cluster.DispatchCode, ClusterIndex: codeIdx}
	ctx.DispatchCodeIndexToName[codeIdx] = name
	ctx.DispatchSlotMeta[key] = DispatchSlotMeta{Owner: owner, Leaf: leaf}
}

func hierarchyOf(parents map[int][]int) *cluster.ClassHierarchy {
	return &cluster.ClassHierarchy{Parents: parents, Abstract: map[int]bool{}}
}

func TestReceiverBoundElectsTheRowLeafAmongTheReceiversClasses(t *testing.T) {
	ctx := boundContext()
	const imm = -4000
	// Two foreign slots (Ptr, Ptr2) vote `pointer`; the receiver's only slot is `length`.
	addSlot(ctx, imm, 30, 1, "Ptr.pointer", 30, "pointer")
	addSlot(ctx, imm, 31, 2, "Ptr2.pointer", 31, "pointer")
	addSlot(ctx, imm, 20, 3, "Str.length", 20, "length")
	ctx.SetHierarchy(hierarchyOf(map[int][]int{1: nil, 20: {1}, 30: {1}, 31: {30}, 40: {1, 50}, 50: {1}, 171: {1}}))

	// A foreign slot: class 60's subtree {60,61,62} is not filled with `bar`.
	ctx.SuperClass[60], ctx.SuperClass[61], ctx.SuperClass[62] = 1, 60, 60
	addSlot(ctx, imm, 61, 4, "Fam.bar", 60, "bar")
	ctx.SetHierarchy(hierarchyOf(map[int][]int{1: nil, 20: {1}, 30: {1}, 31: {30}, 40: {1, 50}, 50: {1}, 60: {1}, 61: {60}, 62: {60}, 171: {1}}))

	// No receiver fact: rows of unrelated families share this imm, so the answer
	// is the union of the rows that are PROVEN (complete subtree), never a vote
	// and never the foreign half-row.
	want := []string{"Ptr.pointer", "Ptr2.pointer", "Str.length"}
	if got := ctx.selectorCandidatesFor(imm, 0); !reflect.DeepEqual(got, want) {
		t.Fatalf("without a bound: %v, want the proven rows %v", got, want)
	}
	got := ctx.selectorCandidatesFor(imm, 20)
	if !reflect.DeepEqual(got, []string{"Str.length"}) {
		t.Fatalf("bound Str: %v, want [Str.length]", got)
	}
	// The unbounded cache entry is untouched by the bounded query.
	if got := ctx.selectorCandidates(imm); !reflect.DeepEqual(got, want) {
		t.Fatalf("bounded query leaked into the unbounded cache: %v", got)
	}
}

// With no proven row at all (a hierarchy too incomplete to judge) the old
// behaviour -- the most frequent leaf -- is kept rather than answering nothing.
func TestRowElectionFallsBackToTheVoteWhenNoRowIsProven(t *testing.T) {
	ctx := boundContext()
	const imm = 700
	ctx.SuperClass[61], ctx.SuperClass[62] = 30, 30
	// Owner 30's subtree is {30,31,61,62}; only two of them carry the slot.
	addSlot(ctx, imm, 31, 1, "A.go", 30, "go")
	addSlot(ctx, imm, 61, 2, "B.go", 30, "go")
	addSlot(ctx, imm, 20, 3, "S.stop", 20, "stop")
	ctx.SuperClass[20] = 1
	ctx.SetHierarchy(nil)
	// `stop` IS complete (its subtree is just class 20) so it is proven alone.
	if got := ctx.selectorCandidatesFor(imm, 0); !reflect.DeepEqual(got, []string{"S.stop"}) {
		t.Fatalf("proven row = %v, want [S.stop]", got)
	}
	delete(ctx.DispatchSlotMeta, 20+imm)
	ctx.DispatchBySlot[20+imm] = cluster.DispatchTableEntry{Kind: cluster.DispatchNull}
	ctx.SelectorCache = map[int][]string{}
	ctx.SelectorMonomorphic = map[int]string{}
	if got := ctx.selectorCandidatesFor(imm, 0); !reflect.DeepEqual(got, []string{"A.go", "B.go"}) {
		t.Fatalf("vote fallback = %v, want [A.go B.go]", got)
	}
}

// A bound of an interface reaches classes that only implement it.
func TestReceiverBoundFollowsImplementsEdges(t *testing.T) {
	ctx := boundContext()
	const imm = 300
	addSlot(ctx, imm, 40, 1, "Impl.run", 40, "run")
	addSlot(ctx, imm, 30, 2, "Ptr.run", 30, "run")
	ctx.SetHierarchy(hierarchyOf(map[int][]int{1: nil, 20: {1}, 30: {1}, 31: {30}, 40: {1, 50}, 50: {1}, 171: {1}}))
	if got := ctx.selectorCandidatesFor(imm, 50); !reflect.DeepEqual(got, []string{"Impl.run"}) {
		t.Fatalf("bound Iface = %v, want only the implementor [Impl.run]", got)
	}
}

// A bound whose classes own no slot of the row (a missing hierarchy edge, or a
// wrong bound) must not turn into an empty answer that hides real callees.
func TestReceiverBoundFallsBackWhenItsClassesOwnNoSlot(t *testing.T) {
	ctx := boundContext()
	const imm = 400
	addSlot(ctx, imm, 30, 1, "Ptr.go", 30, "go")
	ctx.SetHierarchy(hierarchyOf(map[int][]int{1: nil, 20: {1}, 30: {1}, 31: {30}, 40: {1}, 50: {1}, 171: {1}}))
	if got := ctx.selectorCandidatesFor(imm, 20); !reflect.DeepEqual(got, []string{"Ptr.go"}) {
		t.Fatalf("empty bounded result must fall back to the unbounded one, got %v", got)
	}
}

// An incomplete hierarchy could drop a real callee: it is ignored altogether.
func TestIncompleteHierarchyDisablesTheReceiverBound(t *testing.T) {
	ctx := boundContext()
	const imm = -4000
	addSlot(ctx, imm, 30, 1, "Ptr.pointer", 30, "pointer")
	addSlot(ctx, imm, 31, 2, "Ptr2.pointer", 31, "pointer")
	addSlot(ctx, imm, 20, 3, "Str.length", 20, "length")
	h := hierarchyOf(map[int][]int{1: nil, 20: {1}, 30: {1}, 31: {30}, 171: {1}})
	h.Unresolved = 1
	ctx.SetHierarchy(h)
	// Ignored: the same answer as with no bound at all.
	want := ctx.selectorCandidatesFor(imm, 0)
	if got := ctx.selectorCandidatesFor(imm, 20); !reflect.DeepEqual(got, want) {
		t.Fatalf("bound applied despite an unresolved hierarchy: %v, want %v", got, want)
	}
}

// Null can sit behind any nullable static type, so its row entry always stays.
func TestReceiverBoundKeepsNull(t *testing.T) {
	ctx := boundContext()
	const imm = 500
	addSlot(ctx, imm, 20, 1, "Str.toString", 20, "toString")
	addSlot(ctx, imm, 171, 2, "Null.toString", 171, "toString")
	addSlot(ctx, imm, 30, 3, "Ptr.toString", 30, "toString")
	ctx.SetHierarchy(hierarchyOf(map[int][]int{1: nil, 20: {1}, 30: {1}, 31: {30}, 171: {1}}))
	if got := ctx.selectorCandidatesFor(imm, 20); !reflect.DeepEqual(got, []string{"Null.toString", "Str.toString"}) {
		t.Fatalf("bound Str = %v, want Str's and Null's slots", got)
	}
}

func TestSelectorDispatchJoinKeepsTheSelectorAndDropsADisagreeingBound(t *testing.T) {
	a, b := SelectorDispatch(-7, 20), SelectorDispatch(-7, 30)
	j := joinType(a, b, nil)
	if j.Kind != LatticeKnownDispatchIndex || !j.SelectorOnly || j.SelectorImm != -7 || j.RecvBound != 0 {
		t.Fatalf("join = %+v, want selector -7 with no bound", j)
	}
	if same := joinType(a, a, nil); same.RecvBound != 20 {
		t.Fatalf("join of equal facts lost the bound: %+v", same)
	}
	if other := joinType(a, SelectorDispatch(-8, 20), nil); other.Kind != LatticeTop {
		t.Fatalf("different selectors must join to Top, got %+v", other)
	}
}
