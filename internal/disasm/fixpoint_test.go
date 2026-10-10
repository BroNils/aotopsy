package disasm

import "testing"

func TestRunProvFixpointMergeConflictIsBottom(t *testing.T) {
	// b0 branches to b1/b2; b1 produces A, b2 produces B; b3 joins them.
	effects := make([]provBlockEffect, 4)
	for i := range effects {
		effects[i] = provBlockEffect{
			touched:  []bool{false},
			final:    []lvalue{{}},
			copyFrom: []int{-1},
		}
	}
	effects[1].touched[0] = true
	effects[1].final[0] = lvalue{kind: lvKnown, note: "A"}
	effects[2].touched[0] = true
	effects[2].final[0] = lvalue{kind: lvKnown, note: "B"}
	succs := [][]Succ{
		{{BlockID: 1}, {BlockID: 2}},
		{{BlockID: 3}},
		{{BlockID: 3}},
		nil,
	}
	got := runProvFixpoint(4, 1, func(b int) []Succ { return succs[b] }, effects)
	if got[3][0].kind != lvBottom {
		t.Fatalf("conflicting merge = %+v, want Bottom", got[3][0])
	}
}

func TestProvVisitLimitDoesNotOverflow(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	if got := provVisitLimit(maxInt); got != maxInt {
		t.Fatalf("provVisitLimit(maxInt) = %d, want %d", got, maxInt)
	}
	if got := provVisitLimit(4); got != 80 {
		t.Fatalf("provVisitLimit(4) = %d, want 80", got)
	}
}
