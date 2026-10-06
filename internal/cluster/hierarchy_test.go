package cluster

import (
	"reflect"
	"testing"
)

func TestClassInfoAbstractBitIsBit6(t *testing.T) {
	// Const(0) Implemented(1) Finalized(2..3) Loading(4..5) Abstract(6).
	if (ClassInfo{StateBits: 1 << 6}).IsAbstract() != true {
		t.Error("bit 6 not read as abstract")
	}
	for _, other := range []uint32{1 << 0, 1 << 1, 3 << 2, 3 << 4, 1 << 7} {
		if (ClassInfo{StateBits: other}).IsAbstract() {
			t.Errorf("state bits %#x read as abstract", other)
		}
	}
}

// B extends A, C implements B, D extends C with the mixin M (D's super is the
// application class S&M, whose interfaces hold M): A is abstract.
func TestClassHierarchyExtendsImplementsAndMixins(t *testing.T) {
	const arrB, arrC, arrSM = 900, 901, 902
	r := &Result{
		Types: []TypeInfo{
			{RefID: 10, ClassID: 100}, // A
			{RefID: 11, ClassID: 101}, // B
			{RefID: 12, ClassID: 102}, // C
			{RefID: 13, ClassID: 105}, // M
			{RefID: 14, ClassID: 106}, // S&M
		},
		Arrays: []ArrayInfo{
			{RefID: arrB, ElementRefIDs: nil},
			{RefID: arrC, ElementRefIDs: []int{11}},  // C implements B
			{RefID: arrSM, ElementRefIDs: []int{13}}, // S&M implements M
		},
		Classes: []ClassInfo{
			{ClassID: 100, StateBits: 1 << 6, SuperTypeRefID: -1, InterfacesRefID: -1},
			{ClassID: 101, SuperTypeRefID: 10, InterfacesRefID: arrB},
			{ClassID: 102, SuperTypeRefID: -1, InterfacesRefID: arrC},
			{ClassID: 105, SuperTypeRefID: -1, InterfacesRefID: -1},
			{ClassID: 106, SuperTypeRefID: 12, InterfacesRefID: arrSM},
			{ClassID: 107, SuperTypeRefID: 14, InterfacesRefID: -1}, // D extends S&M
		},
	}
	h := NewClassHierarchy(r, nil)
	if h.Unresolved != 0 {
		t.Fatalf("unresolved = %d", h.Unresolved)
	}
	if !h.Abstract[100] || h.Abstract[101] {
		t.Errorf("abstract = %v", h.Abstract)
	}
	if got, want := h.Ancestors(107), []int{100, 101, 102, 105, 106}; !reflect.DeepEqual(got, want) {
		t.Errorf("Ancestors(D) = %v, want %v", got, want)
	}
	for _, super := range []int{100, 101, 102, 105, 106, 107} {
		if !h.IsSubclassOrImplementor(107, super) {
			t.Errorf("D is not a subtype of %d", super)
		}
	}
	if h.IsSubclassOrImplementor(100, 101) || h.IsSubclassOrImplementor(105, 106) {
		t.Error("subtype relation is not directional")
	}
	// A ref that is not a Type is counted, never silently dropped.
	r.Classes = append(r.Classes, ClassInfo{ClassID: 110, SuperTypeRefID: 999, InterfacesRefID: -1})
	if got := NewClassHierarchy(r, nil).Unresolved; got != 1 {
		t.Errorf("unresolved super type not counted: %d", got)
	}
}
