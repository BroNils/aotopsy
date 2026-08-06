// Package typetrack implements whole-program type inference for Dart AOT
// snapshots to resolve indirect (BLR) call sites. It infers the runtime
// ClassID of receiver objects at each call site, then maps
// class_id + selector_offset → dispatch table slot → target function.
//
// The type lattice has five levels:
//   - Top:      no type information yet (initial state)
//   - KnownClass: a specific ClassID is known
//   - KnownDispatchIndex: a dispatch table selector offset is known
//     (from ADD Xn, X21, #offset — the offset IS the slot index)
//   - KnownStub: a THR-cached stub entry point is known (e.g. AllocateObject)
//   - Bottom:   conflicting type information (join of incompatible types)
package typetrack

import (
	"aotopsy/internal/cluster"
)

// TypeLatticeKind enumerates the five lattice levels.
type TypeLatticeKind int

const (
	LatticeTop    TypeLatticeKind = iota // no info yet
	LatticeKnownClass                    // ClassID is known
	LatticeKnownDispatchIndex            // dispatch table slot offset is known
	LatticeKnownStub                     // THR-cached stub entry point is known
	LatticeBottom                        // conflicting/unresolvable
)

// TypeLattice is the type abstraction for a register or SSA value.
// For LatticeKnownClass, ClassID holds the Dart class ID.
// For LatticeKnownDispatchIndex, DispatchIndex holds the dispatch table slot.
// For LatticeKnownStub, StubName holds the stub name and StubOff the THR offset.
type TypeLattice struct {
	Kind          TypeLatticeKind
	ClassID       int    // valid when Kind == LatticeKnownClass
	DispatchIndex int    // valid when Kind == LatticeKnownDispatchIndex
	StubName      string // valid when Kind == LatticeKnownStub
	StubOff       int    // valid when Kind == LatticeKnownStub
}

// Top returns the top element of the lattice.
func Top() TypeLattice { return TypeLattice{Kind: LatticeTop} }

// Bottom returns the bottom element of the lattice.
func Bottom() TypeLattice { return TypeLattice{Kind: LatticeBottom} }

// KnownClass returns a lattice element for a specific ClassID.
func KnownClass(classID int) TypeLattice {
	return TypeLattice{Kind: LatticeKnownClass, ClassID: classID}
}

// KnownDispatch returns a lattice element for a dispatch table slot offset.
func KnownDispatch(slot int) TypeLattice {
	return TypeLattice{Kind: LatticeKnownDispatchIndex, DispatchIndex: slot}
}

// KnownStub returns a lattice element for a THR-cached stub entry point.
func KnownStub(name string, off int) TypeLattice {
	return TypeLattice{Kind: LatticeKnownStub, StubName: name, StubOff: off}
}

// Equal reports whether two lattice elements are identical.
func (a TypeLattice) Equal(b TypeLattice) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case LatticeKnownClass:
		return a.ClassID == b.ClassID
	case LatticeKnownDispatchIndex:
		return a.DispatchIndex == b.DispatchIndex
	case LatticeKnownStub:
		return a.StubOff == b.StubOff
	}
	return true
}

// meetType computes the meet (greatest lower bound) of two lattice elements.
// The meet rules:
//   - Top ∧ x = x
//   - Bottom ∧ x = Bottom
//   - KnownClass(a) ∧ KnownClass(b) = LCA(a,b) if a≠b, or KnownClass(a) if a==b
//   - KnownDispatch(a) ∧ KnownDispatch(b) = KnownDispatch(a) if a==b, else Bottom
//   - KnownStub ∧ anything = Bottom (stubs don't combine with other types)
//   - KnownClass ∧ KnownDispatch = Bottom (different abstraction levels)
func meetType(a, b TypeLattice, lca func(int, int) int) TypeLattice {
	if a.Kind == LatticeTop {
		return b
	}
	if b.Kind == LatticeTop {
		return a
	}
	if a.Kind == LatticeBottom || b.Kind == LatticeBottom {
		return Bottom()
	}
	// KnownStub: identical stubs (same StubOff) combine to themselves;
	// different stubs or stub+other → Bottom (H-1 fix: previously ALL
	// KnownStub meets returned Bottom, losing allocation-site info at
	// join points where both paths load the same stub).
	if a.Kind == LatticeKnownStub && b.Kind == LatticeKnownStub {
		if a.StubOff == b.StubOff {
			return a
		}
		return Bottom()
	}
	if a.Kind == LatticeKnownStub || b.Kind == LatticeKnownStub {
		return Bottom()
	}
	if a.Kind == LatticeKnownClass && b.Kind == LatticeKnownClass {
		if a.ClassID == b.ClassID {
			return a
		}
		if lca != nil {
			if l := lca(a.ClassID, b.ClassID); l >= 0 {
				return KnownClass(l)
			}
		}
		return Bottom()
	}
	if a.Kind == LatticeKnownDispatchIndex && b.Kind == LatticeKnownDispatchIndex {
		if a.DispatchIndex == b.DispatchIndex {
			return a
		}
		return Bottom()
	}
	// Mixed KnownClass ∧ KnownDispatch → Bottom
	return Bottom()
}

// BuildClassHierarchy builds a superclass map from cluster.ClassInfo data.
// Returns a map: classID → superclassID (or -1 if no superclass / unknown).
func BuildClassHierarchy(classes []cluster.ClassInfo, types []cluster.TypeInfo, refToNamed map[int]*cluster.NamedObject) map[int]int {
	hierarchy := make(map[int]int, len(classes))

	// Build ref→ClassInfo lookup.
	refToClass := make(map[int]*cluster.ClassInfo, len(classes))
	for i := range classes {
		refToClass[classes[i].RefID] = &classes[i]
	}

	// Build ref→TypeInfo lookup (v3.x: Type.type_class_id gives the CID).
	refToType := make(map[int]*cluster.TypeInfo, len(types))
	for i := range types {
		refToType[types[i].RefID] = &types[i]
	}

	for i := range classes {
		c := &classes[i]
		superID := -1

		// ClassInfo.SuperTypeRefID points to a Type object (v3.x).
		if c.SuperTypeRefID >= 0 {
			if ti, ok := refToType[c.SuperTypeRefID]; ok && ti.ClassID >= 0 {
				superID = int(ti.ClassID)
			}
		}

		hierarchy[int(c.ClassID)] = superID
	}

	return hierarchy
}

// LCA computes the lowest common ancestor of two class IDs in the
// hierarchy. Returns -1 if no common ancestor exists (one or both
// have no superclass chain).
func LCA(classA, classB int, hierarchy map[int]int) int {
	// Collect all ancestors of A (including A itself).
	ancestorsA := make(map[int]bool)
	c := classA
	for c >= 0 && !ancestorsA[c] {
		ancestorsA[c] = true
		next, ok := hierarchy[c]
		if !ok {
			break
		}
		c = next
	}

	// Walk B's chain and return the first match.
	c = classB
	for c >= 0 {
		if ancestorsA[c] {
			return c
		}
		next, ok := hierarchy[c]
		if !ok {
			break
		}
		c = next
	}
	return -1
}
