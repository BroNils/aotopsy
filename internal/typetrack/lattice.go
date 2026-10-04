// Package typetrack implements whole-program abstract interpretation for Dart
// AOT snapshots. The lattice deliberately separates facts about OBJECT values
// from facts about the integer CLASS-ID values extracted from object headers.
// Mixing those two domains is unsound: a class-id integer is not an instance of
// that class, and a declared static type is not an exact runtime class.
package typetrack

import "aotopsy/internal/cluster"

// TypeLatticeKind orders neither precision nor subtype relation. Join semantics
// are implemented explicitly in joinType.
type TypeLatticeKind int

const (
	// Bottom is the unreachable/no-predecessor element. It is an accumulator
	// identity only and must not be used to mean "reachable but unknown".
	LatticeBottom TypeLatticeKind = iota
	// Top is a reachable value for which this analysis has no safe fact.
	LatticeTop
	// ExactClass means the register contains a Dart heap object whose runtime CID
	// is exactly ClassID (for example a canonical pool object or allocation result).
	LatticeExactClass
	// ClassBound means the register contains an object whose runtime class is
	// ClassID or a subclass. Declared parameter/field/return types and an instance
	// method's declaring owner produce this state; they are not exact runtime CIDs.
	LatticeClassBound
	// HeaderTags states mean the register contains the raw object tags word,
	// before the ClassIdTag bitfield has been extracted. Keeping this separate
	// prevents arithmetic on a tags word from being mistaken for CID arithmetic.
	LatticeExactHeaderTags
	LatticeUnknownHeaderTags
	// ExactClassID means the register contains the integer CID exactly ClassID.
	// It is produced by extracting a header from an ExactClass or by equality
	// narrowing an UnknownClassID.
	LatticeExactClassID
	// UnknownClassID means the register is proven to contain a class-id integer,
	// but its concrete value is unknown. This is useful for selector-only dispatch.
	LatticeUnknownClassID
	// KnownDispatchIndex is either an exact dispatch-table-relative slot or, when
	// SelectorOnly is set, only the selector immediate with an unknown CID.
	LatticeKnownDispatchIndex
	LatticeKnownStub
	LatticePPBase
)

type TypeLattice struct {
	Kind          TypeLatticeKind
	ClassID       int
	DispatchIndex int
	StubName      string
	StubOff       int

	SelectorOnly bool
	SelectorImm  int

	PPBaseOffset int
}

func Bottom() TypeLattice { return TypeLattice{Kind: LatticeBottom} }
func Top() TypeLattice    { return TypeLattice{Kind: LatticeTop} }

func ExactClass(classID int) TypeLattice {
	return TypeLattice{Kind: LatticeExactClass, ClassID: classID}
}

func ClassBound(classID int) TypeLattice {
	return TypeLattice{Kind: LatticeClassBound, ClassID: classID}
}

func ExactHeaderTags(classID int) TypeLattice {
	return TypeLattice{Kind: LatticeExactHeaderTags, ClassID: classID}
}

func UnknownHeaderTags() TypeLattice { return TypeLattice{Kind: LatticeUnknownHeaderTags} }

func ExactClassID(classID int) TypeLattice {
	return TypeLattice{Kind: LatticeExactClassID, ClassID: classID}
}

func UnknownClassID() TypeLattice { return TypeLattice{Kind: LatticeUnknownClassID} }

func KnownDispatch(slot int) TypeLattice {
	return TypeLattice{Kind: LatticeKnownDispatchIndex, DispatchIndex: slot}
}

func SelectorDispatch(imm int) TypeLattice {
	return TypeLattice{Kind: LatticeKnownDispatchIndex, SelectorOnly: true, SelectorImm: imm}
}

func KnownStub(name string, off int) TypeLattice {
	return TypeLattice{Kind: LatticeKnownStub, StubName: name, StubOff: off}
}

func (a TypeLattice) Equal(b TypeLattice) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case LatticeExactClass, LatticeClassBound, LatticeExactHeaderTags, LatticeExactClassID:
		return a.ClassID == b.ClassID
	case LatticeKnownDispatchIndex:
		if a.SelectorOnly != b.SelectorOnly {
			return false
		}
		if a.SelectorOnly {
			return a.SelectorImm == b.SelectorImm
		}
		return a.DispatchIndex == b.DispatchIndex
	case LatticeKnownStub:
		return a.StubOff == b.StubOff && a.StubName == b.StubName
	case LatticePPBase:
		return a.PPBaseOffset == b.PPBaseOffset
	default:
		return true
	}
}

// joinType computes the least upper bound of facts from two control-flow paths.
// Bottom is used only for an unreachable/no-predecessor accumulator. Top is a
// reachable unknown and therefore absorbs any more precise fact. This distinction
// is essential: the previous implementation used Top as the join identity, so a
// register killed on one branch stayed exact-class when another branch preserved
// it, creating confident call targets that were not true on every path.
func joinType(a, b TypeLattice, lca func(int, int) int) TypeLattice {
	if a.Kind == LatticeBottom {
		return b
	}
	if b.Kind == LatticeBottom {
		return a
	}
	if a.Kind == LatticeTop || b.Kind == LatticeTop {
		return Top()
	}

	// Object values can safely lose precision to their common static bound.
	if isObjectClass(a.Kind) && isObjectClass(b.Kind) {
		if a.ClassID == b.ClassID {
			if a.Kind == LatticeExactClass && b.Kind == LatticeExactClass {
				return a
			}
			return ClassBound(a.ClassID)
		}
		if lca != nil {
			if cid := lca(a.ClassID, b.ClassID); cid >= 0 {
				return ClassBound(cid)
			}
		}
		return Top()
	}

	// CID scalars remain CID scalars across merges; disagreement loses only the
	// concrete number, not the fact that selector arithmetic is operating on a CID.
	if isClassID(a.Kind) && isClassID(b.Kind) {
		if a.Kind == LatticeExactClassID && b.Kind == LatticeExactClassID && a.ClassID == b.ClassID {
			return a
		}
		return UnknownClassID()
	}
	if isHeaderTags(a.Kind) && isHeaderTags(b.Kind) {
		if a.Kind == LatticeExactHeaderTags && b.Kind == LatticeExactHeaderTags && a.ClassID == b.ClassID {
			return a
		}
		return UnknownHeaderTags()
	}

	if a.Kind == LatticeKnownDispatchIndex && b.Kind == LatticeKnownDispatchIndex {
		if a.Equal(b) {
			return a
		}
		return Top()
	}
	if a.Kind == LatticeKnownStub && b.Kind == LatticeKnownStub {
		if a.Equal(b) {
			return a
		}
		return Top()
	}
	if a.Kind == LatticePPBase && b.Kind == LatticePPBase {
		if a.Equal(b) {
			return a
		}
		return Top()
	}
	return Top()
}

func isObjectClass(k TypeLatticeKind) bool {
	return k == LatticeExactClass || k == LatticeClassBound
}

func objectClassID(t TypeLattice) (int, bool) {
	if !isObjectClass(t.Kind) || t.ClassID < 0 {
		return 0, false
	}
	return t.ClassID, true
}

func exactObjectClassID(t TypeLattice) (int, bool) {
	if t.Kind != LatticeExactClass || t.ClassID < 0 {
		return 0, false
	}
	return t.ClassID, true
}

func isClassID(k TypeLatticeKind) bool {
	return k == LatticeExactClassID || k == LatticeUnknownClassID
}

func isHeaderTags(k TypeLatticeKind) bool {
	return k == LatticeExactHeaderTags || k == LatticeUnknownHeaderTags
}

// BuildClassHierarchy builds a superclass map from cluster.ClassInfo data.
func BuildClassHierarchy(classes []cluster.ClassInfo, types []cluster.TypeInfo) map[int]int {
	hierarchy := make(map[int]int, len(classes))
	refToType := make(map[int]*cluster.TypeInfo, len(types))
	for i := range types {
		refToType[types[i].RefID] = &types[i]
	}
	for i := range classes {
		c := &classes[i]
		superID := -1
		if c.SuperTypeRefID >= 0 {
			if ti, ok := refToType[c.SuperTypeRefID]; ok && ti.ClassID >= 0 {
				superID = int(ti.ClassID)
			}
		}
		hierarchy[int(c.ClassID)] = superID
	}
	return hierarchy
}

// LCA computes the lowest common ancestor of two class IDs.
func LCA(classA, classB int, hierarchy map[int]int) int {
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
	c = classB
	seenB := make(map[int]bool)
	for c >= 0 && !seenB[c] {
		seenB[c] = true
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
