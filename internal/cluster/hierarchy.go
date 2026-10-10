package cluster

import "sort"

// ClassHierarchy is the class-level subtype relation of a snapshot: `extends`
// (UntaggedClass::super_type) and `implements` (UntaggedClass::interfaces) edges
// between class ids, plus the abstract bit. A transformed mixin application
// `S&M` appears as an ordinary class with super S and M among its interfaces
// (see ClassInfo.InterfacesRefID), so the two edge kinds are the whole relation.
//
// Classes of the VM snapshot (core types such as Object, List, num) are merged
// in: their Class objects, Types and interface Arrays live there, and refs below
// the isolate's first own ref point into it (Result.Types of the VM result).
type ClassHierarchy struct {
	// Parents maps a class id to its direct super types: the superclass first (if
	// any), then the interfaces. Class ids only; type arguments are ignored, which
	// is exactly what CidCheckerForRanges does (it compares RareTypes).
	Parents  map[int][]int
	Abstract map[int]bool
	// Unresolved counts interface/super type refs that could not be turned into a
	// class id (a ref that is not a Type, or a Type without a class id). Callers
	// that need a sound relation must treat a non-zero count as "incomplete".
	Unresolved int
}

// NewClassHierarchy merges the isolate result with the VM snapshot result (nil
// for unified snapshots, where everything is in iso).
func NewClassHierarchy(iso, vm *Result) *ClassHierarchy {
	h := &ClassHierarchy{Parents: map[int][]int{}, Abstract: map[int]bool{}}
	typeClass := map[int]int{}
	arrays := map[int][]int{}
	var classes []ClassInfo
	for _, r := range []*Result{vm, iso} {
		if r == nil {
			continue
		}
		for _, t := range r.Types {
			if t.ClassID >= 0 {
				typeClass[t.RefID] = int(t.ClassID)
			}
		}
		for _, a := range r.Arrays {
			arrays[a.RefID] = a.ElementRefIDs
		}
		classes = append(classes, r.Classes...)
	}
	for _, c := range classes {
		cid := int(c.ClassID)
		h.Abstract[cid] = c.IsAbstract()
		var parents []int
		if c.SuperTypeRefID > RefNull {
			if sc, ok := typeClass[c.SuperTypeRefID]; ok {
				parents = append(parents, sc)
			} else {
				h.Unresolved++
			}
		}
		if c.InterfacesRefID > RefNull {
			for _, e := range arrays[c.InterfacesRefID] {
				if ic, ok := typeClass[e]; ok {
					parents = append(parents, ic)
				} else {
					h.Unresolved++
				}
			}
		}
		h.Parents[cid] = parents
	}
	return h
}

// Ancestors returns every class id cid is a subtype of (transitively, cid
// itself excluded), sorted.
func (h *ClassHierarchy) Ancestors(cid int) []int {
	seen := map[int]bool{cid: true}
	stack := []int{cid}
	var out []int
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, p := range h.Parents[c] {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
				stack = append(stack, p)
			}
		}
	}
	sort.Ints(out)
	return out
}

// IsSubclassOrImplementor reports whether sub == super or super is an ancestor of sub.
func (h *ClassHierarchy) IsSubclassOrImplementor(sub, super int) bool {
	if sub == super {
		return true
	}
	seen := map[int]bool{sub: true}
	stack := []int{sub}
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, p := range h.Parents[c] {
			if p == super {
				return true
			}
			if !seen[p] {
				seen[p] = true
				stack = append(stack, p)
			}
		}
	}
	return false
}
