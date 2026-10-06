package typetrack

import "aotopsy/internal/cluster"

// Receiver subtype bounds for selector scans.
//
// A selector-only dispatch (`ADD/SUB X, cid, #imm; LDR X30, [DT, X, LSL #3]`)
// reaches the slot `imm + cid(receiver)`, so the possible callees are exactly the
// slots of the runtime cids the receiver can have. When the receiver is known to
// be an instance of C, those cids are the classes that extend or implement C
// (UntaggedClass::super_type and ::interfaces; a transformed mixin application
// has the mixin among its interfaces) -- plus Null, which can sit behind any
// nullable static type and has its own row for the members of Object.
//
// The bound comes from ClassBound facts (declared parameter/field/return types,
// the owner of an instance method), which are upper bounds, never exact cids.
// That is why the subtype closure -- not the superclass chain alone -- is the
// right test: a `List` field holds a _GrowableList that only IMPLEMENTS List
// through ListBase.

// SetHierarchy installs the subtype relation used by subtypeFilter. A hierarchy
// with an unresolved edge is incomplete, and an incomplete relation could drop a
// real callee, so it is ignored.
func (ctx *TypeContext) SetHierarchy(h *cluster.ClassHierarchy) {
	ctx.subtypeSets = nil
	ctx.nullCID = -1
	ctx.hierarchy = nil
	if h == nil || h.Unresolved != 0 {
		return
	}
	ctx.hierarchy = h
	for cid, name := range ctx.ClassIDToName {
		if name == "Null" && (ctx.nullCID < 0 || cid < ctx.nullCID) {
			ctx.nullCID = cid
		}
	}
}

// subtypeFilter returns the predicate "cid is a possible runtime class of an
// instance of bound", or nil when no bound is known (bound <= 0) or no usable
// hierarchy is installed.
func (ctx *TypeContext) subtypeFilter(bound int) func(cid int) bool {
	if bound <= 0 || ctx.hierarchy == nil {
		return nil
	}
	if _, known := ctx.hierarchy.Parents[bound]; !known {
		return nil // a bound the hierarchy has never heard of: say nothing
	}
	set, ok := ctx.subtypeSets[bound]
	if !ok {
		set = make(map[int]bool)
		for cid := range ctx.hierarchy.Parents {
			if ctx.hierarchy.IsSubclassOrImplementor(cid, bound) {
				set[cid] = true
			}
		}
		if ctx.nullCID >= 0 {
			set[ctx.nullCID] = true
		}
		if ctx.subtypeSets == nil {
			ctx.subtypeSets = make(map[int]map[int]bool)
		}
		ctx.subtypeSets[bound] = set
	}
	return func(cid int) bool { return set[cid] }
}
