package typetrack

import (
	"strings"

	"aotopsy/internal/cluster"
)

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

// smiCID returns the class id of the Smi class (`_Smi`), as named in the
// snapshot, or false when the class table does not name it.
func (ctx *TypeContext) smiCID() (int, bool) {
	if ctx.smiCIDKnown {
		return ctx.smiCIDValue, ctx.smiCIDValue >= 0
	}
	ctx.smiCIDKnown, ctx.smiCIDValue = true, -1
	for cid, name := range ctx.ClassIDToName {
		// Core private classes carry their library mangling: `_Smi@0150898`.
		if name == "_Smi" || strings.HasPrefix(name, "_Smi@") {
			ctx.smiCIDValue = cid
			break
		}
	}
	return ctx.smiCIDValue, ctx.smiCIDValue >= 0
}

// stampReceiverBounds records, on every header-tag / class-id value that still
// has a live source link, the class bound of the object it was read from. Run
// after each instruction and BEFORE the written-register links are dropped, so
// the bound is captured while the object is still where the link says: the
// dispatch sequence overwrites the object's register with the dispatch table
// (`mov rax,[r14+DT]`; ARM64 reuses LR) before it consumes the class id.
func stampReceiverBounds(state *[31]TypeLattice) {
	for r := range state {
		t := &state[r]
		if !carriesSrcLink(t.Kind) || t.SrcReg == 0 || t.RecvBound != 0 {
			continue
		}
		if src := t.SrcReg - 1; src < 31 && state[src].Kind == LatticeClassBound {
			t.RecvBound = state[src].ClassID
		}
	}
}
