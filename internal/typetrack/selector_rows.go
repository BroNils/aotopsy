package typetrack

import (
	"sort"

	"aotopsy/internal/cluster"
)

// DispatchSlotMeta is the row identity of one dispatch-table Code slot: the
// class that declares the implementing Function and the Function's selector
// leaf name ("foo", "get:foo", "set:foo", "[]", ...). Owner is -1 when the
// declaring class could not be resolved.
type DispatchSlotMeta struct {
	Owner int
	Leaf  string
}

// maxHierarchyDepth bounds ancestor walks so a corrupt SuperClass cycle cannot
// spin forever.
const maxHierarchyDepth = 512

// isAncestorOrSelf reports whether anc is cid or one of its superclasses.
func (ctx *TypeContext) isAncestorOrSelf(anc, cid int) bool {
	cur := cid
	for steps := 0; steps < maxHierarchyDepth; steps++ {
		if cur == anc {
			return true
		}
		next, ok := ctx.SuperClass[cur]
		if !ok || next < 0 || next == cur {
			return false
		}
		cur = next
	}
	return false
}

// inferSelectorRowImms recovers, for every selector leaf, the register-relative
// selector immediates (selector_offset - kOriginElement) of the table rows that
// implement it. A slot (key, ownerClass) fixes the row only up to the receiver
// class it was written for: key = imm + cid with cid any concrete descendant of
// the declaring class (FillTable writes the implementation for every concrete
// subclass). So imm is searched among {key - cid : cid descends from owner} and
// scored by how many of the leaf's slots it explains (key - imm must again be a
// class descending from that slot's owner). Rows of one leaf in unrelated
// hierarchies (distinct selector ids, see selectorRowCandidates) come out as
// separate immediates, largest first.
func (ctx *TypeContext) inferSelectorRowImms() map[string][]int {
	out := map[string][]int{}
	if len(ctx.DispatchSlotMeta) == 0 || len(ctx.SuperClass) == 0 {
		return out
	}
	desc := make(map[int][]int, len(ctx.SuperClass))
	cids := make([]int, 0, len(ctx.SuperClass))
	for cid := range ctx.SuperClass {
		if cid >= 0 {
			cids = append(cids, cid)
		}
	}
	sort.Ints(cids)
	for _, c := range cids {
		cur := c
		for steps := 0; steps < maxHierarchyDepth; steps++ {
			desc[cur] = append(desc[cur], c)
			next, ok := ctx.SuperClass[cur]
			if !ok || next < 0 || next == cur {
				break
			}
			cur = next
		}
	}

	type slot struct{ key, owner int }
	byLeaf := map[string][]slot{}
	for key, meta := range ctx.DispatchSlotMeta {
		if meta.Leaf == "" || meta.Owner < 0 {
			continue
		}
		byLeaf[meta.Leaf] = append(byLeaf[meta.Leaf], slot{key: key, owner: meta.Owner})
	}
	leaves := make([]string, 0, len(byLeaf))
	for leaf := range byLeaf {
		leaves = append(leaves, leaf)
	}
	sort.Strings(leaves)

	explains := func(s slot, imm int) bool {
		cid := s.key - imm
		if cid < 0 {
			return false
		}
		if _, ok := ctx.SuperClass[cid]; !ok {
			return false
		}
		return ctx.isAncestorOrSelf(s.owner, cid)
	}
	for _, leaf := range leaves {
		remaining := byLeaf[leaf]
		sort.Slice(remaining, func(i, j int) bool { return remaining[i].key < remaining[j].key })
		for len(remaining) > 0 {
			first := remaining[0]
			bestImm, bestN := 0, 0
			tried := map[int]bool{}
			for _, c := range desc[first.owner] {
				imm := first.key - c
				if tried[imm] {
					continue
				}
				tried[imm] = true
				n := 0
				for _, s := range remaining {
					if explains(s, imm) {
						n++
					}
				}
				if n > bestN || (n == bestN && n > 0 && imm < bestImm) {
					bestImm, bestN = imm, n
				}
			}
			if bestN == 0 {
				remaining = remaining[1:] // owner has no known descendant: unexplainable
				continue
			}
			out[leaf] = append(out[leaf], bestImm)
			kept := remaining[:0]
			for _, s := range remaining {
				if !explains(s, bestImm) {
					kept = append(kept, s)
				}
			}
			remaining = kept
		}
		sort.Ints(out[leaf])
	}
	return out
}

// selectorRowCandidates returns the Code slots that belong to the dispatch-table
// row whose register-relative selector immediate is imm, as the distinct
// implementation names, sorted.
//
// SDK (runtime/vm/compiler/aot/dispatch_table_generator.cc; identical in shape
// for every supported version, md5-identical 3.2.5..3.13.0):
//
//   - SelectorRow::FillTable writes `entries[selector.offset + cid] = code` for
//     every cid of the implementing class's CONCRETE subclass intervals, so the
//     implementation at slot offset+cid is declared by cid itself or one of its
//     superclasses (`depth`-ordered, "more specific overrides more general").
//   - RowFitter packs the rows by row displacement into the holes of earlier
//     rows. The slot offset+cid of a cid that row does NOT implement is
//     therefore usually occupied by a DIFFERENT selector's entry.
//   - Selector ids are assigned per (class-hierarchy member, Name) with
//     implemented-interface merging (pkg/vm/.../table_selector_assigner.dart), so
//     one Name can own several rows in unrelated hierarchies, but every Function
//     inside one row has the same Name (and the same getter/method-or-setter
//     kind, which is encoded in the snapshot leaf as get:/set:).
//
// A slot s = imm+cid therefore belongs to this row only if
//
//	(1) its Code's owner class is an ancestor-or-self of cid, and
//	(2) its selector leaf equals the row's leaf.
//
// The row leaf is the most frequent leaf among the slots that satisfy (1);
// slots whose owner could not be resolved (Owner == -1) are judged by (2)
// alone. Without this filter the scan returned the union of unrelated
// selectors that merely share the same table region (576 "targets" for one
// Map-literal call on a real 3.9.2 app, whose whole table holds ~400 selectors
// and whose largest real row has 168 implementations).
//
// allowed, when non-nil, restricts the runtime cids consulted (a receiver known
// to be a subtype of some class), and it does so BEFORE the row leaf is elected.
// That is deliberate: the receiver's own slot imm+cid is by construction in the
// selector's row, so the leaf elected among the receiver's possible classes is
// the selector's; electing it among ALL cids lets another selector whose slots
// overlap this region (row displacement packs rows into each other's holes) win
// the vote, which for a sparse row (a String receiver, 2-3 cids) it routinely
// did -- the candidates came back as `PointerEvent.get:pointer`.
func (ctx *TypeContext) selectorRowCandidates(imm int, allowed func(cid int) bool) []string {
	type member struct {
		cid   int
		key   int
		meta  DispatchSlotMeta
		owned bool // owner resolved AND ancestor-or-self of cid
	}
	var members []member
	cids := make([]int, 0, len(ctx.SuperClass))
	for cid := range ctx.SuperClass {
		if cid >= 0 {
			cids = append(cids, cid)
		}
	}
	sort.Ints(cids)
	for _, cid := range cids {
		if allowed != nil && !allowed(cid) {
			continue
		}
		key := cid + imm
		entry, ok := ctx.DispatchBySlot[key]
		if !ok || entry.Kind != cluster.DispatchCode {
			continue
		}
		meta, hasMeta := ctx.DispatchSlotMeta[key]
		if !hasMeta {
			meta = DispatchSlotMeta{Owner: -1}
		}
		m := member{cid: cid, key: key, meta: meta}
		if meta.Owner >= 0 {
			if !ctx.isAncestorOrSelf(meta.Owner, cid) {
				// Declared by a class unrelated to cid: this slot is another row's.
				continue
			}
			m.owned = true
		}
		members = append(members, m)
	}
	if len(members) == 0 {
		return nil
	}

	// Row leaf: most frequent among ownership-verified slots, else among all.
	counts := map[string]int{}
	for _, m := range members {
		if m.owned {
			counts[m.meta.Leaf]++
		}
	}
	if len(counts) == 0 {
		for _, m := range members {
			counts[m.meta.Leaf]++
		}
	}
	rowLeaf, best := "", -1
	for leaf, n := range counts {
		if n > best || (n == best && leaf < rowLeaf) {
			rowLeaf, best = leaf, n
		}
	}

	seen := map[string]bool{}
	var names []string
	for _, m := range members {
		if m.meta.Leaf != rowLeaf {
			continue
		}
		entry := ctx.DispatchBySlot[m.key]
		name, ok := ctx.DispatchCodeIndexToName[entry.ClusterIndex]
		if !ok || name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
