package render

import (
	"fmt"
	"sort"
	"strings"

	"aotopsy/internal/disasm"
)

// concreteCallTargets returns function targets backed by call-resolution
// evidence. Via is intentionally excluded: it can be a provenance label such
// as "dispatch_table" or "object_field+0x30", not a function name.
func concreteCallTargets(e disasm.CallEdgeRecord) []string {
	if e.Target != "" {
		if isRawCallAddress(e.Target) {
			return nil
		}
		return []string{e.Target}
	}
	if len(e.Targets) > 0 {
		return e.Targets
	}
	return nil
}

func isRawCallAddress(s string) bool {
	if len(s) <= 2 || (s[:2] != "0x" && s[:2] != "0X") {
		return false
	}
	for _, r := range s[2:] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// FindEntryPoints returns functions that have no incoming BL or resolved BLR edges.
// Runtime stubs (sub_*) are excluded since they're callees, not true entry points.
func FindEntryPoints(funcs []disasm.FuncRecord, edges []disasm.CallEdgeRecord) []string {
	funcSet := make(map[string]bool, len(funcs))
	for _, f := range funcs {
		funcSet[f.Name] = true
	}
	// Collect all named BL and resolved BLR targets, including the candidate
	// callees of polymorphic sites: a function that is only ever reached
	// through virtual dispatch is not an entry point, and treating it as one
	// makes the entry list mostly noise.
	blTargets := make(map[string]bool)
	for _, e := range edges {
		if !funcSet[e.FromFunc] || !isSupportedCallKind(e.Kind) {
			continue
		}
		for _, t := range concreteCallTargets(e) {
			blTargets[t] = true
		}
	}

	// Functions not targeted by any BL = entry points.
	var entries []string
	for _, f := range funcs {
		if strings.HasPrefix(f.Name, "sub_") {
			continue // runtime stubs are not meaningful entry points
		}
		if !blTargets[f.Name] {
			entries = append(entries, f.Name)
		}
	}
	sort.Strings(entries)
	return entries
}

// ReachableSet performs BFS from entry points following BL edges
// and resolved BLR edges (dispatch-table calls resolved by the type
// inference engine), and returns the set of all reachable function names.
func ReachableSet(entryPoints []string, edges []disasm.CallEdgeRecord) map[string]bool {
	// Build adjacency from BL edges, resolved BLR edges, and the candidate
	// callees of polymorphic BLR edges.
	//
	// Following every candidate is a deliberate OVER-approximation: at most
	// one of them runs at a given call site, so this can mark code reachable
	// that never executes. For reachability that is the safe direction --
	// under-approximating hides real code. (It also used to happen by
	// accident, and wrongly: the joined "a | b | c" string was followed as if
	// it were one callee, so it reached nothing and added a junk node.)
	adj := make(map[string][]string)
	for _, e := range edges {
		if !isSupportedCallKind(e.Kind) {
			continue
		}
		adj[e.FromFunc] = append(adj[e.FromFunc], concreteCallTargets(e)...)
	}

	reachable := make(map[string]bool)
	queue := make([]string, 0, len(entryPoints))
	for _, ep := range entryPoints {
		if !reachable[ep] {
			reachable[ep] = true
			queue = append(queue, ep)
		}
	}

	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		for _, target := range adj[fn] {
			if !reachable[target] {
				reachable[target] = true
				queue = append(queue, target)
			}
		}
	}
	return reachable
}

// ReachabilityDOT renders a callgraph filtered to the reachable set.
// Entry points are highlighted. Direct and resolved indirect edges preserve
// their provenance styling.
func ReachabilityDOT(funcs []disasm.FuncRecord, edges []disasm.CallEdgeRecord, reachable map[string]bool, entryPoints []string, title string, t Theme) string {
	entrySet := make(map[string]bool, len(entryPoints))
	for _, ep := range entryPoints {
		entrySet[ep] = true
	}

	// Build func name→owner map.
	funcOwner := make(map[string]string, len(funcs))
	for _, f := range funcs {
		funcOwner[f.Name] = f.Owner
	}

	// Deduplicate direct, resolved indirect, and polymorphic-candidate edges
	// within the reachable set while retaining how each edge was resolved.
	type edgeKey struct{ from, to, prov string }
	edgeCount := make(map[edgeKey]int)
	addEdge := func(from, to, prov string) {
		if to == "" || !reachable[from] || !reachable[to] {
			return
		}
		edgeCount[edgeKey{from, to, prov}]++
	}
	for _, e := range edges {
		if !isSupportedCallKind(e.Kind) {
			continue
		}
		prov := ClassifyEdgeProv(e)
		for _, target := range concreteCallTargets(e) {
			addEdge(e.FromFunc, target, prov)
		}
	}

	// Collect referenced nodes.
	refNodes := make(map[string]bool)
	for k := range edgeCount {
		refNodes[k.from] = true
		refNodes[k.to] = true
	}
	// Also include entry points even if they have no edges.
	for _, ep := range entryPoints {
		refNodes[ep] = true
	}

	// Group by owner for clustering.
	ownerFuncs := make(map[string][]string)
	var noOwner []string
	for name := range refNodes {
		owner := funcOwner[name]
		if owner != "" {
			ownerFuncs[owner] = append(ownerFuncs[owner], name)
		} else {
			noOwner = append(noOwner, name)
		}
	}

	var b strings.Builder
	b.WriteString("digraph reachable {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  compound=true;\n")
	b.WriteString("  splines=true;\n")
	b.WriteString("  nodesep=0.4;\n")
	b.WriteString("  ranksep=0.6;\n")
	fmt.Fprintf(&b, "  bgcolor=%q;\n", t.Background)
	fmt.Fprintf(&b, "  node [shape=rect, style=filled, fillcolor=%q, color=%q, penwidth=0.5, fontname=\"Helvetica Neue,Helvetica,Arial\", fontsize=9, fontcolor=%q, height=0.3, margin=\"0.12,0.06\"];\n",
		t.NodeFill, t.NodeBorder, t.TextColor)
	fmt.Fprintf(&b, "  edge [penwidth=0.5, arrowsize=0.5, arrowhead=vee, color=%q];\n", t.EdgeDirect)
	if title != "" {
		fmt.Fprintf(&b, "  labelloc=t;\n  labeljust=l;\n")
		fmt.Fprintf(&b, "  label=<<font face=\"Helvetica Neue,Helvetica\" point-size=\"8\" color=\"%s\">%s</font>>;\n",
			t.TextColor, dotEscape(title))
	}
	b.WriteByte('\n')

	writeNode := func(name string) {
		id := dotID(name)
		label := truncLabel(name, 50)
		if entrySet[name] {
			fmt.Fprintf(&b, "    %s [label=%q, penwidth=1.5, color=%q];\n", id, label, t.EdgeTHR)
		} else {
			fmt.Fprintf(&b, "    %s [label=%q];\n", id, label)
		}
	}

	// Clustered nodes.
	owners := make([]string, 0, len(ownerFuncs))
	for owner := range ownerFuncs {
		owners = append(owners, owner)
	}
	sort.Strings(owners)
	for _, owner := range owners {
		names := ownerFuncs[owner]
		if len(names) < 2 {
			noOwner = append(noOwner, names...)
			continue
		}
		sort.Strings(names)
		clusterID := "cluster_" + dotID(owner)
		fmt.Fprintf(&b, "  subgraph %s {\n", clusterID)
		fmt.Fprintf(&b, "    label=<<font point-size=\"8\" color=\"%s\">%s</font>>;\n",
			t.ClusterLabel, dotEscape(stripOwnerHash(owner)))
		fmt.Fprintf(&b, "    style=dotted; color=%q; penwidth=0.3;\n", t.ClusterBorder)
		for _, name := range names {
			writeNode(name)
		}
		b.WriteString("  }\n")
	}
	sort.Strings(noOwner)
	for _, name := range noOwner {
		b.WriteString("  ")
		writeNode(name)
	}
	b.WriteByte('\n')

	// Edges.
	type edgeEntry struct {
		key   edgeKey
		count int
	}
	edgesSorted := make([]edgeEntry, 0, len(edgeCount))
	for k, count := range edgeCount {
		edgesSorted = append(edgesSorted, edgeEntry{k, count})
	}
	sort.Slice(edgesSorted, func(i, j int) bool {
		if edgesSorted[i].key.from != edgesSorted[j].key.from {
			return edgesSorted[i].key.from < edgesSorted[j].key.from
		}
		if edgesSorted[i].key.to != edgesSorted[j].key.to {
			return edgesSorted[i].key.to < edgesSorted[j].key.to
		}
		return edgesSorted[i].key.prov < edgesSorted[j].key.prov
	})
	for _, edge := range edgesSorted {
		k, count := edge.key, edge.count
		fromID := dotID(k.from)
		toID := dotID(k.to)
		attrs := fmt.Sprintf("color=%q, style=%q", edgeColor(k.prov, t), edgeStyle(k.prov))
		if count > 1 {
			attrs += fmt.Sprintf(", penwidth=%.1f", 0.5+float64(count)*0.1)
		}
		fmt.Fprintf(&b, "  %s -> %s [%s];\n", fromID, toID, attrs)
	}

	b.WriteString("}\n")
	return b.String()
}
