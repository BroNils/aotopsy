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
	return inspectCallSite(e).StaticTargets
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

// FindRootCandidates returns the functions in source strongly-connected
// components of the resolved static call graph. For an acyclic component this
// is the familiar "no incoming call" root. For a root cycle there is no honest
// single entry point, so every member is returned as a candidate rather
// than making the entire cycle disappear from reachability.
//
// These are structural root candidates, not a claim that Dart/VM metadata proved
// a language-level entry point.
func FindRootCandidates(funcs []disasm.FuncRecord, edges []disasm.CallEdgeRecord) []string {
	funcSet := make(map[string]bool, len(funcs))
	for _, f := range funcs {
		funcSet[f.Name] = true
	}

	adj := make(map[string][]string, len(funcs))
	for _, e := range edges {
		if !funcSet[e.FromFunc] || !isSupportedCallKind(e.Kind) {
			continue
		}
		seen := make(map[string]bool)
		for _, target := range concreteCallTargets(e) {
			if funcSet[target] && !seen[target] {
				seen[target] = true
				adj[e.FromFunc] = append(adj[e.FromFunc], target)
			}
		}
		sort.Strings(adj[e.FromFunc])
	}

	// Tarjan SCC. Function names are visited in lexical order so the result is
	// independent of functions.jsonl ordering.
	names := make([]string, 0, len(funcSet))
	for name := range funcSet {
		names = append(names, name)
	}
	sort.Strings(names)
	index := 0
	indices := make(map[string]int, len(names))
	lowlink := make(map[string]int, len(names))
	onStack := make(map[string]bool, len(names))
	stack := make([]string, 0, len(names))
	componentOf := make(map[string]int, len(names))
	var components [][]string
	var strongConnect func(string)
	strongConnect = func(v string) {
		indices[v] = index + 1 // zero means unseen
		lowlink[v] = index + 1
		index++
		stack = append(stack, v)
		onStack[v] = true
		for _, w := range adj[v] {
			if indices[w] == 0 {
				strongConnect(w)
				if lowlink[w] < lowlink[v] {
					lowlink[v] = lowlink[w]
				}
			} else if onStack[w] && indices[w] < lowlink[v] {
				lowlink[v] = indices[w]
			}
		}
		if lowlink[v] != indices[v] {
			return
		}
		componentID := len(components)
		var component []string
		for {
			w := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			onStack[w] = false
			componentOf[w] = componentID
			component = append(component, w)
			if w == v {
				break
			}
		}
		sort.Strings(component)
		components = append(components, component)
	}
	for _, name := range names {
		if indices[name] == 0 {
			strongConnect(name)
		}
	}

	hasIncomingComponent := make([]bool, len(components))
	for from, targets := range adj {
		fromComp := componentOf[from]
		for _, to := range targets {
			toComp := componentOf[to]
			if fromComp != toComp {
				hasIncomingComponent[toComp] = true
			}
		}
	}

	var roots []string
	for componentID, component := range components {
		if hasIncomingComponent[componentID] {
			continue
		}
		roots = append(roots, component...)
	}
	sort.Strings(roots)
	return roots
}

// ReachabilityResult is the structural closure of the observed static graph from
// all source SCC candidates. Functions contains only identities present in
// functions.jsonl. Because every finite SCC DAG has a source, this closure covers
// the known graph; it is not evidence that every function is reachable from a VM
// or language-level program entry. Completeness counters describe missing call
// relations that the static artifacts could not recover.
type ReachabilityResult struct {
	Functions                  map[string]bool
	IncompletePolymorphicSites int
	UnknownCandidateCountSites int
	UnresolvedIndirectSites    int
	UnsupportedCallSites       int
}

// ReachableSet computes the observed static graph's structural closure from its
// source SCC candidates. Runtime observations are deliberately excluded; they
// are execution evidence, not proof of a static relation. External target names
// are also excluded from Functions because the population is functions.jsonl.
func ReachableSet(funcs []disasm.FuncRecord, rootCandidates []string, edges []disasm.CallEdgeRecord) ReachabilityResult {
	funcSet := make(map[string]bool, len(funcs))
	for _, f := range funcs {
		funcSet[f.Name] = true
	}
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
		if !funcSet[e.FromFunc] || !isSupportedCallKind(e.Kind) {
			continue
		}
		seen := make(map[string]bool)
		for _, target := range concreteCallTargets(e) {
			if funcSet[target] && !seen[target] {
				seen[target] = true
				adj[e.FromFunc] = append(adj[e.FromFunc], target)
			}
		}
		sort.Strings(adj[e.FromFunc])
	}

	reachable := make(map[string]bool)
	queue := make([]string, 0, len(rootCandidates))
	for _, ep := range rootCandidates {
		if funcSet[ep] && !reachable[ep] {
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

	result := ReachabilityResult{Functions: reachable}
	incompleteSites := make(map[string]bool)
	unknownCandidateSites := make(map[string]bool)
	unresolvedSites := make(map[string]bool)
	unsupportedSites := make(map[string]bool)
	for edgeIndex, e := range edges {
		if !reachable[e.FromFunc] {
			continue
		}
		siteKey := callSitePopulationKey(e, edgeIndex)
		if !isSupportedCallKind(e.Kind) {
			unsupportedSites[siteKey] = true
			continue
		}
		if e.Kind != "blr" && e.Kind != "call_indirect" {
			continue
		}
		sem := inspectCallSite(e)
		if sem.Unresolved {
			unresolvedSites[siteKey] = true
		}
		if sem.omittedCandidates() > 0 {
			incompleteSites[siteKey] = true
		}
		if sem.candidateCountUnknown() {
			unknownCandidateSites[siteKey] = true
		}
	}
	result.IncompletePolymorphicSites = len(incompleteSites)
	result.UnknownCandidateCountSites = len(unknownCandidateSites)
	result.UnresolvedIndirectSites = len(unresolvedSites)
	result.UnsupportedCallSites = len(unsupportedSites)
	return result
}

// ReachabilityDOT renders the observed static structural closure. Root candidates
// are highlighted, and incompleteness is stated explicitly when an included
// indirect site has unresolved or truncated targets.
func ReachabilityDOT(funcs []disasm.FuncRecord, edges []disasm.CallEdgeRecord, reach ReachabilityResult, rootCandidates []string, title string, t Theme) string {
	reachable := reach.Functions
	rootSet := make(map[string]bool, len(rootCandidates))
	for _, root := range rootCandidates {
		rootSet[root] = true
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
	// Also include structural roots even if they have no edges.
	for _, root := range rootCandidates {
		if reachable[root] {
			refNodes[root] = true
		}
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
		if rootSet[name] {
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

	if reach.IncompletePolymorphicSites > 0 || reach.UnknownCandidateCountSites > 0 || reach.UnresolvedIndirectSites > 0 || reach.UnsupportedCallSites > 0 {
		note := fmt.Sprintf("static structural closure is incomplete: %d incomplete polymorphic site(s), %d unknown candidate-count site(s), %d unresolved indirect site(s), %d unsupported call-kind site(s)",
			reach.IncompletePolymorphicSites, reach.UnknownCandidateCountSites, reach.UnresolvedIndirectSites, reach.UnsupportedCallSites)
		fmt.Fprintf(&b, "  %s [label=%q, shape=note, style=\"filled\", fillcolor=%q, color=%q, fontcolor=%q, fontsize=8];\n",
			dotID("\x00reachability-completeness"), note, t.StubFill, t.EdgeUnresolved, t.TextColor)
	}

	b.WriteString("}\n")
	return b.String()
}
