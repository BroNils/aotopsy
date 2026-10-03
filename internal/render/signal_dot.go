package render

import (
	"fmt"
	"sort"
	"strings"

	"aotopsy/internal/signal"
)

// SignalDOT renders a focused callgraph showing paths from structural roots to signal functions.
// Uses forward BFS from root candidates, traces shortest paths to each reachable signal function,
// includes all intermediate nodes. Signal functions show their referenced strings as leaf nodes.
// Runtime/external/unresolved evidence is rendered separately and never traversed as a static edge.
func SignalDOT(g *signal.SignalGraph, title string, t Theme) string {
	// Index functions and collect string refs.
	type funcInfo struct {
		role       string
		severity   string
		isRoot     bool
		categories []string
		owner      string
		stringRefs []signal.ClassifiedStringRef
	}
	funcMap := make(map[string]*funcInfo, len(g.Funcs))
	for _, f := range g.Funcs {
		funcMap[f.Name] = &funcInfo{
			role:       f.Role,
			severity:   f.Severity,
			isRoot:     f.IsRootCandidate,
			categories: f.Categories,
			owner:      f.Owner,
			stringRefs: f.StringRefs,
		}
	}
	validEdges := signalTraversalEdges(g)

	// Build complete adjacency. Indirect/polymorphic targets have already been
	// expanded into SignalEdge records by signal.BuildSignalGraph, so traversal
	// must not drop them here.
	fwd := make(map[string][]signal.SignalEdge)
	for _, e := range validEdges {
		if e.To == "" {
			continue
		}
		fwd[e.From] = append(fwd[e.From], e)
	}
	for from := range fwd {
		sort.Slice(fwd[from], func(i, j int) bool {
			a, b := fwd[from][i], fwd[from][j]
			if a.To != b.To {
				return a.To < b.To
			}
			if a.Kind != b.Kind {
				return a.Kind < b.Kind
			}
			return a.Via < b.Via
		})
	}

	// Find high+medium severity signal functions.
	signalSet := make(map[string]bool)
	for _, f := range g.Funcs {
		if f.Role == "signal" && (f.Severity == "high" || f.Severity == "medium") {
			signalSet[f.Name] = true
		}
	}
	if len(signalSet) == 0 {
		for _, f := range g.Funcs {
			if f.Role == "signal" {
				signalSet[f.Name] = true
			}
		}
	}

	// Forward BFS from producer-supplied structural root candidates. The signal
	// graph schema owns root semantics; the renderer must not invent a second
	// policy from partial edge data. The visited set bounds cycles without an
	// arbitrary depth cap that would hide legitimate deep paths.
	parent := make(map[string]string) // child → parent
	dist := make(map[string]int)

	type bfsItem struct {
		name string
		d    int
	}
	var roots []string
	for _, f := range g.Funcs {
		if f.IsRootCandidate {
			roots = append(roots, f.Name)
		}
	}
	sort.Strings(roots)
	var queue []bfsItem
	for _, root := range roots {
		if _, ok := dist[root]; !ok {
			dist[root] = 0
			queue = append(queue, bfsItem{root, 0})
		}
	}
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		for _, edge := range fwd[item.name] {
			next := edge.To
			if _, ok := dist[next]; !ok {
				dist[next] = item.d + 1
				parent[next] = item.name
				queue = append(queue, bfsItem{next, item.d + 1})
			}
		}
	}

	// For each reachable signal function, trace back to the structural root.
	pathNodes := make(map[string]bool)
	reachableSignals := 0
	for name := range signalSet {
		if _, ok := dist[name]; !ok {
			continue // unreachable from any structural root
		}
		reachableSignals++
		cur := name
		for cur != "" {
			pathNodes[cur] = true
			p, ok := parent[cur]
			if !ok {
				break // reached a structural root (no parent)
			}
			cur = p
		}
	}

	// Also add every edge-connected signal function for intra-signal structure.
	for _, e := range validEdges {
		if e.To != "" && signalSet[e.From] && signalSet[e.To] {
			pathNodes[e.From] = true
			pathNodes[e.To] = true
		}
	}

	_ = reachableSignals

	// Render the exact induced edge set among selected nodes. Do not collapse
	// context chains: doing so changes graph semantics and can turn an indirect
	// path into a visually direct edge.
	type pathEdge struct{ from, to, kind, via string }
	seenEdges := make(map[pathEdge]bool)
	var pathEdges []pathEdge
	for _, e := range validEdges {
		if e.To == "" || e.From == e.To || !pathNodes[e.From] || !pathNodes[e.To] {
			continue
		}
		pe := pathEdge{e.From, e.To, e.Kind, e.Via}
		if !seenEdges[pe] {
			seenEdges[pe] = true
			pathEdges = append(pathEdges, pe)
		}
	}
	sort.Slice(pathEdges, func(i, j int) bool {
		a, b := pathEdges[i], pathEdges[j]
		if a.from != b.from {
			return a.from < b.from
		}
		if a.to != b.to {
			return a.to < b.to
		}
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		return a.via < b.via
	})

	// Collect string ref nodes for signal functions in the path.
	// Deduplicate by value per function, cap at 5 strings per function.
	type strNode struct {
		id    string // unique DOT id
		label string
		cat   string // primary category
	}
	const maxStrPerFunc = 5
	var strNodes []strNode
	strEdges := make(map[[2]string]bool) // func DOT id → str DOT id
	strIdx := 0
	// Sorted: strIdx numbers the emitted str_N nodes, so map order would
	// rename every string node between runs.
	for _, name := range sortedSet(pathNodes) {
		fi := funcMap[name]
		if fi == nil || !signalSet[name] || len(fi.stringRefs) == 0 {
			continue
		}
		seen := make(map[string]bool)
		count := 0
		uniqueCount := 0
		for _, sr := range fi.stringRefs {
			if seen[sr.Value] {
				continue
			}
			seen[sr.Value] = true
			uniqueCount++
			if count >= maxStrPerFunc {
				continue
			}
			count++
			sid := fmt.Sprintf("str_%d", strIdx)
			strIdx++
			label := truncLabel(sr.Value, 60)
			cat := ""
			if len(sr.Categories) > 0 {
				cat = sr.Categories[0]
			}
			strNodes = append(strNodes, strNode{id: sid, label: label, cat: cat})
			strEdges[[2]string{dotID(name), sid}] = true
		}
		if uniqueCount > count {
			sid := fmt.Sprintf("str_%d", strIdx)
			strIdx++
			more := uniqueCount - count
			strNodes = append(strNodes, strNode{id: sid, label: fmt.Sprintf("+%d more", more)})
			strEdges[[2]string{dotID(name), sid}] = true
		}
	}

	// Render DOT.
	var b strings.Builder
	b.WriteString("digraph signal {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  compound=true;\n")
	b.WriteString("  splines=true;\n")
	b.WriteString("  nodesep=0.3;\n")
	b.WriteString("  ranksep=0.5;\n")
	fmt.Fprintf(&b, "  bgcolor=%q;\n", t.Background)
	fmt.Fprintf(&b, "  node [shape=rect, style=filled, fillcolor=%q, color=%q, penwidth=0.5, fontname=\"Helvetica Neue,Helvetica,Arial\", fontsize=9, fontcolor=%q, height=0.3, margin=\"0.10,0.05\"];\n",
		t.NodeFill, t.NodeBorder, t.TextColor)
	fmt.Fprintf(&b, "  edge [penwidth=0.6, arrowsize=0.5, arrowhead=vee, color=%q];\n", t.EdgeDirect)
	if title != "" {
		fmt.Fprintf(&b, "  labelloc=t; labeljust=l;\n")
		fmt.Fprintf(&b, "  label=<<font face=\"Helvetica Neue,Helvetica\" point-size=\"9\" color=\"%s\">%s</font>>;\n",
			t.TextColor, dotEscape(title))
	}
	b.WriteByte('\n')

	// Group by owner for clustering.
	ownerNodes := make(map[string][]string)
	var noOwner []string
	for _, name := range sortedSet(pathNodes) {
		fi := funcMap[name]
		if fi != nil && fi.owner != "" {
			ownerNodes[fi.owner] = append(ownerNodes[fi.owner], name)
		} else {
			noOwner = append(noOwner, name)
		}
	}

	writeNode := func(name string) {
		fi := funcMap[name]
		id := dotID(name)
		label := truncLabel(name, 40)
		attrs := ""

		if signalSet[name] {
			switch fi.severity {
			case "high":
				attrs = `, fillcolor="#FCE4EC", color="#C62828", penwidth=1.5, fontcolor="#C62828"`
			case "medium":
				attrs = `, fillcolor="#FFF3E0", color="#E65100", penwidth=1.2, fontcolor="#E65100"`
			default:
				attrs = `, fillcolor="#E3F2FD", color="#1565C0", penwidth=1.0`
			}
			if len(fi.categories) > 0 {
				cats := truncLabel(strings.Join(fi.categories, ","), 30)
				label += "\\n" + cats
			}
		} else if fi != nil && fi.isRoot {
			attrs = fmt.Sprintf(`, fillcolor="#E8F5E9", color="%s", penwidth=1.2`, t.EdgeTHR)
		} else {
			// Intermediate context node.
			attrs = `, fillcolor="#F5F5F5", color="#BDBDBD", fontcolor="#757575"`
		}

		fmt.Fprintf(&b, "    %s [label=%q%s];\n", id, label, attrs)
	}

	owners := make([]string, 0, len(ownerNodes))
	for owner := range ownerNodes {
		owners = append(owners, owner)
	}
	sort.Strings(owners)
	for _, owner := range owners {
		names := ownerNodes[owner]
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

	// String literal nodes.
	if len(strNodes) > 0 {
		b.WriteString("  // String literals\n")
		for _, sn := range strNodes {
			color := "#C2185B" // pink
			switch sn.cat {
			case "crypto", "encryption":
				color = "#C62828" // red
			case "auth":
				color = "#AD1457" // dark pink
			case "url", "host":
				color = "#0B3D91" // blue
			case "cloaking", "sim", "sms", "contacts":
				color = "#C62828" // red
			}
			fmt.Fprintf(&b, "  %s [shape=rect, style=\"filled,rounded\", fillcolor=\"#FFF8E1\", color=%q, penwidth=0.3, fontsize=7, fontcolor=%q, fontname=\"Courier,monospace\", margin=\"0.06,0.03\", height=0.2, label=%q];\n",
				sn.id, color, color, sn.label)
		}
		b.WriteByte('\n')
	}

	// Preserve direct vs indirect semantics in the selected subgraph.
	for _, e := range pathEdges {
		fromID := dotID(e.from)
		toID := dotID(e.to)
		if e.kind == "blr" || e.kind == "call_indirect" {
			via := truncLabel(e.via, 20)
			attrs := fmt.Sprintf("style=dashed, color=%q, penwidth=0.5", t.EdgePP)
			if via != "" {
				attrs += fmt.Sprintf(", label=%q, fontsize=7, fontcolor=%q", via, t.ClusterLabel)
			}
			fmt.Fprintf(&b, "  %s -> %s [%s];\n", fromID, toID, attrs)
		} else {
			attrs := fmt.Sprintf("color=%q", t.EdgeDirect)
			if signalSet[e.to] {
				attrs = fmt.Sprintf("color=%q, penwidth=1.0", t.EdgeTHR)
			}
			fmt.Fprintf(&b, "  %s -> %s [%s];\n", fromID, toID, attrs)
		}
	}

	// String ref edges — dotted, thin.
	for _, edge := range sortedPairs(strEdges) {
		fmt.Fprintf(&b, "  %s -> %s [style=dotted, arrowsize=0.3, penwidth=0.4, color=\"#C2185B\"];\n",
			edge[0], edge[1])
	}
	writeSignalEvidenceRelations(&b, signalEvidenceRelations(g, pathNodes), t)
	writeSignalCompletenessNote(&b, g, t)

	b.WriteString("}\n")
	return b.String()
}

func writeSignalCompletenessNote(b *strings.Builder, g *signal.SignalGraph, t Theme) {
	if g == nil {
		return
	}
	stats := g.Stats
	if stats.IncompletePolymorphicSites == 0 && stats.UnknownCandidateCountSites == 0 && stats.UnresolvedIndirectSites == 0 && stats.RuntimeObservedSites == 0 {
		return
	}
	label := fmt.Sprintf("static signal graph: %d incomplete polymorphic site(s), %d unknown candidate-count site(s), %d unresolved indirect site(s); runtime evidence on %d site(s) is not promoted to static reachability",
		stats.IncompletePolymorphicSites, stats.UnknownCandidateCountSites, stats.UnresolvedIndirectSites, stats.RuntimeObservedSites)
	fmt.Fprintf(b, "  %s [label=%q, shape=note, style=\"filled\", fillcolor=%q, color=%q, fontcolor=%q, fontsize=8];\n",
		dotID("\x00signal-completeness"), label, t.StubFill, t.EdgeUnresolved, t.TextColor)
}

// sortedSet returns a set's keys in a stable order.
//
// Every rendered artifact has to be byte-identical across runs -- the golden
// gate compares hashes, and a graph that wobbles makes any diff unreadable.
// signal.dot and signal_cfg.dot are not in the golden manifest, which is
// exactly why four `for k := range someMap` loops here went unnoticed: one of
// them deleted nodes while iterating, so the graph's SHAPE differed run to
// run, not just its line order.
func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedPairs returns an edge set's keys in a stable order.
func sortedPairs(m map[[2]string]bool) [][2]string {
	out := make([][2]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a][0] != out[b][0] {
			return out[a][0] < out[b][0]
		}
		return out[a][1] < out[b][1]
	})
	return out
}
