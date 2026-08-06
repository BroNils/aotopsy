package render

import (
	"fmt"
	"sort"
	"strings"

	"aotopsy/internal/signal"
)

// SignalDOT renders a focused callgraph showing paths from entry points to signal functions.
// Uses forward BFS from entry points, traces shortest paths to each reachable signal function,
// includes all intermediate nodes. Signal functions show their referenced strings as leaf nodes.
// BLR (indirect call) edges between path nodes are shown with dashed lines.
func SignalDOT(g *signal.SignalGraph, title string, t Theme) string {
	// Index functions and collect string refs.
	type funcInfo struct {
		role       string
		severity   string
		isEntry    bool
		categories []string
		owner      string
		stringRefs []signal.ClassifiedStringRef
	}
	funcMap := make(map[string]*funcInfo, len(g.Funcs))
	for _, f := range g.Funcs {
		funcMap[f.Name] = &funcInfo{
			role:       f.Role,
			severity:   f.Severity,
			isEntry:    f.IsEntryPoint,
			categories: f.Categories,
			owner:      f.Owner,
			stringRefs: f.StringRefs,
		}
	}

	// Build BL and BLR adjacency.
	fwd := make(map[string][]string)       // BL only
	blrEdges := make(map[[2]string]string) // [from,to] → via label
	for _, e := range g.Edges {
		if e.To == "" {
			continue
		}
		if e.Kind == "bl" || e.Kind == "call" {
			fwd[e.From] = append(fwd[e.From], e.To)
		} else if e.Kind == "blr" || e.Kind == "call_indirect" {
			key := [2]string{e.From, e.To}
			if _, ok := blrEdges[key]; !ok {
				blrEdges[key] = e.Via
			}
		}
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

	// Build reverse adjacency to find true roots (no BL callers).
	hasCaller := make(map[string]bool)
	for _, e := range g.Edges {
		if (e.Kind == "bl" || e.Kind == "call") && e.To != "" {
			hasCaller[e.To] = true
		}
	}

	// Forward BFS from all root functions (no incoming BL edges).
	parent := make(map[string]string) // child → parent
	dist := make(map[string]int)
	maxDist := 8

	type bfsItem struct {
		name string
		d    int
	}
	var queue []bfsItem
	for _, f := range g.Funcs {
		if !hasCaller[f.Name] {
			if _, ok := dist[f.Name]; !ok {
				dist[f.Name] = 0
				queue = append(queue, bfsItem{f.Name, 0})
			}
		}
	}
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		if item.d >= maxDist {
			continue
		}
		for _, next := range fwd[item.name] {
			if _, ok := dist[next]; !ok {
				dist[next] = item.d + 1
				parent[next] = item.name
				queue = append(queue, bfsItem{next, item.d + 1})
			}
		}
	}

	// For each reachable signal function, trace back to the entry point.
	pathNodes := make(map[string]bool)
	pathEdges := make(map[[2]string]bool)
	for name := range signalSet {
		if _, ok := dist[name]; !ok {
			continue // unreachable from any entry point
		}
		cur := name
		for cur != "" {
			pathNodes[cur] = true
			p, ok := parent[cur]
			if !ok {
				break // reached an entry point (no parent)
			}
			pathEdges[[2]string{p, cur}] = true
			cur = p
		}
	}

	// Also add direct edges between signal functions for intra-signal structure.
	for _, e := range g.Edges {
		if (e.Kind == "bl" || e.Kind == "call") && signalSet[e.From] && signalSet[e.To] {
			pathNodes[e.From] = true
			pathNodes[e.To] = true
			pathEdges[[2]string{e.From, e.To}] = true
		}
	}

	// Include signal functions that are roots (no callers).
	for name := range signalSet {
		if !hasCaller[name] {
			pathNodes[name] = true
		}
	}

	// If no paths found (signal funcs unreachable from entry points),
	// just show signal funcs and their 1-hop neighbors.
	if len(pathEdges) == 0 {
		for name := range signalSet {
			pathNodes[name] = true
			for _, callee := range fwd[name] {
				pathNodes[callee] = true
				pathEdges[[2]string{name, callee}] = true
			}
		}
	}

	// Prune long chains: collapse intermediate nodes that are neither
	// entry points nor signal functions and have exactly 1 in + 1 out edge.
	for changed := true; changed; {
		changed = false
		for name := range pathNodes {
			fi := funcMap[name]
			if fi == nil {
				continue
			}
			if !hasCaller[name] || signalSet[name] || fi.role == "signal" {
				continue
			}
			var ins, outs [][2]string
			for e := range pathEdges {
				if e[1] == name {
					ins = append(ins, e)
				}
				if e[0] == name {
					outs = append(outs, e)
				}
			}
			if len(ins) == 1 && len(outs) == 1 {
				from := ins[0][0]
				to := outs[0][1]
				delete(pathEdges, ins[0])
				delete(pathEdges, outs[0])
				pathEdges[[2]string{from, to}] = true
				delete(pathNodes, name)
				changed = true
			}
		}
	}

	// Collect BLR edges between path nodes.
	type blrEdge struct {
		from, to, via string
	}
	var pathBLR []blrEdge
	for key, via := range blrEdges {
		if pathNodes[key[0]] && pathNodes[key[1]] && key[0] != key[1] {
			// Skip if a BL edge already exists for this pair.
			if !pathEdges[key] {
				pathBLR = append(pathBLR, blrEdge{key[0], key[1], via})
			}
		}
	}

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
	for name := range pathNodes {
		fi := funcMap[name]
		if fi == nil || !signalSet[name] || len(fi.stringRefs) == 0 {
			continue
		}
		seen := make(map[string]bool)
		count := 0
		for _, sr := range fi.stringRefs {
			if seen[sr.Value] || count >= maxStrPerFunc {
				continue
			}
			seen[sr.Value] = true
			count++
			sid := fmt.Sprintf("str_%d", strIdx)
			strIdx++
			label := sr.Value
			if len(label) > 60 {
				label = label[:57] + "..."
			}
			cat := ""
			if len(sr.Categories) > 0 {
				cat = sr.Categories[0]
			}
			strNodes = append(strNodes, strNode{id: sid, label: label, cat: cat})
			strEdges[[2]string{dotID(name), sid}] = true
		}
		if len(fi.stringRefs) > maxStrPerFunc && count == maxStrPerFunc {
			sid := fmt.Sprintf("str_%d", strIdx)
			strIdx++
			more := len(fi.stringRefs) - maxStrPerFunc
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
	for name := range pathNodes {
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
				cats := strings.Join(fi.categories, ",")
				if len(cats) > 30 {
					cats = cats[:30] + "..."
				}
				label += "\\n" + cats
			}
		} else if !hasCaller[name] {
			attrs = fmt.Sprintf(`, fillcolor="#E8F5E9", color="%s", penwidth=1.2`, t.EdgeTHR)
		} else {
			// Intermediate context node.
			attrs = `, fillcolor="#F5F5F5", color="#BDBDBD", fontcolor="#757575"`
		}

		fmt.Fprintf(&b, "    %s [label=%q%s];\n", id, label, attrs)
	}

	for owner, names := range ownerNodes {
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

	// BL edges (direct calls).
	for edge := range pathEdges {
		fromID := dotID(edge[0])
		toID := dotID(edge[1])
		attrs := fmt.Sprintf("color=%q", t.EdgeDirect)
		if signalSet[edge[1]] {
			attrs = fmt.Sprintf("color=%q, penwidth=1.0", t.EdgeTHR)
		}
		fmt.Fprintf(&b, "  %s -> %s [%s];\n", fromID, toID, attrs)
	}

	// BLR edges (indirect calls) — dashed.
	for _, e := range pathBLR {
		fromID := dotID(e.from)
		toID := dotID(e.to)
		via := e.via
		if len(via) > 20 {
			via = via[:20]
		}
		attrs := fmt.Sprintf("style=dashed, color=%q, penwidth=0.5", t.EdgePP)
		if via != "" {
			attrs += fmt.Sprintf(", label=%q, fontsize=7, fontcolor=%q", via, t.ClusterLabel)
		}
		fmt.Fprintf(&b, "  %s -> %s [%s];\n", fromID, toID, attrs)
	}

	// String ref edges — dotted, thin.
	for edge := range strEdges {
		fmt.Fprintf(&b, "  %s -> %s [style=dotted, arrowsize=0.3, penwidth=0.4, color=\"#C2185B\"];\n",
			edge[0], edge[1])
	}

	b.WriteString("}\n")
	return b.String()
}
