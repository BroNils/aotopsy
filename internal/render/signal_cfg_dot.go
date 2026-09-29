package render

import (
	"fmt"
	"sort"
	"strings"

	"aotopsy/internal/signal"
)

// ClassifiedString is a string ref with its signal category for rendering.
type ClassifiedString struct {
	Value    string
	Category string // primary category (e.g. "encryption", "auth", "url")
}

// SignalFuncContent holds the interesting calls and string refs for one signal function,
// collected by re-disassembly from bin files.
type SignalFuncContent struct {
	Calls   []string           // deduplicated callee names
	Strings []ClassifiedString // deduplicated classified string refs
}

// SignalCFGDOT renders a connected signal graph where each signal function is a node
// showing its interesting calls and string refs, and edges show how signal functions
// call each other (both directly and through intermediate context functions).
func SignalCFGDOT(g *signal.SignalGraph, content map[string]*SignalFuncContent, title string, t Theme) string {
	// Index functions.
	type funcInfo struct {
		severity   string
		categories []string
		owner      string
	}
	funcMap := make(map[string]*funcInfo, len(g.Funcs))
	signalSet := make(map[string]bool)
	for _, f := range g.Funcs {
		funcMap[f.Name] = &funcInfo{
			severity:   f.Severity,
			categories: f.Categories,
			owner:      f.Owner,
		}
		if f.Role == "signal" {
			signalSet[f.Name] = true
		}
	}
	validEdges := validSignalEdges(g)

	// Build forward adjacency from every resolved edge. SignalGraph has already
	// expanded polymorphic indirect candidates, so dropping BLR/call_indirect
	// here would make the "through context" path search semantically incomplete.
	fwd := make(map[string][]signal.SignalEdge)
	for _, e := range validEdges {
		if e.To != "" {
			fwd[e.From] = append(fwd[e.From], e)
		}
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

	// Find direct signal→signal edges (BL and BLR).
	type edgeInfo struct {
		from, to string
		kind     string // exact call kind, "path", or "path_indirect"
		via      string
	}
	var signalEdges []edgeInfo
	edgeSeen := make(map[[3]string]bool)

	for _, e := range validEdges {
		if e.To == "" {
			continue
		}
		from, to := e.From, e.To
		if !signalSet[from] || !signalSet[to] {
			continue
		}
		key := [3]string{from, to, e.Kind}
		if edgeSeen[key] {
			continue
		}
		edgeSeen[key] = true
		signalEdges = append(signalEdges, edgeInfo{from, to, e.Kind, e.Via})
	}

	// BFS from each signal function through context nodes to find signal→signal reachability.
	// This captures indirect paths: signal_A → context → context → signal_B.
	// Sorted: signalEdges is appended to in this order and rendered in
	// order, so map iteration would reorder the graph between runs.
	for _, src := range sortedSet(signalSet) {
		type pathState struct {
			name       string
			indirect   bool
			hasContext bool
		}
		visited := map[pathState]bool{{name: src}: true}
		queue := []pathState{{name: src}}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, edge := range fwd[cur.name] {
				next := edge.To
				nextState := pathState{
					name:       next,
					indirect:   cur.indirect || edge.Kind == "blr" || edge.Kind == "call_indirect",
					hasContext: cur.hasContext || !signalSet[next],
				}
				if visited[nextState] {
					continue
				}
				visited[nextState] = true
				if signalSet[next] {
					if !nextState.hasContext {
						continue // exact signal→signal call; already represented above
					}
					// Found a path from src to next signal function. Keep a
					// transitive path visually distinct from an exact call and retain
					// whether any hop was indirect.
					kind := "path"
					if nextState.indirect {
						kind = "path_indirect"
					}
					key := [3]string{src, next, kind}
					if !edgeSeen[key] {
						edgeSeen[key] = true
						signalEdges = append(signalEdges, edgeInfo{src, next, kind, ""})
					}
					// Don't continue BFS through signal nodes (they're their own roots).
				} else {
					// Context/other node — keep searching through it.
					queue = append(queue, nextState)
				}
			}
		}
	}
	sort.Slice(signalEdges, func(i, j int) bool {
		a, b := signalEdges[i], signalEdges[j]
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

	// Only render signal functions that have content or edges.
	hasEdge := make(map[string]bool)
	for _, e := range signalEdges {
		hasEdge[e.from] = true
		hasEdge[e.to] = true
	}
	activeSignal := make(map[string]bool)
	for name := range signalSet {
		if hasEdge[name] {
			activeSignal[name] = true
			continue
		}
		if c, ok := content[name]; ok && (len(c.Calls) > 0 || len(c.Strings) > 0) {
			activeSignal[name] = true
		}
	}

	// Render DOT.
	var b strings.Builder
	b.WriteString("digraph signal_cfg {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  compound=true;\n")
	b.WriteString("  splines=true;\n")
	b.WriteString("  nodesep=0.4;\n")
	b.WriteString("  ranksep=0.6;\n")
	fmt.Fprintf(&b, "  bgcolor=%q;\n", t.Background)
	fmt.Fprintf(&b, "  node [shape=plaintext, fontname=\"Helvetica Neue,Helvetica,Arial\", fontsize=9, fontcolor=%q];\n", t.TextColor)
	fmt.Fprintf(&b, "  edge [penwidth=0.7, arrowsize=0.5, arrowhead=vee, color=%q];\n", t.EdgeDirect)
	if title != "" {
		fmt.Fprintf(&b, "  labelloc=t; labeljust=l;\n")
		fmt.Fprintf(&b, "  label=<<font face=\"Helvetica Neue,Helvetica\" point-size=\"9\" color=\"%s\">%s</font>>;\n",
			t.TextColor, dotEscape(title))
	}
	b.WriteByte('\n')

	// Group by owner for clustering.
	ownerNodes := make(map[string][]string)
	var noOwner []string
	for _, name := range sortedSet(activeSignal) {
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
		label := truncLabel(name, 45)

		// Pick border/header color by severity.
		borderColor := "#1565C0" // blue (low/default)
		headerBG := "#E3F2FD"
		if fi != nil {
			switch fi.severity {
			case "high":
				borderColor = "#C62828"
				headerBG = "#FCE4EC"
			case "medium":
				borderColor = "#E65100"
				headerBG = "#FFF3E0"
			}
		}

		// Build HTML table label.
		var tbl strings.Builder
		tbl.WriteString("<<TABLE BORDER=\"1\" CELLBORDER=\"0\" CELLSPACING=\"0\" CELLPADDING=\"3\"")
		fmt.Fprintf(&tbl, " COLOR=%q BGCOLOR=\"white\"", borderColor)
		tbl.WriteString(">\n")

		// Header: function name + categories.
		fmt.Fprintf(&tbl, "    <TR><TD BGCOLOR=%q ALIGN=\"LEFT\"><FONT POINT-SIZE=\"9\" COLOR=%q><B>%s</B></FONT>",
			headerBG, borderColor, dotEscape(label))
		if fi != nil && len(fi.categories) > 0 {
			cats := truncLabel(strings.Join(fi.categories, ", "), 35)
			fmt.Fprintf(&tbl, "<BR/><FONT POINT-SIZE=\"7\" COLOR=\"#757575\">%s</FONT>", dotEscape(cats))
		}
		tbl.WriteString("</TD></TR>\n")

		// Calls section.
		c := content[name]
		if c != nil && len(c.Calls) > 0 {
			tbl.WriteString("    <HR/>\n")
			maxCalls := 8
			for i, callee := range c.Calls {
				if i >= maxCalls {
					fmt.Fprintf(&tbl, "    <TR><TD ALIGN=\"LEFT\"><FONT POINT-SIZE=\"7\" COLOR=\"#757575\">+%d more calls</FONT></TD></TR>\n",
						len(c.Calls)-maxCalls)
					break
				}
				cl := truncLabel(callee, 45)
				icon := "&#x2192;" // →
				fmt.Fprintf(&tbl, "    <TR><TD ALIGN=\"LEFT\"><FONT POINT-SIZE=\"7\" FACE=\"monospace\" COLOR=\"#424242\">%s %s</FONT></TD></TR>\n",
					icon, dotEscape(cl))
			}
		}

		// Strings section — classified with category colors.
		if c != nil && len(c.Strings) > 0 {
			tbl.WriteString("    <HR/>\n")
			maxStrs := 5
			for i, s := range c.Strings {
				if i >= maxStrs {
					fmt.Fprintf(&tbl, "    <TR><TD ALIGN=\"LEFT\"><FONT POINT-SIZE=\"7\" COLOR=\"#757575\">+%d more strings</FONT></TD></TR>\n",
						len(c.Strings)-maxStrs)
					break
				}
				sv := truncLabel(s.Value, 50)
				color := strCategoryColor(s.Category)
				catLabel := ""
				if s.Category != "" {
					catLabel = " [" + s.Category + "]"
				}
				fmt.Fprintf(&tbl, "    <TR><TD ALIGN=\"LEFT\"><FONT POINT-SIZE=\"7\" FACE=\"Courier\" COLOR=%q>\"%s\"%s</FONT></TD></TR>\n",
					color, dotEscape(sv), dotEscape(catLabel))
			}
		}

		tbl.WriteString("  </TABLE>>")
		fmt.Fprintf(&b, "    %s [label=%s];\n", id, tbl.String())
	}

	// Render clusters.
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

	// Render edges.
	for _, e := range signalEdges {
		fromID := dotID(e.from)
		toID := dotID(e.to)
		if e.kind == "blr" || e.kind == "call_indirect" {
			attrs := fmt.Sprintf("style=dashed, color=%q, penwidth=0.5", t.EdgePP)
			if e.via != "" {
				via := truncLabel(e.via, 20)
				attrs += fmt.Sprintf(", label=%q, fontsize=7, fontcolor=%q", via, t.ClusterLabel)
			}
			fmt.Fprintf(&b, "  %s -> %s [%s];\n", fromID, toID, attrs)
		} else if e.kind == "path" || e.kind == "path_indirect" {
			style := "dotted"
			label := "via context"
			if e.kind == "path_indirect" {
				style = "dashed"
				label = "via indirect/context"
			}
			fmt.Fprintf(&b, "  %s -> %s [style=%s, color=%q, penwidth=0.5, label=%q, fontsize=7, fontcolor=%q];\n",
				fromID, toID, style, t.EdgePP, label, t.ClusterLabel)
		} else {
			fmt.Fprintf(&b, "  %s -> %s [color=%q];\n", fromID, toID, t.EdgeDirect)
		}
	}

	b.WriteString("}\n")
	return b.String()
}

// strCategoryColor returns a DOT color for a signal string category.
func strCategoryColor(cat string) string {
	switch cat {
	case "crypto", "encryption":
		return "#C62828" // red
	case "auth":
		return "#AD1457" // dark pink
	case "url", "host":
		return "#0B3D91" // blue
	case "cloaking", "sim", "sms", "contacts":
		return "#C62828" // red
	case "device", "location":
		return "#E65100" // orange
	default:
		return "#C2185B" // pink
	}
}
