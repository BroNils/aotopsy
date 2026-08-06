package render

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"aotopsy/internal/disasm"
)

// stripOwnerHash removes the @hash suffix from Dart owner names.
// "_Future@5048458" → "_Future", "PlatformDispatcher" → "PlatformDispatcher".
func stripOwnerHash(s string) string {
	if i := strings.LastIndex(s, "@"); i > 0 {
		return s[:i]
	}
	return s
}

// ClassgraphDOT renders a class-level callgraph where each owner class is one node
// and edges represent aggregated inter-class calls. maxNodes limits rendered classes
// (0 = all). Functions without an owner are grouped under "(unowned)".
func ClassgraphDOT(funcs []disasm.FuncRecord, edges []disasm.CallEdgeRecord, title string, t Theme, maxNodes int) string {
	const unowned = "(unowned)"

	// Map function name → owner.
	funcOwner := make(map[string]string, len(funcs))
	ownerMethodCount := make(map[string]int)
	for _, f := range funcs {
		owner := f.Owner
		if owner == "" {
			owner = unowned
		}
		funcOwner[f.Name] = owner
		ownerMethodCount[owner]++
	}

	// Aggregate inter-class edges.
	// For BLR (indirect) edges, attempt to resolve the target class via
	// e.Via (the annotated call target name, e.g. "PP[36] foo" or
	// "THR.allocateArray_ep"). If Via matches a known function name in
	// funcOwner, use that function's owner as the destination class.
	// This makes inter-class indirect calls (virtual dispatch, dispatch
	// table) visible in the class graph. (P1-5 / G-014)
	type classEdge struct {
		from, to string
	}
	classCounts := make(map[classEdge]int)
	indirectCounts := make(map[classEdge]int) // separate count for indirect edges
	for _, e := range edges {
		srcOwner := funcOwner[e.FromFunc]
		if srcOwner == "" {
			srcOwner = unowned
		}

		// For BL/call edges, resolve target owner directly.
		// For BLR/call_indirect edges, try to resolve via the Via annotation.
		// x86_64 uses "call"/"call_indirect" edge kinds, ARM64 uses "bl"/"blr".
		var dstOwner string
		if (e.Kind == "bl" || e.Kind == "call") && e.Target != "" {
			dstOwner = funcOwner[e.Target]
			if dstOwner == "" {
				dstOwner = unowned
			}
		} else if (e.Kind == "blr" || e.Kind == "call_indirect") && e.Via != "" {
			// Try to resolve Via as a function name.
			dstOwner = funcOwner[e.Via]
			if dstOwner == "" {
				continue // Can't resolve target class — skip this indirect edge
			}
		} else {
			continue
		}

		if srcOwner == dstOwner {
			continue // skip intra-class calls
		}
		ce := classEdge{srcOwner, dstOwner}
		classCounts[ce]++
		if e.Kind == "blr" || e.Kind == "call_indirect" {
			indirectCounts[ce]++
		}
	}

	// Collect all classes involved in inter-class edges.
	classInvolvement := make(map[string]int) // total edges touching this class
	for ce, count := range classCounts {
		classInvolvement[ce.from] += count
		classInvolvement[ce.to] += count
	}

	// Rank classes by involvement for maxNodes limit.
	type rankedClass struct {
		name        string
		involvement int
	}
	ranked := make([]rankedClass, 0, len(classInvolvement))
	for name, inv := range classInvolvement {
		ranked = append(ranked, rankedClass{name, inv})
	}
	sort.Slice(ranked, func(i, j int) bool {
		return ranked[i].involvement > ranked[j].involvement
	})

	renderSet := make(map[string]bool)
	limit := len(ranked)
	if maxNodes > 0 && limit > maxNodes {
		limit = maxNodes
	}
	for _, rc := range ranked[:limit] {
		renderSet[rc.name] = true
	}

	// Build DOT.
	var b strings.Builder
	b.WriteString("digraph classgraph {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  splines=true;\n")
	b.WriteString("  nodesep=0.5;\n")
	b.WriteString("  ranksep=0.8;\n")
	fmt.Fprintf(&b, "  bgcolor=%q;\n", t.Background)
	fmt.Fprintf(&b, "  node [shape=rect, style=\"filled,rounded\", fillcolor=%q, color=%q, penwidth=0.5, fontname=\"Helvetica Neue,Helvetica,Arial\", fontsize=10, fontcolor=%q, height=0.4, margin=\"0.15,0.08\"];\n",
		t.NodeFill, t.NodeBorder, t.TextColor)
	fmt.Fprintf(&b, "  edge [penwidth=0.5, arrowsize=0.5, arrowhead=vee, color=%q];\n", t.EdgeDirect)
	if title != "" {
		fmt.Fprintf(&b, "  labelloc=t;\n  labeljust=l;\n")
		fmt.Fprintf(&b, "  label=<<font face=\"Helvetica Neue,Helvetica\" point-size=\"8\" color=\"%s\">%s</font>>;\n",
			t.TextColor, dotEscape(title))
	}
	b.WriteByte('\n')

	// Render class nodes.
	maxMethods := 1
	for name := range renderSet {
		if c := ownerMethodCount[name]; c > maxMethods {
			maxMethods = c
		}
	}
	for _, rc := range ranked[:limit] {
		name := rc.name
		id := dotID(name)
		label := stripOwnerHash(name)
		methods := ownerMethodCount[name]

		// Scale node height by method count (log scale).
		height := 0.4 + 0.3*math.Log2(float64(methods)+1)/math.Log2(float64(maxMethods)+1)

		// Subtitle with method count.
		htmlLabel := fmt.Sprintf("<<font point-size=\"10\">%s</font><br/><font point-size=\"7\" color=\"%s\">%d methods</font>>",
			dotEscape(label), t.ExternalText, methods)

		if name == unowned {
			fmt.Fprintf(&b, "  %s [label=%s, fillcolor=%q, height=%.2f];\n",
				id, htmlLabel, t.StubFill, height)
		} else {
			fmt.Fprintf(&b, "  %s [label=%s, height=%.2f];\n",
				id, htmlLabel, height)
		}
	}
	b.WriteByte('\n')

	// Render inter-class edges.
	maxEdgeCount := 1
	for ce := range classCounts {
		if !renderSet[ce.from] || !renderSet[ce.to] {
			continue
		}
		if c := classCounts[classEdge{ce.from, ce.to}]; c > maxEdgeCount {
			maxEdgeCount = c
		}
	}

	for ce, count := range classCounts {
		if !renderSet[ce.from] || !renderSet[ce.to] {
			continue
		}
		fromID := dotID(ce.from)
		toID := dotID(ce.to)

		pw := 0.5 + 2.0*math.Log2(float64(count)+1)/math.Log2(float64(maxEdgeCount)+1)
		attrs := fmt.Sprintf("penwidth=%.1f", pw)
		// If this edge has indirect (BLR) contributions, render as dotted
		// to distinguish direct from indirect inter-class coupling.
		if indirectCounts[ce] > 0 && indirectCounts[ce] == count {
			attrs += ", style=dotted"
		} else if indirectCounts[ce] > 0 {
			attrs += ", style=dashed"
		}
		if count > 1 {
			attrs += fmt.Sprintf(", label=<<font point-size=\"7\" color=\"%s\">%d</font>>",
				t.ExternalText, count)
		}
		fmt.Fprintf(&b, "  %s -> %s [%s];\n", fromID, toID, attrs)
	}

	b.WriteString("}\n")
	return b.String()
}
