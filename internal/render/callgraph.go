package render

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"aotopsy/internal/disasm"
)

// Provenance categories extracted from CallEdgeRecord.Via.
const (
	ProvTHR        = "thr"
	ProvPP         = "pp"
	ProvDispatch   = "dispatch_table"
	ProvObject     = "object_field"
	ProvDirect     = "direct"
	ProvUnresolved = "unresolved"
)

// ClassifyEdgeProv returns the provenance category for a call edge.
func ClassifyEdgeProv(e disasm.CallEdgeRecord) string {
	if e.Kind == "bl" || e.Kind == "call" {
		return ProvDirect
	}
	switch {
	case strings.HasPrefix(e.Via, "THR."):
		return ProvTHR
	case strings.HasPrefix(e.Via, "PP["):
		return ProvPP
	case e.Via == ProvDispatch:
		return ProvDispatch
	// Prefix, not equality: an object-field via carries the field offset
	// (`object_field+0x30`) so unresolved sites can be told apart. See
	// disasm.ObjectFieldViaAt.
	case strings.HasPrefix(e.Via, ProvObject):
		return ProvObject
	case e.Via == "":
		return ProvUnresolved
	default:
		return ProvUnresolved
	}
}

// edgeColor returns the DOT color for an edge provenance category.
func edgeColor(prov string, t Theme) string {
	switch prov {
	case ProvTHR:
		return t.EdgeTHR
	case ProvPP:
		return t.EdgePP
	case ProvDispatch:
		return t.EdgeDispatch
	case ProvObject:
		return t.EdgeObject
	case ProvDirect:
		return t.EdgeDirect
	case ProvUnresolved:
		return t.EdgeUnresolved
	default:
		return t.EdgeDirect
	}
}

// edgeStyle returns dot style attributes for provenance.
func edgeStyle(prov string) string {
	switch prov {
	case ProvDispatch:
		return "dotted"
	case ProvObject:
		return "dotted"
	case ProvUnresolved:
		return "dashed"
	default:
		return "solid"
	}
}

// CallgraphDOT renders a callgraph from functions and call edges as DOT.
// Only edges between known functions are rendered (internal edges).
// External targets (stubs, runtime) are shown as plaintext nodes.
// maxNodes limits the number of function nodes rendered (0 = all).
func CallgraphDOT(funcs []disasm.FuncRecord, edges []disasm.CallEdgeRecord, title string, t Theme, maxNodes int) string {
	// Build set of known function names.
	funcSet := make(map[string]bool, len(funcs))
	for _, f := range funcs {
		funcSet[f.Name] = true
	}

	// Deduplicate edges: caller→callee→prov.
	type edgeKey struct {
		from, to, prov string
	}
	type edgeVal struct {
		count int
	}
	dedupEdges := make(map[edgeKey]*edgeVal)

	for _, e := range edges {
		prov := ClassifyEdgeProv(e)
		targets := e.ResolvedTargets()
		if len(targets) == 0 {
			if e.Kind == "blr" || e.Kind == "call_indirect" {
				targets = []string{"unresolved_blr"}
			} else {
				continue
			}
		}
		for _, target := range targets {
			k := edgeKey{e.FromFunc, target, prov}
			if v, ok := dedupEdges[k]; ok {
				v.count++
			} else {
				dedupEdges[k] = &edgeVal{count: 1}
			}
		}
	}

	// Identify referenced nodes (callers + callees).
	refNodes := make(map[string]bool)
	for k := range dedupEdges {
		refNodes[k.from] = true
		refNodes[k.to] = true
	}

	// Filter to functions that participate in edges.
	var renderFuncs []disasm.FuncRecord
	for _, f := range funcs {
		if refNodes[f.Name] {
			renderFuncs = append(renderFuncs, f)
		}
	}
	if maxNodes > 0 && len(renderFuncs) > maxNodes {
		renderFuncs = renderFuncs[:maxNodes]
		// Rebuild funcSet to only include rendered functions.
		funcSet = make(map[string]bool, len(renderFuncs))
		for _, f := range renderFuncs {
			funcSet[f.Name] = true
		}
		// Filter dedupEdges to only edges where BOTH endpoints are in
		// funcSet OR the callee is a genuinely external node (not a
		// truncated function). Without this, truncated functions appear
		// as undeclared external nodes in the DOT output, which Graphviz
		// auto-creates with default styling — the maxNodes limit is
		// effectively bypassed for callees. (G-013)
		//
		// A callee is "genuinely external" if it's NOT in the original
		// funcSet (i.e., not a known function at all, just a stub/runtime
		// target). Truncated functions ARE in the original funcSet, so
		// they're distinguishable from real external nodes.
		origFuncSet := make(map[string]bool, len(funcs))
		for _, f := range funcs {
			origFuncSet[f.Name] = true
		}
		filteredEdges := make(map[edgeKey]*edgeVal, len(dedupEdges))
		for k, v := range dedupEdges {
			if !funcSet[k.from] {
				continue // edge from non-rendered function — skip
			}
			if !funcSet[k.to] && origFuncSet[k.to] {
				continue // callee is a truncated function — skip edge to avoid orphan
			}
			filteredEdges[k] = v
		}
		dedupEdges = filteredEdges
	}

	// Collect external nodes (targets not in funcSet, reachable from rendered funcs).
	externalNodes := make(map[string]bool)
	for k := range dedupEdges {
		if !funcSet[k.from] {
			continue // edge from non-rendered function — skip entirely
		}
		if !funcSet[k.to] {
			externalNodes[k.to] = true
		}
	}

	// Group rendered functions by owner for clustering.
	ownerFuncs := make(map[string][]disasm.FuncRecord)
	var noOwner []disasm.FuncRecord
	for _, f := range renderFuncs {
		if f.Owner != "" {
			ownerFuncs[f.Owner] = append(ownerFuncs[f.Owner], f)
		} else {
			noOwner = append(noOwner, f)
		}
	}

	var b strings.Builder
	b.WriteString("digraph callgraph {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  compound=true;\n")
	b.WriteString("  splines=true;\n")
	b.WriteString("  nodesep=0.4;\n")
	b.WriteString("  ranksep=0.6;\n")
	fmt.Fprintf(&b, "  bgcolor=%q;\n", t.Background)
	fmt.Fprintf(&b, "  node [shape=rect, style=filled, fillcolor=%q, color=%q, penwidth=0.5, fontname=\"Helvetica Neue,Helvetica,Arial\", fontsize=9, fontcolor=%q, height=0.3, margin=\"0.12,0.06\"];\n",
		t.NodeFill, t.NodeBorder, t.TextColor)
	fmt.Fprintf(&b, "  edge [penwidth=0.5, arrowsize=0.5, arrowhead=vee];\n")
	if title != "" {
		fmt.Fprintf(&b, "  labelloc=t;\n  labeljust=l;\n")
		fmt.Fprintf(&b, "  label=<<font face=\"Helvetica Neue,Helvetica\" point-size=\"8\" color=\"%s\">%s</font>>;\n",
			t.TextColor, dotEscape(title))
	}
	b.WriteByte('\n')

	// Render clustered function nodes (grouped by owner).
	ownerNames := make([]string, 0, len(ownerFuncs))
	for owner := range ownerFuncs {
		ownerNames = append(ownerNames, owner)
	}
	slices.Sort(ownerNames)

	for _, owner := range ownerNames {
		funcsInOwner := ownerFuncs[owner]
		if len(funcsInOwner) < 2 {
			// Singletons go at top level.
			noOwner = append(noOwner, funcsInOwner...)
			continue
		}
		slices.SortFunc(funcsInOwner, func(a, b disasm.FuncRecord) int {
			return cmp.Compare(a.Name, b.Name)
		})
		clusterID := "cluster_" + dotID(owner)
		ownerLabel := stripOwnerHash(owner)
		fmt.Fprintf(&b, "  subgraph %s {\n", clusterID)
		fmt.Fprintf(&b, "    label=<<font point-size=\"8\" color=\"%s\">%s</font>>;\n",
			t.ClusterLabel, dotEscape(ownerLabel))
		fmt.Fprintf(&b, "    style=dotted; color=%q; penwidth=0.3;\n", t.ClusterBorder)
		for _, f := range funcsInOwner {
			id := dotID(f.Name)
			// Inside a cluster, strip owner prefix for shorter labels.
			label := stripMethodName(f.Name, owner)
			label = truncLabel(label, 50)
			if strings.HasPrefix(f.Name, "sub_") {
				fmt.Fprintf(&b, "    %s [label=%q, fillcolor=%q];\n", id, label, t.StubFill)
			} else {
				fmt.Fprintf(&b, "    %s [label=%q];\n", id, label)
			}
		}
		fmt.Fprintf(&b, "  }\n")
	}

	// Render unclustered nodes (no owner or singletons).
	slices.SortFunc(noOwner, func(a, b disasm.FuncRecord) int {
		return cmp.Compare(a.Name, b.Name)
	})
	for _, f := range noOwner {
		id := dotID(f.Name)
		label := truncLabel(f.Name, 60)
		if strings.HasPrefix(f.Name, "sub_") {
			fmt.Fprintf(&b, "  %s [label=%q, fillcolor=%q];\n", id, label, t.StubFill)
		} else {
			fmt.Fprintf(&b, "  %s [label=%q];\n", id, label)
		}
	}
	b.WriteByte('\n')

	// Render external nodes.
	extNames := make([]string, 0, len(externalNodes))
	for name := range externalNodes {
		extNames = append(extNames, name)
	}
	slices.Sort(extNames)
	for _, name := range extNames {
		id := dotID(name)
		label := truncLabel(name, 50)
		fmt.Fprintf(&b, "  %s [label=%q, shape=plaintext, style=\"\", fillcolor=none, fontcolor=%q, fontsize=8];\n",
			id, label, t.ExternalText)
	}
	b.WriteByte('\n')

	// Render edges.
	type edgeEntry struct {
		k edgeKey
		v *edgeVal
	}
	sortedEdges := make([]edgeEntry, 0, len(dedupEdges))
	for k, v := range dedupEdges {
		sortedEdges = append(sortedEdges, edgeEntry{k: k, v: v})
	}
	slices.SortFunc(sortedEdges, func(a, b edgeEntry) int {
		if c := cmp.Compare(a.k.from, b.k.from); c != 0 {
			return c
		}
		if c := cmp.Compare(a.k.to, b.k.to); c != 0 {
			return c
		}
		return cmp.Compare(a.k.prov, b.k.prov)
	})

	for _, e := range sortedEdges {
		k, v := e.k, e.v
		if !funcSet[k.from] && !externalNodes[k.from] {
			continue
		}
		fromID := dotID(k.from)
		toID := dotID(k.to)
		color := edgeColor(k.prov, t)
		style := edgeStyle(k.prov)

		attrs := fmt.Sprintf("color=%q, style=%q", color, style)
		if v.count > 1 {
			attrs += fmt.Sprintf(", penwidth=%.1f", 0.5+float64(v.count)*0.1)
			if v.count > 2 {
				attrs += fmt.Sprintf(", label=<<font point-size=\"7\" color=\"%s\">%dx</font>>", color, v.count)
			}
		}
		fmt.Fprintf(&b, "  %s -> %s [%s];\n", fromID, toID, attrs)
	}

	b.WriteString("}\n")
	return b.String()
}

// CallgraphStats computes summary statistics from edges.
type CallgraphStats struct {
	TotalFunctions int
	TotalEdges     int
	BLEdges        int
	BLREdges       int
	BLRAnnotated   int
	UniqueOwners   int
	ProvCounts     map[string]int
	TopCallers     []NameCount // sorted desc
	TopCallees     []NameCount // sorted desc
	TopOwners      []NameCount // sorted desc by method count
}

// NameCount pairs a name with a count.
type NameCount struct {
	Name  string
	Count int
}

// ComputeStats computes callgraph statistics from JSONL data.
func ComputeStats(funcs []disasm.FuncRecord, edges []disasm.CallEdgeRecord) CallgraphStats {
	stats := CallgraphStats{
		TotalFunctions: len(funcs),
		TotalEdges:     len(edges),
		ProvCounts:     make(map[string]int),
	}

	callerCount := make(map[string]int)
	calleeCount := make(map[string]int)

	for _, e := range edges {
		prov := ClassifyEdgeProv(e)
		stats.ProvCounts[prov]++

		callerCount[e.FromFunc]++
		if e.Kind == "bl" || e.Kind == "call" {
			stats.BLEdges++
			for _, t := range e.ResolvedTargets() {
				calleeCount[t]++
			}
		} else {
			stats.BLREdges++
			if len(e.ResolvedTargets()) > 0 {
				stats.BLRAnnotated++
			}
		}
	}

	// Count methods per owner class.
	ownerCount := make(map[string]int)
	for _, f := range funcs {
		if f.Owner != "" {
			ownerCount[f.Owner]++
		}
	}
	stats.UniqueOwners = len(ownerCount)

	stats.TopCallers = topNMap(callerCount, 20)
	stats.TopCallees = topNMap(calleeCount, 20)
	stats.TopOwners = topNMap(ownerCount, 30)
	return stats
}

// topNMap returns the top N entries from a map, sorted descending.
func topNMap(m map[string]int, n int) []NameCount {
	entries := make([]NameCount, 0, len(m))
	for name, count := range m {
		entries = append(entries, NameCount{name, count})
	}
	// Sort descending by count.
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].Count > entries[i].Count {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}
