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
	ProvRuntime    = "runtime_observed"
)

func isSupportedCallKind(kind string) bool {
	switch kind {
	case "bl", "call", "blr", "call_indirect":
		return true
	default:
		return false
	}
}

func isDirectCallKind(kind string) bool {
	return kind == "bl" || kind == "call"
}

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
	case ProvRuntime:
		return t.EdgeRuntime
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
	case ProvUnresolved, ProvRuntime:
		return "dashed"
	default:
		return "solid"
	}
}

// CallgraphDOT renders static call relations plus explicitly separate runtime
// observations. Unknown indirect sites and truncated candidate sets are shown as
// per-call-site evidence nodes; they are never collapsed into a fake function.
// maxNodes limits known function nodes only (0 = all).
func CallgraphDOT(funcs []disasm.FuncRecord, edges []disasm.CallEdgeRecord, title string, t Theme, maxNodes int) string {
	origFuncSet := make(map[string]bool, len(funcs))
	funcByName := make(map[string]disasm.FuncRecord, len(funcs))
	for _, f := range funcs {
		origFuncSet[f.Name] = true
		funcByName[f.Name] = f
	}

	type edgeKey struct {
		from, to, prov, label string
	}
	type edgeVal struct {
		count int
	}
	dedupEdges := make(map[edgeKey]*edgeVal)
	nodeLabels := make(map[string]string)
	seenSiteRelations := make(map[string]bool)
	addEdge := func(from, to, prov, label, nodeLabel string, count int) {
		if from == "" || to == "" || count <= 0 {
			return
		}
		if nodeLabel != "" {
			nodeLabels[to] = nodeLabel
		}
		k := edgeKey{from: from, to: to, prov: prov, label: label}
		if v := dedupEdges[k]; v != nil {
			v.count += count
		} else {
			dedupEdges[k] = &edgeVal{count: count}
		}
	}
	addSiteEdge := func(siteKey, from, to, prov, label, nodeLabel string, count int) {
		relationKey := siteKey + "\x00" + to + "\x00" + prov + "\x00" + label
		if seenSiteRelations[relationKey] {
			return
		}
		seenSiteRelations[relationKey] = true
		addEdge(from, to, prov, label, nodeLabel, count)
	}

	for edgeIndex, e := range edges {
		if !origFuncSet[e.FromFunc] {
			continue
		}
		siteKey := callSitePopulationKey(e, edgeIndex)
		if !isSupportedCallKind(e.Kind) {
			key := callSiteKey(e, "unsupported-kind")
			addSiteEdge(siteKey, e.FromFunc, key, ProvUnresolved, "unsupported call kind", unsupportedCallKindLabel(e), 1)
			continue
		}
		sem := inspectCallSite(e)
		prov := ClassifyEdgeProv(e)
		for _, target := range sem.StaticTargets {
			addSiteEdge(siteKey, e.FromFunc, target, prov, "", "", 1)
		}
		if sem.RawTarget != "" {
			key := callSiteKey(e, "direct-address")
			addSiteEdge(siteKey, e.FromFunc, key, ProvDirect, "address only", directAddressLabel(e, sem.RawTarget), 1)
		}
		if sem.Unresolved {
			key := callSiteKey(e, "unresolved")
			addSiteEdge(siteKey, e.FromFunc, key, ProvUnresolved, "unresolved", unresolvedCallSiteLabel(e), 1)
		}
		if omitted := sem.omittedCandidates(); omitted > 0 {
			key := callSiteKey(e, "incomplete")
			addSiteEdge(siteKey, e.FromFunc, key, ProvUnresolved, "candidate set incomplete", incompleteCallSiteLabel(e, omitted), 1)
		}
		if sem.candidateCountUnknown() {
			key := callSiteKey(e, "candidate-count-unknown")
			addSiteEdge(siteKey, e.FromFunc, key, ProvUnresolved, "candidate completeness unknown", unknownCandidateCountLabel(e), 1)
		}
		for _, observed := range sem.RuntimeTargets {
			if observed.Target == "" {
				continue
			}
			count := observed.Count
			if count <= 0 {
				count = 1
			}
			label := "runtime"
			if sem.RuntimeAgreement != "" {
				label += " " + string(sem.RuntimeAgreement)
			}
			addSiteEdge(siteKey, e.FromFunc, observed.Target, ProvRuntime, label, "", count)
		}
	}

	// Rank participating known functions by relation involvement, with a lexical
	// tie-breaker. maxNodes therefore has deterministic semantics independent of
	// functions.jsonl or edge record ordering.
	type involvementCount struct{ static, runtime int }
	involvement := make(map[string]involvementCount)
	for k, v := range dedupEdges {
		add := func(name string) {
			if !origFuncSet[name] {
				return
			}
			count := involvement[name]
			if k.prov == ProvRuntime {
				count.runtime++
			} else {
				count.static += v.count
			}
			involvement[name] = count
		}
		add(k.from)
		add(k.to)
	}
	type rankedFunc struct {
		name    string
		static  int
		runtime int
	}
	ranked := make([]rankedFunc, 0, len(involvement))
	for name, count := range involvement {
		ranked = append(ranked, rankedFunc{name: name, static: count.static, runtime: count.runtime})
	}
	slices.SortFunc(ranked, func(a, b rankedFunc) int {
		if c := cmp.Compare(b.static, a.static); c != 0 {
			return c
		}
		if c := cmp.Compare(b.runtime, a.runtime); c != 0 {
			return c
		}
		return cmp.Compare(a.name, b.name)
	})
	omittedKnownFunctions := 0
	if maxNodes > 0 && len(ranked) > maxNodes {
		omittedKnownFunctions = len(ranked) - maxNodes
		ranked = ranked[:maxNodes]
	}
	funcSet := make(map[string]bool, len(ranked))
	var renderFuncs []disasm.FuncRecord
	for _, rf := range ranked {
		funcSet[rf.name] = true
		renderFuncs = append(renderFuncs, funcByName[rf.name])
	}

	filteredEdges := make(map[edgeKey]*edgeVal, len(dedupEdges))
	for k, v := range dedupEdges {
		if !funcSet[k.from] {
			continue
		}
		if origFuncSet[k.to] && !funcSet[k.to] {
			continue
		}
		filteredEdges[k] = v
	}
	dedupEdges = filteredEdges

	// External/evidence nodes are named targets absent from functions.jsonl or
	// per-call-site marker nodes. Keep their display label separate from the DOT
	// identity so recovered names cannot collide with marker identities.
	externalNodes := make(map[string]string)
	for k := range dedupEdges {
		if funcSet[k.to] {
			continue
		}
		label := nodeLabels[k.to]
		if label == "" {
			label = k.to
		}
		externalNodes[k.to] = label
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
		label := truncLabel(externalNodes[name], 70)
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
		if c := cmp.Compare(a.k.prov, b.k.prov); c != 0 {
			return c
		}
		return cmp.Compare(a.k.label, b.k.label)
	})

	for _, e := range sortedEdges {
		k, v := e.k, e.v
		if !funcSet[k.from] {
			continue
		}
		fromID := dotID(k.from)
		toID := dotID(k.to)
		color := edgeColor(k.prov, t)
		style := edgeStyle(k.prov)

		attrs := fmt.Sprintf("color=%q, style=%q", color, style)
		if k.label != "" {
			attrs += fmt.Sprintf(", label=%q, fontsize=7, fontcolor=%q", truncLabel(k.label, 36), color)
		}
		if v.count > 1 {
			attrs += fmt.Sprintf(", penwidth=%.1f", 0.5+float64(v.count)*0.1)
			if v.count > 2 && k.label == "" {
				attrs += fmt.Sprintf(", label=<<font point-size=\"7\" color=\"%s\">%dx</font>>", color, v.count)
			}
		}
		fmt.Fprintf(&b, "  %s -> %s [%s];\n", fromID, toID, attrs)
	}
	if omittedKnownFunctions > 0 {
		label := fmt.Sprintf("display truncated by maxNodes: %d participating known function(s) and their incident relation(s) omitted", omittedKnownFunctions)
		fmt.Fprintf(&b, "  %s [label=%q, shape=note, style=\"filled\", fillcolor=%q, color=%q, fontcolor=%q, fontsize=8];\n",
			dotID("\x00callgraph-display-truncation"), label, t.StubFill, t.EdgeUnresolved, t.TextColor)
	}

	b.WriteString("}\n")
	return b.String()
}

// CallgraphStats computes summary statistics from edges.
type CallgraphStats struct {
	TotalFunctions             int
	TotalCallSites             int
	DirectCallSites            int
	IndirectCallSites          int
	UnsupportedCallSites       int
	IndirectStaticResolved     int
	IndirectUnresolved         int
	PolymorphicSites           int
	IncompletePolymorphicSites int
	UnknownCandidateCountSites int
	StaticTargetRelations      int
	RuntimeObservedSites       int
	RuntimeTargetRelations     int
	UniqueOwners               int
	ProvCounts                 map[string]int
	TopCallers                 []NameCount // call-site count, sorted desc
	TopCallees                 []NameCount // static relation count, sorted desc
	TopRuntimeCallees          []NameCount // runtime observation count, sorted desc
	TopOwners                  []NameCount // sorted desc by method count
}

// NameCount pairs a name with a count.
type NameCount struct {
	Name  string
	Count int
}

// ComputeStats computes callgraph statistics from JSONL data.
func ComputeStats(funcs []disasm.FuncRecord, edges []disasm.CallEdgeRecord) CallgraphStats {
	stats := CallgraphStats{
		ProvCounts: make(map[string]int),
	}
	funcSet := make(map[string]bool, len(funcs))
	ownerByFunc := make(map[string]string, len(funcs))
	for _, f := range funcs {
		funcSet[f.Name] = true
		if _, seen := ownerByFunc[f.Name]; !seen {
			ownerByFunc[f.Name] = f.Owner
		}
	}
	stats.TotalFunctions = len(funcSet)

	callerCount := make(map[string]int)
	calleeCount := make(map[string]int)
	runtimeCalleeCount := make(map[string]int)
	seenSites := make(map[string]bool)
	seenStaticRelations := make(map[string]bool)
	seenRuntimeRelations := make(map[string]bool)
	seenRuntimeSites := make(map[string]bool)

	for edgeIndex, e := range edges {
		if !funcSet[e.FromFunc] {
			continue
		}
		siteKey := callSitePopulationKey(e, edgeIndex)
		if !isSupportedCallKind(e.Kind) {
			if !seenSites[siteKey] {
				seenSites[siteKey] = true
				stats.TotalCallSites++
				stats.UnsupportedCallSites++
				stats.ProvCounts[ProvUnresolved]++
				callerCount[e.FromFunc]++
			}
			continue
		}
		sem := inspectCallSite(e)
		if !seenSites[siteKey] {
			seenSites[siteKey] = true
			stats.TotalCallSites++
			stats.ProvCounts[ClassifyEdgeProv(e)]++
			callerCount[e.FromFunc]++
			if isDirectCallKind(e.Kind) {
				stats.DirectCallSites++
			} else {
				stats.IndirectCallSites++
				if len(sem.StaticTargets) > 0 {
					stats.IndirectStaticResolved++
				} else {
					stats.IndirectUnresolved++
				}
			}
			if len(e.Targets) > 0 || sem.CandidateCount > 1 {
				stats.PolymorphicSites++
				if sem.omittedCandidates() > 0 {
					stats.IncompletePolymorphicSites++
				}
				if sem.candidateCountUnknown() {
					stats.UnknownCandidateCountSites++
				}
			}
		}
		for _, target := range sem.StaticTargets {
			relationKey := siteKey + "\x00" + target
			if !seenStaticRelations[relationKey] {
				seenStaticRelations[relationKey] = true
				stats.StaticTargetRelations++
				calleeCount[target]++
			}
		}
		if e.Runtime != nil && (e.Runtime.Observations > 0 || len(sem.RuntimeTargets) > 0) {
			if !seenRuntimeSites[siteKey] {
				seenRuntimeSites[siteKey] = true
				stats.RuntimeObservedSites++
			}
		}
		for _, observed := range sem.RuntimeTargets {
			if observed.Target == "" {
				continue
			}
			relationKey := siteKey + "\x00" + observed.Target
			if seenRuntimeRelations[relationKey] {
				continue
			}
			seenRuntimeRelations[relationKey] = true
			stats.RuntimeTargetRelations++
			count := observed.Count
			if count <= 0 {
				count = 1
			}
			runtimeCalleeCount[observed.Target] += count
		}
	}

	// Count methods per owner class.
	ownerCount := make(map[string]int)
	for _, owner := range ownerByFunc {
		if owner != "" {
			ownerCount[owner]++
		}
	}
	stats.UniqueOwners = len(ownerCount)

	stats.TopCallers = topNMap(callerCount, 20)
	stats.TopCallees = topNMap(calleeCount, 20)
	stats.TopRuntimeCallees = topNMap(runtimeCalleeCount, 20)
	stats.TopOwners = topNMap(ownerCount, 30)
	return stats
}

// topNMap returns the top N entries from a map, sorted descending.
func topNMap(m map[string]int, n int) []NameCount {
	entries := make([]NameCount, 0, len(m))
	for name, count := range m {
		entries = append(entries, NameCount{name, count})
	}
	// O(n log n), with a lexical tie-breaker so map iteration cannot change
	// equal-count output ordering.
	slices.SortFunc(entries, func(a, b NameCount) int {
		if c := cmp.Compare(b.Count, a.Count); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})
	if n <= 0 {
		return nil
	}
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}
