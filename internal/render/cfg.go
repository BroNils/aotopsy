package render

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"aotopsy/internal/disasm"
)

// maxBlockCalls caps how many callees are drawn out of one block, so a
// dispatch-heavy block does not bury the control flow it belongs to.
const maxBlockCalls = 10

func cfgBlockID(id int) string {
	if id < 0 {
		return "bb_n" + strings.TrimPrefix(strconv.Itoa(id), "-")
	}
	return fmt.Sprintf("bb%d", id)
}

// CFGDOT renders a per-function basic-block CFG as DOT.
// Each basic block is a node; edges represent control flow. Call sites in
// a block are drawn as edges to plaintext callee nodes. Entry block is
// highlighted. Conditional edges use T/F colors.
//
// edges are the call edges of THIS function (call_edges.jsonl records
// whose FromFunc is cfg.Name); pass nil to draw control flow only.
//
// The callee edges are here because the renderer this replaced drew them
// and the replacement did not. internal/callgraph's DOTCFG read
// BasicBlock.Calls, disasm.BasicBlock has no such field, and so the
// consolidation quietly turned a CFG that showed what each block called
// into one that showed only where it branched. Nothing caught it: golden
// covers the JSONL artifacts, and no test reads a .dot at all.
func CFGDOT(cfg disasm.FuncCFG, edges []disasm.CallEdgeRecord, t Theme) string {
	if len(cfg.Blocks) == 0 {
		return ""
	}
	blockRange := func(blk disasm.BasicBlock) (int, int) {
		start, end := blk.Start, blk.End
		if start < 0 {
			start = 0
		} else if start > len(cfg.Insts) {
			start = len(cfg.Insts)
		}
		if end < start {
			end = start
		} else if end > len(cfg.Insts) {
			end = len(cfg.Insts)
		}
		return start, end
	}
	blockIDs := make(map[int]bool, len(cfg.Blocks))
	for _, blk := range cfg.Blocks {
		blockIDs[blk.ID] = true
	}

	// Call sites by the PC they occur at, so each can be attributed to the
	// block containing that instruction without flattening polymorphic,
	// unresolved, or runtime evidence into a fake callee name.
	type cfgCallSite struct {
		edge      disasm.CallEdgeRecord
		sem       callSiteSemantics
		supported bool
	}
	callSitesAt := make(map[uint64][]cfgCallSite, len(edges))
	for _, e := range edges {
		if e.FromFunc != cfg.Name {
			continue
		}
		pcText := strings.TrimSpace(e.FromPC)
		pcText = strings.TrimPrefix(pcText, "0x")
		pcText = strings.TrimPrefix(pcText, "0X")
		pc, err := strconv.ParseUint(pcText, 16, 64)
		if err != nil {
			continue
		}
		supported := isSupportedCallKind(e.Kind)
		sem := callSiteSemantics{}
		if supported {
			sem = inspectCallSite(e)
		}
		callSitesAt[pc] = append(callSitesAt[pc], cfgCallSite{edge: e, sem: sem, supported: supported})
	}

	var b strings.Builder
	b.WriteString("digraph cfg {\n")
	b.WriteString("  rankdir=TB;\n")
	b.WriteString("  nodesep=0.3;\n")
	b.WriteString("  ranksep=0.4;\n")
	fmt.Fprintf(&b, "  bgcolor=%q;\n", t.Background)
	fmt.Fprintf(&b, "  node [shape=rect, style=filled, fillcolor=%q, color=%q, penwidth=0.5, fontname=\"Courier,monospace\", fontsize=8, fontcolor=%q, margin=\"0.08,0.04\"];\n",
		t.NodeFill, t.NodeBorder, t.TextColor)
	fmt.Fprintf(&b, "  edge [penwidth=0.7, arrowsize=0.5, arrowhead=vee];\n")
	fmt.Fprintf(&b, "  labelloc=t;\n  labeljust=l;\n")
	fmt.Fprintf(&b, "  label=<<font face=\"Helvetica Neue,Helvetica\" point-size=\"9\" color=\"%s\">%s</font>>;\n",
		t.TextColor, dotEscape(cfg.Name))
	b.WriteByte('\n')

	// Render blocks as nodes.
	for _, blk := range cfg.Blocks {
		id := cfgBlockID(blk.ID)

		// Build label: one line per instruction.
		var lines []string
		start, end := blockRange(blk)
		for i := start; i < end; i++ {
			inst := cfg.Insts[i]
			line := fmt.Sprintf("0x%x: %s", inst.Addr, inst.Text)
			lines = append(lines, dotEscape(line))
		}
		// Truncate long blocks.
		if len(lines) > 12 {
			kept := append(lines[:5], fmt.Sprintf("... (%d more)", len(lines)-10))
			lines = append(kept, lines[len(lines)-5:]...)
		}

		label := strings.Join(lines, "<br align=\"left\"/>")
		label += "<br align=\"left\"/>"

		attrs := ""
		if blk.IsEntry {
			attrs = fmt.Sprintf(", penwidth=1.5, color=%q", t.EdgeTHR)
		}
		if blk.IsTerm {
			attrs += fmt.Sprintf(", fillcolor=%q", t.StubFill)
		}
		fmt.Fprintf(&b, "  %s [label=<%s>%s];\n", id, label, attrs)
	}
	b.WriteByte('\n')

	// Render semantic target/evidence nodes and the call edges into them.
	externalSeen := map[string]bool{}
	type blockRelation struct {
		target string
		prov   string
		label  string
	}
	for _, blk := range cfg.Blocks {
		from := cfgBlockID(blk.ID)
		start, end := blockRange(blk)
		relations := make(map[blockRelation]bool)
		nodeLabels := make(map[string]string)
		namedTargets := make(map[string]bool)
		for i := start; i < end; i++ {
			for _, site := range callSitesAt[cfg.Insts[i].Addr] {
				if !site.supported {
					key := callSiteKey(site.edge, "cfg-unsupported-kind")
					nodeLabels[key] = unsupportedCallKindLabel(site.edge)
					relations[blockRelation{target: key, prov: ProvUnresolved, label: "unsupported call kind"}] = true
					continue
				}
				prov := ClassifyEdgeProv(site.edge)
				for _, target := range site.sem.StaticTargets {
					namedTargets[target] = true
					relations[blockRelation{target: target, prov: prov}] = true
				}
				if site.sem.RawTarget != "" {
					key := callSiteKey(site.edge, "cfg-direct-address")
					nodeLabels[key] = directAddressLabel(site.edge, site.sem.RawTarget)
					relations[blockRelation{target: key, prov: ProvDirect, label: "address only"}] = true
				}
				if site.sem.Unresolved {
					key := callSiteKey(site.edge, "cfg-unresolved")
					nodeLabels[key] = unresolvedCallSiteLabel(site.edge)
					relations[blockRelation{target: key, prov: ProvUnresolved, label: "unresolved"}] = true
				}
				if omitted := site.sem.omittedCandidates(); omitted > 0 {
					key := callSiteKey(site.edge, "cfg-incomplete")
					nodeLabels[key] = incompleteCallSiteLabel(site.edge, omitted)
					relations[blockRelation{target: key, prov: ProvUnresolved, label: "candidate set incomplete"}] = true
				}
				if site.sem.candidateCountUnknown() {
					key := callSiteKey(site.edge, "cfg-candidate-count-unknown")
					nodeLabels[key] = unknownCandidateCountLabel(site.edge)
					relations[blockRelation{target: key, prov: ProvUnresolved, label: "candidate completeness unknown"}] = true
				}
				for _, observed := range site.sem.RuntimeTargets {
					if observed.Target == "" {
						continue
					}
					namedTargets[observed.Target] = true
					label := "runtime"
					if site.sem.RuntimeAgreement != "" {
						label += " " + string(site.sem.RuntimeAgreement)
					}
					if observed.Count > 1 {
						label += fmt.Sprintf(" ×%d", observed.Count)
					}
					relations[blockRelation{target: observed.Target, prov: ProvRuntime, label: label}] = true
				}
			}
		}

		// Display bounds are explicit. The first maxBlockCalls named target nodes
		// are deterministic, and a marker states exactly how many listed targets
		// were omitted from this visual projection.
		targetNames := make([]string, 0, len(namedTargets))
		for name := range namedTargets {
			targetNames = append(targetNames, name)
		}
		slices.Sort(targetNames)
		visibleTargets := make(map[string]bool, len(targetNames))
		limit := len(targetNames)
		if limit > maxBlockCalls {
			limit = maxBlockCalls
		}
		for _, name := range targetNames[:limit] {
			visibleTargets[name] = true
		}
		if omitted := len(targetNames) - limit; omitted > 0 {
			key := fmt.Sprintf("\x00cfg-display-cap\x00%s\x00%d", cfg.Name, blk.ID)
			nodeLabels[key] = fmt.Sprintf("+%d more listed/observed target(s) hidden by display cap", omitted)
			relations[blockRelation{target: key, prov: ProvUnresolved, label: "display cap"}] = true
		}

		relationList := make([]blockRelation, 0, len(relations))
		for rel := range relations {
			if _, evidenceNode := nodeLabels[rel.target]; !evidenceNode && !visibleTargets[rel.target] {
				continue
			}
			relationList = append(relationList, rel)
		}
		slices.SortFunc(relationList, func(a, b blockRelation) int {
			if a.target != b.target {
				return strings.Compare(a.target, b.target)
			}
			if a.prov != b.prov {
				return strings.Compare(a.prov, b.prov)
			}
			return strings.Compare(a.label, b.label)
		})
		for _, rel := range relationList {
			id := dotID(rel.target)
			if !externalSeen[rel.target] {
				externalSeen[rel.target] = true
				label := rel.target
				if evidenceLabel := nodeLabels[rel.target]; evidenceLabel != "" {
					label = evidenceLabel
				}
				font := "Helvetica Neue,Helvetica"
				if IsAllCaps(label) {
					font = "Courier,monospace"
				}
				fmt.Fprintf(&b, "  %s [label=%q, shape=plaintext, style=\"\", fillcolor=none, fontname=%q, fontcolor=%q, fontsize=8];\n",
					id, truncLabel(label, 70), font, edgeColor(rel.prov, t))
			}
			attrs := fmt.Sprintf("color=%q, style=%q, arrowsize=0.4", edgeColor(rel.prov, t), edgeStyle(rel.prov))
			if rel.label != "" {
				attrs += fmt.Sprintf(", label=%q, fontsize=7, fontcolor=%q", truncLabel(rel.label, 32), edgeColor(rel.prov, t))
			}
			fmt.Fprintf(&b, "  %s -> %s [%s];\n", from, id, attrs)
		}
	}
	b.WriteByte('\n')

	// Render edges.
	for _, blk := range cfg.Blocks {
		from := cfgBlockID(blk.ID)
		for _, s := range blk.Succs {
			if !blockIDs[s.BlockID] {
				continue
			}
			to := cfgBlockID(s.BlockID)
			switch s.Cond {
			case "T":
				fmt.Fprintf(&b, "  %s -> %s [color=%q, label=<<font point-size=\"7\" color=\"%s\">T</font>>];\n",
					from, to, t.EdgeTHR, t.EdgeTHR)
			case "F":
				fmt.Fprintf(&b, "  %s -> %s [color=%q, label=<<font point-size=\"7\" color=\"%s\">F</font>>];\n",
					from, to, t.EdgeUnresolved, t.EdgeUnresolved)
			default:
				fmt.Fprintf(&b, "  %s -> %s [color=%q];\n", from, to, t.EdgeDirect)
			}
		}
	}

	b.WriteString("}\n")
	return b.String()
}
