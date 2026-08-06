package render

import (
	"fmt"
	"strings"

	"aotopsy/internal/disasm"
)

// CFGDOT renders a per-function basic-block CFG as DOT.
// Each basic block is a node; edges represent control flow.
// Entry block is highlighted. Conditional edges use T/F colors.
func CFGDOT(cfg disasm.FuncCFG, t Theme) string {
	if len(cfg.Blocks) == 0 {
		return ""
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
		id := fmt.Sprintf("bb%d", blk.ID)

		// Build label: one line per instruction.
		var lines []string
		end := blk.End
		if end > len(cfg.Insts) {
			end = len(cfg.Insts)
		}
		for i := blk.Start; i < end; i++ {
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

	// Render edges.
	for _, blk := range cfg.Blocks {
		from := fmt.Sprintf("bb%d", blk.ID)
		for _, s := range blk.Succs {
			to := fmt.Sprintf("bb%d", s.BlockID)
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
