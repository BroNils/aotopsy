package render

import (
	"fmt"
	"strings"

	"aotopsy/internal/callgraph"
)

// maxBlockCalls limits how many calls to show in a single block label.
const maxBlockCalls = 10

// DOTCFG renders the CFG in Graphviz DOT format.
// Style: Japanese minimalist — ma (間), kanso (簡素), shibumi (渋み).
// Ink on washi: sumi strokes, one vermillion accent, generous emptiness.
func DOTCFG(g *callgraph.CFGGraph, title string) string {
	const (
		sumi   = "#2D2D2D" // 墨 ink black
		ai     = "#2D4A7A" // 藍 indigo
		shu    = "#BF3F2F" // 朱 vermillion
		kinari = "#FAF6F0" // 生成 unbleached white
		nezumi = "#8E8E8E" // 鼠 warm gray
	)

	var b strings.Builder
	b.WriteString("digraph cfg {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  splines=true;\n")
	b.WriteString("  nodesep=0.5;\n")
	b.WriteString("  ranksep=0.6;\n")
	b.WriteString("  compound=true;\n")
	fmt.Fprintf(&b, "  bgcolor=%q;\n", kinari)
	fmt.Fprintf(&b, "  node [shape=rect, style=\"\", color=%q, penwidth=0.3, fontname=\"Helvetica Neue,Helvetica,Arial\", fontsize=8, fontcolor=%q, height=0.3, margin=\"0.14,0.08\"];\n", nezumi, sumi)
	fmt.Fprintf(&b, "  edge [color=%q, penwidth=0.4, arrowsize=0.35, arrowhead=vee];\n", nezumi)
	if title != "" {
		fmt.Fprintf(&b, "  labelloc=t;\n  labeljust=l;\n")
		fmt.Fprintf(&b, "  label=<<font face=\"Helvetica Neue,Helvetica\" point-size=\"8\" color=\"%s\">%s</font>>;\n", sumi, DotEscape(title))
	}
	b.WriteByte('\n')

	funcIndex := map[string]int{}
	for fi, f := range g.Funcs {
		funcIndex[f.Name] = fi
	}
	externalSeen := map[string]bool{}

	for fi, f := range g.Funcs {
		clusterID := fmt.Sprintf("cluster_%d", fi)
		fmt.Fprintf(&b, "  subgraph %s {\n", clusterID)
		fmt.Fprintf(&b, "    label=<<font face=\"Helvetica Neue,Helvetica\" point-size=\"8\" color=\"%s\">%s</font>>;\n", sumi, DotEscape(f.Name))
		fmt.Fprintf(&b, "    style=dotted;\n    color=%q;\n    penwidth=0.3;\n", nezumi)

		hasContent := map[int]bool{}
		for _, block := range f.Blocks {
			if len(block.Calls) > 0 || len(block.Props) > 0 || len(block.Succs) > 1 {
				hasContent[block.ID] = true
			}
		}
		if len(f.Blocks) > 0 {
			hasContent[0] = true
		}
		for _, block := range f.Blocks {
			if block.Term && len(block.Succs) == 0 {
				hasContent[block.ID] = true
			}
		}

		for _, block := range f.Blocks {
			if !hasContent[block.ID] {
				continue
			}
			nodeID := blockNodeID(fi, block.ID)
			label := buildBlockLabel(block, f.Name, block.ID == 0)

			if block.ID == 0 {
				fmt.Fprintf(&b, "    %s [label=%s, style=filled, fillcolor=%q, fontcolor=%q, color=%q, penwidth=0];\n",
					nodeID, label, sumi, kinari, sumi)
			} else if len(block.Succs) > 1 {
				if len(block.Calls) == 0 && len(block.Props) == 0 {
					fmt.Fprintf(&b, "    %s [label=\"\", shape=diamond, width=0.15, height=0.15, color=%q, penwidth=0.3];\n",
						nodeID, sumi)
				} else {
					fmt.Fprintf(&b, "    %s [label=%s];\n", nodeID, label)
				}
			} else if block.Term && len(block.Succs) == 0 {
				if len(block.Calls) == 0 && len(block.Props) == 0 {
					fmt.Fprintf(&b, "    %s [label=\"ret\", shape=plaintext, fontsize=8, fontcolor=%q];\n",
						nodeID, nezumi)
				} else {
					fmt.Fprintf(&b, "    %s [label=%s];\n", nodeID, label)
				}
			} else {
				fmt.Fprintf(&b, "    %s [label=%s];\n", nodeID, label)
			}
		}

		// Intra-function control flow edges
		for _, block := range f.Blocks {
			if !hasContent[block.ID] {
				continue
			}
			srcID := blockNodeID(fi, block.ID)

			type resolvedEdge struct {
				targetID int
				cond     string
			}
			var resolved []resolvedEdge
			for _, succ := range block.Succs {
				tid := ResolveTarget(f, succ.BlockID, hasContent)
				if tid >= 0 {
					resolved = append(resolved, resolvedEdge{tid, succ.Cond})
				}
			}

			if len(resolved) == 2 && resolved[0].targetID == resolved[1].targetID &&
				resolved[0].cond != "" && resolved[1].cond != "" {
				dstID := blockNodeID(fi, resolved[0].targetID)
				fmt.Fprintf(&b, "    %s -> %s;\n", srcID, dstID)
			} else {
				seen := map[int]bool{}
				for _, re := range resolved {
					if seen[re.targetID] {
						continue
					}
					seen[re.targetID] = true
					dstID := blockNodeID(fi, re.targetID)
					if re.cond != "" {
						color := ai
						if re.cond == "F" {
							color = shu
						}
						fmt.Fprintf(&b, "    %s -> %s [color=%q, label=<<font point-size=\"8\" color=\"%s\">%s</font>>];\n",
							srcID, dstID, color, color, re.cond)
					} else {
						fmt.Fprintf(&b, "    %s -> %s;\n", srcID, dstID)
					}
				}
			}
		}

		fmt.Fprintf(&b, "  }\n\n")

		// Inter-function and external call edges
		for _, block := range f.Blocks {
			if !hasContent[block.ID] {
				continue
			}
			srcID := blockNodeID(fi, block.ID)
			edgeSeen := map[string]bool{}
			for _, call := range block.Calls {
				targetFI, inGraph := funcIndex[call.Callee]
				if inGraph && targetFI != fi {
					// Cross-function call
					dstID := blockNodeID(targetFI, 0)
					edgeKey := srcID + "->" + dstID
					if edgeSeen[edgeKey] {
						continue
					}
					edgeSeen[edgeKey] = true
					targetCluster := fmt.Sprintf("cluster_%d", targetFI)
					fmt.Fprintf(&b, "  %s -> %s [lhead=%q, color=%q, penwidth=0.5];\n",
						srcID, dstID, targetCluster, ai)
				} else if inGraph && targetFI == fi {
					// Self-recursive call — edge back to own entry block
					dstID := blockNodeID(fi, 0)
					edgeKey := srcID + "->" + dstID + ":self"
					if edgeSeen[edgeKey] {
						continue
					}
					edgeSeen[edgeKey] = true
					fmt.Fprintf(&b, "  %s -> %s [color=%q, style=dashed, penwidth=0.4];\n",
						srcID, dstID, ai)
				} else if !inGraph {
					calleeNodeID := DotID(call.Callee)
					if !externalSeen[call.Callee] {
						externalSeen[call.Callee] = true
						if IsAllCaps(call.Callee) {
							fmt.Fprintf(&b, "  %s [label=%q, shape=plaintext, fontname=\"Courier,monospace\", fontcolor=%q, fontsize=8];\n",
								calleeNodeID, call.Callee, nezumi)
						} else {
							fmt.Fprintf(&b, "  %s [label=%q, shape=plaintext, fontcolor=%q, fontsize=8];\n",
								calleeNodeID, call.Callee, shu)
						}
					}
					edgeKey := srcID + "->" + calleeNodeID
					if edgeSeen[edgeKey] {
						continue
					}
					edgeSeen[edgeKey] = true
					if IsAllCaps(call.Callee) {
						fmt.Fprintf(&b, "  %s -> %s [color=%q, style=dotted, penwidth=0.2];\n",
							srcID, calleeNodeID, nezumi)
					} else {
						fmt.Fprintf(&b, "  %s -> %s [color=%q, style=dashed, penwidth=0.3];\n",
							srcID, calleeNodeID, shu)
					}
				}
			}
		}

		// Parent→child edges (from entry block — no bytecode offset tracking for definitions)
		for _, childIdx := range f.Children {
			if childIdx < len(g.Funcs) {
				srcID := blockNodeID(fi, 0)
				dstID := blockNodeID(childIdx, 0)
				targetCluster := fmt.Sprintf("cluster_%d", childIdx)
				fmt.Fprintf(&b, "  %s -> %s [lhead=%q, color=%q, style=dashed, penwidth=0.3];\n",
					srcID, dstID, targetCluster, ai)
			}
		}
	}

	b.WriteString("}\n")
	return b.String()
}

// ResolveTarget follows chains of empty blocks to find the next visible block.
func ResolveTarget(f *callgraph.FuncCFG, blockID int, visible map[int]bool) int {
	visited := map[int]bool{}
	for !visible[blockID] {
		if visited[blockID] || blockID < 0 || blockID >= len(f.Blocks) {
			return -1
		}
		visited[blockID] = true
		block := f.Blocks[blockID]
		if len(block.Succs) == 0 {
			return -1
		}
		blockID = block.Succs[0].BlockID
	}
	return blockID
}

// blockNodeID creates a unique DOT node ID for a basic block.
func blockNodeID(funcIdx, blockID int) string {
	return fmt.Sprintf("f%d_b%d", funcIdx, blockID)
}

// buildBlockLabel creates an HTML label showing calls in order.
// Washi palette: sumi for callees, cha for args, enji for strings, ai for booleans.
// When dark=true (entry blocks), uses light colors for readability on sumi background.
func buildBlockLabel(block *callgraph.BasicBlock, funcName string, dark bool) string {
	var (
		textColor string
		propColor string
		strColor  string
		boolColor string
	)
	if dark {
		textColor = "#FAF6F0" // kinari
		propColor = "#D4C5A9" // light cha
		strColor  = "#E8A0A0" // light enji
		boolColor = "#8FAED4" // light ai
	} else {
		textColor = "#2D2D2D" // sumi
		propColor = "#8B7355" // cha
		strColor  = "#9B2335" // enji
		boolColor = "#2D4A7A" // ai
	}

	hasCalls := len(block.Calls) > 0
	hasProps := len(block.Props) > 0

	const pt = "8"

	if !hasCalls && !hasProps {
		if block.ID == 0 {
			return fmt.Sprintf("<<font point-size=\"%s\" color=\"%s\">entry</font>>", pt, textColor)
		}
		return fmt.Sprintf("<<font point-size=\"%s\" color=\"%s\">@%d</font>>", pt, textColor, block.Start)
	}

	var b strings.Builder
	b.WriteString("<<table border=\"0\" cellborder=\"0\" cellspacing=\"0\" cellpadding=\"2\">")
	lineCount := 0

	for _, prop := range block.Props {
		if lineCount >= maxBlockCalls {
			break
		}
		fmt.Fprintf(&b, "<tr><td align=\"left\"><font point-size=\"%s\" color=\"%s\">%s</font></td></tr>",
			pt, propColor, DotEscape(prop.Name))
		lineCount++
	}

	for _, call := range block.Calls {
		if lineCount >= maxBlockCalls {
			break
		}
		b.WriteString("<tr><td align=\"left\">")
		callee := DotEscape(call.Callee)
		fmt.Fprintf(&b, "<font point-size=\"%s\" color=\"%s\">%s", pt, textColor, callee)
		if len(call.Args) > 0 {
			fmt.Fprintf(&b, " <font color=\"%s\">(</font>", propColor)
			for j, arg := range call.Args {
				if j > 0 {
					fmt.Fprintf(&b, "<font color=\"%s\">, </font>", propColor)
				}
				if strings.HasPrefix(arg, "\"") {
					fmt.Fprintf(&b, "<font color=\"%s\">%s</font>", strColor, DotEscape(arg))
				} else if arg == "true" || arg == "false" || arg == "null" {
					fmt.Fprintf(&b, "<font color=\"%s\">%s</font>", boolColor, arg)
				} else {
					fmt.Fprintf(&b, "<font color=\"%s\">%s</font>", propColor, DotEscape(arg))
				}
			}
			fmt.Fprintf(&b, "<font color=\"%s\">)</font>", propColor)
		}
		b.WriteString("</font></td></tr>")
		lineCount++
	}

	total := len(block.Calls) + len(block.Props)
	if total > maxBlockCalls {
		fmt.Fprintf(&b, "<tr><td align=\"left\"><font point-size=\"%s\" color=\"%s\">+%d more</font></td></tr>",
			pt, propColor, total-maxBlockCalls)
	}
	b.WriteString("</table>>")
	return b.String()
}
