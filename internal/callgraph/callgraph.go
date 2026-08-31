// Package callgraph converts aotopsy's disassembly output (ARM64 via
// internal/disasm, x86_64 via internal/decompiler's x86 CFG lifter, see
// cfgx86.go) into callgraph Graph types for DOT
// rendering and whole-binary call-graph construction.
package callgraph

import (
	"aotopsy/internal/disasm"
)

// FuncInfo holds the data needed to build call graph and CFG for one function.
type FuncInfo struct {
	Name      string
	Insts     []disasm.Inst
	CallEdges []disasm.CallEdge
}

// BuildCallGraph constructs a Graph from disassembled functions.
// Each function becomes a node. Each resolved call edge becomes an edge.
// Unresolved BLR targets (no TargetName or Via) are skipped.
func BuildCallGraph(funcs []FuncInfo) *Graph {
	g := &Graph{}
	for _, f := range funcs {
		g.Nodes = append(g.Nodes, f.Name)
		for _, e := range f.CallEdges {
			callee := e.TargetName
			if callee == "" {
				callee = e.Via
			}
			if callee == "" {
				continue
			}
			g.Edges = append(g.Edges, Edge{
				Caller: f.Name,
				Callee: callee,
			})
		}
	}
	g.Dedup()
	return g
}
