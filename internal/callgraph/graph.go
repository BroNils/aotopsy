package callgraph

// This file merges lattice/graph.go and lattice/cfg.go into callgraph.

// rendering for call graphs and control flow graphs.
//
// Vendored from github.com/zboralski/lattice by Anthony Zboralski.
// Modified locally for AOTopsy-specific needs.

// Edge represents a call from one function to another.
type Edge struct {
	Caller string
	Callee string
	Args   []string // literal arguments observed at call site
}

// Graph holds a callgraph.
type Graph struct {
	Nodes []string
	Edges []Edge
}

// Dedup removes duplicate nodes and duplicate edges.
// Edges are deduplicated by (Caller, Callee) pair; the first occurrence is kept.
func (g *Graph) Dedup() {
	seen := map[string]bool{}
	var nodes []string
	for _, n := range g.Nodes {
		if !seen[n] {
			seen[n] = true
			nodes = append(nodes, n)
		}
	}
	g.Nodes = nodes

	type edgeKey struct{ caller, callee string }
	seenEdges := map[edgeKey]bool{}
	var edges []Edge
	for _, e := range g.Edges {
		k := edgeKey{e.Caller, e.Callee}
		if !seenEdges[k] {
			seenEdges[k] = true
			edges = append(edges, e)
		}
	}
	g.Edges = edges
}

// CallSite records a call found during bytecode or source scanning.
type CallSite struct {
	Offset int
	Callee string
	Args   []string
}

// Successor describes a control flow edge to another basic block.
type Successor struct {
	BlockID int
	Cond    string // "" (unconditional), "T" (true), "F" (false)
}

// PropAccess records a property read or name lookup that isn't a call target.
type PropAccess struct {
	Name string
}

// BasicBlock is a straight-line sequence of instructions.
type BasicBlock struct {
	ID    int
	Start int
	End   int // exclusive
	Calls []CallSite
	Props []PropAccess // property accesses not consumed by calls
	Succs []Successor
	// Term indicates the block ends with a control flow opcode
	// (goto, ifeq, return, throw, etc.). Note: Term=true does NOT mean
	// "no successors" — branches have Term=true with Succs populated.
	// A true exit block has Term=true AND len(Succs)==0.
	Term bool
}

// FuncCFG is a per-function control flow graph.
type FuncCFG struct {
	Name     string
	Blocks   []*BasicBlock
	Children []int // indices of child functions in CFGGraph.Funcs
}

// CFGGraph holds a full program control flow graph.
type CFGGraph struct {
	Funcs []*FuncCFG
}
