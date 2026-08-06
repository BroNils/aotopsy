// Package lattice provides architecture-neutral graph IR with DOT
// rendering for call graphs and control flow graphs.
//
// Vendored from github.com/zboralski/lattice by Anthony Zboralski.
// Modified locally for AOTopsy-specific needs.
package lattice

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
