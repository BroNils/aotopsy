package render

import (
	"fmt"
	"testing"

	"aotopsy/internal/signal"
)

// buildWobbleGraph makes a graph shaped to expose map-iteration order:
// many same-named-ish nodes, several owners, chains of context nodes that the
// pruner can collapse, and signal functions carrying string refs.
//
// Chains matter most. SignalDOT's pruning loop deletes from pathNodes and
// rewires pathEdges while iterating it, so with map order two runs collapse
// different chains and the graph's SHAPE differs -- not just its line order.
func buildWobbleGraph() *signal.SignalGraph {
	g := &signal.SignalGraph{}
	add := func(name, owner, role, sev string, refs []signal.ClassifiedStringRef) {
		g.Funcs = append(g.Funcs, signal.SignalFunc{
			Name: name, Owner: owner, Role: role, Severity: sev,
			Categories: []string{"net"}, StringRefs: refs,
		})
	}
	edge := func(from, to, kind string) {
		g.Edges = append(g.Edges, signal.SignalEdge{From: from, To: to, Kind: kind, Via: "v_" + to})
	}
	for i := 0; i < 12; i++ {
		root := fmt.Sprintf("root_%02d", i)
		add(root, "", "", "", nil)
		prev := root
		// A collapsible chain of context nodes.
		for j := 0; j < 3; j++ {
			mid := fmt.Sprintf("ctx_%02d_%d", i, j)
			add(mid, fmt.Sprintf("Owner%d", i%4), "context", "", nil)
			edge(prev, mid, "bl")
			prev = mid
		}
		sig := fmt.Sprintf("sig_%02d", i)
		add(sig, fmt.Sprintf("Owner%d", i%4), "signal", "high", []signal.ClassifiedStringRef{
			{Value: fmt.Sprintf("secret-%02d", i), Categories: []string{"crypto"}},
			{Value: fmt.Sprintf("https://host-%02d/api", i), Categories: []string{"net"}},
		})
		edge(prev, sig, "bl")
		if i > 0 {
			edge(fmt.Sprintf("sig_%02d", i-1), sig, "blr")
		}
	}
	return g
}

// TestSignalDOTIsDeterministic covers what the golden gate structurally
// cannot: signal.dot and signal_cfg.dot are produced only with Signal:true,
// which the golden harness disables because their titles embed the host path.
// That gap let nine map-order dependencies survive across both renderers.
//
// Rendering the same graph repeatedly must give the same bytes.
func TestSignalDOTIsDeterministic(t *testing.T) {
	g := buildWobbleGraph()
	first := SignalDOT(g, "title", NASA)
	for i := 0; i < 20; i++ {
		if got := SignalDOT(g, "title", NASA); got != first {
			t.Fatalf("SignalDOT run %d differs from run 0 -- map iteration order is leaking into the output", i+1)
		}
	}
}

func TestSignalCFGDOTIsDeterministic(t *testing.T) {
	g := buildWobbleGraph()
	content := map[string]*SignalFuncContent{}
	for _, f := range g.Funcs {
		if f.Role != "signal" {
			continue
		}
		strs := make([]ClassifiedString, 0, len(f.StringRefs))
		for _, sr := range f.StringRefs {
			strs = append(strs, ClassifiedString{Value: sr.Value})
		}
		content[f.Name] = &SignalFuncContent{Strings: strs}
	}
	first := SignalCFGDOT(g, content, "title", NASA)
	for i := 0; i < 20; i++ {
		if got := SignalCFGDOT(g, content, "title", NASA); got != first {
			t.Fatalf("SignalCFGDOT run %d differs from run 0 -- map iteration order is leaking into the output", i+1)
		}
	}
}
