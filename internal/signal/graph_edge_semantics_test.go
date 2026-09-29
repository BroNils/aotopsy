package signal

import (
	"testing"

	"aotopsy/internal/disasm"
)

func TestBuildSignalGraphExpandsPolymorphicTargets(t *testing.T) {
	funcs := []disasm.FuncRecord{{Name: "caller"}, {Name: "Impl.a"}, {Name: "Impl.b"}}
	edges := []disasm.CallEdgeRecord{{
		FromFunc: "caller", Kind: "call_indirect", Via: "dispatch_table",
		Targets: []string{"Impl.a", "Impl.b"}, Candidates: 2,
	}}
	g := BuildSignalGraph(funcs, edges, nil, 1, nil)
	got := make(map[string]SignalEdge)
	for _, e := range g.Edges {
		got[e.To] = e
	}
	for _, target := range []string{"Impl.a", "Impl.b"} {
		e, ok := got[target]
		if !ok {
			t.Fatalf("polymorphic target %q missing from SignalGraph edges: %+v", target, g.Edges)
		}
		if e.Kind != "call_indirect" || e.Via != "dispatch_table" {
			t.Fatalf("edge to %q lost indirect provenance: %+v", target, e)
		}
	}
}
