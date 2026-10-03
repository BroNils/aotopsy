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
		if e.Resolution != ResolutionPolymorphicCandidate || e.CandidateCount != 2 || !e.CandidateCountKnown || !e.TargetsComplete {
			t.Fatalf("edge to %q lost polymorphic completeness metadata: %+v", target, e)
		}
	}
}

func TestBuildSignalGraphTreatsMissingPolymorphicCandidateCountAsUnknown(t *testing.T) {
	funcs := []disasm.FuncRecord{{Name: "caller"}, {Name: "Impl.a"}, {Name: "Impl.b"}}
	edges := []disasm.CallEdgeRecord{{
		FromFunc: "caller", FromPC: "0x1000", Kind: "call_indirect", Via: "dispatch_table",
		Targets: []string{"Impl.a", "Impl.b"},
	}}
	g := BuildSignalGraph(funcs, edges, nil, 1, nil)
	if g.Stats.UnknownCandidateCountSites != 1 || g.Stats.IncompletePolymorphicSites != 0 {
		t.Fatalf("unknown candidate count stats = %+v", g.Stats)
	}
	for _, e := range g.Edges {
		if e.Resolution == ResolutionPolymorphicCandidate && (e.CandidateCountKnown || e.TargetsComplete) {
			t.Fatalf("missing candidate count was guessed complete: %+v", e)
		}
	}
}

func TestBuildSignalGraphDoesNotPromoteViaToCallee(t *testing.T) {
	funcs := []disasm.FuncRecord{{Name: "caller"}, {Name: "dispatch_table"}}
	edges := []disasm.CallEdgeRecord{{
		FromFunc: "caller", Kind: "call_indirect", Via: "dispatch_table",
	}}
	g := BuildSignalGraph(funcs, edges, nil, 1, nil)
	if len(g.Edges) != 1 || g.Edges[0].To != "" || g.Edges[0].Resolution != ResolutionUnresolved {
		t.Fatalf("unresolved call-site evidence was not preserved distinctly: %+v", g.Edges)
	}
	for _, f := range g.Funcs {
		if f.Name == "dispatch_table" && f.Role == "context" {
			t.Fatalf("Via-only provenance made %q reachable context", f.Name)
		}
	}
}

func TestBuildSignalGraphPreservesIncompletePolymorphicAndRuntimeEvidence(t *testing.T) {
	funcs := []disasm.FuncRecord{{Name: "caller"}, {Name: "Impl.a"}, {Name: "Impl.b"}, {Name: "Runtime.only"}}
	edges := []disasm.CallEdgeRecord{{
		FromFunc: "caller", FromPC: "0x1000", Kind: "call_indirect", Via: "dispatch_table",
		Targets: []string{"Impl.a", "Impl.b"}, Candidates: 50,
		Runtime: &disasm.RuntimeEvidence{
			Agreement: disasm.RuntimeIndeterminate, Observations: 3,
			Targets: []disasm.RuntimeTargetObservation{{Target: "Runtime.only", Count: 3}},
		},
	}}
	g := BuildSignalGraph(funcs, edges, nil, 1, nil)
	if g.Stats.IncompletePolymorphicSites != 1 || g.Stats.StaticRelations != 2 || g.Stats.RuntimeObservedSites != 1 || g.Stats.RuntimeRelations != 1 {
		t.Fatalf("signal graph stats lost call-site semantics: %+v", g.Stats)
	}
	static, runtime := 0, 0
	for _, e := range g.Edges {
		switch e.Resolution {
		case ResolutionPolymorphicCandidate:
			static++
			if e.CandidateCount != 50 || e.TargetsComplete {
				t.Fatalf("incomplete candidate set was presented as complete: %+v", e)
			}
		case ResolutionRuntimeObserved:
			runtime++
			if e.RuntimeAgreement != disasm.RuntimeIndeterminate || e.RuntimeObservations != 3 {
				t.Fatalf("runtime evidence lost provenance/agreement: %+v", e)
			}
		}
	}
	if static != 2 || runtime != 1 {
		t.Fatalf("edge partition = static %d runtime %d, want 2/1: %+v", static, runtime, g.Edges)
	}
}

func TestBuildSignalGraphDoesNotCountExternalContextOrUnknownSignalFunctions(t *testing.T) {
	funcs := []disasm.FuncRecord{{Name: "known"}}
	edges := []disasm.CallEdgeRecord{{FromFunc: "known", Kind: "bl", Target: "external.semantic.name"}}
	refs := []disasm.StringRefRecord{
		{Func: "known", Value: "https://example.com"},
		{Func: "ghost", Value: "https://ghost.example.com"},
	}
	g := BuildSignalGraph(funcs, edges, refs, 2, nil)
	if g.Stats.SignalFuncs != 1 || g.Stats.ContextFuncs != 0 || g.Stats.StringRefCount != 1 {
		t.Fatalf("unknown functions inflated signal/context population: %+v", g.Stats)
	}
	if len(g.Funcs) != 1 || g.Funcs[0].Name != "known" {
		t.Fatalf("unexpected function population: %+v", g.Funcs)
	}
}

func TestBuildSignalGraphKeepsRawDirectAddressOutOfFunctionRelations(t *testing.T) {
	funcs := []disasm.FuncRecord{{Name: "caller"}}
	edges := []disasm.CallEdgeRecord{{
		FromFunc: "caller", FromPC: "0x1000", Kind: "bl",
		Target: "0x1234", TargetAddress: "0x1234",
	}}
	g := BuildSignalGraph(funcs, edges, nil, 1, nil)
	if g.Stats.StaticRelations != 0 || len(g.Edges) != 1 {
		t.Fatalf("raw address became a static function relation: stats=%+v edges=%+v", g.Stats, g.Edges)
	}
	e := g.Edges[0]
	if e.To != "" || e.Resolution != ResolutionAddressOnly || e.TargetAddress != "0x1234" || !e.TargetsComplete {
		t.Fatalf("raw direct address edge = %+v, want exact address-only evidence", e)
	}
}

func TestBuildSignalGraphDeduplicatesCodeAliasesByFunctionIdentity(t *testing.T) {
	funcs := []disasm.FuncRecord{
		{Name: "Alias.same", Owner: "Alias", PC: "0x1000", Size: 16, RefID: 1},
		{Name: "Alias.same", Owner: "Alias", PC: "0x1000", Size: 16, RefID: 2},
	}
	g := BuildSignalGraph(funcs, nil, []disasm.StringRefRecord{{Func: "Alias.same", Value: "https://example.com"}}, 1, nil)
	if g.Stats.TotalFuncs != 1 || g.Stats.SignalFuncs != 1 || len(g.Funcs) != 1 {
		t.Fatalf("code alias inflated signal graph function population: stats=%+v funcs=%+v", g.Stats, g.Funcs)
	}
}

func TestBuildSignalGraphStatsMatchDeduplicatedEdges(t *testing.T) {
	funcs := []disasm.FuncRecord{{Name: "caller"}, {Name: "callee"}}
	edge := disasm.CallEdgeRecord{FromFunc: "caller", FromPC: "0x1000", Kind: "bl", Target: "callee", TargetAddress: "0x2000"}
	g := BuildSignalGraph(funcs, []disasm.CallEdgeRecord{edge, edge}, nil, 1, nil)
	if g.Stats.CallSites != 1 || g.Stats.StaticRelations != 1 || len(g.Edges) != 1 {
		t.Fatalf("duplicate record inflated signal stats: stats=%+v edges=%+v", g.Stats, g.Edges)
	}
}

func TestBuildSignalGraphPreservesUnsupportedCallKindAsEvidence(t *testing.T) {
	funcs := []disasm.FuncRecord{{Name: "caller"}, {Name: "callee"}}
	edge := disasm.CallEdgeRecord{FromFunc: "caller", FromPC: "0x1000", Kind: "future_call_kind", Target: "callee"}
	g := BuildSignalGraph(funcs, []disasm.CallEdgeRecord{edge}, nil, 1, nil)
	if g.Stats.CallSites != 1 || g.Stats.UnsupportedCallSites != 1 || g.Stats.StaticRelations != 0 || len(g.Edges) != 1 {
		t.Fatalf("unsupported kind was dropped or traversed: stats=%+v edges=%+v", g.Stats, g.Edges)
	}
	if g.Edges[0].Resolution != ResolutionUnsupported || g.Edges[0].To != "" || g.Edges[0].Kind != "future_call_kind" {
		t.Fatalf("unsupported kind evidence = %+v", g.Edges[0])
	}
}
