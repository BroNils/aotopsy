package analysis

import (
	"slices"
	"testing"

	"aotopsy/internal/disasm"
)

func TestStaticSignalCallsPreservesPolymorphicTargetsAndExcludesRuntimeEvidence(t *testing.T) {
	edges := map[uint64][]disasm.CallEdgeRecord{
		0x1000: {{
			FromFunc: "caller", FromPC: "0x1000", Kind: "call_indirect",
			Targets: []string{"Impl.b", "Impl.a"}, Candidates: 2,
			Runtime: &disasm.RuntimeEvidence{
				Targets:      []disasm.RuntimeTargetObservation{{Target: "Runtime.only", Count: 9}},
				Observations: 9,
			},
		}},
	}
	got := staticSignalCalls(edges, []uint64{0x1000})
	want := []string{"Impl.a", "Impl.b"}
	if !slices.Equal(got, want) {
		t.Fatalf("staticSignalCalls = %v, want %v", got, want)
	}
}

func TestStaticSignalCallsKeepsDistinctCallRecordsAtSamePC(t *testing.T) {
	edges := map[uint64][]disasm.CallEdgeRecord{
		0x1000: {
			{FromFunc: "caller", FromPC: "0x1000", Kind: "bl", Target: "Direct.one"},
			{FromFunc: "caller", FromPC: "0x1000", Kind: "call_indirect", Targets: []string{"Poly.two"}, Candidates: 1},
		},
	}
	got := staticSignalCalls(edges, []uint64{0x1000})
	want := []string{"Direct.one", "Poly.two"}
	if !slices.Equal(got, want) {
		t.Fatalf("staticSignalCalls = %v, want %v", got, want)
	}
}
