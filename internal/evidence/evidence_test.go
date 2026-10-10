package evidence

import (
	"reflect"
	"strings"
	"testing"

	"aotopsy/internal/disasm"
	"aotopsy/internal/output"
	"aotopsy/internal/typetrack"
)

const evidenceTestDartVersion = "3.13.0"

func testRuntimeEvidence(targets ...disasm.RuntimeTargetObservation) disasm.RuntimeEvidence {
	observations := 0
	for _, target := range targets {
		observations += target.Count
	}
	return disasm.RuntimeEvidence{
		Source:       "frida",
		GenerationID: strings.Repeat("b", 64),
		SourceSHA256: strings.Repeat("a", 64),
		SourceSize:   1234,
		ModuleName:   "libapp.so",
		DartVersion:  evidenceTestDartVersion,
		Architecture: "arm64",
		Agreement:    disasm.RuntimeObservedOnly,
		Targets:      targets,
		ClassIDs:     []int{10, 11},
		Observations: observations,
	}
}

func TestCallEdgeEvidenceHasStrictConfidenceRulesAndSDKRefs(t *testing.T) {
	c := NewCollector(evidenceTestDartVersion)
	c.FromCallEdges([]disasm.CallEdgeRecord{
		{FromFunc: "F", FromPC: "0x100", Kind: "bl", Target: "Direct", TargetAddress: "0x900"},
		{FromFunc: "F", FromPC: "0x200", Kind: "blr", Target: "AllocateArrayStub", Via: "THR.AllocateArray_entry_point", Reg: "X16"},
		{FromFunc: "F", FromPC: "0x300", Kind: "blr", Via: "THR.AllocateArray_entry_point", Reg: "X16"},
		{FromFunc: "F", FromPC: "0x400", Kind: "blr", Targets: []string{"A.paint", "B.paint"}, Candidates: 2, Via: "dispatch_table"},
	})
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	records := c.Records()
	if len(records) != 5 {
		t.Fatalf("records = %d, want 5", len(records))
	}
	if got := records[0]; got.Source != SourceCallEdges || got.Confidence != ConfExact || got.Rule != RuleDirectCallAddress || got.Result["target_address"] != "0x900" {
		t.Fatalf("direct evidence = %+v", got)
	} else if got.SDKRef != nil {
		t.Fatalf("encoded direct target should not need SDK support: %+v", got.SDKRef)
	}
	if got := records[1]; got.Source != SourceCallEdges || got.Confidence != ConfStaticInferred || got.Rule != RuleDirectCallTarget || got.Result["target"] != "Direct" {
		t.Fatalf("direct symbolic identity = %+v", got)
	}
	if got := records[2]; got.Confidence != ConfStub || got.Rule != RuleIndirectStub {
		t.Fatalf("resolved THR evidence = %+v", got)
	} else if got.SDKRef != nil {
		t.Fatalf("THR runtime-entry provenance fabricated SDK symbol: %+v", got.SDKRef)
	}
	if got := records[3]; got.Confidence != ConfUnknown || got.Rule != RuleIndirectUnresolved {
		t.Fatalf("unresolved provenance raised certainty: %+v", got)
	}
	if got := records[4]; got.Confidence != ConfPolymorphic || got.Rule != RuleIndirectPolymorphic {
		t.Fatalf("polymorphic evidence = %+v", got)
	} else if _, hasSingleTarget := got.Result["target"]; hasSingleTarget {
		t.Fatalf("polymorphic evidence fabricated single target: %+v", got.Result)
	}
}

func TestBLRResolutionEvidenceNeverPromotesIndirectCallToExact(t *testing.T) {
	c := NewCollector(evidenceTestDartVersion)
	c.FromBLRResolutions("F", []typetrack.BlrResolution{
		{PC: 0x1000, Resolved: true, TargetName: "A", Confidence: typetrack.ResolutionStaticInferred, Derivation: typetrack.DerivationDispatchTable},
		{PC: 0x2000, Resolved: true, Polymorphic: true, TargetNames: []string{"A", "B"}, Candidates: 2, Confidence: typetrack.ResolutionPolymorphic, Derivation: typetrack.DerivationDispatchTable},
		{PC: 0x3000, Resolved: false, Confidence: typetrack.ResolutionUnknown, Derivation: typetrack.DerivationUnknown},
		{PC: 0x4000, Resolved: true, TargetName: "C", Confidence: typetrack.ResolutionStaticInferred, Derivation: typetrack.DerivationUnlinkedCall},
	}, true)
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	records := c.Records()
	if records[0].Confidence != ConfStaticInferred || records[0].Confidence == ConfExact {
		t.Fatalf("indirect monomorphic confidence = %q", records[0].Confidence)
	}
	if records[0].SDKRef == nil || records[0].SDKRef.Tag != evidenceTestDartVersion || records[0].SDKRef.Symbol != "EmitDispatchTableCall" {
		t.Fatalf("dispatch sdk ref = %+v", records[0].SDKRef)
	}
	if records[1].Confidence != ConfPolymorphic || records[2].Confidence != ConfUnknown {
		t.Fatalf("unexpected confidence sequence: %+v", records)
	}
	if records[3].SDKRef != nil || records[3].Inputs["derivation"] != string(typetrack.DerivationUnlinkedCall) {
		t.Fatalf("unlinked-call inference acquired dispatch SDK provenance: %+v", records[3])
	}
}

func TestSignalEvidencePreservesRuleAndProducerConfidenceSeparately(t *testing.T) {
	c := NewCollector(evidenceTestDartVersion)
	c.FromSignalFindings([]output.SignalFinding{{
		Category:           "behavioral",
		StringValue:        "credential_function_calls_network_function",
		Function:           "F",
		RuleID:             "signal.behavioral.credential_function_calls_network_function",
		ProducerConfidence: "low",
	}})
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	got := c.Records()[0]
	if got.Source != SourceSignal || got.Confidence != ConfHeuristic || got.Rule != "signal.behavioral.credential_function_calls_network_function" {
		t.Fatalf("signal evidence = %+v", got)
	}
	if got.Result["producer_confidence"] != "low" {
		t.Fatalf("producer confidence lost: %+v", got.Result)
	}
}

func TestMergeRuntimePreservesStaticClaimAndRecordsRelationship(t *testing.T) {
	base := Evidence{
		PC:         "0x100",
		Function:   "F",
		Kind:       "dispatch",
		Source:     SourceTypeTrack,
		Result:     map[string]any{"target": "A"},
		Confidence: ConfStaticInferred,
		Rule:       RuleTypeTrackDispatch,
	}
	c := NewCollectorFromRecords(evidenceTestDartVersion, []Evidence{base})
	match := RuntimeObservation{
		PC:       "0x100",
		Function: "F",
		Runtime:  testRuntimeEvidence(disasm.RuntimeTargetObservation{Target: "A", Count: 3}),
	}
	if err := c.MergeRuntime([]RuntimeObservation{match}); err != nil {
		t.Fatalf("MergeRuntime: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	got := c.Records()[0]
	if got.Confidence != ConfStaticInferred || got.Result["target"] != "A" {
		t.Fatalf("runtime changed static claim: %+v", got)
	}
	if got.Runtime == nil || got.Runtime.Agreement != disasm.RuntimeAgrees || got.Runtime.Observations != 3 {
		t.Fatalf("runtime agreement = %+v", got.Runtime)
	}

	c = NewCollectorFromRecords(evidenceTestDartVersion, []Evidence{base})
	conflict := match
	conflict.Runtime = testRuntimeEvidence(disasm.RuntimeTargetObservation{Target: "B", Count: 2})
	if err := c.MergeRuntime([]RuntimeObservation{conflict}); err != nil {
		t.Fatalf("MergeRuntime conflict: %v", err)
	}
	got = c.Records()[0]
	if got.Confidence != ConfStaticInferred || got.Result["target"] != "A" || got.Runtime == nil || got.Runtime.Agreement != disasm.RuntimeConflicts {
		t.Fatalf("runtime conflict overwrote static claim: %+v", got)
	}
}

func TestMergeRuntimeDistinguishesUnresolvedFromAbsentEvidence(t *testing.T) {
	unresolved := Evidence{
		PC:         "0x100",
		Function:   "F",
		Kind:       "dispatch",
		Source:     SourceTypeTrack,
		Result:     map[string]any{"resolved": false},
		Confidence: ConfUnknown,
		Rule:       RuleTypeTrackDispatch,
	}
	observation := RuntimeObservation{
		PC:       "0x100",
		Function: "F",
		Runtime:  testRuntimeEvidence(disasm.RuntimeTargetObservation{Target: "A", Count: 1}),
	}
	c := NewCollectorFromRecords(evidenceTestDartVersion, []Evidence{unresolved})
	if err := c.MergeRuntime([]RuntimeObservation{observation}); err != nil {
		t.Fatalf("MergeRuntime unresolved: %v", err)
	}
	got := c.Records()[0]
	if got.Confidence != ConfUnknown || got.Runtime == nil || got.Runtime.Agreement != disasm.RuntimeObservedOnly {
		t.Fatalf("unresolved observation semantics = %+v", got)
	}

	observation.PC = "0x200"
	c = NewCollector(evidenceTestDartVersion)
	if err := c.MergeRuntime([]RuntimeObservation{observation}); err != nil {
		t.Fatalf("MergeRuntime runtime-only: %v", err)
	}
	records := c.Records()
	if len(records) != 1 || records[0].Kind != "runtime_call" || records[0].Source != SourceFrida || records[0].Confidence != ConfRuntimeObserved {
		t.Fatalf("runtime-only row = %+v", records)
	}
}

func TestMergeRuntimeRejectsMixedBinaryIdentity(t *testing.T) {
	first := RuntimeObservation{PC: "0x100", Function: "F", Runtime: testRuntimeEvidence(disasm.RuntimeTargetObservation{Target: "A", Count: 1})}
	second := RuntimeObservation{PC: "0x200", Function: "G", Runtime: testRuntimeEvidence(disasm.RuntimeTargetObservation{Target: "B", Count: 1})}
	second.Runtime.GenerationID = strings.Repeat("c", 64)

	c := NewCollector(evidenceTestDartVersion)
	if err := c.MergeRuntime([]RuntimeObservation{first, second}); err == nil {
		t.Fatal("mixed runtime generations were accepted")
	}
	report := c.Coverage([]RuntimeObservation{first, second})
	if report.TotalRuntime != 1 || report.InvalidRuntime != 1 {
		t.Fatalf("mixed runtime identity coverage = %+v", report)
	}
}

func TestRuntimeEvidenceRejectsImpossibleCountsAndClassIDs(t *testing.T) {
	tests := []disasm.RuntimeEvidence{
		func() disasm.RuntimeEvidence {
			rt := testRuntimeEvidence(disasm.RuntimeTargetObservation{Target: "A", Count: 2})
			rt.Observations = 1
			return rt
		}(),
		func() disasm.RuntimeEvidence {
			rt := testRuntimeEvidence(disasm.RuntimeTargetObservation{Target: "A", Count: 1})
			rt.ClassIDs = []int{0}
			return rt
		}(),
	}
	for i := range tests {
		if err := validateRuntimeEvidence(&tests[i]); err == nil {
			t.Fatalf("runtime invariant case %d was accepted: %+v", i, tests[i])
		}
	}
}

func TestValidateRejectsMalformedCertaintyAndProvenance(t *testing.T) {
	tests := []struct {
		name string
		rec  Evidence
	}{
		{
			name: "dynamic rule text",
			rec:  Evidence{PC: "0x1", Kind: "call", Source: SourceCallEdges, Result: map[string]any{"target": "A"}, Confidence: ConfExact, Rule: RuleID("call via THR.foo")},
		},
		{
			name: "unknown with target",
			rec:  Evidence{PC: "0x1", Kind: "dispatch", Source: SourceTypeTrack, Result: map[string]any{"target": "A"}, Confidence: ConfUnknown, Rule: RuleTypeTrackDispatch},
		},
		{
			name: "polymorphic as single target",
			rec:  Evidence{PC: "0x1", Kind: "dispatch", Source: SourceTypeTrack, Result: map[string]any{"target": "A"}, Confidence: ConfPolymorphic, Rule: RuleTypeTrackDispatch},
		},
		{
			name: "wrong sdk version",
			rec:  Evidence{PC: "0x1", Kind: "call", Source: SourceCallEdges, Result: map[string]any{"target_address": "0x2"}, Confidence: ConfExact, Rule: RuleDirectCallAddress, SDKRef: &SDKReference{Tag: "3.12.2", File: "runtime/vm/compiler/backend/flow_graph_compiler_arm64.cc", Symbol: "GenerateStaticDartCall"}},
		},
		{
			name: "fabricated sdk symbol",
			rec: Evidence{
				PC: "0x1", Kind: "dispatch", Source: SourceTypeTrack,
				Result: map[string]any{"target": "A"}, Confidence: ConfStaticInferred, Rule: RuleTypeTrackDispatch,
				SDKRef: &SDKReference{Tag: evidenceTestDartVersion, File: "runtime/vm/compiler/runtime_offsets_extracted.h", Symbol: "Thread_Fabricated_entry_point_offset"},
			},
		},
		{
			name: "fabricated call rule",
			rec: Evidence{
				PC: "0x1", Kind: "call", Source: SourceCallEdges,
				Result: map[string]any{"resolved": false}, Confidence: ConfUnknown, Rule: "call.fabricated",
			},
		},
		{
			name: "fabricated typetrack rule",
			rec: Evidence{
				PC: "0x1", Kind: "dispatch", Source: SourceTypeTrack,
				Result: map[string]any{"resolved": false}, Confidence: ConfUnknown, Rule: "typetrack.fabricated",
			},
		},
		{
			name: "non canonical pc",
			rec: Evidence{
				PC: "0X0001", Kind: "call", Source: SourceCallEdges,
				Result: map[string]any{"target_address": "0x2"}, Confidence: ConfExact, Rule: RuleDirectCallAddress,
			},
		},
		{
			name: "unsorted polymorphic candidates",
			rec: Evidence{
				PC: "0x1", Kind: "dispatch", Source: SourceTypeTrack,
				Result: map[string]any{"targets": []string{"B", "A"}, "candidate_count": 2}, Confidence: ConfPolymorphic, Rule: RuleTypeTrackDispatch,
			},
		},
		{
			name: "call rule confidence mismatch",
			rec: Evidence{
				PC: "0x1", Kind: "call", Source: SourceCallEdges,
				Result: map[string]any{"target": "A"}, Confidence: ConfStaticInferred, Rule: RuleIndirectStub,
			},
		},
		{
			name: "runtime version mismatch",
			rec: func() Evidence {
				rt := testRuntimeEvidence(disasm.RuntimeTargetObservation{Target: "A", Count: 1})
				rt.DartVersion = "3.12.2"
				rt.Agreement = disasm.RuntimeAgrees
				return Evidence{PC: "0x1", Function: "F", Kind: "dispatch", Source: SourceTypeTrack, Result: map[string]any{"target": "A"}, Confidence: ConfStaticInferred, Rule: RuleTypeTrackDispatch, Runtime: &rt}
			}(),
		},
		{
			name: "false runtime agreement",
			rec: func() Evidence {
				rt := testRuntimeEvidence(disasm.RuntimeTargetObservation{Target: "B", Count: 1})
				rt.Agreement = disasm.RuntimeAgrees
				return Evidence{PC: "0x1", Function: "F", Kind: "dispatch", Source: SourceTypeTrack, Result: map[string]any{"target": "A"}, Confidence: ConfStaticInferred, Rule: RuleTypeTrackDispatch, Runtime: &rt}
			}(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCollectorFromRecords(evidenceTestDartVersion, []Evidence{tc.rec})
			if err := c.Validate(); err == nil {
				t.Fatalf("Validate accepted malformed evidence: %+v", tc.rec)
			}
		})
	}
}

func TestRecordsAreDeterministicAndDeduplicateExactClaims(t *testing.T) {
	a := Evidence{PC: "0x20", Function: "B", Kind: "call", Source: SourceCallEdges, Result: map[string]any{"target_address": "0x200"}, Confidence: ConfExact, Rule: RuleDirectCallAddress}
	b := Evidence{PC: "0x10", Function: "A", Kind: "call", Source: SourceCallEdges, Result: map[string]any{"target_address": "0x100"}, Confidence: ConfExact, Rule: RuleDirectCallAddress}
	c := NewCollectorFromRecords(evidenceTestDartVersion, []Evidence{a, b, a})
	first := c.Records()
	second := c.Records()
	if len(first) != 2 {
		t.Fatalf("deduped records = %d, want 2: %+v", len(first), first)
	}
	if first[0].PC != "0x10" || first[1].PC != "0x20" {
		t.Fatalf("numeric ordering = %+v", first)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Records is nondeterministic:\nfirst=%+v\nsecond=%+v", first, second)
	}
}
