package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aotopsy/internal/disasm"
	"aotopsy/internal/output"
	"aotopsy/internal/typetrack"
)

func TestFromCallEdges(t *testing.T) {
	edges := []disasm.CallEdgeRecord{
		{FromFunc: "Foo.bar", FromPC: "0x1000", Kind: "bl", Target: "Baz.qux"},
		{FromFunc: "Foo.bar", FromPC: "0x2000", Kind: "blr", Via: "THR.AllocateArray_ep"},
		{FromFunc: "Foo.bar", FromPC: "0x3000", Kind: "blr", Targets: []string{"A.paint", "B.paint"}, Candidates: 2},
		{FromFunc: "Foo.bar", FromPC: "0x4000", Kind: "blr"},
		{FromFunc: "Foo.bar", FromPC: "0x5000", Kind: "blr", Target: "Inferred.target"},
	}

	c := NewCollector()
	c.FromCallEdges(edges)
	records := c.Records()
	if len(records) != 5 {
		t.Fatalf("want 5 records, got %d", len(records))
	}

	// Direct call → exact
	if records[0].Confidence != "exact" {
		t.Errorf("record 0 confidence = %s, want exact", records[0].Confidence)
	}
	if records[0].Result["target"] != "Baz.qux" {
		t.Errorf("record 0 target = %v, want Baz.qux", records[0].Result["target"])
	}

	// Via only → stub
	if records[1].Confidence != "stub" {
		t.Errorf("record 1 confidence = %s, want stub", records[1].Confidence)
	}

	// Polymorphic → polymorphic
	if records[2].Confidence != "polymorphic" {
		t.Errorf("record 2 confidence = %s, want polymorphic", records[2].Confidence)
	}

	// Unresolved → unknown
	if records[3].Confidence != "unknown" {
		t.Errorf("record 3 confidence = %s, want unknown", records[3].Confidence)
	}

	// An indirect edge may carry a single statically inferred target after
	// typetrack. The mere presence of Target does not make the machine code a
	// direct call and must never be labelled exact.
	if records[4].Confidence != ConfStaticInferred {
		t.Errorf("record 4 confidence = %s, want static_inferred", records[4].Confidence)
	}
	if records[4].Rule != "indirect_call_static_inferred" {
		t.Errorf("record 4 rule = %q", records[4].Rule)
	}
}

func TestWriteJSONL(t *testing.T) {
	edges := []disasm.CallEdgeRecord{
		{FromFunc: "Foo.bar", FromPC: "0x1000", Kind: "bl", Target: "Baz.qux"},
	}
	c := NewCollector()
	c.FromCallEdges(edges)

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "sub", "evidence.jsonl")
	if err := c.WriteJSONL(path); err != nil {
		t.Fatalf("WriteJSONL: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var rec Evidence
	if err := json.Unmarshal(data[:len(data)-1], &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec.Function != "Foo.bar" {
		t.Errorf("function = %s, want Foo.bar", rec.Function)
	}
	if rec.Confidence != "exact" {
		t.Errorf("confidence = %s, want exact", rec.Confidence)
	}
}

func TestRecordsSortedByPC(t *testing.T) {
	edges := []disasm.CallEdgeRecord{
		{FromFunc: "F", FromPC: "0x3000", Kind: "bl", Target: "C"},
		{FromFunc: "F", FromPC: "0x1000", Kind: "bl", Target: "A"},
		{FromFunc: "F", FromPC: "0x20", Kind: "bl", Target: "B"},
	}
	c := NewCollector()
	c.FromCallEdges(edges)
	records := c.Records()
	if records[0].PC != "0x20" || records[1].PC != "0x1000" || records[2].PC != "0x3000" {
		t.Errorf("records not sorted numerically by PC: %s, %s, %s", records[0].PC, records[1].PC, records[2].PC)
	}
}

func TestFromSignalFindingsAndFieldAccesses(t *testing.T) {
	c := NewCollector()
	c.FromSignalFindings([]output.SignalFinding{
		{Category: "rooting", StringValue: "su", Function: "SecurityCheck", PC: "0x50"},
	})
	c.FromFieldAccesses("User.getName", []typetrack.FieldAccess{
		{ClassID: 42, ByteOffset: 16, IsStore: false, PC: 0x60},
	}, func(cid int) string {
		if cid == 42 {
			return "User"
		}
		return ""
	})
	records := c.Records()
	if len(records) != 2 {
		t.Fatalf("want 2 records, got %d", len(records))
	}
	if records[0].Kind != "signal" || records[0].Confidence != "static_inferred" {
		t.Errorf("record 0 = %+v", records[0])
	}
	if records[1].Kind != "field_access" || records[1].Result["class_name"] != "User" {
		t.Errorf("record 1 = %+v", records[1])
	}
}

func TestMergeRuntime(t *testing.T) {
	edges := []disasm.CallEdgeRecord{
		{FromFunc: "F", FromPC: "0x1000", Kind: "bl", Target: "A.foo"},
		{FromFunc: "F", FromPC: "0x2000", Kind: "blr", Via: "THR.stub"},
		{FromFunc: "F", FromPC: "0x3000", Kind: "blr"},
	}
	c := NewCollector()
	c.FromCallEdges(edges)

	// Runtime confirms 0x1000 (exact match) and 0x3000 (was unknown).
	rt := []RuntimeResolution{
		{PC: "0x1000", Function: "F", TargetName: "A.foo"},
		{PC: "0x3000", Function: "F", TargetName: "B.bar"},
	}
	c.MergeRuntime(rt)
	records := c.Records()

	// 0x1000: exact → runtime_confirmed
	if records[0].Confidence != "runtime_confirmed" {
		t.Errorf("0x1000 confidence = %s, want runtime_confirmed", records[0].Confidence)
	}
	if records[0].Result["runtime_target"] != "A.foo" {
		t.Errorf("0x1000 runtime_target = %v, want A.foo", records[0].Result["runtime_target"])
	}

	// 0x2000: stub, no runtime match → stays stub
	if records[1].Confidence != "stub" {
		t.Errorf("0x2000 confidence = %s, want stub (no runtime match)", records[1].Confidence)
	}

	// 0x3000: unknown → runtime_confirmed
	if records[2].Confidence != "runtime_confirmed" {
		t.Errorf("0x3000 confidence = %s, want runtime_confirmed", records[2].Confidence)
	}
}

func TestMergeRuntimeRequiresTargetAgreement(t *testing.T) {
	t.Run("exact conflict does not upgrade", func(t *testing.T) {
		c := NewCollectorFromRecords([]Evidence{{
			PC: "0x1000", Function: "F", Kind: "call", Confidence: ConfExact,
			Result: map[string]any{"target": "Static.target"},
		}})
		c.MergeRuntime([]RuntimeResolution{{PC: "0x1000", Function: "F", TargetName: "Runtime.other"}})
		got := c.records[0]
		if got.Confidence != ConfExact {
			t.Fatalf("conflicting runtime target upgraded confidence to %q", got.Confidence)
		}
		if conflict, _ := got.Result["runtime_conflict"].(bool); !conflict {
			t.Fatalf("conflict not recorded: %+v", got.Result)
		}
	})

	t.Run("polymorphic outside candidate stays conflict", func(t *testing.T) {
		c := NewCollectorFromRecords([]Evidence{{
			PC: "0x2000", Function: "F", Kind: "dispatch", Confidence: ConfPolymorphic,
			Result: map[string]any{"targets": []string{"A.run", "B.run"}, "candidate_count": 2},
		}})
		c.MergeRuntime([]RuntimeResolution{
			{PC: "0x2000", Function: "F", TargetName: "B.run"},
			{PC: "0x2000", Function: "F", TargetName: "Z.run"},
		})
		got := c.records[0]
		if got.Confidence != ConfPolymorphic {
			t.Fatalf("polymorphic confidence changed to %q", got.Confidence)
		}
		if conflict, _ := got.Result["runtime_conflict"].(bool); !conflict {
			t.Fatalf("out-of-set runtime target not marked conflict: %+v", got.Result)
		}
	})
}

func TestRuntimeObservationsPreserveMultipleTargetsAndRejectMalformedPCs(t *testing.T) {
	c := NewCollectorFromRecords([]Evidence{{
		PC: "0x3000", Function: "F", Kind: "call", Confidence: ConfUnknown,
		Result: map[string]any{"resolved": false},
	}})
	runtime := []RuntimeResolution{
		{PC: "0x3000", Function: "F", TargetName: "A.run"},
		{PC: "0x3000", Function: "F", TargetName: "B.run"},
		{PC: "definitely-not-an-address", Function: "F", TargetName: "Never.zero"},
	}
	c.MergeRuntime(runtime)
	got := c.records[0]
	if got.Confidence != ConfRuntimeConfirmed {
		t.Fatalf("unknown site with runtime evidence confidence = %q", got.Confidence)
	}
	targets, ok := got.Result["runtime_targets"].([]string)
	if !ok || len(targets) != 2 || targets[0] != "A.run" || targets[1] != "B.run" {
		t.Fatalf("runtime target multiset collapsed: %#v", got.Result["runtime_targets"])
	}
	rep := c.Coverage(runtime)
	if rep.InvalidRuntime != 1 {
		t.Fatalf("InvalidRuntime = %d, want 1", rep.InvalidRuntime)
	}
	if rep.RuntimeOnly != 0 {
		t.Fatalf("malformed PC became runtime-only address: %+v", rep)
	}
}

func TestFromBLRResolutionsUsesArchitectureSpecificDispatchReference(t *testing.T) {
	r := typetrack.BlrResolution{
		PC: 0x1234, SlotIndex: 9, Resolved: true, TargetName: "A.run", Confidence: "static_inferred",
	}
	c := NewCollector()
	c.FromBLRResolutions("F", []typetrack.BlrResolution{r}, false)
	if len(c.records) != 1 || c.records[0].SDKRef == nil ||
		c.records[0].SDKRef.File != "runtime/vm/compiler/backend/flow_graph_compiler_x64.cc" {
		t.Fatalf("x64 dispatch SDK reference = %+v", c.records)
	}

	c = NewCollector()
	r.Confidence = "stub"
	c.FromBLRResolutions("F", []typetrack.BlrResolution{r}, true)
	if len(c.records) != 1 || c.records[0].SDKRef != nil {
		t.Fatalf("stub resolution incorrectly cites dispatch lowering: %+v", c.records[0].SDKRef)
	}
}

func TestFromBLRResolutionsDoesNotCallIndirectDispatchExact(t *testing.T) {
	c := NewCollector()
	c.FromBLRResolutions("F", []typetrack.BlrResolution{{
		PC: 0x1234, SlotIndex: 7, Resolved: true, TargetName: "A.run", Confidence: "exact",
	}}, true)
	if len(c.records) != 1 {
		t.Fatalf("records = %d, want 1", len(c.records))
	}
	if got := c.records[0].Confidence; got != ConfStaticInferred {
		t.Fatalf("indirect dispatch confidence = %q, want %q", got, ConfStaticInferred)
	}
}

func TestResolvedStubTargetKeepsStubProvenance(t *testing.T) {
	c := NewCollector()
	c.FromCallEdges([]disasm.CallEdgeRecord{{
		FromFunc: "F", FromPC: "0x1000", Kind: "blr",
		Via: "THR.AllocateArray_entry_point", Target: "AllocateArray",
	}})
	got := c.records[0]
	if got.Confidence != ConfStub {
		t.Fatalf("confidence = %q, want stub", got.Confidence)
	}
	if got.Rule != "indirect_call_via_THR.AllocateArray_entry_point" {
		t.Fatalf("rule = %q", got.Rule)
	}
}

func TestUnresolvedProvenanceDoesNotImplyStub(t *testing.T) {
	tests := []struct {
		name string
		via  string
		want Confidence
	}{
		{name: "dispatch table", via: "dispatch_table", want: ConfUnknown},
		{name: "object field", via: disasm.ObjectFieldViaAt(0x17), want: ConfUnknown},
		{name: "generic provenance", via: "some_register_origin", want: ConfUnknown},
		{name: "pool placeholder", via: "PP[9] <Instance_42>", want: ConfUnknown},
		{name: "pool string", via: `pp[12] "hello world"`, want: ConfUnknown},
		{name: "pool callable display", via: "PP[7] Widget.build", want: ConfStub},
		{name: "thread data field", via: "THR.dispatch_table_array", want: ConfUnknown},
		{name: "thread scalar field", via: "THR.stack_limit", want: ConfUnknown},
		{name: "thread entry point", via: "THR.AllocateArray_ep", want: ConfStub},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCollector()
			c.FromCallEdges([]disasm.CallEdgeRecord{{
				FromFunc: "F", FromPC: "0x1000", Kind: "blr", Via: tt.via,
			}})
			if got := c.records[0].Confidence; got != tt.want {
				t.Fatalf("Via %q confidence = %q, want %q", tt.via, got, tt.want)
			}
		})
	}
}

func TestCoverage(t *testing.T) {
	edges := []disasm.CallEdgeRecord{
		{FromFunc: "F", FromPC: "0x1000", Kind: "bl", Target: "A.foo"},
		{FromFunc: "F", FromPC: "0x2000", Kind: "bl", Target: "B.bar"},
		{FromFunc: "F", FromPC: "0x3000", Kind: "blr"},
	}
	c := NewCollector()
	c.FromCallEdges(edges)

	rt := []RuntimeResolution{
		{PC: "0x1000", TargetName: "A.foo"},  // match
		{PC: "0x2000", TargetName: "C.baz"},  // conflict
		{PC: "0x3000", TargetName: "D.qux"},  // runtime confirmed (was unknown)
		{PC: "0x9999", TargetName: "E.only"}, // runtime only
	}
	rep := c.Coverage(rt)

	if rep.BothMatch != 1 {
		t.Errorf("BothMatch = %d, want 1", rep.BothMatch)
	}
	if rep.BothConflict != 1 {
		t.Errorf("BothConflict = %d, want 1", rep.BothConflict)
	}
	if rep.RuntimeConfirmed != 1 {
		t.Errorf("RuntimeConfirmed = %d, want 1", rep.RuntimeConfirmed)
	}
	if rep.StaticOnly != 0 {
		t.Errorf("StaticOnly = %d, want 0", rep.StaticOnly)
	}
	if rep.RuntimeOnly != 1 {
		t.Errorf("RuntimeOnly = %d, want 1", rep.RuntimeOnly)
	}
	if rep.TotalStatic != 3 {
		t.Errorf("TotalStatic = %d, want 3", rep.TotalStatic)
	}
	if rep.TotalRuntime != 4 {
		t.Errorf("TotalRuntime = %d, want 4", rep.TotalRuntime)
	}
}

func TestCoverageCountsCallAndDispatchAsOneSite(t *testing.T) {
	c := NewCollectorFromRecords([]Evidence{
		{PC: "0x1000", Function: "F", Kind: "call", Confidence: ConfStaticInferred,
			Result: map[string]any{"target": "A.run"}},
		{PC: "0x1000", Function: "F", Kind: "dispatch", Confidence: ConfStaticInferred,
			Result: map[string]any{"target": "A.run"}},
	})
	rep := c.Coverage([]RuntimeResolution{{PC: "0x1000", Function: "F", TargetName: "A.run"}})
	if rep.TotalStatic != 1 || rep.TotalRuntime != 1 || rep.BothMatch != 1 {
		t.Fatalf("duplicate provenance rows counted as sites: %+v", rep)
	}
}

func TestRuntimeMergeAndCoverageIgnoreNonCallEvidence(t *testing.T) {
	c := NewCollectorFromRecords([]Evidence{
		{PC: "0x1000", Function: "F", Kind: "signal", Confidence: ConfStaticInferred,
			Result: map[string]any{"signal": "interesting"}},
		{PC: "0x1000", Function: "F", Kind: "field_access", Confidence: ConfStaticInferred,
			Result: map[string]any{"class_name": "C"}},
	})
	runtime := []RuntimeResolution{{PC: "0x1000", Function: "F", TargetName: "A.run"}}
	c.MergeRuntime(runtime)
	for i, rec := range c.records {
		if _, ok := rec.Result["runtime_target"]; ok {
			t.Fatalf("non-call evidence %d was annotated with runtime target: %+v", i, rec)
		}
	}
	rep := c.Coverage(runtime)
	if rep.TotalStatic != 0 || rep.StaticOnly != 0 || rep.RuntimeConfirmed != 0 || rep.RuntimeOnly != 1 {
		t.Fatalf("non-call evidence polluted runtime coverage: %+v", rep)
	}
}

func TestTruncatedCandidateListIsIndeterminateNotConflict(t *testing.T) {
	targets := []string{"A", "B", "C", "D", "E", "F", "G", "H"}
	c := NewCollectorFromRecords([]Evidence{{
		PC: "0x2000", Function: "F", Kind: "dispatch", Confidence: ConfPolymorphic,
		Result: map[string]any{"targets": targets, "candidate_count": 9},
	}})
	runtime := []RuntimeResolution{{PC: "0x2000", Function: "F", TargetName: "I"}}
	c.MergeRuntime(runtime)
	if conflict, _ := c.records[0].Result["runtime_conflict"].(bool); conflict {
		t.Fatalf("truncated candidate list produced false conflict: %+v", c.records[0].Result)
	}
	if indeterminate, _ := c.records[0].Result["runtime_indeterminate"].(bool); !indeterminate {
		t.Fatalf("truncated candidate list did not record indeterminate result: %+v", c.records[0].Result)
	}
	rep := c.Coverage(runtime)
	if rep.BothIndeterminate != 1 || rep.BothConflict != 0 || rep.BothMatch != 0 {
		t.Fatalf("coverage = %+v, want one indeterminate site", rep)
	}
}

func TestCandidateCountSmallerThanListIsMalformed(t *testing.T) {
	c := NewCollectorFromRecords([]Evidence{{
		PC: "0x2000", Function: "F", Kind: "dispatch", Confidence: ConfPolymorphic,
		Result: map[string]any{"targets": []string{"A", "B"}, "candidate_count": 1},
	}})
	runtime := []RuntimeResolution{{PC: "0x2000", Function: "F", TargetName: "Z"}}
	c.MergeRuntime(runtime)
	if conflict, _ := c.records[0].Result["runtime_conflict"].(bool); conflict {
		t.Fatalf("malformed candidate count produced false conflict: %+v", c.records[0].Result)
	}
	if indeterminate, _ := c.records[0].Result["runtime_indeterminate"].(bool); !indeterminate {
		t.Fatalf("malformed candidate count did not stay indeterminate: %+v", c.records[0].Result)
	}
	rep := c.Coverage(runtime)
	if rep.BothIndeterminate != 1 || rep.BothConflict != 0 {
		t.Fatalf("coverage = %+v, want malformed candidate list to be indeterminate", rep)
	}
}
