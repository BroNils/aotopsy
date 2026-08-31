package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aotopsy/internal/disasm"
)

func TestFromCallEdges(t *testing.T) {
	edges := []disasm.CallEdgeRecord{
		{FromFunc: "Foo.bar", FromPC: "0x1000", Kind: "bl", Target: "Baz.qux"},
		{FromFunc: "Foo.bar", FromPC: "0x2000", Kind: "blr", Via: "THR.AllocateArray_ep"},
		{FromFunc: "Foo.bar", FromPC: "0x3000", Kind: "blr", Targets: []string{"A.paint", "B.paint"}, Candidates: 2},
		{FromFunc: "Foo.bar", FromPC: "0x4000", Kind: "blr"},
	}

	c := NewCollector()
	c.FromCallEdges(edges)
	records := c.Records()
	if len(records) != 4 {
		t.Fatalf("want 4 records, got %d", len(records))
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
		{FromFunc: "F", FromPC: "0x2000", Kind: "bl", Target: "B"},
	}
	c := NewCollector()
	c.FromCallEdges(edges)
	records := c.Records()
	if records[0].PC != "0x1000" || records[1].PC != "0x2000" || records[2].PC != "0x3000" {
		t.Errorf("records not sorted by PC: %s, %s, %s", records[0].PC, records[1].PC, records[2].PC)
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

func TestCoverage(t *testing.T) {
	edges := []disasm.CallEdgeRecord{
		{FromFunc: "F", FromPC: "0x1000", Kind: "bl", Target: "A.foo"},
		{FromFunc: "F", FromPC: "0x2000", Kind: "bl", Target: "B.bar"},
		{FromFunc: "F", FromPC: "0x3000", Kind: "blr"},
	}
	c := NewCollector()
	c.FromCallEdges(edges)

	rt := []RuntimeResolution{
		{PC: "0x1000", TargetName: "A.foo"},   // match
		{PC: "0x2000", TargetName: "C.baz"},   // conflict
		{PC: "0x3000", TargetName: "D.qux"},   // runtime confirmed (was unknown)
		{PC: "0x9999", TargetName: "E.only"},  // runtime only
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
