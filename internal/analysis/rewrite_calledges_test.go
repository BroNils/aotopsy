package analysis

import (
	"path/filepath"
	"testing"

	"aotopsy/internal/disasm"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/typetrack"
)

func TestRewriteCallEdgesOnlyResolvesKnownThreadStubFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "call_edges.jsonl")
	edges := []disasm.CallEdgeRecord{
		{FromFunc: "dataCaller", FromPC: "0x1000", Kind: "call_indirect", Via: "THR.dispatch_table_array"},
		{FromFunc: "stubCaller", FromPC: "0x2000", Kind: "call_indirect", Via: "THR.stack_overflow_shared_without_fpu_regs_entry_point"},
	}
	if _, err := jsonutil.WriteJSONLFile(path, edges); err != nil {
		t.Fatal(err)
	}

	bd, err := rewriteCallEdges(
		dir,
		&typetrack.InterResult{},
		nil,
		map[string]string{
			"stack_overflow_shared_without_fpu_regs_entry_point": "StackOverflowSharedWithoutFPURegs",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if bd.Total != 2 || bd.Stub != 1 || bd.Unresolved != 1 {
		t.Fatalf("breakdown = %+v, want total=2 stub=1 unresolved=1", bd)
	}

	got, err := jsonutil.ReadJSONL[disasm.CallEdgeRecord](path, jsonutil.StandardLimits)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Target != "" {
		t.Fatalf("Thread data field became fabricated target %q", got[0].Target)
	}
	if got[1].Target != "StackOverflowSharedWithoutFPURegs" {
		t.Fatalf("known Thread stub target = %q", got[1].Target)
	}
}

func TestBuildThreadCallableTargetsUsesSDKStubNamesWithoutDataFields(t *testing.T) {
	fields := map[int]string{
		0x60:  "dispatch_table_array",
		0x198: "stack_overflow_shared_without_fpu_regs_entry_point",
	}
	stubs := map[int64]string{0x198: "StackOverflowSharedWithoutFPURegs"}
	got := buildThreadCallableTargets(fields, stubs)
	if len(got) != 1 || got["stack_overflow_shared_without_fpu_regs_entry_point"] != "StackOverflowSharedWithoutFPURegs" {
		t.Fatalf("thread stub targets = %#v", got)
	}
	if got["dispatch_table_array"] != "" {
		t.Fatalf("Thread data field leaked into stub target map: %#v", got)
	}
}
