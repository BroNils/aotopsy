package disasm

import "testing"

// TestResolvedTargets verifies the unified helper that all consumers should
// use instead of checking Target/Via/Candidates individually.
func TestResolvedTargets(t *testing.T) {
	// Direct call: Target is set.
	direct := CallEdgeRecord{Kind: "bl", Target: "MyClass.method"}
	got := direct.ResolvedTargets()
	if len(got) != 1 || got[0] != "MyClass.method" {
		t.Errorf("direct call: got %v, want [MyClass.method]", got)
	}

	// Polymorphic indirect: Targets list is set, Target is empty.
	poly := CallEdgeRecord{
		Kind:     "blr",
		Via:      "dispatch_table",
		Targets:  []string{"Foo.paint", "Bar.paint"},
		Candidates: 2,
	}
	got = poly.ResolvedTargets()
	if len(got) != 2 || got[0] != "Foo.paint" || got[1] != "Bar.paint" {
		t.Errorf("polymorphic: got %v, want [Foo.paint Bar.paint]", got)
	}

	// Indirect with Via only (no Target, no Targets).
	viaOnly := CallEdgeRecord{Kind: "blr", Via: "THR.AllocateArray_ep"}
	got = viaOnly.ResolvedTargets()
	if len(got) != 1 || got[0] != "THR.AllocateArray_ep" {
		t.Errorf("via-only: got %v, want [THR.AllocateArray_ep]", got)
	}

	// Truly unresolved.
	empty := CallEdgeRecord{Kind: "blr"}
	got = empty.ResolvedTargets()
	if got != nil {
		t.Errorf("unresolved: got %v, want nil", got)
	}

	// Target takes priority over Targets and Via.
	priority := CallEdgeRecord{
		Kind:    "bl",
		Target:  "exact.target",
		Via:     "via.fallback",
		Targets: []string{"poly1", "poly2"},
	}
	got = priority.ResolvedTargets()
	if len(got) != 1 || got[0] != "exact.target" {
		t.Errorf("priority: got %v, want [exact.target]", got)
	}

	// Targets takes priority over Via when Target is empty.
	targetsOverVia := CallEdgeRecord{
		Kind:    "blr",
		Via:     "via.fallback",
		Targets: []string{"poly1", "poly2"},
	}
	got = targetsOverVia.ResolvedTargets()
	if len(got) != 2 {
		t.Errorf("targets over via: got %v, want 2 targets", got)
	}
}
