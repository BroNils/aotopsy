package typetrack

import "testing"

// A polymorphic site must NOT be reported as a resolved callee.
//
// The regression this guards: applySelectorCandidates used to join every
// candidate into TargetName with " | ". Downstream, disasm.CallEdgeRecord.Target
// is treated as a callee name (render.ReachableSet follows it, the call graph
// draws it), so a 43-way virtual call became a single graph node literally
// named "detach | get:first | paint | ...", and the headline "resolved N/M"
// counted it as a resolution.
func TestApplySelectorCandidatesSeparatesMonoFromPoly(t *testing.T) {
	t.Run("single candidate is monomorphic", func(t *testing.T) {
		var res BlrResolution
		applySelectorCandidates(&res, []string{"Widget.build"})
		if !res.Resolved {
			t.Fatal("one candidate should resolve")
		}
		if res.Polymorphic {
			t.Error("one candidate must not be marked polymorphic")
		}
		if res.TargetName != "Widget.build" {
			t.Errorf("TargetName = %q, want Widget.build", res.TargetName)
		}
		if len(res.TargetNames) != 0 {
			t.Errorf("TargetNames should be empty for a single callee, got %v", res.TargetNames)
		}
		if res.Candidates != 1 {
			t.Errorf("Candidates = %d, want 1", res.Candidates)
		}
	})

	t.Run("many candidates name no single callee", func(t *testing.T) {
		var res BlrResolution
		applySelectorCandidates(&res, []string{"a.build", "b.build", "c.build"})
		if !res.Polymorphic {
			t.Error("three candidates must be marked polymorphic")
		}
		if res.TargetName != "" {
			t.Errorf("TargetName must stay empty for a polymorphic site, got %q", res.TargetName)
		}
		if len(res.TargetNames) != 3 || res.Candidates != 3 {
			t.Errorf("TargetNames=%v Candidates=%d, want 3 and 3", res.TargetNames, res.Candidates)
		}
	})

	t.Run("candidate list is capped but the count is not", func(t *testing.T) {
		many := make([]string, 0, 50)
		for i := 0; i < 50; i++ {
			many = append(many, string(rune('a'+i%26))+".build")
		}
		var res BlrResolution
		applySelectorCandidates(&res, many)
		if len(res.TargetNames) != maxPolymorphicNames {
			t.Errorf("listed %d names, want the cap %d", len(res.TargetNames), maxPolymorphicNames)
		}
		if res.Candidates != 50 {
			t.Errorf("Candidates = %d, want the true count 50", res.Candidates)
		}
	})

	t.Run("no candidates resolves nothing", func(t *testing.T) {
		var res BlrResolution
		applySelectorCandidates(&res, nil)
		if res.Resolved || res.Polymorphic || res.TargetName != "" {
			t.Errorf("empty candidate set must leave the site unresolved: %+v", res)
		}
	})
}

// Resolved() counts single-callee sites only.
func TestBLRBreakdownResolved(t *testing.T) {
	bd := BLRBreakdown{
		Total: 100, Monomorphic: 10, Stub: 5,
		Polymorphic: 40, PolymorphicCandidates: 2000, Unresolved: 45,
	}
	if got := bd.Resolved(); got != 15 {
		t.Errorf("Resolved() = %d, want 15 (monomorphic + stub, NOT polymorphic)", got)
	}
	if bd.Monomorphic+bd.Stub+bd.Polymorphic+bd.Unresolved != bd.Total {
		t.Error("the four categories must partition Total")
	}
}
