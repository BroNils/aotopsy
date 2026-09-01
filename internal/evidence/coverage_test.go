package evidence

import "testing"

// A runtime resolution and a static record describe the same address even
// when they spell it differently. Matching on the raw string made a
// format difference indistinguishable from "runtime never saw this PC" --
// and the whole point of MergeRuntime is to tell those two apart.
func TestPCMatchingIgnoresFormat(t *testing.T) {
	for _, spelling := range []string{"0x1000", "0X1000", "1000", " 0x1000 "} {
		c := NewCollector()
		c.records = []Evidence{{PC: "0x1000", Function: "f", Kind: "call",
			Confidence: ConfExact, Result: map[string]any{"target": "g"}}}
		c.MergeRuntime([]RuntimeResolution{{PC: spelling, Function: "f", TargetName: "g"}})
		if got := c.records[0].Confidence; got != ConfRuntimeConfirmed {
			t.Errorf("runtime PC %q did not match static PC 0x1000: confidence = %q", spelling, got)
		}
	}

	// A bare string is ambiguous, and the tie is broken towards hex --
	// every producer in this codebase writes addresses as hex, with or
	// without the 0x. So "4096" is 0x4096, NOT decimal 4096, and it must
	// not match 0x1000. Pinned because silently reading it as decimal
	// would make a handful of addresses match the wrong record.
	c := NewCollector()
	c.records = []Evidence{{PC: "0x1000", Kind: "call", Confidence: ConfExact}}
	c.MergeRuntime([]RuntimeResolution{{PC: "4096", TargetName: "g"}})
	if got := c.records[0].Confidence; got != ConfExact {
		t.Errorf("bare \"4096\" matched 0x1000; it is 0x4096 and must not")
	}
}

// A polymorphic record predicts a SET of targets. Coverage read only
// Result["target"], so those records fell through to "runtime confirmed"
// -- counted as agreement even when the runtime target was not among the
// candidates, which is exactly the disagreement the report exists to find.
func TestCoverageChecksPolymorphicCandidates(t *testing.T) {
	poly := func(targets ...string) Evidence {
		return Evidence{PC: "0x2000", Function: "f", Kind: "dispatch",
			Confidence: ConfPolymorphic,
			Result:     map[string]any{"targets": targets, "candidate_count": len(targets)}}
	}

	t.Run("runtime target among candidates", func(t *testing.T) {
		c := NewCollector()
		c.records = []Evidence{poly("A.run", "B.run", "C.run")}
		rep := c.Coverage([]RuntimeResolution{{PC: "0x2000", TargetName: "B.run"}})
		if rep.BothMatch != 1 || rep.BothConflict != 0 || rep.RuntimeConfirmed != 0 {
			t.Errorf("match=%d conflict=%d confirmed=%d, want 1/0/0",
				rep.BothMatch, rep.BothConflict, rep.RuntimeConfirmed)
		}
	})

	t.Run("runtime target NOT among candidates", func(t *testing.T) {
		c := NewCollector()
		c.records = []Evidence{poly("A.run", "B.run")}
		rep := c.Coverage([]RuntimeResolution{{PC: "0x2000", TargetName: "Z.run"}})
		if rep.BothConflict != 1 || rep.BothMatch != 0 || rep.RuntimeConfirmed != 0 {
			t.Errorf("match=%d conflict=%d confirmed=%d, want 0/1/0 -- the runtime target "+
				"is not one of the candidates, which is a conflict, not a confirmation",
				rep.BothMatch, rep.BothConflict, rep.RuntimeConfirmed)
		}
	})

	// A record with no prediction at all is the only case that should
	// count as "runtime told us something static analysis could not".
	t.Run("no static prediction", func(t *testing.T) {
		c := NewCollector()
		c.records = []Evidence{{PC: "0x3000", Function: "f", Kind: "call",
			Confidence: ConfUnknown, Result: map[string]any{"resolved": false}}}
		rep := c.Coverage([]RuntimeResolution{{PC: "0x3000", TargetName: "Q.run"}})
		if rep.RuntimeConfirmed != 1 {
			t.Errorf("runtimeConfirmed = %d, want 1", rep.RuntimeConfirmed)
		}
	})
}

// Candidates survive a JSON round trip as []any, so Coverage has to read
// both shapes or a report built from a written evidence.jsonl would
// silently take the no-prediction path.
func TestCoverageReadsCandidatesAfterJSONRoundTrip(t *testing.T) {
	c := NewCollector()
	c.records = []Evidence{{PC: "0x2000", Kind: "dispatch", Confidence: ConfPolymorphic,
		Result: map[string]any{"targets": []any{"A.run", "B.run"}}}}
	rep := c.Coverage([]RuntimeResolution{{PC: "0x2000", TargetName: "B.run"}})
	if rep.BothMatch != 1 {
		t.Errorf("bothMatch = %d, want 1 (candidates arrived as []any)", rep.BothMatch)
	}
}

func TestConfidenceNormalization(t *testing.T) {
	for _, s := range []string{"exact", "static_inferred", "polymorphic", "stub",
		"unknown", "runtime_confirmed"} {
		if !Confidence(s).Valid() {
			t.Errorf("%q should be a valid confidence", s)
		}
	}
	for _, s := range []string{"", "EXACT", "probably", "high"} {
		if Confidence(s).Valid() {
			t.Errorf("%q should not be a valid confidence", s)
		}
		if got := normalizeConfidence(s); got != ConfUnknown {
			t.Errorf("normalizeConfidence(%q) = %q, want %q", s, got, ConfUnknown)
		}
	}
}
