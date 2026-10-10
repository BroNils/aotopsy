package evidence

import (
	"testing"

	"aotopsy/internal/disasm"
)

func coverageRuntime(pc, fn, target string) RuntimeObservation {
	return RuntimeObservation{
		PC:       pc,
		Function: fn,
		Runtime:  testRuntimeEvidence(disasm.RuntimeTargetObservation{Target: target, Count: 1}),
	}
}

func TestCoverageSeparatesAgreementConflictIndeterminateAndUnresolved(t *testing.T) {
	tests := []struct {
		name string
		rec  Evidence
		run  RuntimeObservation
		want func(CoverageReport) bool
	}{
		{
			name: "agreement",
			rec:  Evidence{PC: "0x10", Function: "F", Kind: "dispatch", Source: SourceTypeTrack, Result: map[string]any{"target": "A"}, Confidence: ConfStaticInferred, Rule: RuleTypeTrackDispatch},
			run:  coverageRuntime("0x10", "F", "A"),
			want: func(r CoverageReport) bool { return r.BothMatch == 1 },
		},
		{
			name: "complete candidate conflict",
			rec:  Evidence{PC: "0x20", Function: "F", Kind: "dispatch", Source: SourceTypeTrack, Result: map[string]any{"targets": []string{"A", "B"}, "candidate_count": 2}, Confidence: ConfPolymorphic, Rule: RuleTypeTrackDispatch},
			run:  coverageRuntime("0x20", "F", "C"),
			want: func(r CoverageReport) bool { return r.BothConflict == 1 },
		},
		{
			name: "truncated candidate indeterminate",
			rec:  Evidence{PC: "0x30", Function: "F", Kind: "dispatch", Source: SourceTypeTrack, Result: map[string]any{"targets": []string{"A", "B"}, "candidate_count": 5}, Confidence: ConfPolymorphic, Rule: RuleTypeTrackDispatch},
			run:  coverageRuntime("0x30", "F", "C"),
			want: func(r CoverageReport) bool { return r.BothIndeterminate == 1 },
		},
		{
			name: "static unresolved observed",
			rec:  Evidence{PC: "0x40", Function: "F", Kind: "dispatch", Source: SourceTypeTrack, Result: map[string]any{"resolved": false}, Confidence: ConfUnknown, Rule: RuleTypeTrackDispatch},
			run:  coverageRuntime("0x40", "F", "A"),
			want: func(r CoverageReport) bool { return r.StaticUnresolvedObserved == 1 },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCollectorFromRecords(evidenceTestDartVersion, []Evidence{tc.rec})
			report := c.Coverage([]RuntimeObservation{tc.run})
			if !tc.want(report) || report.TotalStatic != 1 || report.TotalRuntime != 1 || report.InvalidRuntime != 0 {
				t.Fatalf("coverage = %+v", report)
			}
		})
	}
}

func TestCoverageCountsRuntimeOnlyWithoutInventingStaticEvidence(t *testing.T) {
	c := NewCollector(evidenceTestDartVersion)
	report := c.Coverage([]RuntimeObservation{coverageRuntime("0x50", "F", "A")})
	if report.RuntimeOnly != 1 || report.TotalStatic != 0 || report.TotalRuntime != 1 {
		t.Fatalf("coverage = %+v", report)
	}
}

func TestCoverageRejectsMalformedRuntimeObservation(t *testing.T) {
	bad := coverageRuntime("0x60", "F", "A")
	bad.Runtime.Observations = 2
	c := NewCollector(evidenceTestDartVersion)
	report := c.Coverage([]RuntimeObservation{bad})
	if report.InvalidRuntime != 1 || report.TotalRuntime != 0 {
		t.Fatalf("coverage = %+v", report)
	}
}
