package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestBLRResolutionRate checks that BLR resolution doesn't regress below
// a minimum threshold. This prevents silent BLR drops from code changes.
// Runs on the Dart 3.9.2 ARM64 ground-truth sample from the corpus.
func TestBLRResolutionRate(t *testing.T) {
	tmpDir := sharedPipelineOutDir(t)

	// Read typetrack report
	reportPath := filepath.Join(tmpDir, "typetrack_report.json")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read typetrack_report.json: %v", err)
	}
	var report struct {
		ResolvedBLR int `json:"resolved_blr"`
		TotalBLR    int `json:"total_blr"`
		PoolHits    int `json:"pool_hits"`
		PoolLoads   int `json:"pool_loads"`
		BLR         struct {
			Total       int `json:"total"`
			Monomorphic int `json:"monomorphic"`
			Polymorphic int `json:"polymorphic"`
			Stub        int `json:"stub"`
			Unresolved  int `json:"unresolved"`
		} `json:"blr"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal typetrack_report: %v", err)
	}
	if report.BLR.Total == 0 {
		t.Fatal("blr.total is 0 — pipeline failed")
	}
	// Monomorphic is a confidence-classification counter, not a coverage
	// counter: a more honest resolver can move a site from monomorphic to
	// polymorphic without losing any target information, so a mono-only floor
	// fails on an improvement. Guard total REAL target resolution
	// (monomorphic + polymorphic) instead, while keeping monomorphic non-zero
	// so the single-callee path cannot silently die.
	//
	// Stub calls are deliberately NOT counted as resolved. They are VM runtime
	// stubs, not a Dart function recovered from the snapshot, and adding them
	// inflates the figure exactly the way AGENTS-local warns about
	// (resolved_blr vs blr.monomorphic). Measured on this fixture:
	// mono 931 + poly 2683 = 3614 of 5355 (67.5%); with the 242 stub calls the
	// inflated figure would read 72%.
	total := report.BLR.Total
	classified := report.BLR.Monomorphic + report.BLR.Polymorphic + report.BLR.Stub + report.BLR.Unresolved
	if classified != total {
		t.Errorf("BLR accounting mismatch: mono+poly+stub+unresolved=%d, total=%d", classified, total)
	}
	if report.BLR.Monomorphic == 0 {
		t.Error("BLR monomorphic count is 0 -- single-callee resolution path is dead")
	}
	resolved := report.BLR.Monomorphic + report.BLR.Polymorphic
	rate := resolved * 100 / total
	// 65% sits below the measured 67.5% so noise cannot fail it, and a real
	// coverage collapse does, without rewarding stub calls or guesses.
	const minResolvedRate = 65
	if rate < minResolvedRate {
		t.Errorf("BLR resolved rate = %d%% (%d/%d), minimum %d%%",
			rate, resolved, total, minResolvedRate)
	}
	t.Logf("BLR: resolved=%d/%d (%d%%), monomorphic=%d, polymorphic=%d, stub=%d, unresolved=%d",
		resolved, total, rate, report.BLR.Monomorphic, report.BLR.Polymorphic, report.BLR.Stub, report.BLR.Unresolved)

	// pool_hits counts object-pool loads that RESOLVED; pool_loads counts
	// every pool load seen. A resolution count above the attempt count means
	// the two are being incremented at different places again -- which is
	// exactly what happened when handlePPLoad started counting attempts under
	// the pool_hits name while x86_64 kept counting resolutions.
	if report.PoolLoads > 0 && report.PoolHits > report.PoolLoads {
		t.Errorf("pool_hits=%d exceeds pool_loads=%d -- a pool load cannot resolve "+
			"more often than it happens", report.PoolHits, report.PoolLoads)
	}
	if report.PoolLoads > 0 {
		t.Logf("pool: %d/%d loads resolved (%d%%)",
			report.PoolHits, report.PoolLoads, report.PoolHits*100/report.PoolLoads)
	}
}

// TestSignalExpansionOutputs checks that all signal expansion JSONL files
// are generated and non-empty. This prevents silent output drops.
func TestSignalExpansionOutputs(t *testing.T) {
	tmpDir := sharedPipelineOutDir(t)

	// Files that MUST exist (even if 0 entries, the file should be created
	// by the pipeline for downstream tools to read)
	mustExist := []string{
		"pool_immediates.jsonl",
		"dispatch_table.jsonl",
		"call_edges.jsonl",
		"functions.jsonl",
		"string_refs.jsonl",
	}
	for _, f := range mustExist {
		path := filepath.Join(tmpDir, f)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("required output %s is missing", f)
		}
	}

	// Files that MUST have non-zero entries for 3.9.2 ARM64
	mustHaveEntries := map[string]int{
		"string_refs.jsonl":            100, // was 0 before fix, now 5000+
		"string_value_xref.jsonl":      100, // was 0 before fix, now 1000+
		"selector_dispatch_xref.jsonl": 100, // was MISSING before fix, now 16000+
		"address_callers_xref.jsonl":   100, // was always present
		"method_channels.jsonl":        5,   // should find flutter channels
		"deobfuscation.jsonl":          10,  // should find base64 patterns
		"network_endpoints.jsonl":      10,  // should find URLs/domains
		"yara_findings.jsonl":          1,   // should match at least 1 rule
	}
	for f, minCount := range mustHaveEntries {
		path := filepath.Join(tmpDir, f)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("output %s is missing: %v", f, err)
			continue
		}
		lines := 0
		for _, b := range data {
			if b == '\n' {
				lines++
			}
		}
		if lines < minCount {
			t.Errorf("output %s has %d entries, minimum %d", f, lines, minCount)
		}
	}
}

// The decompiler's own features -- ffi_call naming, instance-field name
// resolution -- are covered in internal/decompiler (features_test.go), not
// here. A TestDecompilerFeatures used to sit at this spot claiming to check
// them; it counted lines in functions.jsonl, a file the decompiler does not
// write, from a package that never invokes the emitter. It could not have
// failed if either feature disappeared, and what it did check -- that the
// pipeline produces functions -- is already asserted exactly by the golden
// records and loosely by TestSignalExpansionOutputs above.
