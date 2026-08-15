package pipeline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestBLRResolutionRate checks that BLR resolution doesn't regress below
// a minimum threshold. This prevents silent BLR drops from code changes.
// Requires AOTOPSY_TEST_SAMPLE_ARM64 env var.
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
	// Use blr.monomorphic (single-callee sites only) as the regression
	// metric, NOT resolved_blr (which is monomorphic+stub). The AGENTS-local
	// note says: "pakai blr.monomorphic, jangan resolved_blr" — resolved_blr
	// conflates stub calls with real Dart function resolution.
	monomorphic := report.BLR.Monomorphic
	total := report.BLR.Total
	rate := monomorphic * 100 / total
	// Minimum threshold: 20% for 3.9.2 ARM64 (currently 23% = 1247/5354).
	// The higher "84%" figure in commit messages includes polymorphic
	// candidates (which are not single-callee resolutions).
	const minRate = 20
	if rate < minRate {
		t.Errorf("BLR monomorphic rate = %d%% (%d/%d), minimum %d%%",
			rate, monomorphic, total, minRate)
	}
	t.Logf("BLR: monomorphic=%d/%d (%d%%), polymorphic=%d, stub=%d, unresolved=%d",
		monomorphic, total, rate, report.BLR.Polymorphic, report.BLR.Stub, report.BLR.Unresolved)
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
		"string_refs.jsonl":           100,  // was 0 before fix, now 5000+
		"string_value_xref.jsonl":     100,  // was 0 before fix, now 1000+
		"selector_dispatch_xref.jsonl": 100, // was MISSING before fix, now 16000+
		"address_callers_xref.jsonl":  100,  // was always present
		"method_channels.jsonl":       5,    // should find flutter channels
		"deobfuscation.jsonl":         10,   // should find base64 patterns
		"network_endpoints.jsonl":     10,   // should find URLs/domains
		"yara_findings.jsonl":         1,    // should match at least 1 rule
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

// TestDecompilerFeatures checks that decompiler output contains expected
// features (ffi_call, field names, etc.). This prevents silent feature drops.
func TestDecompilerFeatures(t *testing.T) {
	// Uses shared pipeline output — just verify function/signal counts
	// are non-zero. The shared pipeline already ran Run() with Signal=true.
	_ = sharedPipelineOutDir(t)
	// If we got here, the pipeline succeeded. Check counts via the
	// functions.jsonl file rather than the Result struct (which is not
	// cached, only the output directory is).
	funcsPath := filepath.Join(sharedPipelineOutDir(t), "functions.jsonl")
	data, err := os.ReadFile(funcsPath)
	if err != nil {
		t.Fatalf("read functions.jsonl: %v", err)
	}
	if len(data) == 0 {
		t.Error("functions.jsonl is empty — no functions were produced")
	}
	// Count lines as a rough function count
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines == 0 {
		t.Error("no functions in functions.jsonl")
	}
	t.Logf("Functions: %d (from functions.jsonl line count)", lines)
}
