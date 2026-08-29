package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteSARIF(t *testing.T) {
	tempDir := t.TempDir()

	findings := []SignalFinding{
		{
			Category:    "rooting",
			StringValue: "su",
			Function:    "isRooted",
			PC:          "0x1000",
		},
		{
			Category:    "ssl_pinning",
			StringValue: "sha256/cert",
			Function:    "checkCert",
			PC:          "0x2000",
		},
		{
			Category:    "custom_unknown_cat",
			StringValue: "token",
			Function:    "doCustom",
			PC:          "0x3000",
		},
	}

	err := WriteSARIF(tempDir, findings, "1.0.0")
	if err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	sarifPath := filepath.Join(tempDir, "report.sarif")
	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("read report.sarif: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("unmarshal report.sarif: %v", err)
	}

	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("len(runs) = %d, want 1", len(log.Runs))
	}

	run := log.Runs[0]
	if run.Tool.Driver.Name != "AOTopsy" {
		t.Errorf("driver name = %q, want AOTopsy", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != 3 {
		t.Errorf("len(rules) = %d, want 3", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 3 {
		t.Errorf("len(results) = %d, want 3", len(run.Results))
	}

	// Verify error level for rooting
	if run.Results[0].Level != "error" {
		t.Errorf("result[0].Level = %q, want error", run.Results[0].Level)
	}
	// Verify warning level for ssl_pinning
	if run.Results[1].Level != "warning" {
		t.Errorf("result[1].Level = %q, want warning", run.Results[1].Level)
	}
	// Verify default fallback level 'note' for unknown category
	if run.Results[2].Level != "note" {
		t.Errorf("result[2].Level = %q, want note", run.Results[2].Level)
	}
}
