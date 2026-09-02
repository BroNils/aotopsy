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

	// A stand-in for the analysed binary, so the artifact entry gets a
	// real name, length and hash.
	libPath := filepath.Join(tempDir, "libapp.so")
	if err := os.WriteFile(libPath, []byte("\x7fELF fake binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := WriteSARIF(tempDir, findings, "1.0.0", libPath)
	if err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	sarifPath := filepath.Join(tempDir, "aotopsy.sarif")
	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("read aotopsy.sarif: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("unmarshal aotopsy.sarif: %v", err)
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

	// The analysed binary must be described, or the report is about a
	// file called libapp.so with no way to tell which one -- every
	// Flutter app ships a file by that name.
	if len(run.Artifacts) != 1 {
		t.Fatalf("len(artifacts) = %d, want 1", len(run.Artifacts))
	}
	art := run.Artifacts[0]
	if art.Location.URI != "libapp.so" {
		t.Errorf("artifact uri = %q, want libapp.so", art.Location.URI)
	}
	if art.Length != 16 {
		t.Errorf("artifact length = %d, want 16", art.Length)
	}
	if art.Hashes["sha-256"] == "" {
		t.Error("artifact has no sha-256; a report cannot be tied to the file it came from")
	}

	// A finding in a binary is located by ADDRESS. SARIF 2.1.0 §3.30.21
	// forbids a text region in a binary artifact, and every result used
	// to carry region.startLine = 1 -- pointing at line 1 of a file with
	// no lines, with the real address buried in a snippet string.
	loc := run.Results[0].Locations[0].PhysicalLocation
	if loc.Address == nil {
		t.Fatal("result has no address")
	}
	if loc.Address.AbsoluteAddress != 0x1000 {
		t.Errorf("absoluteAddress = %#x, want 0x1000", loc.Address.AbsoluteAddress)
	}
	if loc.Address.Name != "isRooted" {
		t.Errorf("address name = %q, want isRooted", loc.Address.Name)
	}
	if loc.ArtifactLocation.Index == nil || *loc.ArtifactLocation.Index != 0 {
		t.Error("result does not index the artifact it was found in")
	}
}

// A binary-level finding carries neither function nor PC. It must still
// produce a valid result -- and a distinguishable fingerprint: keying on
// function and PC alone made every such finding hash to ":".
func TestWriteSARIFBinaryLevelFinding(t *testing.T) {
	dir := t.TempDir()
	findings := []SignalFinding{
		{Category: "obfuscation", StringValue: "aB", Function: "", PC: ""},
		{Category: "obfuscation", StringValue: "cD", Function: "", PC: ""},
	}
	if err := WriteSARIF(dir, findings, "1.0.0", ""); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "aotopsy.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	res := log.Runs[0].Results
	if len(res) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(res))
	}
	for i, r := range res {
		if r.Locations[0].PhysicalLocation.Address != nil {
			t.Errorf("result[%d] has an address; it has no PC and one must not be fabricated", i)
		}
	}
	if res[0].PartialFingerprints["aotopsyFindingV1"] == res[1].PartialFingerprints["aotopsyFindingV1"] {
		t.Error("two distinct binary-level findings share a fingerprint")
	}
}
