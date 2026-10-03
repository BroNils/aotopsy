package output

import (
	"crypto/sha256"
	"encoding/hex"
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
			AddressKind: "function",
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

	sum := sha256.Sum256([]byte("\x7fELF fake binary"))
	err := WriteSARIF(tempDir, findings, "9.9.9", ArtifactIdentity{
		URI: libPath, Size: 16, SHA256: hex.EncodeToString(sum[:]),
	})
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
	if run.Tool.Driver.Version != "9.9.9" {
		t.Errorf("driver version = %q, want 9.9.9", run.Tool.Driver.Version)
	}
	if len(run.Tool.Driver.Rules) != 3 {
		t.Errorf("len(rules) = %d, want 3", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 3 {
		t.Errorf("len(results) = %d, want 3", len(run.Results))
	}

	byRule := make(map[string]sarifResult, len(run.Results))
	for _, result := range run.Results {
		byRule[result.RuleID] = result
	}
	if got := byRule["signal.category.rooting"].Level; got != "error" {
		t.Errorf("rooting level = %q, want error", got)
	}
	if got := byRule["signal.category.ssl_pinning"].Level; got != "warning" {
		t.Errorf("ssl_pinning level = %q, want warning", got)
	}
	if got := byRule["signal.category.custom_unknown_cat"].Level; got != "note" {
		t.Errorf("unknown category level = %q, want note", got)
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
	loc := byRule["signal.category.rooting"].Locations[0].PhysicalLocation
	if loc.Address == nil {
		t.Fatal("result has no address")
	}
	if loc.Address.AbsoluteAddress != 0x1000 {
		t.Errorf("absoluteAddress = %#x, want 0x1000", loc.Address.AbsoluteAddress)
	}
	if loc.Address.Name != "isRooted" {
		t.Errorf("address name = %q, want isRooted", loc.Address.Name)
	}
	if loc.Address.Kind != "function" {
		t.Errorf("address kind = %q, want function", loc.Address.Kind)
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
	if err := WriteSARIF(dir, findings, "1.0.0", ArtifactIdentity{}); err != nil {
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
	if res[0].PartialFingerprints[sarifFindingFingerprintKey] == res[1].PartialFingerprints[sarifFindingFingerprintKey] {
		t.Error("two distinct binary-level findings share a fingerprint")
	}
	if _, ok := res[0].PartialFingerprints["aotopsyFindingV2"]; ok {
		t.Error("fingerprint version is embedded in one component instead of SARIF's /vN version component")
	}
}

func TestWriteSARIFUsesProducerRuleIDsDeduplicatesAndIsDeterministic(t *testing.T) {
	findings := []SignalFinding{
		{Category: "yara", RuleID: "signal.yara.rule_b", StringValue: "b", Function: "f", PC: "0X0020"},
		{Category: "taint", RuleID: "signal.taint.flow", StringValue: "flow", Function: "g", ProducerConfidence: "high"},
		{Category: "yara", RuleID: "signal.yara.rule_a", StringValue: "a", Function: "f", PC: "0x10"},
		{Category: "yara", RuleID: "signal.yara.rule_a", StringValue: "a", Function: "f", PC: "0x0010"}, // exact emitted duplicate
	}
	dirA := t.TempDir()
	if err := WriteSARIF(dirA, findings, "dev", ArtifactIdentity{URI: "app #1.so"}); err != nil {
		t.Fatal(err)
	}
	reversed := append([]SignalFinding(nil), findings...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	dirB := t.TempDir()
	if err := WriteSARIF(dirB, reversed, "dev", ArtifactIdentity{URI: "app #1.so"}); err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile(filepath.Join(dirA, "aotopsy.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dirB, "aotopsy.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("SARIF bytes depend on producer finding order")
	}
	var log sarifLog
	if err := json.Unmarshal(a, &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	if got := len(run.Results); got != 3 {
		t.Fatalf("results = %d, want 3 after exact dedupe", got)
	}
	if got := len(run.Tool.Driver.Rules); got != 3 {
		t.Fatalf("rules = %d, want 3 producer rules", got)
	}
	if run.Tool.Driver.Rules[0].ID != "signal.taint.flow" || run.Tool.Driver.Rules[1].ID != "signal.yara.rule_a" || run.Tool.Driver.Rules[2].ID != "signal.yara.rule_b" {
		t.Fatalf("rules are not stable-sorted producer IDs: %#v", run.Tool.Driver.Rules)
	}
	if got := run.Results[0].Properties["producerConfidence"]; got != "high" {
		t.Fatalf("producer confidence = %q, want high", got)
	}
	if got := run.Artifacts[0].Location.URI; got != "app%20%231.so" {
		t.Fatalf("escaped artifact URI = %q", got)
	}
}

func TestWriteSARIFPartialFingerprintIsStableAcrossAddressAndConfidenceChanges(t *testing.T) {
	findings := []SignalFinding{
		{
			Category:           "taint",
			RuleID:             "signal.taint.flow",
			StringValue:        "device_id -> network (flow, confidence=medium)",
			Function:           "sendDeviceInfo",
			PC:                 "0x1000",
			AddressKind:        "instruction",
			ProducerConfidence: "medium",
			FingerprintParts:   []string{"taint-flow", "device_id", "network", "flow", "readDeviceInfo", "sendDeviceInfo"},
		},
		{
			Category:           "taint",
			RuleID:             "signal.taint.flow",
			StringValue:        "device_id -> network (flow, confidence=high)",
			Function:           "sendDeviceInfo",
			PC:                 "0x2000",
			AddressKind:        "instruction",
			ProducerConfidence: "high",
			FingerprintParts:   []string{"taint-flow", "device_id", "network", "flow", "readDeviceInfo", "sendDeviceInfo"},
		},
	}
	dir := t.TempDir()
	if err := WriteSARIF(dir, findings, "dev", ArtifactIdentity{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "aotopsy.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	results := log.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2 distinct emitted occurrences", len(results))
	}
	a := results[0].PartialFingerprints[sarifFindingFingerprintKey]
	b := results[1].PartialFingerprints[sarifFindingFingerprintKey]
	if a == "" || b == "" {
		t.Fatal("result is missing a partial fingerprint")
	}
	if a != b {
		t.Fatalf("logical finding fingerprint changed with address/confidence: %q != %q", a, b)
	}
}

func TestWriteSARIFRejectsRuleIDCategoryConflictWithoutReplacingReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aotopsy.sarif")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := WriteSARIF(dir, []SignalFinding{
		{Category: "url", RuleID: "same.rule"},
		{Category: "host", RuleID: "same.rule"},
	}, "dev", ArtifactIdentity{})
	if err == nil {
		t.Fatal("conflicting rule/category mapping was accepted")
	}
	b, readErr := os.ReadFile(path)
	if readErr != nil || string(b) != "old\n" {
		t.Fatalf("rejected SARIF input changed current report: %q, %v", b, readErr)
	}
}

func TestWriteSARIFEmptyResultsAreArrays(t *testing.T) {
	dir := t.TempDir()
	if err := WriteSARIF(dir, nil, "1.0.0", ArtifactIdentity{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "aotopsy.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	runs := raw["runs"].([]any)
	run := runs[0].(map[string]any)
	if _, ok := run["results"].([]any); !ok {
		t.Fatalf("results encoded as %T, want JSON array", run["results"])
	}
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if _, ok := driver["rules"].([]any); !ok {
		t.Fatalf("rules encoded as %T, want JSON array", driver["rules"])
	}
}

func TestDescribeArtifactEncodesRelativeURI(t *testing.T) {
	got := describeArtifact(ArtifactIdentity{URI: filepath.Join(t.TempDir(), "app #100%.so")})
	if got.Location.URI != "app%20%23100%25.so" {
		t.Fatalf("artifact URI = %q, want percent-encoded relative URI", got.Location.URI)
	}
}
