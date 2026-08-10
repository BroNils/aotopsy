package signal

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"aotopsy/internal/disasm"
)

// --- ShannonEntropy tests ---

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want float64
		tol  float64
	}{
		{"empty", []byte{}, 0, 0},
		{"single byte", []byte{0x41}, 0, 0},
		{"all same", []byte{0xFF, 0xFF, 0xFF, 0xFF}, 0, 0},
		{"two bytes equal", []byte{0x00, 0xFF}, 1.0, 0.001},
		{"four distinct", []byte{0x00, 0x01, 0x02, 0x03}, 2.0, 0.001},
		{"256 all distinct", makeAllBytes(), 8.0, 0.001},
	}
	for _, tt := range tests {
		got := ShannonEntropy(tt.data)
		if abs(got-tt.want) > tt.tol {
			t.Errorf("ShannonEntropy(%s) = %.4f, want %.4f ± %.4f", tt.name, got, tt.want, tt.tol)
		}
	}
}

func makeAllBytes() []byte {
	b := make([]byte, 256)
	for i := 0; i < 256; i++ {
		b[i] = byte(i)
	}
	return b
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// --- Crypto algorithm identification tests ---

func TestIdentifyCryptoFromBinary(t *testing.T) {
	// Create a small binary with known crypto constants embedded
	// AES Rcon[0] = 0x01000000 (LE: 00 00 00 01)
	// ChaCha20 'expa' = 0x61707865 (LE: 65 78 70 61)
	data := []byte{
		0x00, 0x00, 0x00, 0x01, // AES Rcon[0]
		0x00, 0x00, 0x00, 0x00, // padding
		0x65, 0x78, 0x70, 0x61, // ChaCha20 'expa'
	}
	// Write to temp file and scan
	tmpFile := "/tmp/test_crypto_binary.bin"
	if err := writeFile(tmpFile, data); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	findings, err := IdentifyCryptoFromBinary(tmpFile)
	if err != nil {
		t.Fatalf("IdentifyCryptoFromBinary: %v", err)
	}
	if len(findings) < 2 {
		t.Errorf("expected at least 2 crypto findings, got %d", len(findings))
	}
	// Check that AES Rcon[0] and ChaCha20 'expa' were found
	foundAES := false
	foundChaCha := false
	for _, f := range findings {
		if contains(f.Algorithm, "AES Rcon[0]") {
			foundAES = true
		}
		if contains(f.Algorithm, "ChaCha20") {
			foundChaCha = true
		}
	}
	if !foundAES {
		t.Error("AES Rcon[0] not found in binary scan")
	}
	if !foundChaCha {
		t.Error("ChaCha20 'expa' not found in binary scan")
	}
}

// --- Method Channel enumeration tests ---

func TestEnumerateMethodChannels(t *testing.T) {
	refs := []disasm.StringRefRecord{
		{Value: "flutter/platform", Func: "testFunc"},
		{Value: "dev.flutter/channel-buffers", Func: "testFunc2"},
		{Value: "BinaryMessenger", Func: "testFunc3"},
		{Value: "not a channel", Func: "testFunc4"},
		{Value: "MethodChannel(\"my_channel\")", Func: "testFunc5"},
	}
	sigRefs := convertToSigRefs(refs)
	findings := EnumerateMethodChannels(sigRefs)
	if len(findings) < 4 {
		t.Errorf("expected at least 4 method channel findings, got %d", len(findings))
	}
	found := false
	for _, f := range findings {
		if f.Channel == "flutter/platform" {
			found = true
		}
	}
	if !found {
		t.Error("flutter/platform not found in method channel enumeration")
	}
}

// --- Plugin enumeration tests ---

func TestEnumeratePlugins(t *testing.T) {
	refs := []disasm.StringRefRecord{
		{Value: "video_player", Func: "testFunc"},
		{Value: "path_provider", Func: "testFunc2"},
		{Value: "MissingPluginException", Func: "testFunc3"},
		{Value: "not a plugin", Func: "testFunc4"},
	}
	sigRefs := convertToSigRefs(refs)
	findings := EnumeratePlugins(sigRefs)
	// "not a plugin" contains "plugin" but not any of the specific patterns
	// video_player, path_provider, MissingPluginException should match
	if len(findings) < 2 {
		t.Errorf("expected at least 2 plugin findings, got %d", len(findings))
	}
}

// --- Network endpoint extraction tests ---

func TestExtractNetworkEndpoints(t *testing.T) {
	refs := []disasm.StringRefRecord{
		{Value: "https://api.example.com/v1/users", Func: "testFunc"},
		{Value: "10.0.0.5", Func: "testFunc2"},
		{Value: "api.example.com", Func: "testFunc3"},
		{Value: "not an endpoint", Func: "testFunc4"},
		{Value: "0.0.0.0", Func: "testFunc5"},
		{Value: "127.0.0.1", Func: "testFunc6"},
	}
	sigRefs := convertToSigRefs(refs)
	findings := ExtractNetworkEndpoints(sigRefs)
	if len(findings) < 2 {
		t.Errorf("expected at least 2 network endpoint findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Value == "0.0.0.0" || f.Value == "127.0.0.1" {
			t.Error("local IP should be skipped: " + f.Value)
		}
	}
}

// --- String deobfuscation tests ---

func TestDetectObfuscatedStrings(t *testing.T) {
	refs := []disasm.StringRefRecord{
		{Value: "SGVsbG8gV29ybGQ=", Func: "testFunc"},
		{Value: "short", Func: "testFunc2"},
		{Value: "cGFzc3dvcmQxMjM=", Func: "testFunc3"},
	}
	sigRefs := convertToSigRefs(refs)
	findings := DetectObfuscatedStrings(sigRefs)
	if len(findings) < 2 {
		t.Errorf("expected at least 2 deobfuscation findings, got %d", len(findings))
	}
	found := false
	for _, f := range findings {
		if f.Decoded == "Hello World" {
			found = true
		}
	}
	if !found {
		t.Error("base64 'SGVsbG8gV29ybGQ=' was not decoded to 'Hello World'")
	}
}

// --- YARA-style matching tests ---

func TestYaraMatching(t *testing.T) {
	refs := []disasm.StringRefRecord{
		{Value: "/sbin/magisk", Func: "checkRoot"},
		{Value: "frida-server", Func: "checkFrida"},
		{Value: "ptrace", Func: "checkDebug"},
		{Value: "certificatePinner", Func: "sslPinning"},
		{Value: "innocent string", Func: "normalFunc"},
	}
	tmpDir := t.TempDir()
	err := WriteYaraFindings(tmpDir, refs)
	if err != nil {
		t.Fatalf("WriteYaraFindings: %v", err)
	}
	findings, err := readYaraFindings(tmpDir + "/yara_findings.jsonl")
	if err != nil {
		t.Fatalf("read yara findings: %v", err)
	}
	if len(findings) < 3 {
		t.Errorf("expected at least 3 YARA rule matches, got %d", len(findings))
	}
	found := false
	for _, f := range findings {
		if f.RuleName == "root_check_magisk" {
			found = true
		}
	}
	if !found {
		t.Error("root_check_magisk rule was not matched")
	}
}

// --- Taint analysis tests ---

func TestTaintAnalysis(t *testing.T) {
	tmpDir := t.TempDir()
	refs := []disasm.StringRefRecord{
		{Value: "token:abc123", Func: "getCredential"},
		{Value: "https://api.example.com/upload", Func: "sendData"},
		{Value: "password:secret", Func: "getPassword"},
		{Value: "writeFile:passwords.txt", Func: "saveData"},
	}
	edges := []disasm.CallEdgeRecord{
		{FromFunc: "getCredential", Target: "sendData"},
		{FromFunc: "getPassword", Target: "saveData"},
	}
	err := WriteTaintFindings(tmpDir, refs, edges)
	if err != nil {
		t.Fatalf("WriteTaintFindings: %v", err)
	}
	findings, err := readTaintFindings(tmpDir + "/taint_findings.jsonl")
	if err != nil {
		t.Fatalf("read taint findings: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected taint findings, got 0")
	}
	foundTokenFlow := false
	for _, f := range findings {
		if f.Source == "auth_token" && f.Sink == "network_http" {
			foundTokenFlow = true
		}
	}
	if !foundTokenFlow {
		t.Error("token→http taint flow not found")
	}
}

// convertToSigRefs converts disasm.StringRefRecord to signal.StringRefRecord.
func convertToSigRefs(refs []disasm.StringRefRecord) []StringRefRecord {
	out := make([]StringRefRecord, len(refs))
	for i, r := range refs {
		out[i] = StringRefRecord{
			Func:    r.Func,
			PC:      r.PC,
			Kind:    r.Kind,
			PoolIdx: r.PoolIdx,
			Value:   r.Value,
		}
	}
	return out
}

// --- Helper functions ---

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

func readYaraFindings(path string) ([]YaraFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var findings []YaraFinding
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		var f YaraFinding
		if err := json.Unmarshal([]byte(line), &f); err == nil {
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func readTaintFindings(path string) ([]TaintFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var findings []TaintFinding
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		var f TaintFinding
		if err := json.Unmarshal([]byte(line), &f); err == nil {
			findings = append(findings, f)
		}
	}
	return findings, nil
}
