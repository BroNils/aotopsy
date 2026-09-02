package signal

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	scan := func(t *testing.T, name string, data []byte) []CryptoFinding {
		t.Helper()
		tmpFile := filepath.Join(t.TempDir(), name)
		if err := writeFile(tmpFile, data); err != nil {
			t.Fatalf("write temp file: %v", err)
		}
		findings, err := IdentifyCryptoFromBinary(tmpFile)
		if err != nil {
			t.Fatalf("IdentifyCryptoFromBinary: %v", err)
		}
		return findings
	}
	has := func(findings []CryptoFinding, algo string) bool {
		for _, f := range findings {
			if contains(f.Algorithm, algo) {
				return true
			}
		}
		return false
	}

	// AES Rcon[0]'s little-endian bytes are 00 00 00 01, which occur in
	// every binary ever built (any `MOV #1`, any length-1 array, any
	// zero-padded word). See isDistinctiveConstant.
	t.Run("non-distinctive constant is not evidence", func(t *testing.T) {
		f := scan(t, "rcon.bin", []byte{0x00, 0x00, 0x00, 0x01})
		if has(f, "AES Rcon[0]") {
			t.Error("AES Rcon[0] must not be reported from a raw byte scan")
		}
	})

	// ChaCha20's constants ARE text: "expand 32-byte k" cut into four
	// 32-bit words, so 0x61707865 is literally the bytes "expa". This test
	// used to embed that one word and REQUIRE it to be reported, which is
	// what let a real false positive through: on dart-3.9.2-arm64 the only
	// crypto finding in the whole binary was this constant matched inside
	// `expando_patch.dart`, a Dart core library filename.
	t.Run("lone ASCII constant is not evidence", func(t *testing.T) {
		f := scan(t, "expa.bin", []byte("some/path/expando_patch.dart"))
		if has(f, "ChaCha20") {
			t.Error("a lone ASCII constant must not be reported: " +
				`"expa" occurs in ordinary identifiers`)
		}
	})

	// Corroboration is what makes it evidence: the real cipher constant is
	// the whole 16-byte string, and finding two or more of its words is
	// not something ordinary text does.
	t.Run("corroborated ASCII constants are evidence", func(t *testing.T) {
		f := scan(t, "chacha.bin", []byte("expand 32-byte k"))
		if !has(f, "ChaCha20") {
			t.Error("the full ChaCha20 constant block must be reported")
		}
	})

	// A constant that is not text needs no second witness, so tightening
	// the ASCII case must not weaken any other detection.
	t.Run("lone non-ASCII constant is still evidence", func(t *testing.T) {
		// SHA-256 K[0] = 0x428a2f98, little-endian 98 2f 8a 42.
		f := scan(t, "sha.bin", []byte{0x98, 0x2f, 0x8a, 0x42})
		if !has(f, "SHA-256") {
			t.Error("SHA-256 K[0] must still be reported on its own")
		}
	})
}

func TestIsDistinctiveConstant(t *testing.T) {
	distinctive := []string{"0x61707865", "0x428a2f98", "0xedb88320", "0x9e3779b9",
		"0x428a2f98d728ae22"}
	trivial := []string{"0x01000000", "0x02000000", "0x80000000",
		"0x0000000000000001", "0x8000000080008000"}
	for _, h := range distinctive {
		if !isDistinctiveConstant(h) {
			t.Errorf("isDistinctiveConstant(%s) = false, want true", h)
		}
	}
	for _, h := range trivial {
		if isDistinctiveConstant(h) {
			t.Errorf("isDistinctiveConstant(%s) = true, want false", h)
		}
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
		// A qualified token name: bare "token" is not a source pattern any
		// more because it also matches tokenizer/tokenize in ordinary code.
		{Value: "authToken:abc123", Func: "getCredential"},
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

// --- Regression tests for the classification fixes ---

// containsKeyword matches against normalizeForMatch(value), which strips
// '_', '-', ' ' and '.'. A keyword still containing one of those can never
// match; these were all dead until the lists were normalized at init.
func TestSecurityKeywordsAreNormalized(t *testing.T) {
	for _, list := range [][]string{
		rootingKeywords, antiAnalysisKeywords, sslPinningKeywords,
		accessibilityKeywords, fraudKeywords, dynamicLoadKeywords,
		ipcKeywords, covertChannelKeywords, drmBypassKeywords, pluginKeywords,
	} {
		for _, kw := range list {
			if kw != normalizeForMatch(kw) {
				t.Errorf("keyword %q is not in normalized form (%q) and can never match", kw, normalizeForMatch(kw))
			}
		}
	}
}

func TestSecurityCategoriesFireOnRealStrings(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{"frida-server", CatRooting},
		{"ro.debuggable", CatRooting},
		{"which su", CatRooting},
		{"network_security_config", CatSSLPinning},
		{"android.os.Debug", CatAntiAnalysis},
	}
	for _, tt := range tests {
		if !containsCat(ClassifyString(tt.value), tt.want) {
			t.Errorf("ClassifyString(%q) = %v, want it to contain %q", tt.value, ClassifyString(tt.value), tt.want)
		}
	}
}

// Ordinary Flutter/Dart vocabulary must not be classified as malicious.
func TestSecurityCategoriesNoFalsePositives(t *testing.T) {
	clean := []string{
		"Iterator", "Constructor", "easeInCubic", "Cubic", "Vector3",
		"transaction", "reflectance", "()", "::", "{}", "->",
		"serialize", "deserializer", "allocation", "relocation", "tokenizer",
	}
	for _, v := range clean {
		cats := ClassifyString(v)
		for _, bad := range []string{CatCovertChannel, CatFraud, CatIPC, CatObfuscation, CatDynamicLoad} {
			if containsCat(cats, bad) {
				t.Errorf("ClassifyString(%q) = %v, must not contain %q", v, cats, bad)
			}
		}
	}
}

// Obfuscation is a whole-binary property; a single short name is not evidence.
func TestObfuscationRatio(t *testing.T) {
	clean := []string{"buildContext", "onPressed", "gtk", "widget", "render", "state"}
	if r, n, _ := ObfuscationRatio(clean); n == 0 || r >= ObfuscationThreshold {
		t.Errorf("clean identifier set reported as obfuscated: ratio=%.2f considered=%d", r, n)
	}
	obf := []string{"aB", "cD", "xY", "zQ", "mN", "buildContext"}
	if r, _, _ := ObfuscationRatio(obf); r < ObfuscationThreshold {
		t.Errorf("obfuscated identifier set not detected: ratio=%.2f", r)
	}
}

// Every real domain must survive the file-extension filter: the earlier
// Contains(".c") test threw away every .com host.
func TestExtractNetworkEndpointsKeepsRealDomains(t *testing.T) {
	refs := []StringRefRecord{
		{Value: "google.com", Func: "f"},
		{Value: "api.example.co.id", Func: "f"},
		{Value: "cdn.social", Func: "f"},
		{Value: "package:flutter/src/widgets/framework.dart", Func: "f"},
	}
	got := map[string]bool{}
	for _, f := range ExtractNetworkEndpoints(refs) {
		got[f.Value] = true
	}
	for _, want := range []string{"google.com", "api.example.co.id", "cdn.social"} {
		if !got[want] {
			t.Errorf("domain %q was dropped", want)
		}
	}
	if got["framework.dart"] || got["src.widgets"] {
		t.Errorf("a .dart path was reported as a domain: %v", got)
	}
}
