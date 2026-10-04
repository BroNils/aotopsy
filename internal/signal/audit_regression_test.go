package signal

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"aotopsy/internal/disasm"
)

func encodeMoveWide32(base uint32, rd int, imm uint16, hw uint32) uint32 {
	return base | (hw << 21) | (uint32(imm) << 5) | uint32(rd)
}

func TestIdentifyCryptoFromARM64MoveWideSequence(t *testing.T) {
	// SHA-256 K[0] = 0x428a2f98. Dart/AArch64 materialises this as two
	// instruction words, not the contiguous bytes 98 2f 8a 42.
	code := make([]byte, 8)
	binary.LittleEndian.PutUint32(code[0:4], encodeMoveWide32(0x52800000, 3, 0x2f98, 0)) // movz w3,#0x2f98
	binary.LittleEndian.PutUint32(code[4:8], encodeMoveWide32(0x72800000, 3, 0x428a, 1)) // movk w3,#0x428a,lsl#16
	acc := newCryptoAccumulator()
	identifyCryptoFromARM64Code(code, 0x120, cryptoPatterns(), acc)
	findings := acc.finish()
	for _, f := range findings {
		if f.Constant == "0x428a2f98" && f.Algorithm == "SHA-256 K[0]" {
			if f.Value != "binary_offset=0x120" {
				t.Fatalf("offset = %q, want binary_offset=0x120", f.Value)
			}
			return
		}
	}
	t.Fatalf("ARM64 MOVZ/MOVK SHA-256 constant was not reconstructed: %#v", findings)
}

func TestIdentifyCryptoFromPoolImmediatesRejectsMalformedJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pool_immediates.jsonl")
	data := "{\"index\":1,\"value\":0,\"hex\":\"0x428a2f98\"}\n{malformed}\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	if findings, err := IdentifyCryptoFromPoolImmediates(dir); err == nil {
		t.Fatalf("malformed JSONL returned nil error with partial findings %#v", findings)
	}
}

func TestExpansionAggregatesProvenanceAndReplacesStaleArtifact(t *testing.T) {
	dir := t.TempDir()
	refs := []StringRefRecord{
		{Value: "https://api.example.com/v1", Func: "zFunc"},
		{Value: "https://api.example.com/v1", Func: "aFunc"},
	}
	if err := WriteSignalExpansionJSONL(dir, refs); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "network_endpoints.jsonl")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, `"functions":["aFunc","zFunc"]`) {
		t.Fatalf("network provenance was not aggregated/sorted: %s", text)
	}

	if err := WriteSignalExpansionJSONL(dir, nil); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 0 {
		t.Fatalf("zero-finding rerun left stale network endpoint data: %q", b)
	}
}

func TestYaraCompositeRulesRequireMultipleDistinctWitnesses(t *testing.T) {
	dir := t.TempDir()
	if err := WriteYaraFindings(dir, []disasm.StringRefRecord{{Value: "http://example.com", Func: "f"}}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "yara_findings.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "sensitive_network_indicators") {
		t.Fatalf("one generic URL triggered composite source/network rule: %s", b)
	}

	refs := []disasm.StringRefRecord{
		{Value: "http://example.com", Func: "send"},
		{Value: "android_id", Func: "collect"},
	}
	if err := WriteYaraFindings(dir, refs); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(filepath.Join(dir, "yara_findings.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "sensitive_network_indicators") {
		t.Fatalf("two independent witnesses did not trigger sensitive_network_indicators: %s", b)
	}
	findings, err := readYaraFindings(filepath.Join(dir, "yara_findings.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleName == "sensitive_network_indicators" && f.Confidence != "low" {
			t.Fatalf("cross-function lexical witnesses inflated YARA confidence: %+v", f)
		}
	}

	coLocated := []disasm.StringRefRecord{
		{Value: "android_id", Func: "collectAndSend"},
		{Value: "http://example.com", Func: "collectAndSend"},
	}
	if err := WriteYaraFindings(dir, coLocated); err != nil {
		t.Fatal(err)
	}
	findings, err = readYaraFindings(filepath.Join(dir, "yara_findings.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleName == "sensitive_network_indicators" {
			if f.Confidence != "medium" {
				t.Fatalf("co-located independent witnesses confidence = %q, want medium", f.Confidence)
			}
			return
		}
	}
	t.Fatal("co-located sensitive_network_indicators finding missing")
}

func TestYaraRejectsGenericDebuggerAndHTTPClientNames(t *testing.T) {
	dir := t.TempDir()
	refs := []disasm.StringRefRecord{
		{Value: "debugger", Func: "helpText"},
		{Value: "OkHttp", Func: "httpClient"},
	}
	if err := WriteYaraFindings(dir, refs); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "yara_findings.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 0 {
		t.Fatalf("generic debugger/HTTP client names produced YARA findings: %s", b)
	}

	refs = []disasm.StringRefRecord{
		{Value: "android.os.Debug", Func: "checkDebug"},
		{Value: "certificatePinner", Func: "pinTLS"},
	}
	if err := WriteYaraFindings(dir, refs); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(filepath.Join(dir, "yara_findings.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "anti_debug_debugger") || !strings.Contains(text, "ssl_pinning_cert") {
		t.Fatalf("specific anti-debug/pinning witnesses were lost: %s", text)
	}
	if !strings.Contains(text, `"confidence":"low"`) {
		t.Fatalf("single-pattern YARA match is missing low producer confidence: %s", text)
	}
}

func TestBehavioralAnalysisDoesNotMutateCallEdges(t *testing.T) {
	dir := t.TempDir()
	edges := []disasm.CallEdgeRecord{{FromFunc: "sendRequest", Targets: []string{"0x1000"}}}
	before := append([]string(nil), edges[0].Targets...)
	funcs := []disasm.FuncRecord{{PC: "0x1000", Name: "networkRequest"}, {Name: "sendRequest"}}
	if err := WriteBehavioralFindings(dir, funcs, edges); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(edges[0].Targets, before) {
		t.Fatalf("behavioral analysis mutated caller edge targets: got %v want %v", edges[0].Targets, before)
	}
}

func TestStaticCallerCalleesResolvesDirectTargetAddressButNotRuntimeOnlyTarget(t *testing.T) {
	funcs := []disasm.FuncRecord{{Name: "caller", PC: "0x1000"}, {Name: "callee", PC: "0x2000"}, {Name: "runtime", PC: "0x3000"}}
	edges := []disasm.CallEdgeRecord{{
		FromFunc: "caller", FromPC: "0x1010", Kind: "bl", TargetAddress: "0x2000",
		Runtime: &disasm.RuntimeEvidence{Targets: []disasm.RuntimeTargetObservation{{Target: "runtime", Count: 1}}, Observations: 1},
	}}
	graph := staticCallerCallees(funcs, edges)
	if !graph["caller"]["callee"] || graph["caller"]["runtime"] {
		t.Fatalf("static caller graph = %+v, want address-resolved callee only", graph)
	}
}

func TestSecurityCategorySeverityMatchesSARIFPolicy(t *testing.T) {
	cases := map[string]string{
		CatRooting:       "error",
		CatAntiAnalysis:  "error",
		CatSSLPinning:    "warning",
		CatAccessibility: "error",
		CatFraud:         "error",
		CatDynamicLoad:   "warning",
		CatIPC:           "note",
		CatCovertChannel: "error",
		CatDRM:           "warning",
		CatObfuscation:   "warning",
		CatCryptoConst:   "note",
		CatMethodChannel: "note",
		CatPlugin:        "note",
	}
	for cat, want := range cases {
		if got := CategorySARIFLevel(cat); got != want {
			t.Errorf("CategorySARIFLevel(%q) = %q, want %q", cat, got, want)
		}
	}
}
