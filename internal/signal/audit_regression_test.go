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
	if strings.Contains(string(b), "data_exfil_http") {
		t.Fatalf("one generic URL triggered composite exfiltration rule: %s", b)
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
	if !strings.Contains(string(b), "data_exfil_http") {
		t.Fatalf("two independent witnesses did not trigger data_exfil_http: %s", b)
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
		CatDRMBypass:     "warning",
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
