package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aotopsy/internal/cluster"
	comparepkg "aotopsy/internal/decompiler/compare"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/naming"
)

func TestFingerprintDictionaryCandidatesDoNotMutateSemanticNaming(t *testing.T) {
	code := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	ranges := []cluster.CodeRange{
		{PCOffset: 0x100, Size: 4, RefID: 10},
		{PCOffset: 0x104, Size: 4, RefID: 11},
		{PCOffset: 0x108, Size: 4, RefID: 12},
	}
	pl := &naming.PoolLookups{
		CodeNames: map[int]naming.CodeNameInfo{
			10: {OwnerName: "Owner"},
			11: {FuncName: "alreadyKnown", OwnerName: "Owner"},
		},
		CodeRefDisplay: map[int]string{11: "Owner.alreadyKnown"},
		RefToNamed:     map[int]*cluster.NamedObject{},
		RefCID:         map[int]int{},
		VmRefCID:       map[int]int{},
	}
	dict, err := comparepkg.NewFunctionDictionary("3.12.2", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	dict.Add(comparepkg.ComputeFingerprint(code[:4], "recovered", "Owner"))
	dict.Add(comparepkg.ComputeFingerprint(code[4:8], "wrongReplacement", "Owner"))
	dict.Add(comparepkg.ComputeFingerprint(code[8:], "missingCodeNameRecovered", "RecoveredOwner"))

	n, err := countFingerprintDictionaryCandidates(pl, ranges, code, 0x100, 0x1000, dict)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("candidates = %d, want 2", n)
	}
	if got := pl.CodeNames[10].FuncName; got != "" {
		t.Fatalf("heuristic fingerprint mutated unnamed semantic name: %q", got)
	}
	if got := pl.CodeNames[11].FuncName; got != "alreadyKnown" {
		t.Fatalf("known function was overwritten: %q", got)
	}
	if got := pl.CodeNames[12]; got.FuncName != "" || got.OwnerName != "" {
		t.Fatalf("heuristic fingerprint created authoritative target metadata: %+v", got)
	}
	if got := pl.CodeRefDisplay[10]; got != "" {
		t.Fatalf("heuristic fingerprint mutated CodeRefDisplay: %q", got)
	}
	if _, exists := pl.CodeRefDisplay[12]; exists {
		t.Fatalf("heuristic fingerprint created CodeRefDisplay for unknown target")
	}
}

func TestApplyFingerprintDictionaryRejectsOwnerContradiction(t *testing.T) {
	code := []byte{1, 2, 3, 4}
	pl := &naming.PoolLookups{CodeNames: map[int]naming.CodeNameInfo{
		10: {OwnerName: "TargetOwner"},
	}}
	dict, err := comparepkg.NewFunctionDictionary("3.12.2", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	dict.Add(comparepkg.ComputeFingerprint(code, "name", "DifferentOwner"))
	n, err := countFingerprintDictionaryCandidates(pl, []cluster.CodeRange{{PCOffset: 0x100, Size: 4, RefID: 10}}, code, 0x100, 0x1000, dict)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || pl.CodeNames[10].FuncName != "" {
		t.Fatalf("owner contradiction transferred a name: n=%d info=%+v", n, pl.CodeNames[10])
	}
}

func TestWriteFunctionFingerprintsPersistsRawNameComponents(t *testing.T) {
	dir := t.TempDir()
	code := []byte{1, 2, 3, 4}
	pl := &naming.PoolLookups{CodeNames: map[int]naming.CodeNameInfo{
		10: {FuncName: "method", OwnerName: "Owner"},
	}}
	ranges := []cluster.CodeRange{{PCOffset: 0x100, Size: 4, RefID: 10}}
	if err := writeFunctionFingerprints(dir, ranges, pl, code, 0x100, 0x1000); err != nil {
		t.Fatal(err)
	}
	type rec struct {
		Hash  string `json:"hash"`
		VA    string `json:"va"`
		Size  int    `json:"size"`
		Name  string `json:"name"`
		Owner string `json:"owner"`
	}
	recs, err := jsonutil.ReadJSONL[rec](filepath.Join(dir, "function_fingerprints.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Name != "method" || recs[0].Owner != "Owner" {
		t.Fatalf("fingerprint record = %+v, want raw method + Owner", recs)
	}
	if strings.Contains(recs[0].Name, "_100") || strings.Contains(recs[0].Name, "Owner.") {
		t.Fatalf("display-qualified name leaked into semantic dictionary seed: %+v", recs[0])
	}

	// Sanity: the artifact remains valid one-object-per-line JSON rather than an
	// ad-hoc whitespace format.
	data, err := os.ReadFile(filepath.Join(dir, "function_fingerprints.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data[:len(data)-1], &raw); err != nil {
		t.Fatalf("fingerprint artifact is not JSONL: %v", err)
	}
}
