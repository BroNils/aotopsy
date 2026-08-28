package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aotopsy/internal/disasm"
)

// sampleSpec describes expected thresholds for a sample.
type sampleSpec struct {
	name         string
	libapp       string
	minFunctions int
	minBLRPct    float64 // minimum BLR annotation percentage
}

var samples = []sampleSpec{
	{
		name:         "evil",
		libapp:       "samples/evil-patched.so",
		minFunctions: 1000,
		minBLRPct:    80.0,
	},
	{
		name:         "blutter",
		libapp:       "samples/blutter-lce.so",
		minFunctions: 1000,
		minBLRPct:    80.0,
	},
	{
		name:         "newandromo",
		libapp:       "samples/newandromo.so",
		minFunctions: 1000,
		minBLRPct:    80.0,
	},
}

// findProjectRoot walks up from cwd to find go.mod.
func findProjectRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func TestDisasmPipelineThresholds(t *testing.T) {
	root := findProjectRoot()
	if root == "" {
		t.Skip("project root not found")
	}

	for _, s := range samples {
		t.Run(s.name, func(t *testing.T) {
			libapp := filepath.Join(root, s.libapp)
			if _, err := os.Stat(libapp); err != nil {
				t.Skipf("sample not found: %s", libapp)
			}

			outDir := t.TempDir()
			_, err := Run(Opts{
				LibPath: libapp,
				OutDir:  outDir,
			})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}

			// Check functions.jsonl.
			funcsPath := filepath.Join(outDir, "functions.jsonl")
			funcCount := countJSONLLines(t, funcsPath)
			if funcCount < s.minFunctions {
				t.Errorf("functions: %d < %d minimum", funcCount, s.minFunctions)
			}

			// Check call_edges.jsonl BLR annotation rate.
			edgesPath := filepath.Join(outDir, "call_edges.jsonl")
			totalBLR, annotatedBLR := countBLRAnnotations(t, edgesPath)
			if totalBLR > 0 {
				pct := float64(annotatedBLR) / float64(totalBLR) * 100
				if pct < s.minBLRPct {
					t.Errorf("BLR annotation: %.1f%% < %.1f%% minimum (%d/%d)",
						pct, s.minBLRPct, annotatedBLR, totalBLR)
				}
				t.Logf("BLR: %d/%d (%.1f%%)", annotatedBLR, totalBLR, pct)
			}

			// Check unresolved_thr.jsonl exists.
			unresTHRPath := filepath.Join(outDir, "unresolved_thr.jsonl")
			unresTHRCount := countJSONLLines(t, unresTHRPath)
			t.Logf("functions=%d edges_total=%d blr=%d unres_thr=%d",
				funcCount, countJSONLLines(t, edgesPath), totalBLR, unresTHRCount)
		})
	}
}

func countJSONLLines(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	count := 0
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			t.Fatalf("decode %s line %d: %v", path, count+1, err)
		}
		count++
	}
	return count
}

func countBLRAnnotations(t *testing.T, path string) (total, annotated int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	for dec.More() {
		var rec disasm.CallEdgeRecord
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if rec.Kind != "blr" {
			continue
		}
		total++
		if rec.Via != "" {
			annotated++
		}
	}
	return
}
