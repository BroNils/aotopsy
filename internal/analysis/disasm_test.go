package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aotopsy/internal/disasm"
)

// sampleSpec describes broad pipeline thresholds for a registered corpus
// sample. The old version of this test used three gitignored app-codename paths
// (evil-patched.so, blutter-lce.so, newandromo.so) and silently skipped when
// those local aliases were absent. Two of those aliases are known to have
// drifted onto the wrong Dart versions. Keep the useful threshold coverage, but
// bind it to canonical, validated corpus identities instead.
type sampleSpec struct {
	name         string
	sample       string
	minFunctions int
	minBLRPct    float64
}

var samples = []sampleSpec{
	{name: "dart-2.17.6", sample: "dart-2.17.6-arm64.so", minFunctions: 1000, minBLRPct: 80.0},
	{name: "dart-3.1.0", sample: "dart-3.1.0-arm64.so", minFunctions: 1000, minBLRPct: 80.0},
	{name: "dart-3.9.2", sample: "dart-3.9.2-arm64.so", minFunctions: 1000, minBLRPct: 80.0},
}

func TestDisasmPipelineThresholds(t *testing.T) {
	requireCompleteCorpus(t)
	for _, s := range samples {
		t.Run(s.name, func(t *testing.T) {
			libapp := corpusSample(t, s.sample)
			outDir := t.TempDir()
			_, err := Run(Opts{LibPath: libapp, OutDir: outDir})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}

			funcsPath := filepath.Join(outDir, "functions.jsonl")
			funcCount := countJSONLLines(t, funcsPath)
			if funcCount < s.minFunctions {
				t.Errorf("functions: %d < %d minimum", funcCount, s.minFunctions)
			}

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
