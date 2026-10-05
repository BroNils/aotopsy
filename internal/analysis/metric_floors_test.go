package analysis

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// metricFloors are per-sample lower/upper bounds on the BEHAVIOURAL health of the
// pipeline, checked on every golden run (and on re-record).
//
// A golden hash can only say "the output changed"; it was re-recorded over a
// 5x candidate explosion, a 40% drop in resolved calls, a dead platform-channel
// detector and an OOM, because each of those looks like a plain hash change.
// These floors state what a healthy run of the sample looks like, measured on the
// exact-row dispatch reconstruction (typetrack/selector_rows.go). They are loose
// (~15% margins) on purpose: tighten them with measurements, never loosen them to
// make a red build green -- a sample that violates one has a dead or polluted stage.
type metricFloors struct {
	// MinMonomorphicBLR: indirect call sites with exactly one proven callee.
	MinMonomorphicBLR int
	// MaxAvgPolymorphicCandidates: candidates per polymorphic site. Every real
	// dispatch-table row is <= ~170 implementations on these apps; an average
	// above this means unrelated selector rows are being merged (the 576-target
	// Map-literal call).
	MaxAvgPolymorphicCandidates float64
	// MinAnnotatedBLR: share of blr/call_indirect edges with a provenance (`via`).
	MinAnnotatedBLR float64
	// MinPlatformChannels: const channel Instances (framework SystemChannels).
	MinPlatformChannels int
}

var goldenMetricFloors = map[string]metricFloors{
	"compare_sample_arm64": {MinMonomorphicBLR: 950, MaxAvgPolymorphicCandidates: 80, MinAnnotatedBLR: 0.80, MinPlatformChannels: 8},
	"sample312_x64":        {MinMonomorphicBLR: 1150, MaxAvgPolymorphicCandidates: 90, MinAnnotatedBLR: 0.90, MinPlatformChannels: 8},
	"dart212_arm64":        {MinMonomorphicBLR: 1150, MaxAvgPolymorphicCandidates: 70, MinAnnotatedBLR: 0.80, MinPlatformChannels: 5},
	"sample313_arm64":      {MinMonomorphicBLR: 630, MaxAvgPolymorphicCandidates: 80, MinAnnotatedBLR: 0.80, MinPlatformChannels: 8},
}

func assertMetricFloors(t *testing.T, name, outDir string) {
	t.Helper()
	floors, ok := goldenMetricFloors[name]
	if !ok {
		t.Fatalf("golden sample %s has no metric floors: add an entry to goldenMetricFloors", name)
	}

	var report struct {
		BLR struct {
			Monomorphic           int `json:"monomorphic"`
			Polymorphic           int `json:"polymorphic"`
			PolymorphicCandidates int `json:"polymorphic_candidates"`
		} `json:"blr"`
	}
	data, err := os.ReadFile(filepath.Join(outDir, "typetrack_report.json"))
	if err != nil {
		t.Fatalf("metric floors: %v", err)
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("metric floors: parse typetrack_report.json: %v", err)
	}
	if report.BLR.Monomorphic < floors.MinMonomorphicBLR {
		t.Errorf("%s: monomorphic BLR = %d, floor %d (resolution regressed or a stage is dead)", name, report.BLR.Monomorphic, floors.MinMonomorphicBLR)
	}
	if report.BLR.Polymorphic > 0 {
		avg := float64(report.BLR.PolymorphicCandidates) / float64(report.BLR.Polymorphic)
		if avg > floors.MaxAvgPolymorphicCandidates {
			t.Errorf("%s: %.1f candidates per polymorphic site, ceiling %.0f (unrelated selector rows merged?)", name, avg, floors.MaxAvgPolymorphicCandidates)
		}
	}

	indirect, annotated := 0, 0
	scanJSONL(t, filepath.Join(outDir, "call_edges.jsonl"), func(line []byte) {
		var e struct {
			Kind string `json:"kind"`
			Via  string `json:"via"`
		}
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("metric floors: call_edges.jsonl: %v", err)
		}
		if e.Kind == "blr" || e.Kind == "call_indirect" {
			indirect++
			if e.Via != "" {
				annotated++
			}
		}
	})
	if indirect == 0 {
		t.Errorf("%s: no indirect call edges", name)
	} else if share := float64(annotated) / float64(indirect); share < floors.MinAnnotatedBLR {
		t.Errorf("%s: %.1f%% of indirect calls carry provenance, floor %.0f%%", name, 100*share, 100*floors.MinAnnotatedBLR)
	}

	channels := 0
	scanJSONL(t, filepath.Join(outDir, "platform_channels.jsonl"), func([]byte) { channels++ })
	if channels < floors.MinPlatformChannels {
		t.Errorf("%s: %d platform channels, floor %d (const channel detector dead?)", name, channels, floors.MinPlatformChannels)
	}
}

func scanJSONL(t *testing.T, path string, fn func(line []byte)) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("metric floors: %v", err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			fn(sc.Bytes())
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("metric floors: scan %s: %v", path, err)
	}
}
