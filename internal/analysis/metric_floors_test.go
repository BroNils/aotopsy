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
	// MinResolvedSites: sites the analysis said anything about (monomorphic +
	// polymorphic). Unlike MinMonomorphicBLR this does not depend on how often a
	// row is narrowed to one callee, so it stays a stable "is the stage alive"
	// signal: the selector-election change moved ~25% of sites from monomorphic
	// to polymorphic and left this total unchanged (3.9.2: 3905 before and after).
	MinResolvedSites int
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

// MinMonomorphicBLR CHANGED MEANING with the proven-row selector election
// (typetrack/selector_rows.go ownerRowComplete): the earlier floors (950 / 1150 /
// 1150 / 630) counted single answers that came out of a most-frequent-leaf vote,
// and that vote contained the true callee at only 30 of 91 (3.9.2) and 31 of 64
// (2.12.0) sites where a receiver bound gives an independent answer -- most of
// those "monomorphic" sites were confidently wrong (`Object.==`,
// `PointerEvent.get:pointer`). They are now candidate sets, which is why the count
// fell (x64 1350 -> 639). The new floors are the measured values with ~15% margin
// and still catch a dead stage; they are NOT a licence to loosen a floor to get a
// red build green. The ceiling on candidates per polymorphic site is untouched and
// still passes.
var goldenMetricFloors = map[string]metricFloors{
	"compare_sample_arm64": {MinMonomorphicBLR: 665, MinResolvedSites: 3300, MaxAvgPolymorphicCandidates: 80, MinAnnotatedBLR: 0.80, MinPlatformChannels: 8},
	"sample312_x64":        {MinMonomorphicBLR: 540, MinResolvedSites: 3250, MaxAvgPolymorphicCandidates: 90, MinAnnotatedBLR: 0.90, MinPlatformChannels: 8},
	"dart212_arm64":        {MinMonomorphicBLR: 665, MinResolvedSites: 3900, MaxAvgPolymorphicCandidates: 70, MinAnnotatedBLR: 0.80, MinPlatformChannels: 5},
	"sample313_arm64":      {MinMonomorphicBLR: 320, MinResolvedSites: 3100, MaxAvgPolymorphicCandidates: 80, MinAnnotatedBLR: 0.80, MinPlatformChannels: 8},
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
	if resolved := report.BLR.Monomorphic + report.BLR.Polymorphic; resolved < floors.MinResolvedSites {
		t.Errorf("%s: %d resolved indirect sites (monomorphic + polymorphic), floor %d (a resolution stage is dead)", name, resolved, floors.MinResolvedSites)
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
