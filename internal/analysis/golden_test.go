package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"aotopsy/internal/samplecorpus"
)

// Golden output tests.
//
// The existing regression tests assert loose ranges ("50-300 signals",
// "20000-50000 call edges"). Those ranges stayed satisfied while an
// object-pool indexing bug mislabelled EVERY string reference in the output:
// the totals looked reasonable, every individual line was wrong. Aggregates
// cannot catch that class of error -- only the exact bytes can.
//
// So: run the pipeline on a sample and compare a SHA-256 per output file
// against a committed golden record, plus a few readable counts so a failure
// says what moved rather than just "hash differs".
//
// The sample binaries are not in the repo, so each golden record is keyed by
// the SHA-256 of the input binary AND names the corpus sample it was recorded
// from. The sample is resolved through internal/samplecorpus, the same way
// every other sample-driven test finds its input.
//
// It used to be resolved from a per-record environment variable instead, and
// an unset variable skipped. Nobody sets four environment variables, so
// `go test ./internal/...` reported ok while running none of this: on
// 2026-09-01 two records turned out to be failing and two to be keyed to
// binaries that exist nowhere, and the suite had been green throughout. A
// gate that silently does nothing is worse than no gate, so a missing corpus
// sample now fails.
//
// The records themselves ARE in the repo, under testdata/golden/. That is
// what gives this gate teeth: it compares against a baseline someone reviewed
// and committed, not against whatever the pipeline produced a moment ago.
// Recording is therefore explicit -- a missing record fails rather than
// filling itself in.
//
// Four full pipeline runs cost about 80s, so this package no longer fits
// go test's 10-minute default. Pass -timeout 40m when running the whole
// package; -run Golden alone is fine without it.
//
//	go test ./internal/analysis/ -run Golden
//	go test ./internal/analysis/ -count=1 -timeout 40m         # whole package
//	AOTOPSY_UPDATE_GOLDEN=1 ...                                # rewrite records

// goldenFiles are the pipeline outputs covered. Anything derived from the
// snapshot, the disassembly, or type inference belongs here; files carrying
// absolute paths or timings do not.
var goldenFiles = []string{
	"functions.jsonl",
	"call_edges.jsonl",
	"string_refs.jsonl",
	"index.jsonl",
	"unresolved_thr.jsonl",
	"classes.jsonl",
	"dispatch_table.jsonl",
	"field_accessor_xref.jsonl",
	"address_callers_xref.jsonl",
	"string_value_xref.jsonl",
	"pool_immediates.jsonl",
	"typetrack_report.json",
	"native_capabilities.jsonl",
}

type goldenRecord struct {
	Sample      string            `json:"sample"`
	InputSHA256 string            `json:"input_sha256"`
	DartVersion string            `json:"dart_version"`
	FuncCount   int               `json:"func_count"`
	ClassCount  int               `json:"class_count"`
	Lines       map[string]int    `json:"lines"`
	SHA256      map[string]string `json:"sha256"`
}

// goldenSamples maps each record to the corpus sample it covers.
var goldenSamples = []struct{ sample, name string }{
	{"dart-3.9.2-arm64.so", "compare_sample_arm64"},
	{"dart-3.12.2-x64.so", "sample312_x64"},
	// Dart 2.12 exercises a different instructions path entirely
	// (text-offset deltas, no InstructionsTable), which is where the
	// "395 of 7714 functions" bug lived.
	{"dart-2.12.0-arm64.so", "dart212_arm64"},
	// Dart 3.13.0, the unified-snapshot format: one _kDartSnapshotData /
	// _kDartSnapshotText pair instead of the four legacy symbols, and a
	// single snapshot rather than a VM/isolate pair. Worth a golden of its
	// own precisely because nothing else in the corpus exercises that path.
	{"dart-3.13.0-arm64.so", "sample313_arm64"},
}

func TestGoldenPipelineOutput(t *testing.T) {
	for _, s := range goldenSamples {
		t.Run(s.name, func(t *testing.T) { runGolden(t, s.sample, s.name) })
	}
}

func runGolden(t *testing.T, sample, name string) {
	libPath := samplecorpus.Path(sample)
	if libPath == "" {
		t.Fatalf("corpus sample %s is missing; the golden record for %s cannot be checked.\n"+
			"  Restore the sample rather than deleting the record: an unrunnable golden is\n"+
			"  how this gate spent months reporting ok while checking nothing.", sample, name)
	}
	inputHash, err := fileSHA256(libPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", libPath, err)
	}

	goldenPath := filepath.Join("testdata", "golden", name+".json")
	var want goldenRecord
	haveGolden := false
	if data, err := os.ReadFile(goldenPath); err == nil {
		if err := json.Unmarshal(data, &want); err != nil {
			t.Fatalf("parse %s: %v", goldenPath, err)
		}
		haveGolden = true
	}
	update := os.Getenv("AOTOPSY_UPDATE_GOLDEN") != ""
	// A missing record is a failure, not an invitation to write one.
	//
	// This used to auto-record and pass, which combined with the records
	// being gitignored meant the gate could never fail anywhere it mattered:
	// a fresh clone or a CI checkout has no records, so every sample recorded
	// whatever the pipeline happened to produce and reported success. The
	// records are committed now; creating one is an explicit act.
	if !haveGolden && !update {
		t.Fatalf("no golden record at %s\n"+
			"  The records are committed to the repo, so a missing one means either a\n"+
			"  newly added sample or a deleted file -- not something to fill in silently.\n"+
			"  To record it deliberately: AOTOPSY_UPDATE_GOLDEN=1 go test ./internal/analysis/ -run Golden\n"+
			"  then review the new file before committing it.", goldenPath)
	}
	// A record whose input hash no longer matches the corpus sample it names
	// is unrunnable, and unrunnable used to mean skip. Two of the four
	// records had drifted that way and the gate reported nothing for both.
	// Fail: either the sample was replaced (re-record deliberately) or the
	// record names the wrong sample (fix the mapping).
	if haveGolden && !update && want.InputSHA256 != inputHash {
		t.Fatalf("corpus sample %s does not match the golden record for %s\n"+
			"  golden input: %s\n  actual input: %s\n"+
			"  Re-record deliberately with AOTOPSY_UPDATE_GOLDEN=1 and review the diff,\n"+
			"  or point goldenSamples at the sample the record was made from.",
			sample, name, want.InputSHA256, inputHash)
	}

	outDir := t.TempDir()
	result, err := Run(Opts{
		LibPath:  libPath,
		OutDir:   outDir,
		Quiet:    true,
		Signal:   false, // signal output embeds host paths; the JSONL above is the contract
		MaxSteps: 100000,
	})
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}

	got := goldenRecord{
		Sample:      name,
		InputSHA256: inputHash,
		DartVersion: result.DartVersion,
		FuncCount:   result.FuncCount,
		ClassCount:  result.ClassCount,
		Lines:       map[string]int{},
		SHA256:      map[string]string{},
	}
	for _, f := range goldenFiles {
		p := filepath.Join(outDir, f)
		data, err := os.ReadFile(p)
		if err != nil {
			continue // not every sample produces every file
		}
		sum := sha256.Sum256(data)
		got.SHA256[f] = hex.EncodeToString(sum[:])
		got.Lines[f] = strings.Count(string(data), "\n")
	}

	if update {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		data, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		if !haveGolden {
			t.Logf("recorded new golden file %s (%d outputs)", goldenPath, len(got.SHA256))
		} else {
			t.Logf("updated %s", goldenPath)
		}
		return
	}

	if got.DartVersion != want.DartVersion {
		t.Errorf("dart version: got %s, want %s", got.DartVersion, want.DartVersion)
	}
	if got.FuncCount != want.FuncCount {
		t.Errorf("function count: got %d, want %d", got.FuncCount, want.FuncCount)
	}
	if got.ClassCount != want.ClassCount {
		t.Errorf("class count: got %d, want %d", got.ClassCount, want.ClassCount)
	}

	names := make([]string, 0, len(want.SHA256))
	for f := range want.SHA256 {
		names = append(names, f)
	}
	sort.Strings(names)
	for _, f := range names {
		gotSum, present := got.SHA256[f]
		if !present {
			t.Errorf("%s: not produced any more (golden has %d lines)", f, want.Lines[f])
			continue
		}
		if gotSum == want.SHA256[f] {
			continue
		}
		t.Errorf("%s: content changed\n  golden sha256 %s (%d lines)\n  actual sha256 %s (%d lines)\n"+
			"  If this change is intended, rerun with AOTOPSY_UPDATE_GOLDEN=1 and review the diff.",
			f, want.SHA256[f], want.Lines[f], gotSum, got.Lines[f])
	}
	for f := range got.SHA256 {
		if _, present := want.SHA256[f]; !present {
			t.Errorf("%s: newly produced (%d lines) -- re-record the golden file", f, got.Lines[f])
		}
	}
}

// TestGoldenOutputIsDeterministic runs the pipeline twice on the same input
// and requires identical bytes.
//
// The golden records above are only meaningful if the pipeline is
// reproducible: map iteration order leaking into a JSONL file would make them
// fail at random and train everyone to re-record instead of investigating.
func TestGoldenOutputIsDeterministic(t *testing.T) {
	libPath := samplecorpus.Path("dart-3.9.2-arm64.so")
	if libPath == "" {
		t.Fatal("corpus sample dart-3.9.2-arm64.so is missing; determinism is unchecked without it")
	}
	sums := make([]map[string]string, 2)
	for run := 0; run < 2; run++ {
		outDir := t.TempDir()
		if _, err := Run(Opts{LibPath: libPath, OutDir: outDir, Quiet: true, MaxSteps: 100000}); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		sums[run] = map[string]string{}
		for _, f := range goldenFiles {
			data, err := os.ReadFile(filepath.Join(outDir, f))
			if err != nil {
				continue
			}
			sum := sha256.Sum256(data)
			sums[run][f] = hex.EncodeToString(sum[:])
		}
	}
	for f, a := range sums[0] {
		if b := sums[1][f]; a != b {
			t.Errorf("%s differs between two runs of the same binary (%s vs %s) -- "+
				"something in the pipeline depends on map iteration order", f, a, b)
		}
	}
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}
