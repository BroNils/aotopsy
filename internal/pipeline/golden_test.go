package pipeline

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
// the SHA-256 of the input binary. Pointing the env var at a different
// libapp.so skips (never fails) with a clear message -- a different input is
// not a regression.
//
//	AOTOPSY_TEST_SAMPLE_ARM64=... go test ./internal/pipeline/ -run Golden
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

func TestGoldenPipelineOutput(t *testing.T) {
	samples := []struct{ env, name string }{
		{"AOTOPSY_TEST_SAMPLE_ARM64", "compare_sample_arm64"},
		{"AOTOPSY_TEST_SAMPLE_312_X64", "sample312_x64"},
	}
	for _, s := range samples {
		t.Run(s.name, func(t *testing.T) { runGolden(t, s.env, s.name) })
	}
}

func runGolden(t *testing.T, env, name string) {
	libPath := os.Getenv(env)
	if libPath == "" {
		t.Skipf("%s not set", env)
	}
	inputHash, err := fileSHA256(libPath)
	if err != nil {
		t.Skipf("cannot read %s: %v", libPath, err)
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
	if haveGolden && !update && want.InputSHA256 != inputHash {
		t.Skipf("%s points at a different binary than the golden record\n"+
			"  golden input: %s\n  actual input: %s\n"+
			"  (not a regression -- rerun with AOTOPSY_UPDATE_GOLDEN=1 to re-record)",
			env, want.InputSHA256, inputHash)
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

	if update || !haveGolden {
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
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_ARM64")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_ARM64 not set")
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
