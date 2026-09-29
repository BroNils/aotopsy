package signal

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"aotopsy/internal/disasm"
	"aotopsy/internal/jsonutil"
)

func taintRefs(n int) []disasm.StringRefRecord {
	refs := make([]disasm.StringRefRecord, 0, 2*n)
	for i := 0; i < n; i++ {
		fn := fmt.Sprintf("f%05d", i)
		refs = append(refs,
			disasm.StringRefRecord{Func: fn, Value: "imei"},
			disasm.StringRefRecord{Func: fn, Value: "firebase"})
	}
	return refs
}

func readTaintSummary(t *testing.T, dir string) TaintSummary {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, TaintSummaryFile))
	if err != nil {
		t.Fatal(err)
	}
	s, err := jsonutil.DecodeStrictObject[TaintSummary](b)
	if err != nil {
		t.Fatalf("summary: %v\n%s", err, b)
	}
	return s
}

// Exceeding the budget used to fail the whole analysis. It must keep the
// findings it has, say so explicitly, and do so identically on every run.
func TestTaintBudgetTruncatesExplicitlyAndDeterministically(t *testing.T) {
	refs := taintRefs(10_050) // one same-function flow each: over the 10,000 cap
	var files [2][]byte
	for run := range files {
		dir := t.TempDir()
		if err := WriteTaintFindings(dir, refs, nil); err != nil {
			t.Fatalf("budget overflow failed the stage: %v", err)
		}
		s := readTaintSummary(t, dir)
		if !s.Truncated || s.Findings != 10_000 || s.Reason == "" {
			t.Fatalf("summary = %+v, want truncated at 10000 with a reason", s)
		}
		b, err := os.ReadFile(filepath.Join(dir, "taint_findings.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		files[run] = b
	}
	if !bytes.Equal(files[0], files[1]) {
		t.Fatal("truncated taint output differs between runs")
	}
}

func TestTaintSummaryReportsCompleteRun(t *testing.T) {
	dir := t.TempDir()
	if err := WriteTaintFindings(dir, taintRefs(3), nil); err != nil {
		t.Fatal(err)
	}
	if s := readTaintSummary(t, dir); s.Truncated || s.Findings != 3 {
		t.Fatalf("summary = %+v, want complete with 3 findings", s)
	}
}
