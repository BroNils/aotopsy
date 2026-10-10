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

func sourceSinkRefs(n int) []disasm.StringRefRecord {
	refs := make([]disasm.StringRefRecord, 0, 2*n)
	for i := 0; i < n; i++ {
		fn := fmt.Sprintf("f%05d", i)
		refs = append(refs,
			disasm.StringRefRecord{Func: fn, Value: "imei"},
			disasm.StringRefRecord{Func: fn, Value: "firebase"})
	}
	return refs
}

func readSourceSinkSummary(t *testing.T, dir string) SourceSinkSummary {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, SourceSinkSummaryFile))
	if err != nil {
		t.Fatal(err)
	}
	s, err := jsonutil.DecodeStrictObject[SourceSinkSummary](b)
	if err != nil {
		t.Fatalf("summary: %v\n%s", err, b)
	}
	return s
}

// Exceeding the budget used to fail the whole analysis. It must keep the
// findings it has, say so explicitly, and do so identically on every run.
func TestSourceSinkBudgetTruncatesExplicitlyAndDeterministically(t *testing.T) {
	refs := sourceSinkRefs(10_050) // one same-function proximity finding each: over the 10,000 cap
	var files [2][]byte
	for run := range files {
		dir := t.TempDir()
		if err := WriteSourceSinkFindings(dir, nil, refs, nil); err != nil {
			t.Fatalf("budget overflow failed the stage: %v", err)
		}
		s := readSourceSinkSummary(t, dir)
		if !s.Truncated || s.Findings != 10_000 || s.Reason == "" {
			t.Fatalf("summary = %+v, want truncated at 10000 with a reason", s)
		}
		b, err := os.ReadFile(filepath.Join(dir, "source_sink_findings.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		files[run] = b
	}
	if !bytes.Equal(files[0], files[1]) {
		t.Fatal("truncated source/sink output differs between runs")
	}
}

func TestSourceSinkSummaryReportsCompleteRun(t *testing.T) {
	dir := t.TempDir()
	if err := WriteSourceSinkFindings(dir, nil, sourceSinkRefs(3), nil); err != nil {
		t.Fatal(err)
	}
	if s := readSourceSinkSummary(t, dir); s.Truncated || s.Findings != 3 {
		t.Fatalf("summary = %+v, want complete with 3 findings", s)
	}
}
