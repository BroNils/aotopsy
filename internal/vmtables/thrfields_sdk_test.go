package vmtables

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
)

// TestThreadFieldNamesMatchSDK re-derives every committed Thread field
// table from dart-lang/sdk and diffs it against what is in the tree, by
// running the project's own generator in check mode.
//
// It delegates rather than parsing runtime_offsets_extracted.h itself.
// The first version of this gate re-implemented that parsing, and the
// duplicate was immediately worse than the original: it understood the
// section-guard shape used from 3.0.5 onwards and not the older one, so
// it covered 13 of the 23 versions THRFields answers for -- silently,
// since a version simply absent from its list looks like a passing test.
// extract_thr already handles all 23. One parser, one answer.
//
// What this guards against is not a missing name -- that renders as an
// unnamed THR.fNN and says so -- but a wrong one: a version aliased to a
// neighbour's table after the SDK inserted a field gets every later
// offset named after its neighbour, reported with exactly the confidence
// of a correct answer. Four tables were in that state before this gate
// existed, and one of them was introduced by the fix for the other three.
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/vmtables/ -run ThreadFieldNamesMatchSDK
func TestThreadFieldNamesMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	out, err := runThreadFieldCheck()
	t.Logf("extract_thr -check output:\n%s", out)
	if err != nil {
		t.Fatalf("committed Thread field tables disagree with the Dart SDK: %v\n\n"+
			"Regenerate rather than hand-editing: `go run tools/extract_thr.go -write`.\n"+
			"Hand-correcting a table is how the wb_wrapper block came to sit at its\n"+
			"neighbour's offsets -- the SDK exports it as an array\n"+
			"(AOT_Thread_write_barrier_wrappers_thread_offset[]), which a\n"+
			"single-constant scan does not see, so a partial correction looks complete.", err)
	}
	if !strings.Contains(string(out), "0 with problems") {
		t.Fatalf("extract_thr -check did not report a clean run:\n%s", out)
	}
}

func runThreadFieldCheck() ([]byte, error) {
	cmd := exec.Command("go", "run", "tools/extract_thr.go", "-check")
	cmd.Dir = ".."
	if wd, err := os.Getwd(); err == nil {
		cmd.Dir = strings.TrimSuffix(filepath.ToSlash(wd), "/internal/vmtables")
	}
	return cmd.CombinedOutput()
}
