package disasm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
)

// TestTHRTablesMatchSDK runs `go run tools/extract_thr.go -check`, which
// re-extracts every Thread offset table from dart-lang/sdk's
// runtime_offsets_extracted.h and diffs it against the tables committed in
// thrfields.go / thrfieldsx86.go (now in internal/vmtables/).
//
// These tables cannot be validated by local testing: a wrong offset produces
// a plausible-looking annotation ("THR.allocate_object_stub") that is simply
// the wrong field, and nothing downstream can tell. The only ground truth is
// the SDK header that the offsets came from.
//
// Network- and gh-dependent, so it is opt-in:
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/disasm/ -run THRTablesMatchSDK
func TestTHRTablesMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	out, err := runSDKCheck("-check")
	t.Logf("extract_thr -check output:\n%s", out)
	if err != nil {
		t.Fatalf("THR tables disagree with the Dart SDK headers: %v\n"+
			"Run `go run tools/extract_thr.go -write && gofmt -w internal/vmtables/` to regenerate,\n"+
			"then review the diff before committing.", err)
	}
}

// TestObjectStoreFieldCountsMatchSDK checks every version profile's
// ObjectStoreAOTFieldCount against object_store.h.
//
// That number is the count of roots an AOT snapshot writes before the
// dispatch table (ProgramSerializationRoots::WriteRoots, from() ..
// to_snapshot(kFullAOT) inclusive). One off, and the stream desynchronises
// exactly at the dispatch table: it parses as garbage and BLR resolution
// drops to zero with no other symptom.
func TestObjectStoreFieldCountsMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	out, err := runSDKCheck("-check-objectstore")
	t.Logf("extract_thr -check-objectstore output:\n%s", out)
	if err != nil {
		t.Fatalf("ObjectStoreAOTFieldCount disagrees with the Dart SDK: %v", err)
	}
}

// runSDKCheck runs the extractor from the repo root with the given mode.
func runSDKCheck(mode string) ([]byte, error) {
	cmd := exec.Command("go", "run", "tools/extract_thr.go", mode)
	cmd.Dir = ".."
	if wd, err := os.Getwd(); err == nil {
		// internal/disasm -> repo root
		cmd.Dir = strings.TrimSuffix(filepath.ToSlash(wd), "/internal/disasm")
	}
	return cmd.CombinedOutput()
}
