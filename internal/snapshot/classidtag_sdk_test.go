package snapshot

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
)

// TestClassIdTagLayoutMatchesSDK re-derives the ClassIdTag bitfield layout
// from dart-lang/sdk for every supported version and diffs it against
// ClassIdTagLayout, by running the project's generator in check mode.
//
// This constant had no gate. The Thread fields, stub names, stub offsets,
// runtime entries, object-store field count and roots prefix all have one;
// the bit position that decides how every object header's class id is read
// did not, despite being a hand-written version boundary of exactly the shape
// that has been wrong four times here (AGENTS-local's cross-version
// differential table: the roots section, IsType for the scalar era, a
// hardcoded TypeClassIDShift, and the 2.19.0 stub/THR tables).
//
// It delegates rather than parsing the SDK itself, for the reason the Thread
// field gate learned the hard way: a second parser is a second thing to be
// wrong, and it will be wrong about the versions the first one handles.
// Three declaration shapes exist across the range and extract_thr knows all
// three.
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/snapshot/ -run ClassIdTagLayoutMatchesSDK
func TestClassIdTagLayoutMatchesSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	out, err := runClassIdTagCheck()
	t.Logf("extract_thr -check-classid-tag output:\n%s", out)
	if err != nil {
		t.Fatalf("committed ClassIdTag layout disagrees with the Dart SDK: %v\n\n"+
			"ClassIdTagLayout is the single source for this fact -- fill_strings.go\n"+
			"and typetrack both read it. If the SDK moved the field, change it there\n"+
			"and nowhere else; three separate predicates for this one fact is the\n"+
			"state this function was introduced to end.", err)
	}
	if !strings.Contains(string(out), "matches SDK for all") {
		t.Fatalf("gate did not report a clean run:\n%s", out)
	}
}

// TestClassIdTagLayoutBoundary pins the boundary itself without needing the
// network, so a plain `go test ./...` still fails if someone moves it.
func TestClassIdTagLayoutBoundary(t *testing.T) {
	for _, tc := range []struct {
		version   string
		pos, size int
	}{
		{"2.10.0", 16, 16},
		{"2.17.6", 16, 16},
		{"2.18.0", 16, 16}, // last half-word version
		{"2.19.0", 12, 20}, // first 20-bit version
		{"3.0.5", 12, 20},
		{"3.13.0", 12, 20},
	} {
		pos, size := ClassIdTagLayout(tc.version)
		if pos != tc.pos || size != tc.size {
			t.Errorf("ClassIdTagLayout(%s) = (%d, %d), want (%d, %d)",
				tc.version, pos, size, tc.pos, tc.size)
		}
	}
}

func runClassIdTagCheck() ([]byte, error) {
	cmd := exec.Command("go", "run", "tools/extract_thr.go", "-check-classid-tag")
	cmd.Dir = ".."
	if wd, err := os.Getwd(); err == nil {
		cmd.Dir = strings.TrimSuffix(filepath.ToSlash(wd), "/internal/snapshot")
	}
	return cmd.CombinedOutput()
}
