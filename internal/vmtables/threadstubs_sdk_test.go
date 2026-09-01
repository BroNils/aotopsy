package vmtables

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
)

// TestThreadStubOffsetsMatchSDK runs `go run tools/extract_thr.go
// -check-stub-offsets`, which re-derives every Thread-cached stub offset
// from dart-lang/sdk -- the field name and the stub name both come from
// thread.h's CACHED_ADDRESSES_LIST, the offset from
// runtime_offsets_extracted.h -- and diffs it against the tables in
// threadstubs.go.
//
// This gate did not exist until 2026-09, and its absence is the whole
// story of the bug it found: five tables (2.17.6, 3.0.5/3.2.5, 3.4.3,
// 3.6.2) were each missing the same four entries -- MegamorphicCall,
// SwitchableCallMiss, OptimizeFunction, Deoptimize -- 20 offsets across
// 10 (version, arch) pairs.
//
// Nothing local could catch it, because a missing offset is not a wrong
// annotation, it is an absent one: the call still resolves and prints
// "THR.f248" instead of "THR.MegamorphicCall". The file's own comments
// asserted the four stubs "did not yet exist as Thread-cached stubs in
// 2.17.6" and "were added in 3.7.0"; both were false, and a comment is
// not a gate.
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/vmtables/ -run ThreadStubOffsetsMatchSDK
func TestThreadStubOffsetsMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	out, err := runStubOffsetCheck()
	t.Logf("extract_thr -check-stub-offsets output:\n%s", out)
	if err != nil {
		t.Fatalf("ThreadStubOffsets disagrees with the Dart SDK: %v\n"+
			"A MISSING line means the committed table is short, which downstream reads as\n"+
			"an unnamed THR.fNN call rather than as an error. Do not silence it by trimming\n"+
			"the target list -- add the offsets.", err)
	}
}

// TestThreadStubTargetsCoverSupportedVersions keeps the gate honest: a
// version that ThreadStubOffsets answers for but stubOffsetTargets never
// probes is unverified, and unverified is the state the whole file was
// in. The list lives in the tool, so this checks the other direction --
// every version the switch handles must be a version the tool knows.
func TestThreadStubTargetsCoverSupportedVersions(t *testing.T) {
	supported := []string{
		"2.17.6", "3.0.5", "3.2.5", "3.4.3", "3.6.2",
		"3.7.0", "3.9.2", "3.10.7", "3.11.0", "3.12.2", "3.13.0",
	}
	for _, v := range supported {
		for _, arm := range []bool{true, false} {
			if ThreadStubOffsets(v, arm) == nil {
				t.Errorf("ThreadStubOffsets(%q, arm64=%v) = nil, but the version is listed as supported", v, arm)
			}
		}
	}
	// The deliberate nil for anything else must hold: borrowing a
	// neighbour's offsets is how a whole table ends up shifted.
	for _, v := range []string{"", "2.11.0", "3.14.0", "nonsense"} {
		if ThreadStubOffsets(v, true) != nil {
			t.Errorf("ThreadStubOffsets(%q) returned a table, want nil", v)
		}
	}
}

// TestThreadStubTablesAreInjective is a local invariant needing no
// network: two offsets naming the same stub means an entry was pasted at
// the wrong displacement, which silently steals the real one's name.
func TestThreadStubTablesAreInjective(t *testing.T) {
	for _, v := range []string{
		"2.17.6", "3.0.5", "3.2.5", "3.4.3", "3.6.2",
		"3.7.0", "3.9.2", "3.10.7", "3.11.0", "3.12.2", "3.13.0",
	} {
		tbl := ThreadStubOffsets(v, true)
		seen := map[string]int64{}
		for off, name := range tbl {
			if prev, dup := seen[name]; dup {
				t.Errorf("%s: stub %q appears at both 0x%x and 0x%x", v, name, prev, off)
			}
			seen[name] = off
		}
	}
}

// runStubOffsetCheck runs the extractor from the repo root.
func runStubOffsetCheck() ([]byte, error) {
	cmd := exec.Command("go", "run", "tools/extract_thr.go", "-check-stub-offsets")
	cmd.Dir = ".."
	if wd, err := os.Getwd(); err == nil {
		cmd.Dir = strings.TrimSuffix(filepath.ToSlash(wd), "/internal/vmtables")
	}
	return cmd.CombinedOutput()
}
