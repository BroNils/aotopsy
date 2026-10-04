package analysis

import (
	"path/filepath"
	"testing"

	"aotopsy/internal/snapshot"
	"aotopsy/internal/strutil"
	"aotopsy/internal/vmtables"
)

// The meta stage decodes dart_meta.json with DisallowUnknownFields. If the
// writer (strutil.WriteDartMeta) ever emits a key the reader does not list,
// every real run fails at the meta stage even though each side's own unit
// tests pass. Tie the two together.
func TestDartMetaWriterOutputIsAcceptedByMetaStageReader(t *testing.T) {
	dir := t.TempDir()
	profile := snapshot.ProfileForVersion("3.12.2")
	if profile == nil {
		t.Fatal("missing 3.12.2 profile")
	}
	profile.BuildMode = snapshot.BuildProduct
	profile.CompressedPointers = true
	target, ok := vmtables.TargetProfileFromVersion(profile, true)
	if !ok {
		t.Fatal("could not derive exact metadata target")
	}
	if err := strutil.WriteDartMeta(dir, target); err != nil {
		t.Fatal(err)
	}
	dm, err := readJSONBounded[strutil.DartMetaJSON](filepath.Join(dir, "dart_meta.json"), maxMetadataArtifactBytes)
	if err != nil {
		t.Fatalf("meta-stage reader rejected the writer's dart_meta.json: %v", err)
	}
	if dm.Architecture != "arm64" || dm.DartVersion != "3.12.2" || !dm.CompressedPointers || dm.PointerSize != 4 {
		t.Fatalf("round trip lost scalar fields: %+v", dm)
	}
	if len(dm.THRFields) == 0 {
		t.Fatal("round trip lost the exact THR table")
	}
	if got, err := strutil.ValidateDartMeta(dm); err != nil || got != target {
		t.Fatalf("round trip metadata no longer validates: target=%+v err=%v want=%+v", got, err, target)
	}
}
