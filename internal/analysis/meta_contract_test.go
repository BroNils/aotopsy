package analysis

import (
	"path/filepath"
	"testing"

	"aotopsy/internal/strutil"
)

// The meta stage decodes dart_meta.json with DisallowUnknownFields. If the
// writer (strutil.WriteDartMeta) ever emits a key the reader does not list,
// every real run fails at the meta stage even though each side's own unit
// tests pass. Tie the two together.
func TestDartMetaWriterOutputIsAcceptedByMetaStageReader(t *testing.T) {
	dir := t.TempDir()
	thr := map[int]string{0x20: "top_resource", 0x38: "stack_limit"}
	if err := strutil.WriteDartMeta(dir, "3.12.2", "arm64", true, 4, thr); err != nil {
		t.Fatal(err)
	}
	dm, err := readJSONBounded[dartMetaFile](filepath.Join(dir, "dart_meta.json"), maxMetadataArtifactBytes)
	if err != nil {
		t.Fatalf("meta-stage reader rejected the writer's dart_meta.json: %v", err)
	}
	if dm.Architecture != "arm64" || dm.DartVersion != "3.12.2" || !dm.CompressedPointers || dm.PointerSize != 4 {
		t.Fatalf("round trip lost scalar fields: %+v", dm)
	}
	if len(dm.THRFields) != 2 || dm.THRFields[0].Offset != 0x20 || dm.THRFields[0].Name != "top_resource" {
		t.Fatalf("round trip lost THR fields: %+v", dm.THRFields)
	}
}
