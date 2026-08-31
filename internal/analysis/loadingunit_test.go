package analysis

import (
	"os"
	"testing"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/snapshot"
)

// clusterOnly runs just the front half of the pipeline: ELF -> snapshot ->
// cluster alloc -> fill. It deliberately skips disassembly, which is the
// expensive stage, so these tests can run against very large libapp.so files
// (tens of MB) without the memory cost of a full Run.
func clusterOnly(t *testing.T, libPath string) *cluster.Result {
	t.Helper()
	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}
	ef, err := elfx.Open(libPath)
	if err != nil {
		t.Fatalf("open %s: %v", libPath, err)
	}
	defer func() { _ = ef.Close() }()

	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if info.Version == nil || !info.Version.Supported {
		t.Skipf("unsupported snapshot version in %s", libPath)
	}
	data := info.IsolateData.Data
	start, err := cluster.FindClusterDataStart(data)
	if err != nil {
		t.Fatalf("find cluster start: %v", err)
	}
	res, err := cluster.ScanClusters(data, start, info.Version, false, opts)
	if err != nil {
		t.Fatalf("scan clusters: %v", err)
	}
	// snapshotSize must be the header's TotalSize, NOT len(data). It is what
	// locates the ROData image, so passing len(data) silently disables every
	// ROData-backed capture (strings and PcDescriptors on non-compressed
	// builds) while leaving compressed-pointer samples looking fine, because
	// those route strings through FillString instead.
	var snapshotSize int64
	if info.IsolateHeader != nil {
		snapshotSize = info.IsolateHeader.TotalSize
	}
	if err := cluster.ReadFill(data, res, info.Version, false, snapshotSize); err != nil {
		t.Fatalf("read fill: %v", err)
	}
	return res
}

// TestPartitionCodesByLoadingUnit_Degenerate pins the behaviour on an app with
// no deferred imports, which is every sample in this project's corpus: exactly
// one root unit, every Code in the main bucket, nothing deferred, and
// Degenerate set so callers do not present a one-bucket split as a finding.
func TestPartitionCodesByLoadingUnit_Degenerate(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_ARM64")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_ARM64 not set")
	}
	res := clusterOnly(t, libPath)

	part := PartitionCodesByLoadingUnit(res)
	if part.UnitCount != 1 {
		t.Errorf("UnitCount = %d, want 1", part.UnitCount)
	}
	if part.RootUnitID != 1 {
		t.Errorf("RootUnitID = %d, want 1 (Dart numbers the base unit 1)", part.RootUnitID)
	}
	if len(part.MainCodeRefs) == 0 {
		t.Error("no main codes attributed to the root unit")
	}
	if len(part.DeferredCodeRefs) != 0 {
		t.Errorf("DeferredCodeRefs = %d, want 0 for an app without deferred imports",
			len(part.DeferredCodeRefs))
	}
	if !part.Degenerate {
		t.Error("Degenerate = false; a single unit with no deferred codes carries no information")
	}
	// Every Code must land in exactly one bucket.
	if got, want := len(part.MainCodeRefs)+len(part.DeferredCodeRefs), len(res.Codes); got != want {
		t.Errorf("partition covers %d codes, but there are %d", got, want)
	}
	// UnitOf must agree with the buckets.
	unit, deferred, found := part.UnitOf(part.MainCodeRefs[0])
	if !found || deferred || unit != part.RootUnitID {
		t.Errorf("UnitOf(main code) = (%d, %v, %v), want (%d, false, true)",
			unit, deferred, found, part.RootUnitID)
	}
	if _, _, found := part.UnitOf(-12345); found {
		t.Error("UnitOf reported found=true for a ref that is not a Code")
	}
}

// TestPartitionCodesByLoadingUnit_LargeApp exercises the partition on a real,
// much larger production app than the synthetic samples. Set
// AOTOPSY_TEST_SAMPLE_LARGE to any libapp.so.
//
// It asserts self-consistency rather than fixed counts, and reports whether the
// app actually uses deferred imports -- the non-degenerate path stays unproven
// until a split-AOT sample (app.so + app-N.part.so) is available, and this test
// is where that would be checked.
func TestPartitionCodesByLoadingUnit_LargeApp(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_LARGE")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_LARGE not set")
	}
	res := clusterOnly(t, libPath)

	part := PartitionCodesByLoadingUnit(res)
	t.Logf("units=%d root_id=%d main_codes=%d deferred_codes=%d degenerate=%v",
		part.UnitCount, part.RootUnitID, len(part.MainCodeRefs),
		len(part.DeferredCodeRefs), part.Degenerate)

	if part.UnitCount == 0 {
		t.Skip("no LoadingUnit cluster in this snapshot")
	}
	if part.RootUnitID == 0 {
		t.Error("no root unit found (no LoadingUnit with a null parent)")
	}
	if got, want := len(part.MainCodeRefs)+len(part.DeferredCodeRefs), len(res.Codes); got != want {
		t.Errorf("partition covers %d codes, but there are %d", got, want)
	}
	if part.Degenerate != (part.UnitCount <= 1 && len(part.DeferredCodeRefs) == 0) {
		t.Error("Degenerate disagrees with the unit/deferred counts")
	}
}
