package naming

import (
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
//
// This is a copy of the same helper in internal/analysis/loadingunit_test.go,
// kept here so naming tests that need a real cluster.Result can load one
// without importing the analysis package (which would create an import cycle
// in test binaries: analysis imports naming, so naming cannot import analysis).
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
	start, err := snapshot.FindClusterDataStart(data)
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
