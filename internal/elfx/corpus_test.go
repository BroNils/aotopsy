package elfx_test

import (
	"errors"
	"testing"

	"aotopsy/internal/elfx"
	"aotopsy/internal/samplecorpus"
)

const legacyVMSnapshotSymbol = "_kDartVmSnapshotData"

// corpusSampleWithSymbol selects by capability from the central registry. A
// checkout with no corpus may skip; once samples/ exists, completeness and any
// malformed/mislabelled candidate are failures rather than reasons to keep
// walking until a convenient file happens to work.
func corpusSampleWithSymbol(t *testing.T, sym string) string {
	t.Helper()
	if err := samplecorpus.RequireCompleteCorpus(); err != nil {
		if errors.Is(err, samplecorpus.ErrNoCorpus) {
			t.Skip("no samples/ directory in this checkout")
		}
		t.Fatalf("sample corpus is incomplete or inconsistent: %v", err)
	}
	for _, s := range samplecorpus.Registry {
		path, err := samplecorpus.RequireSample(s.FileName())
		if err != nil {
			t.Fatalf("resolve %s: %v", s.FileName(), err)
		}
		ef, err := elfx.Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", s.FileName(), err)
		}
		if sym == "" {
			_ = ef.Close()
			return path
		}
		_, _, symErr := ef.DynamicSnapshotSymbol(sym)
		_ = ef.Close()
		if symErr == nil {
			return path
		}
	}
	t.Fatalf("complete registered corpus has no sample exporting %s", sym)
	return ""
}

func TestCorpusOpenValid(t *testing.T) {
	path := corpusSampleWithSymbol(t, legacyVMSnapshotSymbol)
	ef, err := elfx.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ef.Close() }()
	if ef.FileSize() == 0 {
		t.Error("file size is 0")
	}
}

func TestCorpusSymbolLookup(t *testing.T) {
	path := corpusSampleWithSymbol(t, legacyVMSnapshotSymbol)
	ef, err := elfx.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ef.Close() }()
	va, size, err := ef.DynamicSnapshotSymbol(legacyVMSnapshotSymbol)
	if err != nil {
		t.Fatal(err)
	}
	if va == 0 || size == 0 {
		t.Fatalf("snapshot symbol has invalid va=%#x size=%#x", va, size)
	}
}

func TestCorpusSymbolNotFound(t *testing.T) {
	path := corpusSampleWithSymbol(t, legacyVMSnapshotSymbol)
	ef, err := elfx.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ef.Close() }()
	if _, _, err := ef.DynamicSnapshotSymbol("_kNonExistentSymbol"); err == nil {
		t.Fatal("expected error for missing symbol")
	}
}

func TestCorpusVAToFileOffset(t *testing.T) {
	path := corpusSampleWithSymbol(t, legacyVMSnapshotSymbol)
	ef, err := elfx.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ef.Close() }()
	va, _, err := ef.DynamicSnapshotSymbol(legacyVMSnapshotSymbol)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ef.VAToFileOffset(va); err != nil {
		t.Fatal(err)
	}
}

func TestCorpusVAToFileOffsetInvalid(t *testing.T) {
	path := corpusSampleWithSymbol(t, legacyVMSnapshotSymbol)
	ef, err := elfx.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ef.Close() }()
	if _, err := ef.VAToFileOffset(0xDEADBEEFDEADBEEF); err == nil {
		t.Fatal("expected error for invalid VA")
	}
}

func TestCorpusLoadSegments(t *testing.T) {
	path := corpusSampleWithSymbol(t, legacyVMSnapshotSymbol)
	ef, err := elfx.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ef.Close() }()
	segs := ef.LoadSegments()
	if len(segs) == 0 {
		t.Fatal("no PT_LOAD segments")
	}
	for _, s := range segs {
		if s.Filesz == 0 && s.Memsz == 0 {
			t.Error("segment with zero size")
		}
	}
}
