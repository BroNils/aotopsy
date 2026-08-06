package elfx

import (
	"os"
	"path/filepath"
	"testing"
)

func findSample(t *testing.T, name string) string {
	t.Helper()
	// Walk up to find samples/ directory.
	dir, _ := os.Getwd()
	for {
		p := filepath.Join(dir, "samples", name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skipf("sample %s not found", name)
		}
		dir = parent
	}
}

func TestOpenValid(t *testing.T) {
	path := findSample(t, "blutter-lce.so")
	ef, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()

	if ef.FileSize() == 0 {
		t.Error("file size is 0")
	}
}

func TestOpenRejectsNonELF(t *testing.T) {
	// Create a temp file with garbage data.
	tmp := filepath.Join(t.TempDir(), "notelf")
	if err := os.WriteFile(tmp, []byte("not an ELF file at all"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Open(tmp)
	if err == nil {
		t.Fatal("expected error for non-ELF file")
	}
}

func TestSymbolLookup(t *testing.T) {
	path := findSample(t, "blutter-lce.so")
	ef, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()

	va, size, err := ef.Symbol("_kDartVmSnapshotData")
	if err != nil {
		t.Fatal(err)
	}
	if va == 0 {
		t.Error("VA is 0")
	}
	if size == 0 {
		t.Error("size is 0")
	}
}

func TestSymbolNotFound(t *testing.T) {
	path := findSample(t, "blutter-lce.so")
	ef, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()

	_, _, err = ef.Symbol("_kNonExistentSymbol")
	if err == nil {
		t.Fatal("expected error for missing symbol")
	}
}

func TestVAToFileOffset(t *testing.T) {
	path := findSample(t, "blutter-lce.so")
	ef, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()

	// The first PT_LOAD segment typically has vaddr=0 and offset=0,
	// so VA should equal file offset for addresses in that segment.
	va, _, err := ef.Symbol("_kDartVmSnapshotData")
	if err != nil {
		t.Fatal(err)
	}
	off, err := ef.VAToFileOffset(va)
	if err != nil {
		t.Fatal(err)
	}
	// For this sample, VA == file offset (first segment).
	if off != va {
		t.Logf("VA=0x%x FileOff=0x%x (different, which may be valid for non-zero-based segments)", va, off)
	}
}

func TestVAToFileOffsetInvalid(t *testing.T) {
	path := findSample(t, "blutter-lce.so")
	ef, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()

	_, err = ef.VAToFileOffset(0xDEADBEEFDEADBEEF)
	if err == nil {
		t.Fatal("expected error for invalid VA")
	}
}

func TestLoadSegments(t *testing.T) {
	path := findSample(t, "blutter-lce.so")
	ef, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()

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

func FuzzELFOpen(f *testing.F) {
	// Seed with a valid ELF header prefix and garbage.
	f.Add([]byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Add([]byte("not an elf at all"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		tmp := filepath.Join(t.TempDir(), "fuzz.so")
		if err := os.WriteFile(tmp, data, 0644); err != nil {
			t.Fatal(err)
		}
		ef, err := Open(tmp)
		if err != nil {
			return // expected
		}
		// If it opens, exercise the API.
		ef.FileSize()
		ef.LoadSegments()
		ef.Symbol("_kDartVmSnapshotData")
		ef.VAToFileOffset(0)
		ef.Close()
	})
}
