package elfx

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// sampleWithSymbol returns any corpus sample exporting sym, or skips.
//
// These tests need "a valid Dart ELF", not a particular app, so they select by
// CAPABILITY rather than by name. The name they used to hardcode --
// blutter-lce.so -- was an app codename under a gitignored directory, and it
// drifted onto a different binary without anything noticing (see
// internal/samplecorpus).
//
// Selecting by symbol also keeps them honest across the 3.13.0 format change:
// _kDartVmSnapshotData does not exist there at all, because the four snapshot
// symbols became two and the VM and isolate snapshots became one blob. A
// hardcoded 3.13.0 sample would fail these tests for a reason that has nothing
// to do with the ELF reader.
//
// samplecorpus is deliberately not imported: it imports this package.
func sampleWithSymbol(t *testing.T, sym string) string {
	t.Helper()
	dir, _ := os.Getwd()
	for {
		matches, _ := filepath.Glob(filepath.Join(dir, "samples", "dart-*.so"))
		sort.Strings(matches)
		for _, p := range matches {
			ef, err := Open(p)
			if err != nil {
				continue
			}
			if sym == "" {
				_ = ef.Close()
				return p
			}
			_, _, err = ef.Symbol(sym)
			_ = ef.Close()
			if err == nil {
				return p
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			if sym == "" {
				t.Skip("no samples/dart-*.so present")
			}
			t.Skipf("no samples/dart-*.so exports %s", sym)
		}
		dir = parent
	}
}

// vmSnapshotSym is the symbol these tests use as a known-present one. It is
// absent from Dart 3.13.0+ unified snapshots, which is why selection is by
// capability.
const vmSnapshotSym = "_kDartVmSnapshotData"

func TestOpenValid(t *testing.T) {
	path := sampleWithSymbol(t, vmSnapshotSym)
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
	path := sampleWithSymbol(t, vmSnapshotSym)
	ef, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()

	va, size, err := ef.Symbol(vmSnapshotSym)
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
	path := sampleWithSymbol(t, vmSnapshotSym)
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
	path := sampleWithSymbol(t, vmSnapshotSym)
	ef, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()

	// The first PT_LOAD segment typically has vaddr=0 and offset=0,
	// so VA should equal file offset for addresses in that segment.
	va, _, err := ef.Symbol(vmSnapshotSym)
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
	path := sampleWithSymbol(t, vmSnapshotSym)
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
	path := sampleWithSymbol(t, vmSnapshotSym)
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
		ef.Symbol(vmSnapshotSym)
		ef.VAToFileOffset(0)
		ef.Close()
	})
}

func TestFileCloseClosesUnderlyingFD(t *testing.T) {
	p := sampleWithSymbol(t, "")
	ef, err := Open(p)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	rawFile, ok := ef.raw.(*os.File)
	if !ok {
		t.Fatalf("expected ef.raw to be *os.File")
	}
	fd := rawFile.Fd()
	if err := ef.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	var buf [1]byte
	if _, readErr := rawFile.Read(buf[:]); readErr == nil {
		t.Fatalf("expected Read on closed raw file (fd %d) to fail, but it succeeded", fd)
	}
}
