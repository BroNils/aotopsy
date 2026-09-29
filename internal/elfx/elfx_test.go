package elfx

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
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

func TestSHA256UsesOpenedFileNotReplacedPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not allow renaming this fixture while the opened descriptor lacks delete sharing")
	}
	p := writeELF64SymbolFixture(t, elf.SHT_DYNSYM, make([]byte, elf.Sym64Size), []byte("\x00"))
	original, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	ef, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()

	// Replace the pathname with a different inode after Open. The already-open
	// descriptor must remain the provenance source.
	oldPath := p + ".opened"
	if err := os.Rename(p, oldPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("replacement bytes that are not an ELF"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ef.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	wantSum := sha256.Sum256(original)
	want := hex.EncodeToString(wantSum[:])
	if got != want {
		t.Fatalf("SHA256 after path replacement = %s, want opened-file hash %s", got, want)
	}
}

func TestSHA256RejectsShortBackingReader(t *testing.T) {
	f := &File{raw: bytes.NewReader([]byte("short")), size: 32}
	if sum, err := f.SHA256(); err == nil {
		t.Fatalf("SHA256 on truncated backing reader returned %q without error", sum)
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

func TestVAToFileOffsetRejectsOverflowingProgramHeader(t *testing.T) {
	f := &File{
		ELF: &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
			Type: elf.PT_LOAD, Vaddr: 0, Memsz: math.MaxUint64, Off: math.MaxUint64 - 10,
		}}}},
		size: 128,
	}
	if off, err := f.VAToFileOffset(20); err == nil {
		t.Fatalf("overflowing PT_LOAD mapped VA to wrapped file offset %#x", off)
	}
}

func TestVAToFileOffsetRejectsBSSOnlyAddress(t *testing.T) {
	f := &File{
		ELF: &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
			Type: elf.PT_LOAD, Vaddr: 0x1000, Memsz: 8, Filesz: 4, Off: 0,
		}}}},
		size: 16,
	}
	if off, err := f.VAToFileOffset(0x1006); err == nil {
		t.Fatalf("BSS-only VA mapped to file offset %#x", off)
	}
}

func TestReadBytesAtVARejectsNegativeLength(t *testing.T) {
	data := []byte{1, 2, 3, 4}
	f := &File{
		ELF: &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
			Type: elf.PT_LOAD, Vaddr: 0x1000, Memsz: uint64(len(data)), Off: 0, Filesz: uint64(len(data)),
		}}}},
		raw:  bytes.NewReader(data),
		size: int64(len(data)),
	}
	if _, err := f.ReadBytesAtVA(0x1000, -1); err == nil {
		t.Fatal("ReadBytesAtVA accepted negative length")
	}
}

func TestReadBytesAtVAIsExactWithinSegment(t *testing.T) {
	data := []byte{1, 2, 3, 4, 9, 9, 9, 9}
	f := &File{
		ELF: &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
			Type: elf.PT_LOAD, Vaddr: 0x1000, Memsz: 4, Filesz: 4, Off: 0,
		}}}},
		raw:  bytes.NewReader(data),
		size: int64(len(data)),
	}
	if got, err := f.ReadBytesAtVA(0x1002, 4); err == nil {
		t.Fatalf("cross-segment exact read succeeded with %v", got)
	}
}

func TestReadBytesAtVARejectsTruncatedBackingFile(t *testing.T) {
	data := []byte{1, 2, 3, 4}
	f := &File{
		ELF: &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
			Type: elf.PT_LOAD, Vaddr: 0x1000, Memsz: 8, Filesz: 8, Off: 0,
		}}}},
		raw:  bytes.NewReader(data),
		size: int64(len(data)),
	}
	if got, err := f.ReadBytesAtVA(0x1000, 8); err == nil {
		t.Fatalf("truncated backing file returned %v without error", got)
	}
}

type shortReaderAt struct{ data []byte }

func (r shortReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	// Deliberately violate the usual ReaderAt behavior by returning a short
	// read with nil error. elfx must still reject the incomplete result.
	n := copy(p, r.data[off:min(int64(len(r.data)), off+2)])
	return n, nil
}

func TestReadBytesAtVARejectsShortReaderAt(t *testing.T) {
	f := &File{
		ELF: &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
			Type: elf.PT_LOAD, Vaddr: 0x1000, Memsz: 4, Filesz: 4, Off: 0,
		}}}},
		raw:  shortReaderAt{data: []byte{1, 2, 3, 4}},
		size: 4,
	}
	if got, err := f.ReadBytesAtVA(0x1000, 4); err == nil {
		t.Fatalf("short ReaderAt returned fabricated complete data %v", got)
	}
}

func TestVAToFileOffsetContinuesPastOverlappingBSS(t *testing.T) {
	f := &File{
		ELF: &elf.File{Progs: []*elf.Prog{
			{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Vaddr: 0x1000, Memsz: 0x100, Filesz: 0x10, Off: 0}},
			{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Vaddr: 0x1080, Memsz: 0x80, Filesz: 0x80, Off: 0x80}},
		}},
		size: 0x200,
	}
	if got, err := f.VAToFileOffset(0x1088); err != nil || got != 0x88 {
		t.Fatalf("overlapping file-backed LOAD mapping = %#x,%v; want %#x,nil", got, err, 0x88)
	}
}

func TestOpenRejectsBigEndianELF(t *testing.T) {
	// Minimal ELF64 ET_DYN AArch64 header; no program/section table needed for
	// debug/elf.NewFile to parse the identity/header fields.
	b := make([]byte, 64)
	copy(b[:4], []byte{0x7f, 'E', 'L', 'F'})
	b[4], b[5], b[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2MSB), 1
	binary.BigEndian.PutUint16(b[16:], uint16(elf.ET_DYN))
	binary.BigEndian.PutUint16(b[18:], uint16(elf.EM_AARCH64))
	binary.BigEndian.PutUint32(b[20:], 1)
	binary.BigEndian.PutUint16(b[52:], 64)
	p := filepath.Join(t.TempDir(), "be.so")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p); !errors.Is(err, ErrNotLittleEndian) {
		t.Fatalf("Open(big-endian) = %v, want ErrNotLittleEndian", err)
	}
}

func TestOpenRejectsSectionExtentBeyondEOF(t *testing.T) {
	p := writeELF64SymbolFixture(t, elf.SHT_SYMTAB, make([]byte, elf.Sym64Size), []byte("\x00"))
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// Section 1 is the linked string table. Move its file offset beyond EOF;
	// debug/elf records this lazily, so elfx must compare it to the real file.
	const stringSectionHeader = 64 + 64
	binary.LittleEndian.PutUint64(b[stringSectionHeader+24:], uint64(len(b))+1)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p); !errors.Is(err, ErrNotELF) {
		t.Fatalf("Open(section beyond EOF) = %v, want ErrNotELF", err)
	}
}

func TestOpenRejectsMalformedLoadExtent(t *testing.T) {
	makeFixture := func(t *testing.T, off, filesz, memsz uint64) string {
		t.Helper()
		const (
			ehSize = 64
			phSize = 56
		)
		b := make([]byte, ehSize+phSize)
		copy(b[:4], []byte{0x7f, 'E', 'L', 'F'})
		b[4], b[5], b[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1
		binary.LittleEndian.PutUint16(b[16:], uint16(elf.ET_DYN))
		binary.LittleEndian.PutUint16(b[18:], uint16(elf.EM_AARCH64))
		binary.LittleEndian.PutUint32(b[20:], 1)
		binary.LittleEndian.PutUint64(b[32:], ehSize)
		binary.LittleEndian.PutUint16(b[52:], ehSize)
		binary.LittleEndian.PutUint16(b[54:], phSize)
		binary.LittleEndian.PutUint16(b[56:], 1)
		ph := b[ehSize:]
		binary.LittleEndian.PutUint32(ph[0:], uint32(elf.PT_LOAD))
		binary.LittleEndian.PutUint64(ph[8:], off)
		binary.LittleEndian.PutUint64(ph[32:], filesz)
		binary.LittleEndian.PutUint64(ph[40:], memsz)
		p := filepath.Join(t.TempDir(), "load.so")
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("outside-file", func(t *testing.T) {
		if _, err := Open(makeFixture(t, 0x1000, 0x10, 0x10)); !errors.Is(err, ErrNotELF) {
			t.Fatalf("Open(PT_LOAD beyond EOF) = %v, want ErrNotELF", err)
		}
	})
	t.Run("filesz-greater-than-memsz", func(t *testing.T) {
		if _, err := Open(makeFixture(t, 0, 64, 32)); !errors.Is(err, ErrNotELF) {
			t.Fatalf("Open(PT_LOAD filesz > memsz) = %v, want ErrNotELF", err)
		}
	})
}

func writeELF64SymbolFixture(t *testing.T, typ elf.SectionType, symbolData, stringData []byte) string {
	t.Helper()
	const (
		ehSize = 64
		shSize = 64
		shNum  = 3
	)
	shoff := uint64(ehSize)
	strOff := uint64(ehSize + shSize*shNum)
	symOff := strOff + uint64(len(stringData))
	buf := make([]byte, int(symOff)+len(symbolData))
	copy(buf[:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4], buf[5], buf[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1
	binary.LittleEndian.PutUint16(buf[16:], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(buf[18:], uint16(elf.EM_AARCH64))
	binary.LittleEndian.PutUint32(buf[20:], 1)
	binary.LittleEndian.PutUint64(buf[40:], shoff)
	binary.LittleEndian.PutUint16(buf[52:], ehSize)
	binary.LittleEndian.PutUint16(buf[58:], shSize)
	binary.LittleEndian.PutUint16(buf[60:], shNum)

	// Section 1: string table.
	sh1 := buf[ehSize+shSize : ehSize+2*shSize]
	binary.LittleEndian.PutUint32(sh1[4:], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(sh1[24:], strOff)
	binary.LittleEndian.PutUint64(sh1[32:], uint64(len(stringData)))
	binary.LittleEndian.PutUint64(sh1[48:], 1)

	// Section 2: symbol table linked to section 1.
	sh2 := buf[ehSize+2*shSize : ehSize+3*shSize]
	binary.LittleEndian.PutUint32(sh2[4:], uint32(typ))
	binary.LittleEndian.PutUint64(sh2[24:], symOff)
	binary.LittleEndian.PutUint64(sh2[32:], uint64(len(symbolData)))
	binary.LittleEndian.PutUint32(sh2[40:], 1)
	binary.LittleEndian.PutUint64(sh2[48:], 8)
	binary.LittleEndian.PutUint64(sh2[56:], elf.Sym64Size)

	copy(buf[strOff:], stringData)
	copy(buf[symOff:], symbolData)
	p := filepath.Join(t.TempDir(), "symbols.so")
	if err := os.WriteFile(p, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func makeSym64(name uint32, info byte, shndx uint16, value, size uint64) []byte {
	b := make([]byte, elf.Sym64Size)
	binary.LittleEndian.PutUint32(b[0:], name)
	b[4] = info
	binary.LittleEndian.PutUint16(b[6:], shndx)
	binary.LittleEndian.PutUint64(b[8:], value)
	binary.LittleEndian.PutUint64(b[16:], size)
	return b
}

func TestSymbolSkipsUndefinedImportAndFindsDefinedDuplicate(t *testing.T) {
	strs := []byte("\x00_kDartSnapshotData\x00")
	symData := make([]byte, elf.Sym64Size) // null symbol
	nameOff := uint32(1)
	symData = append(symData, makeSym64(nameOff, byte(elf.STB_GLOBAL)<<4|byte(elf.STT_OBJECT), uint16(elf.SHN_UNDEF), 0, 0)...)
	symData = append(symData, makeSym64(nameOff, byte(elf.STB_GLOBAL)<<4|byte(elf.STT_OBJECT), 1, 0x1234, 0x80)...)
	p := writeELF64SymbolFixture(t, elf.SHT_DYNSYM, symData, strs)
	f, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	va, size, err := f.Symbol("_kDartSnapshotData")
	if err != nil || va != 0x1234 || size != 0x80 {
		t.Fatalf("Symbol chose undefined import or failed duplicate lookup: va=%#x size=%#x err=%v", va, size, err)
	}
}

func TestFuncSymbolsSurfacesMalformedSymtab(t *testing.T) {
	// 25 bytes is deliberately not a multiple of the 24-byte ELF64 symbol
	// record size. This must be corruption, not "stripped".
	p := writeELF64SymbolFixture(t, elf.SHT_SYMTAB, make([]byte, elf.Sym64Size+1), []byte("\x00name\x00"))
	f, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if syms, err := f.FuncSymbols(); err == nil {
		t.Fatalf("malformed .symtab returned success/stripped: %#v", syms)
	}
}

func TestSymbolTablesRejectZeroLengthSectionsBeforeDebugELF(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  elf.SectionType
		call func(*File) error
	}{
		{"dynsym-lookup", elf.SHT_DYNSYM, func(f *File) error { _, _, err := f.Symbol("x"); return err }},
		{"dynsym-all", elf.SHT_DYNSYM, func(f *File) error { _, err := f.DynamicSymbols(); return err }},
		{"symtab-functions", elf.SHT_SYMTAB, func(f *File) error { _, err := f.FuncSymbols(); return err }},
		{"symtab-all", elf.SHT_SYMTAB, func(f *File) error { _, err := f.Symbols(); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := writeELF64SymbolFixture(t, tc.typ, nil, []byte("\x00"))
			f, err := Open(p)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := tc.call(f); err == nil {
				t.Fatal("zero-length symbol table was accepted")
			}
		})
	}
}

func TestSymbolTablesRejectZeroEntrySize(t *testing.T) {
	p := writeELF64SymbolFixture(t, elf.SHT_SYMTAB, make([]byte, elf.Sym64Size), []byte("\x00"))
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture's symbol table is section 2. In an ELF64 section header,
	// sh_entsize is the uint64 at offset 56.
	const symbolSectionHeader = 64 + 2*64
	binary.LittleEndian.PutUint64(b[symbolSectionHeader+56:], 0)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if syms, err := f.Symbols(); err == nil {
		t.Fatalf("zero sh_entsize returned success: %#v", syms)
	}
}

func TestValidateSymbolTableUsesPhysicalFileSize(t *testing.T) {
	strs := &elf.Section{SectionHeader: elf.SectionHeader{
		Type: elf.SHT_STRTAB, Offset: 80, Size: 1024, FileSize: 8,
	}}
	syms := &elf.Section{SectionHeader: elf.SectionHeader{
		Type: elf.SHT_SYMTAB, Offset: 64, Size: elf.Sym64Size, FileSize: elf.Sym64Size,
		Link: 1, Entsize: elf.Sym64Size,
	}}
	f := &File{ELF: &elf.File{Sections: []*elf.Section{{}, strs, syms}}, size: 128}
	if present, err := f.validateSymbolTable(elf.SHT_SYMTAB, ".symtab"); err != nil || !present {
		t.Fatalf("compressed-size metadata validation = %v,%v; want true,nil", present, err)
	}

	strs.FileSize = 64
	if _, err := f.validateSymbolTable(elf.SHT_SYMTAB, ".symtab"); err == nil {
		t.Fatal("string table physical extent beyond backing file was accepted")
	}
}

func TestFuncSymbolsSkipsUndefinedFunctions(t *testing.T) {
	strs := []byte("\x00missing\x00")
	symData := make([]byte, elf.Sym64Size)
	symData = append(symData, makeSym64(1, byte(elf.STB_GLOBAL)<<4|byte(elf.STT_FUNC), uint16(elf.SHN_UNDEF), 0x1234, 8)...)
	p := writeELF64SymbolFixture(t, elf.SHT_SYMTAB, symData, strs)
	f, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	syms, err := f.FuncSymbols()
	if err != nil {
		t.Fatal(err)
	}
	if len(syms) != 0 {
		t.Fatalf("undefined STT_FUNC leaked into function symbols: %#v", syms)
	}
}

func TestFuncSymbolsSkipsReservedSectionIndexes(t *testing.T) {
	strs := []byte("\x00absolute\x00")
	symData := make([]byte, elf.Sym64Size)
	symData = append(symData, makeSym64(1, byte(elf.STB_GLOBAL)<<4|byte(elf.STT_FUNC), uint16(elf.SHN_ABS), 0x1234, 8)...)
	p := writeELF64SymbolFixture(t, elf.SHT_SYMTAB, symData, strs)
	f, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	syms, err := f.FuncSymbols()
	if err != nil {
		t.Fatalf("valid SHN_ABS function symbol was treated as malformed: %v", err)
	}
	if syms != nil {
		t.Fatalf("reserved-index function leaked into executable function map: %#v", syms)
	}
}

func TestFuncSymbolsStrippedIsNotError(t *testing.T) {
	// A valid ELF with only a .dynsym has no static .symtab.
	strs := []byte("\x00dyn\x00")
	symData := append(make([]byte, elf.Sym64Size), makeSym64(1, byte(elf.STB_GLOBAL)<<4|byte(elf.STT_OBJECT), 1, 0x1000, 8)...)
	p := writeELF64SymbolFixture(t, elf.SHT_DYNSYM, symData, strs)
	f, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if syms, err := f.FuncSymbols(); err != nil || syms != nil {
		t.Fatalf("stripped FuncSymbols = %#v,%v; want nil,nil", syms, err)
	}
}
