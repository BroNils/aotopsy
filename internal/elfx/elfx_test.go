package elfx

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// vmSnapshotSym is a legacy snapshot symbol used by synthetic/fuzz fixtures.
const vmSnapshotSym = "_kDartVmSnapshotData"

func TestSHA256FailsClosedWhenOpenedPathIsReplaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not allow renaming this fixture while the opened descriptor lacks delete sharing")
	}
	p := writeELF64SymbolFixture(t, elf.SHT_DYNSYM, make([]byte, elf.Sym64Size), []byte("\x00"))
	ef, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()

	// Replacing the pathname mutates filesystem metadata for the opened inode on
	// Unix (ctime), even though the descriptor still refers to the old bytes.
	// Fingerprinting treats any such post-Open mutation as a stability failure:
	// returning no identity is safer than proving which metadata-only changes are
	// harmless while trying to catch same-size writes with restored mtime.
	oldPath := p + ".opened"
	if err := os.Rename(p, oldPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("replacement bytes that are not an ELF"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got, err := ef.SHA256(); !errors.Is(err, ErrChanged) || got != "" {
		t.Fatalf("SHA256 after path replacement = %q,%v; want empty + ErrChanged", got, err)
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
		ef.DynamicSnapshotSymbol(vmSnapshotSym)
		ef.VAToFileOffset(0)
		ef.Close()
	})
}

func TestFileCloseClosesUnderlyingFD(t *testing.T) {
	p := writeELF64SymbolFixture(t, elf.SHT_DYNSYM, make([]byte, elf.Sym64Size), []byte("\x00"))
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
		elfFile: &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
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
		elfFile: &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
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
		elfFile: &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
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
		elfFile: &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
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
		elfFile: &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
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
		elfFile: &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
			Type: elf.PT_LOAD, Vaddr: 0x1000, Memsz: 4, Filesz: 4, Off: 0,
		}}}},
		raw:  shortReaderAt{data: []byte{1, 2, 3, 4}},
		size: 4,
	}
	if got, err := f.ReadBytesAtVA(0x1000, 4); err == nil {
		t.Fatalf("short ReaderAt returned fabricated complete data %v", got)
	}
}

func TestVAToFileOffsetRejectsOverlappingBSSAlias(t *testing.T) {
	f := &File{
		elfFile: &elf.File{Progs: []*elf.Prog{
			{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Vaddr: 0x1000, Memsz: 0x100, Filesz: 0x10, Off: 0}},
			{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Vaddr: 0x1080, Memsz: 0x80, Filesz: 0x80, Off: 0x80}},
		}},
		size: 0x200,
	}
	if got, err := f.VAToFileOffset(0x1088); err == nil {
		t.Fatalf("overlapping BSS/file-backed LOAD mapped VA to %#x", got)
	}
}

func TestVAToFileOffsetRejectsAmbiguousFileBackedAlias(t *testing.T) {
	f := &File{
		elfFile: &elf.File{Progs: []*elf.Prog{
			{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Vaddr: 0x1000, Memsz: 0x100, Filesz: 0x100, Off: 0}},
			{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Vaddr: 0x1080, Memsz: 0x80, Filesz: 0x80, Off: 0x180}},
		}},
		size: 0x400,
	}
	if off, err := f.VAToFileOffset(0x1088); err == nil {
		t.Fatalf("ambiguous PT_LOAD aliases mapped VA to %#x", off)
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
	if _, err := Open(p); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Open(section beyond EOF) = %v, want ErrMalformed", err)
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
		if _, err := Open(makeFixture(t, 0x1000, 0x10, 0x10)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("Open(PT_LOAD beyond EOF) = %v, want ErrMalformed", err)
		}
	})
	t.Run("filesz-greater-than-memsz", func(t *testing.T) {
		if _, err := Open(makeFixture(t, 0, 64, 32)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("Open(PT_LOAD filesz > memsz) = %v, want ErrMalformed", err)
		}
	})
	t.Run("huge-memory-claim", func(t *testing.T) {
		if _, err := Open(makeFixture(t, 0, 0, maxLoadMemoryBytes+1)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("Open(huge PT_LOAD memsz) = %v, want ErrMalformed", err)
		}
	})
	t.Run("virtual-extent-overflow", func(t *testing.T) {
		p := makeFixture(t, 0, 0, 16)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		binary.LittleEndian.PutUint64(b[64+16:], math.MaxUint64-7)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(p); !errors.Is(err, ErrMalformed) {
			t.Fatalf("Open(overflowing PT_LOAD virtual extent) = %v, want ErrMalformed", err)
		}
	})
}

func TestOpenRejectsOverlappingLoadMemory(t *testing.T) {
	const (
		ehSize = 64
		phSize = 56
	)
	b := make([]byte, ehSize+2*phSize)
	copy(b[:4], []byte{0x7f, 'E', 'L', 'F'})
	b[4], b[5], b[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1
	binary.LittleEndian.PutUint16(b[16:], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(b[18:], uint16(elf.EM_AARCH64))
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint64(b[32:], ehSize)
	binary.LittleEndian.PutUint16(b[52:], ehSize)
	binary.LittleEndian.PutUint16(b[54:], phSize)
	binary.LittleEndian.PutUint16(b[56:], 2)
	for i, ph := range [][]byte{b[ehSize : ehSize+phSize], b[ehSize+phSize : ehSize+2*phSize]} {
		binary.LittleEndian.PutUint32(ph[0:], uint32(elf.PT_LOAD))
		binary.LittleEndian.PutUint32(ph[4:], uint32(elf.PF_R))
		binary.LittleEndian.PutUint64(ph[8:], uint64(i*64))
		binary.LittleEndian.PutUint64(ph[32:], 32)
	}
	first := b[ehSize : ehSize+phSize]
	second := b[ehSize+phSize : ehSize+2*phSize]
	binary.LittleEndian.PutUint64(first[16:], 0x1000)
	binary.LittleEndian.PutUint64(first[40:], 0x100)
	binary.LittleEndian.PutUint64(second[16:], 0x1080)
	binary.LittleEndian.PutUint64(second[40:], 0x80)
	p := filepath.Join(t.TempDir(), "overlap.so")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if f, err := Open(p); !errors.Is(err, ErrMalformed) {
		if f != nil {
			_ = f.Close()
		}
		t.Fatalf("Open(overlapping PT_LOAD memory) = %v, want ErrMalformed", err)
	}
}

func TestOpenRejectsExcessiveSectionCountBeforeParsingTables(t *testing.T) {
	const (
		ehSize = 64
		shSize = 64
		shNum  = 4097
	)
	b := make([]byte, ehSize+shSize*shNum)
	copy(b[:4], []byte{0x7f, 'E', 'L', 'F'})
	b[4], b[5], b[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1
	binary.LittleEndian.PutUint16(b[16:], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(b[18:], uint16(elf.EM_AARCH64))
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint64(b[40:], ehSize)
	binary.LittleEndian.PutUint16(b[52:], ehSize)
	binary.LittleEndian.PutUint16(b[58:], shSize)
	binary.LittleEndian.PutUint16(b[60:], shNum)
	p := filepath.Join(t.TempDir(), "too-many-sections.so")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if ef, err := Open(p); err == nil {
		_ = ef.Close()
		t.Fatal("ELF with excessive section count was accepted")
	}
}

func TestOpenRejectsSectionNameAllocationAmplificationBeforeDebugELF(t *testing.T) {
	const (
		ehSize  = 64
		shSize  = 64
		shNum   = 4096
		nameLen = 3000
	)
	shoff := uint64(ehSize)
	strOff := uint64(ehSize + shSize*shNum)
	strs := make([]byte, nameLen+2)
	for i := 1; i <= nameLen; i++ {
		strs[i] = 'A'
	}
	buf := make([]byte, int(strOff)+len(strs))
	copy(buf[:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4], buf[5], buf[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1
	binary.LittleEndian.PutUint16(buf[16:], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(buf[18:], uint16(elf.EM_AARCH64))
	binary.LittleEndian.PutUint32(buf[20:], 1)
	binary.LittleEndian.PutUint64(buf[40:], shoff)
	binary.LittleEndian.PutUint16(buf[52:], ehSize)
	binary.LittleEndian.PutUint16(buf[58:], shSize)
	binary.LittleEndian.PutUint16(buf[60:], shNum)
	binary.LittleEndian.PutUint16(buf[62:], 1)

	// Section 1 is the shstrtab. Thousands of later sections deliberately point
	// at the same long string. debug/elf would allocate one copy per section;
	// preflight must cap that amplification before NewFile is called.
	for i := 1; i < shNum; i++ {
		sh := buf[ehSize+i*shSize : ehSize+(i+1)*shSize]
		binary.LittleEndian.PutUint32(sh[0:], 1)
	}
	shstr := buf[ehSize+shSize : ehSize+2*shSize]
	binary.LittleEndian.PutUint32(shstr[4:], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(shstr[24:], strOff)
	binary.LittleEndian.PutUint64(shstr[32:], uint64(len(strs)))
	copy(buf[strOff:], strs)

	p := filepath.Join(t.TempDir(), "section-name-amplification.so")
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	if f, err := Open(p); !errors.Is(err, ErrMalformed) {
		if f != nil {
			_ = f.Close()
		}
		t.Fatalf("Open(section-name allocation amplification) = %v, want ErrMalformed", err)
	}
}

func TestDWARFRejectsLegacyZdebugWithoutDecompression(t *testing.T) {
	f := &File{elfFile: &elf.File{Sections: []*elf.Section{{
		SectionHeader: elf.SectionHeader{Name: ".zdebug_info", Type: elf.SHT_PROGBITS, Size: 16, FileSize: 16},
	}}}}
	if _, err := f.DWARF(); err == nil {
		t.Fatal("DWARF accepted legacy .zdebug section whose expanded size is not bounded by ELF metadata")
	}
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
	data := make([]byte, 0x200)
	f := &File{
		elfFile: &elf.File{
			Sections: []*elf.Section{{}, {SectionHeader: elf.SectionHeader{Type: elf.SHT_PROGBITS, Flags: elf.SHF_ALLOC, Addr: 0x1200, Size: 0x100}}},
			Progs:    []*elf.Prog{{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Vaddr: 0x1200, Memsz: 0x100, Filesz: 0x100, Off: 0}}},
		},
		raw: bytes.NewReader(data), size: int64(len(data)), dynsymPresent: true,
		dynsym: []elf.Symbol{
			{Name: "_kDartSnapshotData", Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_OBJECT), Section: elf.SHN_UNDEF},
			{Name: "_kDartSnapshotData", Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_OBJECT), Section: 1, Value: 0x1234, Size: 0x40},
		},
	}
	va, size, err := f.DynamicSnapshotSymbol("_kDartSnapshotData")
	if err != nil || va != 0x1234 || size != 0x40 {
		t.Fatalf("Symbol chose undefined import or failed duplicate lookup: va=%#x size=%#x err=%v", va, size, err)
	}
}

func TestDynamicSnapshotSymbolAcceptsSDKFuncAndObjectTypes(t *testing.T) {
	for _, typ := range []elf.SymType{elf.STT_FUNC, elf.STT_OBJECT} {
		t.Run(typ.String(), func(t *testing.T) {
			data := make([]byte, 0x100)
			f := &File{
				elfFile: &elf.File{
					Sections: []*elf.Section{{}, {SectionHeader: elf.SectionHeader{Type: elf.SHT_PROGBITS, Flags: elf.SHF_ALLOC, Addr: 0x2000, Size: 0x100}}},
					Progs:    []*elf.Prog{{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Vaddr: 0x2000, Memsz: 0x100, Filesz: 0x100, Off: 0}}},
				},
				raw: bytes.NewReader(data), size: int64(len(data)), dynsymPresent: true,
				dynsym: []elf.Symbol{{
					Name: "_kDartVmSnapshotData", Info: byte(elf.STB_GLOBAL)<<4 | byte(typ),
					Section: 1, Value: 0x2020, Size: 0x40,
				}},
			}
			va, size, err := f.DynamicSnapshotSymbol("_kDartVmSnapshotData")
			if err != nil || va != 0x2020 || size != 0x40 {
				t.Fatalf("SDK snapshot symbol type %s rejected: va=%#x size=%#x err=%v", typ, va, size, err)
			}
		})
	}
}

func TestFuncSymbolsPreservesZeroSizeAddressZeroAndChoosesStableAlias(t *testing.T) {
	data := make([]byte, 0x100)
	f := &File{
		elfFile: &elf.File{
			Sections: []*elf.Section{{}, {SectionHeader: elf.SectionHeader{Type: elf.SHT_PROGBITS, Flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, Addr: 0, Size: 0x100}}},
			Progs:    []*elf.Prog{{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Vaddr: 0, Memsz: 0x100, Filesz: 0x100, Off: 0}}},
		},
		raw: bytes.NewReader(data), size: int64(len(data)), symtabPresent: true,
		symtab: []elf.Symbol{
			{Name: "zeta", Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC), Section: 1, Value: 0, Size: 0},
			{Name: "alpha", Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC), Section: 1, Value: 0, Size: 0},
		},
	}
	got, err := f.FuncSymbols()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "alpha" {
		t.Fatalf("zero-size address-zero aliases = %#v, want deterministic alpha at VA 0", got)
	}
}

func TestFuncSymbolsAllowsZeroSizeTerminalLabel(t *testing.T) {
	data := make([]byte, 0x100)
	f := &File{
		elfFile: &elf.File{
			Sections: []*elf.Section{{}, {SectionHeader: elf.SectionHeader{Type: elf.SHT_PROGBITS, Flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, Addr: 0x4000, Size: 0x100}}},
			Progs:    []*elf.Prog{{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Vaddr: 0x4000, Memsz: 0x100, Filesz: 0x100, Off: 0}}},
		},
		raw: bytes.NewReader(data), size: int64(len(data)), symtabPresent: true,
		symtab: []elf.Symbol{{
			Name: "terminal", Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC), Section: 1, Value: 0x4100, Size: 0,
		}},
	}
	got, err := f.FuncSymbols()
	if err != nil {
		t.Fatalf("valid terminal zero-size function label rejected: %v", err)
	}
	if got[0x4100] != "terminal" {
		t.Fatalf("terminal zero-size function label missing: %#v", got)
	}
}

func TestOpenRejectsOverlongSymbolName(t *testing.T) {
	strs := append([]byte{0}, bytes.Repeat([]byte{'A'}, int(maxSymbolNameBytes)+1)...)
	strs = append(strs, 0)
	symData := append(make([]byte, elf.Sym64Size), makeSym64(1, byte(elf.STB_GLOBAL)<<4|byte(elf.STT_OBJECT), uint16(elf.SHN_UNDEF), 0, 0)...)
	p := writeELF64SymbolFixture(t, elf.SHT_DYNSYM, symData, strs)
	if f, err := Open(p); !errors.Is(err, ErrMalformed) {
		if f != nil {
			_ = f.Close()
		}
		t.Fatalf("Open(overlong symbol name) = %v, want ErrMalformed", err)
	}
}

func TestOpenRejectsCompressedSymbolTable(t *testing.T) {
	p := writeELF64SymbolFixture(t, elf.SHT_SYMTAB, make([]byte, elf.Sym64Size), []byte("\x00"))
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	const symbolSectionHeader = 64 + 2*64
	binary.LittleEndian.PutUint64(b[symbolSectionHeader+8:], uint64(elf.SHF_COMPRESSED))
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if f, err := Open(p); !errors.Is(err, ErrMalformed) {
		if f != nil {
			_ = f.Close()
		}
		t.Fatalf("Open(compressed .symtab) = %v, want ErrMalformed", err)
	}
}

func TestOpenedFileDetectsInPlaceMutation(t *testing.T) {
	p := writeELF64SymbolFixture(t, elf.SHT_DYNSYM, make([]byte, elf.Sym64Size), []byte("\x00"))
	f, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	w, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("platform does not allow concurrent fixture mutation: %v", err)
	}
	if _, err := w.WriteAt([]byte{0x7e}, int64(before.Size()-1)); err != nil {
		_ = w.Close()
		t.Skipf("platform does not allow in-place fixture mutation: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	forced := before.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(p, forced, forced); err != nil {
		t.Fatal(err)
	}
	if _, err := f.SHA256(); !errors.Is(err, ErrChanged) {
		t.Fatalf("SHA256 after in-place mutation = %v, want ErrChanged", err)
	}
}

func TestOpenedFileDetectsMutationAfterMtimeRestoreWhenCtimeAvailable(t *testing.T) {
	p := writeELF64SymbolFixture(t, elf.SHT_DYNSYM, make([]byte, elf.Sym64Size), []byte("\x00"))
	f, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	of, ok := f.raw.(*os.File)
	if !ok {
		t.Fatal("opened fixture is not backed by *os.File")
	}
	beforeSec, beforeNsec, beforeHasChange := fileChangeTime(of, before)
	if !beforeHasChange {
		t.Skip("filesystem does not expose a ctime/change-time token through os.FileInfo")
	}
	w, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteAt([]byte{0x7e}, int64(before.Size()-1)); err != nil {
		_ = w.Close()
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	afterSec, afterNsec, afterHasChange := fileChangeTime(of, after)
	if !afterHasChange || (beforeSec == afterSec && beforeNsec == afterNsec) {
		t.Skip("filesystem did not expose a changed ctime after fixture mutation")
	}
	if _, err := f.SHA256(); !errors.Is(err, ErrChanged) {
		t.Fatalf("SHA256 after mutation + mtime restore = %v, want ErrChanged", err)
	}
}

func TestExecutableSectionsIgnoreUnmappedExecFlaggedSection(t *testing.T) {
	data := make([]byte, 0x40)
	f := &File{
		elfFile: &elf.File{Sections: []*elf.Section{{
			SectionHeader: elf.SectionHeader{
				Name: ".dead-code", Type: elf.SHT_PROGBITS, Flags: elf.SHF_EXECINSTR,
				Addr: 0x9000, Offset: 0, Size: uint64(len(data)), FileSize: uint64(len(data)),
			},
		}}},
		raw: bytes.NewReader(data), size: int64(len(data)),
	}
	sections, err := f.ExecutableSections(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(sections) != 0 {
		t.Fatalf("unmapped SHF_EXECINSTR section became production code: %+v", sections)
	}
}

func TestFuncSymbolsSurfacesMalformedSymtab(t *testing.T) {
	// 25 bytes is deliberately not a multiple of the 24-byte ELF64 symbol
	// record size. This must be corruption, not "stripped".
	p := writeELF64SymbolFixture(t, elf.SHT_SYMTAB, make([]byte, elf.Sym64Size+1), []byte("\x00name\x00"))
	if f, err := Open(p); err == nil {
		_ = f.Close()
		t.Fatal("malformed .symtab crossed the Open trust boundary")
	}
}

func TestOpenRejectsMalformedPresentSymtabAtTrustBoundary(t *testing.T) {
	p := writeELF64SymbolFixture(t, elf.SHT_SYMTAB, make([]byte, elf.Sym64Size+1), []byte("\x00name\x00"))
	if ef, err := Open(p); err == nil {
		_ = ef.Close()
		t.Fatal("Open accepted malformed present .symtab")
	}
}

func TestOpenRejectsZeroLengthSymbolTables(t *testing.T) {
	for _, typ := range []elf.SectionType{elf.SHT_DYNSYM, elf.SHT_SYMTAB} {
		p := writeELF64SymbolFixture(t, typ, nil, []byte("\x00"))
		if f, err := Open(p); err == nil {
			_ = f.Close()
			t.Fatalf("Open accepted zero-length %s", typ)
		}
	}
}

func TestLoadSymbolTableRejectsExcessiveCountBeforeMaterialization(t *testing.T) {
	tableSize := (maxSymbolCount + 2) * elf.Sym64Size // null symbol + too many real entries
	f := &File{elfFile: &elf.File{Sections: []*elf.Section{{
		SectionHeader: elf.SectionHeader{
			Type: elf.SHT_SYMTAB, Size: tableSize, FileSize: tableSize, Entsize: elf.Sym64Size,
		},
	}}}}
	if _, _, err := f.loadSymbolTable(elf.SHT_SYMTAB, ".symtab"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("loadSymbolTable(excessive count) = %v, want ErrMalformed before table read", err)
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
	if f, err := Open(p); err == nil {
		_ = f.Close()
		t.Fatal("Open accepted zero symbol sh_entsize")
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
