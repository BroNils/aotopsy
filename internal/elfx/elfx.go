// Package elfx owns the trust boundary between untrusted ELF files and the
// rest of AOTopsy. Callers receive validated metadata/data rather than the raw
// debug/elf parser so arithmetic and allocation policy cannot silently drift.
package elfx

import (
	"bytes"
	"crypto/sha256"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"sort"
	"strings"
)

var (
	ErrNotELF             = errors.New("elfx: not an ELF file")
	ErrMalformed          = errors.New("elfx: malformed ELF")
	ErrChanged            = errors.New("elfx: backing file changed while open")
	ErrUnsupportedMachine = errors.New("elfx: unsupported machine (want EM_AARCH64 or EM_X86_64)")
	ErrNotLittleEndian    = errors.New("elfx: not little-endian ELF")
	ErrNotShared          = errors.New("elfx: not a shared object")
	ErrNot64Bit           = errors.New("elfx: not 64-bit ELF")
	ErrNoSymbol           = errors.New("elfx: symbol not found")
	ErrNoSegment          = errors.New("elfx: no PT_LOAD segment covers address")
)

const (
	elf64HeaderSize      = uint64(64)
	elf64ProgramHeader   = uint64(56)
	elf64SectionHeader   = uint64(64)
	maxProgramHeaders    = uint64(4096)
	maxSectionHeaders    = uint64(4096)
	maxSectionNameBytes  = uint64(4 << 20)
	maxSectionNameLength = uint64(4 << 10)
	maxSectionNamesTotal = uint64(8 << 20)
	maxSymbolTableBytes  = uint64(16 << 20)
	maxSymbolCount       = uint64(500000)
	maxSymbolStringBytes = uint64(64 << 20)
	maxSymbolNameBytes   = uint64(64 << 10)
	maxSymbolNamesTotal  = uint64(32 << 20)
	maxExactReadBytes    = uint64(256 << 20)
	maxProgramReadBytes  = uint64(512 << 20)
	maxSectionReadBytes  = uint64(512 << 20)
	maxDWARFBytes        = uint64(64 << 20)
	maxELFFileBytes      = int64(1 << 30)
	maxLoadMemoryBytes   = uint64(1 << 30)
	maxLoadMemoryTotal   = uint64(2 << 30)
)

// File is one validated AOT ELF. The parsed debug/elf.File and ReaderAt stay
// private deliberately: every consumer must use the bounded APIs below.
type File struct {
	elfFile *elf.File
	raw     io.ReaderAt
	closer  io.Closer
	size    int64
	stamp   fileStamp

	symtabPresent bool
	dynsymPresent bool
	symtab        []elf.Symbol
	dynsym        []elf.Symbol
}

type fileStamp struct {
	size       int64
	modNano    int64
	identity   os.FileInfo
	changeSec  int64
	changeNsec int64
	hasChange  bool
}

// ProgramInfo is immutable program-header metadata copied out of debug/elf.
type ProgramInfo struct {
	Index  int
	Type   elf.ProgType
	Flags  elf.ProgFlag
	Offset uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}

// SegmentInfo describes a validated PT_LOAD segment.
type SegmentInfo struct {
	Index  int
	Vaddr  uint64
	Memsz  uint64
	Filesz uint64
	Offset uint64
	Flags  elf.ProgFlag
}

// SectionInfo is immutable section-header metadata copied out of debug/elf.
type SectionInfo struct {
	Index     int
	Name      string
	Type      elf.SectionType
	Flags     elf.SectionFlag
	Addr      uint64
	Size      uint64
	Offset    uint64
	FileSize  uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64
}

// SectionData is a bounded materialized section.
type SectionData struct {
	SectionInfo
	Data []byte
}

// ExecutableSymbol is a symbol proven to live wholly inside a file-backed
// executable section. Zero-size symbols are allowed and represent labels.
type ExecutableSymbol struct {
	Name        string
	Addr        uint64
	Size        uint64
	Type        elf.SymType
	Binding     elf.SymBind
	Section     elf.SectionIndex
	SectionName string
	Dynamic     bool
}

func malformedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

// Open opens exactly the ELF family AOTopsy can analyse: ELF64,
// little-endian, ET_DYN, AArch64 or x86_64. A small manual preflight is done
// before debug/elf.NewFile so hostile header counts/string tables cannot force
// large allocations before AOTopsy's own policy is applied.
func Open(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("elfx: open: %w", err)
	}
	fail := func(err error) (*File, error) {
		_ = f.Close()
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		return fail(fmt.Errorf("elfx: stat: %w", err))
	}
	if !info.Mode().IsRegular() {
		return fail(fmt.Errorf("elfx: input is not a regular file"))
	}
	if info.Size() < 0 || info.Size() > maxELFFileBytes {
		return fail(malformedf("file size %d exceeds limit %d", info.Size(), maxELFFileBytes))
	}
	changeSec, changeNsec, hasChange := fileChangeTime(f, info)
	openStamp := fileStamp{
		size: info.Size(), modNano: info.ModTime().UnixNano(), identity: info,
		changeSec: changeSec, changeNsec: changeNsec, hasChange: hasChange,
	}
	if err := preflightELF64(f, info.Size()); err != nil {
		return fail(err)
	}

	ef, err := elf.NewFile(f)
	if err != nil {
		return fail(fmt.Errorf("%w: debug/elf parse: %v", ErrMalformed, err))
	}
	if ef.Class != elf.ELFCLASS64 {
		return fail(ErrNot64Bit)
	}
	if ef.Data != elf.ELFDATA2LSB {
		return fail(ErrNotLittleEndian)
	}
	if ef.Machine != elf.EM_AARCH64 && ef.Machine != elf.EM_X86_64 {
		return fail(ErrUnsupportedMachine)
	}
	if ef.Type != elf.ET_DYN {
		return fail(ErrNotShared)
	}
	if err := validateFileExtents(ef, info.Size()); err != nil {
		return fail(err)
	}

	out := &File{
		elfFile: ef, raw: f, closer: f, size: info.Size(),
		stamp: openStamp,
	}
	if err := out.loadSymbolTables(); err != nil {
		_ = out.Close()
		return nil, err
	}
	if err := out.checkStable(); err != nil {
		_ = out.Close()
		return nil, err
	}
	return out, nil
}

func preflightELF64(r io.ReaderAt, size int64) error {
	if r == nil || size < 0 {
		return malformedf("invalid backing file size %d", size)
	}
	if size < 16 {
		return fmt.Errorf("%w: truncated ELF identification", ErrNotELF)
	}
	var ident [16]byte
	if err := readExactAt(r, ident[:], 0); err != nil {
		return fmt.Errorf("%w: identification: %v", ErrNotELF, err)
	}
	if !bytes.Equal(ident[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return fmt.Errorf("%w: bad magic", ErrNotELF)
	}
	if elf.Class(ident[elf.EI_CLASS]) != elf.ELFCLASS64 {
		return ErrNot64Bit
	}
	if elf.Data(ident[elf.EI_DATA]) != elf.ELFDATA2LSB {
		return ErrNotLittleEndian
	}
	if elf.Version(ident[elf.EI_VERSION]) != elf.EV_CURRENT {
		return malformedf("unsupported ELF identification version %d", ident[elf.EI_VERSION])
	}
	if uint64(size) < elf64HeaderSize {
		return malformedf("truncated ELF64 header: size %d", size)
	}

	h := make([]byte, elf64HeaderSize)
	if err := readExactAt(r, h, 0); err != nil {
		return malformedf("read ELF64 header: %v", err)
	}
	bo := binary.LittleEndian
	if elf.Type(bo.Uint16(h[16:18])) != elf.ET_DYN {
		return ErrNotShared
	}
	machine := elf.Machine(bo.Uint16(h[18:20]))
	if machine != elf.EM_AARCH64 && machine != elf.EM_X86_64 {
		return ErrUnsupportedMachine
	}
	if elf.Version(bo.Uint32(h[20:24])) != elf.EV_CURRENT {
		return malformedf("invalid ELF header version")
	}
	if got := uint64(bo.Uint16(h[52:54])); got != elf64HeaderSize {
		return malformedf("ELF header size %d, want %d", got, elf64HeaderSize)
	}

	phoff := bo.Uint64(h[32:40])
	shoff := bo.Uint64(h[40:48])
	phentsize := uint64(bo.Uint16(h[54:56]))
	phnum := uint64(bo.Uint16(h[56:58]))
	shentsize := uint64(bo.Uint16(h[58:60]))
	shnum16 := uint64(bo.Uint16(h[60:62]))
	shstr16 := uint64(bo.Uint16(h[62:64]))
	fileSize := uint64(size)

	if phnum > maxProgramHeaders {
		return malformedf("program header count %d exceeds limit %d", phnum, maxProgramHeaders)
	}
	if phnum > 0 {
		if phoff == 0 || phentsize != elf64ProgramHeader {
			return malformedf("invalid program header table offset/entry size")
		}
		if err := validateTableExtent("program header", phoff, phentsize, phnum, fileSize); err != nil {
			return err
		}
	}

	if shoff == 0 {
		if shnum16 != 0 || shstr16 != 0 {
			return malformedf("section metadata present with no section table")
		}
		return nil
	}
	if shentsize != elf64SectionHeader {
		return malformedf("section header entry size %d, want %d", shentsize, elf64SectionHeader)
	}
	if shoff > fileSize || elf64SectionHeader > fileSize-shoff {
		return malformedf("initial section header lies outside backing file")
	}

	section0 := make([]byte, elf64SectionHeader)
	if err := readExactAt(r, section0, int64(shoff)); err != nil {
		return malformedf("read initial section header: %v", err)
	}
	shnum := shnum16
	if shnum == 0 {
		shnum = bo.Uint64(section0[32:40])
		if shnum < uint64(elf.SHN_LORESERVE) {
			return malformedf("extended section count %d below SHN_LORESERVE", shnum)
		}
	}
	if shnum > maxSectionHeaders {
		return malformedf("section header count %d exceeds limit %d", shnum, maxSectionHeaders)
	}
	if shnum == 0 {
		return malformedf("nonzero section table offset with zero sections")
	}
	if err := validateTableExtent("section header", shoff, shentsize, shnum, fileSize); err != nil {
		return err
	}

	shstr := shstr16
	if shstr == uint64(elf.SHN_XINDEX) {
		shstr = uint64(bo.Uint32(section0[40:44]))
	}
	if shstr == 0 {
		return nil
	}
	if shstr >= shnum {
		return malformedf("section-name string table index %d outside %d sections", shstr, shnum)
	}
	entryOff, ok := checkedMulAdd(shoff, shstr, shentsize)
	if !ok || entryOff > fileSize || elf64SectionHeader > fileSize-entryOff {
		return malformedf("section-name string table header offset overflows")
	}
	sh := make([]byte, elf64SectionHeader)
	if err := readExactAt(r, sh, int64(entryOff)); err != nil {
		return malformedf("read section-name string table header: %v", err)
	}
	if elf.SectionType(bo.Uint32(sh[4:8])) != elf.SHT_STRTAB {
		return malformedf("section-name table is not SHT_STRTAB")
	}
	flags := elf.SectionFlag(bo.Uint64(sh[8:16]))
	if flags&elf.SHF_COMPRESSED != 0 {
		return malformedf("compressed section-name string table is not accepted")
	}
	off := bo.Uint64(sh[24:32])
	sz := bo.Uint64(sh[32:40])
	if sz > maxSectionNameBytes {
		return malformedf("section-name string table size %d exceeds limit %d", sz, maxSectionNameBytes)
	}
	if off > fileSize || sz > fileSize-off {
		return malformedf("section-name string table lies outside backing file")
	}
	if sz == 0 {
		return malformedf("section-name string table is empty")
	}
	if sz > uint64(int(^uint(0)>>1)) {
		return malformedf("section-name string table is not addressable")
	}
	shstrtab := make([]byte, int(sz))
	if err := readExactAt(r, shstrtab, int64(off)); err != nil {
		return malformedf("read section-name string table: %v", err)
	}
	if shstrtab[0] != 0 {
		return malformedf("section-name string table does not start with NUL")
	}

	// debug/elf materializes one Go string per section name. A hostile file can
	// point thousands of section headers at progressively overlapping suffixes of
	// one modest string table and amplify a few MiB of input into much more heap
	// before NewFile returns. Validate every sh_name and cap the exact amount of
	// string data debug/elf can copy before crossing that boundary.
	headerBytes := shentsize * shnum // validateTableExtent proved this cannot overflow.
	if headerBytes > uint64(int(^uint(0)>>1)) {
		return malformedf("section header table is not addressable")
	}
	headers := make([]byte, int(headerBytes))
	if err := readExactAt(r, headers, int64(shoff)); err != nil {
		return malformedf("read section header table: %v", err)
	}
	var totalNameBytes uint64
	for i := uint64(0); i < shnum; i++ {
		base := i * shentsize
		nameOff := uint64(bo.Uint32(headers[base : base+4]))
		if nameOff >= sz {
			return malformedf("section %d name offset %d outside section-name table of %d bytes", i, nameOff, sz)
		}
		end := bytes.IndexByte(shstrtab[int(nameOff):], 0)
		if end < 0 {
			return malformedf("section %d name is not NUL-terminated", i)
		}
		nameLen := uint64(end)
		if nameLen > maxSectionNameLength {
			return malformedf("section %d name length %d exceeds limit %d", i, nameLen, maxSectionNameLength)
		}
		if totalNameBytes > maxSectionNamesTotal-nameLen {
			return malformedf("aggregate section-name bytes exceed limit %d", maxSectionNamesTotal)
		}
		totalNameBytes += nameLen
	}
	return nil
}

func validateTableExtent(label string, off, entsize, count, fileSize uint64) error {
	if entsize == 0 || count > math.MaxUint64/entsize {
		return malformedf("%s table size overflows", label)
	}
	sz := entsize * count
	if off > fileSize || sz > fileSize-off {
		return malformedf("%s table lies outside backing file", label)
	}
	return nil
}

func checkedMulAdd(base, n, width uint64) (uint64, bool) {
	if width != 0 && n > math.MaxUint64/width {
		return 0, false
	}
	delta := n * width
	if base > math.MaxUint64-delta {
		return 0, false
	}
	return base + delta, true
}

func readExactAt(r io.ReaderAt, dst []byte, off int64) error {
	n, err := r.ReadAt(dst, off)
	if n != len(dst) {
		if err == nil || errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	if err != nil {
		return err
	}
	return nil
}

func validateFileExtents(ef *elf.File, size int64) error {
	if ef == nil || size < 0 {
		return malformedf("invalid backing file size %d", size)
	}
	fileSize := uint64(size)
	var loadMemoryTotal uint64
	for i, p := range ef.Progs {
		if p == nil {
			return malformedf("nil program header %d", i)
		}
		if p.Off > fileSize || p.Filesz > fileSize-p.Off {
			return malformedf("program header %d file extent lies outside backing file", i)
		}
		if p.Type != elf.PT_LOAD {
			continue
		}
		if p.Filesz > p.Memsz {
			return malformedf("PT_LOAD %d file size 0x%x exceeds memory size 0x%x", i, p.Filesz, p.Memsz)
		}
		if p.Memsz > math.MaxUint64-p.Vaddr {
			return malformedf("PT_LOAD %d virtual extent overflows", i)
		}
		if p.Memsz > maxLoadMemoryBytes {
			return malformedf("PT_LOAD %d memory size 0x%x exceeds limit 0x%x", i, p.Memsz, maxLoadMemoryBytes)
		}
		if loadMemoryTotal > maxLoadMemoryTotal-p.Memsz {
			return malformedf("aggregate PT_LOAD memory exceeds limit 0x%x", maxLoadMemoryTotal)
		}
		loadMemoryTotal += p.Memsz
		if p.Align > 1 {
			if p.Align&(p.Align-1) != 0 {
				return malformedf("PT_LOAD %d alignment 0x%x is not a power of two", i, p.Align)
			}
			if p.Vaddr%p.Align != p.Off%p.Align {
				return malformedf("PT_LOAD %d has incongruent virtual/file alignment", i)
			}
		}
	}
	if err := validateLoadAliases(ef.Progs); err != nil {
		return err
	}
	for i, sec := range ef.Sections {
		if sec == nil {
			return malformedf("nil section header %d", i)
		}
		if sec.Size > math.MaxUint64-sec.Addr {
			return malformedf("section %d (%q) virtual extent overflows", i, sec.Name)
		}
		if sec.Addralign > 1 && sec.Addralign&(sec.Addralign-1) != 0 {
			return malformedf("section %d (%q) alignment 0x%x is not a power of two", i, sec.Name, sec.Addralign)
		}
		if sec.Type == elf.SHT_NOBITS {
			if sec.Flags&elf.SHF_EXECINSTR != 0 {
				return malformedf("section %d (%q) is executable SHT_NOBITS", i, sec.Name)
			}
			if sec.Flags&elf.SHF_ALLOC != 0 && sec.Size > 0 {
				remaining, ok := vaMemoryRemainingFromProgs(ef.Progs, sec.Addr)
				if !ok || sec.Size > remaining {
					return malformedf("allocated SHT_NOBITS section %d (%q) is not covered by PT_LOAD memory", i, sec.Name)
				}
			}
			continue
		}
		if sec.Offset > fileSize || sec.FileSize > fileSize-sec.Offset {
			return malformedf("section %d (%q) file extent lies outside backing file", i, sec.Name)
		}
		if sec.Flags&elf.SHF_ALLOC != 0 && sec.Size > 0 {
			off, remaining, err := vaFileMappingFromProgs(ef.Progs, fileSize, sec.Addr)
			if err != nil {
				return malformedf("allocated section %d (%q) is not file-backed: %v", i, sec.Name, err)
			}
			if off != sec.Offset || sec.Size > remaining {
				return malformedf("allocated section %d (%q) disagrees with PT_LOAD mapping", i, sec.Name)
			}
		}
	}
	return nil
}

func vaMemoryRemainingFromProgs(progs []*elf.Prog, va uint64) (uint64, bool) {
	var best uint64
	for _, p := range progs {
		if p == nil || p.Type != elf.PT_LOAD || va < p.Vaddr {
			continue
		}
		rel := va - p.Vaddr
		if rel >= p.Memsz {
			continue
		}
		remaining := p.Memsz - rel
		if remaining > best {
			best = remaining
		}
	}
	return best, best != 0
}

func validateLoadAliases(progs []*elf.Prog) error {
	for i := 0; i < len(progs); i++ {
		a := progs[i]
		if a == nil || a.Type != elf.PT_LOAD || a.Memsz == 0 {
			continue
		}
		aEnd := a.Vaddr + a.Memsz
		for j := i + 1; j < len(progs); j++ {
			b := progs[j]
			if b == nil || b.Type != elf.PT_LOAD || b.Memsz == 0 {
				continue
			}
			bEnd := b.Vaddr + b.Memsz
			start := max(a.Vaddr, b.Vaddr)
			end := min(aEnd, bEnd)
			if start < end {
				return malformedf("PT_LOAD %d and %d overlap in memory at [0x%x,0x%x)", i, j, start, end)
			}
		}
	}
	return nil
}

// Close releases the descriptor opened by Open. debug/elf.NewFile itself does
// not own a ReaderAt supplied by the caller, so the descriptor is closed here.
func (f *File) Close() error {
	if f == nil {
		return nil
	}
	var err error
	if f.elfFile != nil {
		err = f.elfFile.Close()
		f.elfFile = nil
	}
	if f.closer != nil {
		err = errors.Join(err, f.closer.Close())
		f.closer = nil
	}
	return err
}

func (f *File) FileSize() int64 { return f.size }

func (f *File) checkStable() error {
	if f == nil {
		return fmt.Errorf("elfx: unavailable backing file")
	}
	if f.raw == nil {
		return nil
	}
	of, ok := f.raw.(*os.File)
	if !ok {
		return nil // synthetic unit-test ReaderAt; no filesystem identity exists.
	}
	info, err := of.Stat()
	if err != nil {
		return fmt.Errorf("%w: stat: %v", ErrChanged, err)
	}
	if f.stamp.identity != nil && !os.SameFile(f.stamp.identity, info) {
		return fmt.Errorf("%w: file identity changed", ErrChanged)
	}
	if info.Size() != f.stamp.size || info.ModTime().UnixNano() != f.stamp.modNano {
		return fmt.Errorf("%w: size/mtime changed", ErrChanged)
	}
	changeSec, changeNsec, hasChange := fileChangeTime(of, info)
	if hasChange != f.stamp.hasChange || (hasChange && (changeSec != f.stamp.changeSec || changeNsec != f.stamp.changeNsec)) {
		return fmt.Errorf("%w: filesystem change time changed", ErrChanged)
	}
	return nil
}

// fileChangeTime extracts a filesystem-maintained status/change timestamp.
// Windows supplies ChangeTime through the open file handle; Unix-like os.Stat
// payloads expose ctime. These tokens are distinct from mtime, so ordinary
// same-size mutations followed by an mtime restore are still visible. This is
// a change detector, not an immutable snapshot: a privileged/local writer that
// can deliberately rewrite all filesystem metadata remains outside this API's
// stability guarantee.
func fileChangeTime(file *os.File, info os.FileInfo) (sec, nsec int64, ok bool) {
	if change, ok := platformFileChangeTime(file); ok {
		return change, 0, true
	}
	if info == nil || info.Sys() == nil {
		return 0, 0, false
	}
	v := reflect.ValueOf(info.Sys())
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return 0, 0, false
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return 0, 0, false
	}
	for _, name := range []string{"Ctim", "Ctimespec"} {
		ct := v.FieldByName(name)
		if !ct.IsValid() {
			continue
		}
		if ct.Kind() == reflect.Pointer {
			if ct.IsNil() {
				continue
			}
			ct = ct.Elem()
		}
		if ct.Kind() != reflect.Struct {
			continue
		}
		secField, nsecField := ct.FieldByName("Sec"), ct.FieldByName("Nsec")
		if secField.IsValid() && nsecField.IsValid() && secField.CanInt() && nsecField.CanInt() {
			return secField.Int(), nsecField.Int(), true
		}
	}
	// Some Unix stat structs expose ctime as separate scalar fields.
	secField, nsecField := v.FieldByName("Ctime"), v.FieldByName("Ctimensec")
	if secField.IsValid() && nsecField.IsValid() && secField.CanInt() && nsecField.CanInt() {
		return secField.Int(), nsecField.Int(), true
	}
	return 0, 0, false
}

func (f *File) Machine() elf.Machine {
	if f == nil || f.elfFile == nil {
		return elf.EM_NONE
	}
	return f.elfFile.Machine
}

func (f *File) Class() elf.Class {
	if f == nil || f.elfFile == nil {
		return elf.ELFCLASSNONE
	}
	return f.elfFile.Class
}

func (f *File) IsARM64() bool { return f.Machine() == elf.EM_AARCH64 }

// SHA256 hashes the exact descriptor Open validated. It never reopens path.
func (f *File) SHA256() (string, error) {
	if f == nil || f.raw == nil || f.size < 0 {
		return "", fmt.Errorf("elfx: unavailable backing file")
	}
	if err := f.checkStable(); err != nil {
		return "", err
	}
	h := sha256.New()
	r := io.NewSectionReader(f.raw, 0, f.size)
	n, err := io.Copy(h, r)
	if err != nil {
		return "", fmt.Errorf("elfx: hash backing file: %w", err)
	}
	if n != f.size {
		return "", fmt.Errorf("elfx: hash backing file: read %d of %d bytes: %w", n, f.size, io.ErrUnexpectedEOF)
	}
	if err := f.checkStable(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (f *File) loadSymbolTables() error {
	var err error
	f.symtab, f.symtabPresent, err = f.loadSymbolTable(elf.SHT_SYMTAB, ".symtab")
	if err != nil {
		return err
	}
	f.dynsym, f.dynsymPresent, err = f.loadSymbolTable(elf.SHT_DYNSYM, ".dynsym")
	return err
}

func (f *File) loadSymbolTable(typ elf.SectionType, label string) ([]elf.Symbol, bool, error) {
	if f == nil || f.elfFile == nil {
		return nil, false, fmt.Errorf("elfx: unavailable ELF")
	}
	var table *elf.Section
	for _, sec := range f.elfFile.Sections {
		if sec.Type != typ {
			continue
		}
		if table != nil {
			return nil, true, malformedf("multiple %s sections", label)
		}
		table = sec
	}
	if table == nil {
		return nil, false, nil
	}
	if table.Flags&elf.SHF_COMPRESSED != 0 {
		return nil, true, malformedf("compressed %s is not accepted", label)
	}
	if table.Size != table.FileSize || table.Size < elf.Sym64Size || table.Size%elf.Sym64Size != 0 {
		return nil, true, malformedf("%s size %d is not a non-empty uncompressed multiple of ELF64 symbol size %d", label, table.Size, elf.Sym64Size)
	}
	if table.Entsize != elf.Sym64Size {
		return nil, true, malformedf("%s entry size %d, want %d", label, table.Entsize, elf.Sym64Size)
	}
	if table.Size > maxSymbolTableBytes {
		return nil, true, malformedf("%s size %d exceeds limit %d", label, table.Size, maxSymbolTableBytes)
	}
	if count := table.Size/elf.Sym64Size - 1; count > maxSymbolCount {
		return nil, true, malformedf("%s symbol count %d exceeds limit %d", label, count, maxSymbolCount)
	}
	if table.Link >= uint32(len(f.elfFile.Sections)) {
		return nil, true, malformedf("%s has invalid string-table link %d", label, table.Link)
	}
	strs := f.elfFile.Sections[table.Link]
	if strs == nil || strs.Type != elf.SHT_STRTAB {
		return nil, true, malformedf("%s link %d is not a string table", label, table.Link)
	}
	if strs.Flags&elf.SHF_COMPRESSED != 0 || strs.Size != strs.FileSize {
		return nil, true, malformedf("%s string table must be uncompressed", label)
	}
	if strs.Size == 0 || strs.Size > maxSymbolStringBytes {
		return nil, true, malformedf("%s string table size %d outside allowed range", label, strs.Size)
	}

	tableData, err := f.readFileRange(table.Offset, table.Size, maxSymbolTableBytes)
	if err != nil {
		return nil, true, malformedf("read %s: %v", label, err)
	}
	strData, err := f.readFileRange(strs.Offset, strs.Size, maxSymbolStringBytes)
	if err != nil {
		return nil, true, malformedf("read %s string table: %v", label, err)
	}
	if len(strData) == 0 || strData[0] != 0 {
		return nil, true, malformedf("%s string table does not start with NUL", label)
	}
	if !allZero(tableData[:elf.Sym64Size]) {
		return nil, true, malformedf("%s null symbol is not all zero", label)
	}

	count := len(tableData)/elf.Sym64Size - 1
	if uint64(table.Info) > uint64(count+1) {
		return nil, true, malformedf("%s sh_info %d exceeds symbol count %d", label, table.Info, count+1)
	}
	syms := make([]elf.Symbol, 0, count)
	nameCache := make(map[uint32]string)
	var materializedNames uint64
	for off := elf.Sym64Size; off < len(tableData); off += elf.Sym64Size {
		rec := tableData[off : off+elf.Sym64Size]
		nameOff := binary.LittleEndian.Uint32(rec[0:4])
		if uint64(nameOff) >= uint64(len(strData)) {
			return nil, true, malformedf("%s symbol name offset %d lies outside string table", label, nameOff)
		}
		name, cached := nameCache[nameOff]
		if !cached {
			nameTail := strData[nameOff:]
			scanLen := min(uint64(len(nameTail)), maxSymbolNameBytes+1)
			nameEnd := bytes.IndexByte(nameTail[:scanLen], 0)
			if nameEnd < 0 {
				return nil, true, malformedf("%s symbol name at offset %d is unterminated or exceeds %d bytes", label, nameOff, maxSymbolNameBytes)
			}
			if materializedNames > maxSymbolNamesTotal-uint64(nameEnd) {
				return nil, true, malformedf("%s materialized symbol names exceed %d-byte budget", label, maxSymbolNamesTotal)
			}
			name = string(nameTail[:nameEnd])
			materializedNames += uint64(nameEnd)
			nameCache[nameOff] = name
		}
		shndx := elf.SectionIndex(binary.LittleEndian.Uint16(rec[6:8]))
		if shndx == elf.SHN_XINDEX {
			return nil, true, malformedf("%s uses unsupported SHN_XINDEX symbol", label)
		}
		if shndx != elf.SHN_UNDEF && shndx < elf.SHN_LORESERVE && int(shndx) >= len(f.elfFile.Sections) {
			return nil, true, malformedf("%s symbol section index %d exceeds section count %d", label, shndx, len(f.elfFile.Sections))
		}
		syms = append(syms, elf.Symbol{
			Name:    name,
			Info:    rec[4],
			Other:   rec[5],
			Section: shndx,
			Value:   binary.LittleEndian.Uint64(rec[8:16]),
			Size:    binary.LittleEndian.Uint64(rec[16:24]),
		})
	}
	return syms, true, nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// DynamicSnapshotSymbol resolves one defined global/default-visible snapshot
// section symbol. Dart 2.12's ELF writer emits these as STT_FUNC, while 2.14+
// emits STT_OBJECT; both shapes are exact SDK behavior. No other symbol type is
// accepted. Multiple exact aliases are okay only when they describe the
// identical address/size.
func (f *File) DynamicSnapshotSymbol(name string) (addr, size uint64, err error) {
	if f == nil {
		return 0, 0, fmt.Errorf("elfx: unavailable ELF")
	}
	if err := f.checkStable(); err != nil {
		return 0, 0, err
	}
	if !f.dynsymPresent {
		return 0, 0, fmt.Errorf("%w: %s", ErrNoSymbol, name)
	}
	found := false
	for _, s := range f.dynsym {
		if s.Name != name || s.Section == elf.SHN_UNDEF {
			continue
		}
		typ := elf.ST_TYPE(s.Info)
		if (typ != elf.STT_OBJECT && typ != elf.STT_FUNC) || elf.ST_BIND(s.Info) != elf.STB_GLOBAL || elf.ST_VISIBILITY(s.Other) != elf.STV_DEFAULT {
			return 0, 0, malformedf("dynamic snapshot symbol %q has type=%s binding=%s visibility=%s", name, typ, elf.ST_BIND(s.Info), elf.ST_VISIBILITY(s.Other))
		}
		if err := f.validateMappedSymbol(s); err != nil {
			return 0, 0, malformedf("dynamic snapshot symbol %q: %v", name, err)
		}
		if !found {
			addr, size, found = s.Value, s.Size, true
			continue
		}
		if addr != s.Value || size != s.Size {
			return 0, 0, malformedf("dynamic symbol %q has conflicting definitions", name)
		}
	}
	if !found {
		return 0, 0, fmt.Errorf("%w: %s", ErrNoSymbol, name)
	}
	return addr, size, nil
}

func (f *File) validateMappedSymbol(s elf.Symbol) error {
	if s.Section == elf.SHN_UNDEF || s.Section >= elf.SHN_LORESERVE {
		return fmt.Errorf("invalid section index %d", s.Section)
	}
	idx := int(s.Section)
	if idx < 0 || idx >= len(f.elfFile.Sections) {
		return fmt.Errorf("section index %d out of range", s.Section)
	}
	sec := f.elfFile.Sections[idx]
	if sec == nil || sec.Flags&elf.SHF_ALLOC == 0 || sec.Type == elf.SHT_NOBITS {
		return fmt.Errorf("section %d is not file-backed allocated data", s.Section)
	}
	if s.Value < sec.Addr {
		return fmt.Errorf("value 0x%x precedes section %q", s.Value, sec.Name)
	}
	rel := s.Value - sec.Addr
	if rel >= sec.Size {
		return fmt.Errorf("value 0x%x lies outside section %q", s.Value, sec.Name)
	}
	if s.Size > 0 && s.Size > sec.Size-rel {
		return fmt.Errorf("size 0x%x exceeds section %q", s.Size, sec.Name)
	}
	_, remaining, err := f.vaFileMapping(s.Value)
	if err != nil {
		return err
	}
	if s.Size > remaining {
		return fmt.Errorf("size 0x%x exceeds file-backed PT_LOAD extent", s.Size)
	}
	return nil
}

// validateExecutableSymbol is the function-label variant of
// validateMappedSymbol. A zero-size symbol is allowed exactly at the end of an
// executable section: ELF symbol sizes may be unknown/zero, and a terminal
// label does not claim any backing byte. Any non-zero range, or any zero-size
// symbol before the end, still has to resolve through the unique file-backed
// PT_LOAD mapping.
func (f *File) validateExecutableSymbol(s elf.Symbol) error {
	if s.Section == elf.SHN_UNDEF || s.Section >= elf.SHN_LORESERVE {
		return fmt.Errorf("invalid section index %d", s.Section)
	}
	idx := int(s.Section)
	if idx < 0 || idx >= len(f.elfFile.Sections) {
		return fmt.Errorf("section index %d out of range", s.Section)
	}
	sec := f.elfFile.Sections[idx]
	if sec == nil || sec.Flags&elf.SHF_ALLOC == 0 || sec.Flags&elf.SHF_EXECINSTR == 0 || sec.Type == elf.SHT_NOBITS {
		return fmt.Errorf("section %d is not file-backed executable data", s.Section)
	}
	if s.Value < sec.Addr {
		return fmt.Errorf("value 0x%x precedes section %q", s.Value, sec.Name)
	}
	rel := s.Value - sec.Addr
	if rel > sec.Size || (rel == sec.Size && s.Size != 0) {
		return fmt.Errorf("value/range 0x%x+0x%x lies outside section %q", s.Value, s.Size, sec.Name)
	}
	if rel == sec.Size { // terminal zero-size label: no byte range is claimed.
		return nil
	}
	if s.Size > sec.Size-rel {
		return fmt.Errorf("size 0x%x exceeds section %q", s.Size, sec.Name)
	}
	_, remaining, err := f.vaFileMapping(s.Value)
	if err != nil {
		return err
	}
	if s.Size > remaining {
		return fmt.Errorf("size 0x%x exceeds file-backed PT_LOAD extent", s.Size)
	}
	return nil
}

// ExecutableSymbols returns validated function-like symbols from both static
// and dynamic tables. Invalid executable claims are errors; non-executable
// symbols are simply irrelevant to this API.
func (f *File) ExecutableSymbols() ([]ExecutableSymbol, error) {
	if f == nil || f.elfFile == nil {
		return nil, fmt.Errorf("elfx: unavailable ELF")
	}
	if err := f.checkStable(); err != nil {
		return nil, err
	}
	var out []ExecutableSymbol
	add := func(syms []elf.Symbol, dynamic bool) error {
		for _, s := range syms {
			typ := elf.ST_TYPE(s.Info)
			if typ != elf.STT_FUNC && typ != elf.STT_NOTYPE && typ != elf.STT_GNU_IFUNC {
				continue
			}
			if s.Name == "" || s.Section == elf.SHN_UNDEF || s.Section >= elf.SHN_LORESERVE {
				continue
			}
			idx := int(s.Section)
			if idx < 0 || idx >= len(f.elfFile.Sections) {
				return malformedf("executable symbol %q has invalid section index %d", s.Name, s.Section)
			}
			sec := f.elfFile.Sections[idx]
			if sec == nil || sec.Flags&elf.SHF_EXECINSTR == 0 {
				continue
			}
			if err := f.validateExecutableSymbol(s); err != nil {
				return malformedf("executable symbol %q: %v", s.Name, err)
			}
			out = append(out, ExecutableSymbol{
				Name: s.Name, Addr: s.Value, Size: s.Size,
				Type: typ, Binding: elf.ST_BIND(s.Info), Section: s.Section,
				SectionName: sec.Name, Dynamic: dynamic,
			})
		}
		return nil
	}
	if err := add(f.symtab, false); err != nil {
		return nil, err
	}
	if err := add(f.dynsym, true); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr != out[j].Addr {
			return out[i].Addr < out[j].Addr
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Dynamic != out[j].Dynamic {
			return !out[i].Dynamic
		}
		return out[i].Type < out[j].Type
	})
	return out, nil
}

// StaticSymbolsPresent reports whether a validated .symtab was present.
func (f *File) StaticSymbolsPresent() bool { return f != nil && f.symtabPresent }

// VAToFileOffset converts a VA to a unique file-backed PT_LOAD offset.
func (f *File) VAToFileOffset(va uint64) (uint64, error) {
	if err := f.checkStable(); err != nil {
		return 0, err
	}
	off, _, err := f.vaFileMapping(va)
	return off, err
}

// FileBackedRemaining returns how many exact bytes remain in the unique
// file-backed PT_LOAD mapping starting at va.
func (f *File) FileBackedRemaining(va uint64) (uint64, error) {
	if err := f.checkStable(); err != nil {
		return 0, err
	}
	_, remaining, err := f.vaFileMapping(va)
	return remaining, err
}

func (f *File) vaFileMapping(va uint64) (offset, remaining uint64, err error) {
	if f == nil || f.elfFile == nil || f.size < 0 {
		return 0, 0, fmt.Errorf("elfx: unavailable ELF")
	}
	return vaFileMappingFromProgs(f.elfFile.Progs, uint64(f.size), va)
}

func vaFileMappingFromProgs(progs []*elf.Prog, fileSize, va uint64) (offset, remaining uint64, err error) {
	bssMatch := false
	found := false
	for _, p := range progs {
		if p == nil || p.Type != elf.PT_LOAD || va < p.Vaddr {
			continue
		}
		rel := va - p.Vaddr
		if rel >= p.Memsz {
			continue
		}
		if rel >= p.Filesz {
			bssMatch = true
			continue
		}
		if p.Off > math.MaxUint64-rel {
			return 0, 0, malformedf("VA 0x%x file offset overflows uint64", va)
		}
		candidate := p.Off + rel
		if candidate >= fileSize {
			return 0, 0, malformedf("VA 0x%x maps beyond backing file", va)
		}
		candidateRemaining := min(p.Filesz-rel, fileSize-candidate)
		if !found {
			offset, remaining, found = candidate, candidateRemaining, true
			continue
		}
		if candidate != offset {
			return 0, 0, malformedf("VA 0x%x has ambiguous PT_LOAD file mappings 0x%x and 0x%x", va, offset, candidate)
		}
		remaining = min(remaining, candidateRemaining)
	}
	if found && bssMatch {
		return 0, 0, malformedf("VA 0x%x is both file-backed and zero-fill PT_LOAD memory", va)
	}
	if found {
		return offset, remaining, nil
	}
	if bssMatch {
		return 0, 0, fmt.Errorf("elfx: VA 0x%x lies in non-file-backed PT_LOAD memory", va)
	}
	return 0, 0, fmt.Errorf("%w: VA 0x%x", ErrNoSegment, va)
}

// ReadBytesAtVA performs one exact bounded read from a unique PT_LOAD mapping.
func (f *File) ReadBytesAtVA(va uint64, n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("elfx: negative read length %d", n)
	}
	if uint64(n) > maxExactReadBytes {
		return nil, fmt.Errorf("elfx: read length %d exceeds limit %d", n, maxExactReadBytes)
	}
	off, remaining, err := f.vaFileMapping(va)
	if err != nil {
		return nil, err
	}
	if uint64(n) > remaining {
		return nil, fmt.Errorf("elfx: exact read of %d bytes at VA 0x%x exceeds file-backed PT_LOAD extent (%d bytes remain)", n, va, remaining)
	}
	return f.readFileRange(off, uint64(n), maxExactReadBytes)
}

func (f *File) readFileRange(off, size, limit uint64) ([]byte, error) {
	if f == nil || f.raw == nil || f.size < 0 {
		return nil, fmt.Errorf("elfx: unavailable backing file")
	}
	if err := f.checkStable(); err != nil {
		return nil, err
	}
	if size > limit {
		return nil, fmt.Errorf("elfx: requested range size %d exceeds limit %d", size, limit)
	}
	fileSize := uint64(f.size)
	if off > fileSize || size > fileSize-off {
		return nil, fmt.Errorf("elfx: file range [0x%x,+0x%x) outside backing file", off, size)
	}
	if size > uint64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("elfx: requested range is not addressable")
	}
	buf := make([]byte, int(size))
	if err := readExactAt(f.raw, buf, int64(off)); err != nil {
		return nil, fmt.Errorf("elfx: read at 0x%x: %w", off, err)
	}
	if err := f.checkStable(); err != nil {
		return nil, err
	}
	return buf, nil
}

// Programs returns copied metadata for all program headers.
func (f *File) Programs() []ProgramInfo {
	if f == nil || f.elfFile == nil {
		return nil
	}
	out := make([]ProgramInfo, 0, len(f.elfFile.Progs))
	for i, p := range f.elfFile.Progs {
		if p == nil {
			continue
		}
		out = append(out, ProgramInfo{Index: i, Type: p.Type, Flags: p.Flags, Offset: p.Off, Vaddr: p.Vaddr, Paddr: p.Paddr, Filesz: p.Filesz, Memsz: p.Memsz, Align: p.Align})
	}
	return out
}

func (f *File) LoadSegments() []SegmentInfo {
	var out []SegmentInfo
	for _, p := range f.Programs() {
		if p.Type == elf.PT_LOAD {
			out = append(out, SegmentInfo{Index: p.Index, Vaddr: p.Vaddr, Memsz: p.Memsz, Filesz: p.Filesz, Offset: p.Offset, Flags: p.Flags})
		}
	}
	return out
}

// ReadProgram materializes one exact program payload under a caller-provided
// cap, additionally bounded by the package hard limit.
func (f *File) ReadProgram(index int, limit uint64) ([]byte, error) {
	if f == nil || f.elfFile == nil || index < 0 || index >= len(f.elfFile.Progs) {
		return nil, fmt.Errorf("elfx: invalid program index %d", index)
	}
	p := f.elfFile.Progs[index]
	if p == nil {
		return nil, malformedf("nil program header %d", index)
	}
	limit = min(limit, maxProgramReadBytes)
	return f.readFileRange(p.Off, p.Filesz, limit)
}

// HashProgram hashes one exact file-backed program payload without materializing
// it. The header extent was already validated by Open.
func (f *File) HashProgram(index int) (string, error) {
	if f == nil || f.elfFile == nil || f.raw == nil || index < 0 || index >= len(f.elfFile.Progs) {
		return "", fmt.Errorf("elfx: invalid program index %d", index)
	}
	p := f.elfFile.Progs[index]
	if p == nil || p.Filesz > math.MaxInt64 {
		return "", malformedf("invalid program payload %d", index)
	}
	if err := f.checkStable(); err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.CopyN(h, io.NewSectionReader(f.raw, int64(p.Off), int64(p.Filesz)), int64(p.Filesz))
	if err != nil || uint64(n) != p.Filesz {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return "", fmt.Errorf("elfx: hash program %d: %w", index, err)
	}
	if err := f.checkStable(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Sections returns copied metadata for all sections.
func (f *File) Sections() []SectionInfo {
	if f == nil || f.elfFile == nil {
		return nil
	}
	out := make([]SectionInfo, 0, len(f.elfFile.Sections))
	for i, s := range f.elfFile.Sections {
		if s == nil {
			continue
		}
		out = append(out, SectionInfo{Index: i, Name: s.Name, Type: s.Type, Flags: s.Flags, Addr: s.Addr, Size: s.Size, Offset: s.Offset, FileSize: s.FileSize, Link: s.Link, Info: s.Info, Addralign: s.Addralign, Entsize: s.Entsize})
	}
	return out
}

// ReadSection materializes one section under a cap. SHT_NOBITS has no file
// bytes and is never materialized. Compressed sections are streamed through
// debug/elf only after their advertised uncompressed size has passed the cap.
func (f *File) ReadSection(index int, limit uint64) ([]byte, error) {
	if f == nil || f.elfFile == nil || index < 0 || index >= len(f.elfFile.Sections) {
		return nil, fmt.Errorf("elfx: invalid section index %d", index)
	}
	if err := f.checkStable(); err != nil {
		return nil, err
	}
	s := f.elfFile.Sections[index]
	if s == nil {
		return nil, malformedf("nil section %d", index)
	}
	if s.Type == elf.SHT_NOBITS {
		return nil, fmt.Errorf("elfx: section %q is SHT_NOBITS", s.Name)
	}
	limit = min(limit, maxSectionReadBytes)
	if s.Size > limit || s.Size > math.MaxInt64 {
		return nil, fmt.Errorf("elfx: section %q size %d exceeds read limit %d", s.Name, s.Size, limit)
	}
	r := s.Open()
	data, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("elfx: read section %q: %w", s.Name, err)
	}
	if uint64(len(data)) != s.Size {
		return nil, fmt.Errorf("elfx: section %q produced %d bytes, want %d", s.Name, len(data), s.Size)
	}
	if err := f.checkStable(); err != nil {
		return nil, err
	}
	return data, nil
}

// ExecutableSections materializes all executable file-backed sections with an
// aggregate budget. Overlapping executable VA ranges are rejected because
// scanners otherwise get two competing byte identities for one instruction VA.
func (f *File) ExecutableSections(maxTotal uint64) ([]SectionData, error) {
	if maxTotal == 0 || maxTotal > maxSectionReadBytes {
		maxTotal = maxSectionReadBytes
	}
	var total uint64
	var out []SectionData
	for _, s := range f.Sections() {
		// SHF_EXECINSTR on its own is only a section-table annotation. Production
		// code must come from an allocated section that the loader maps through a
		// unique file-backed PT_LOAD; otherwise attacker-controlled dead bytes can
		// masquerade as executable evidence.
		if s.Flags&elf.SHF_EXECINSTR == 0 || s.Flags&elf.SHF_ALLOC == 0 || s.Size == 0 {
			continue
		}
		if s.Type == elf.SHT_NOBITS {
			return nil, malformedf("executable section %q is SHT_NOBITS", s.Name)
		}
		off, remaining, err := f.vaFileMapping(s.Addr)
		if err != nil || off != s.Offset || s.Size > remaining {
			return nil, malformedf("executable section %q is not uniquely file-backed by PT_LOAD", s.Name)
		}
		if s.Size > maxTotal-total {
			return nil, fmt.Errorf("elfx: executable data exceeds %d-byte budget", maxTotal)
		}
		for _, prev := range out {
			if rangesOverlap(s.Addr, s.Size, prev.Addr, prev.Size) {
				return nil, malformedf("executable sections %q and %q overlap in VA space", prev.Name, s.Name)
			}
		}
		data, err := f.ReadSection(s.Index, maxTotal-total)
		if err != nil {
			return nil, err
		}
		total += s.Size
		out = append(out, SectionData{SectionInfo: s, Data: data})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out, nil
}

func rangesOverlap(a, aSize, b, bSize uint64) bool {
	if aSize == 0 || bSize == 0 {
		return false
	}
	if a <= b {
		return b-a < aSize
	}
	return a-b < bSize
}

// MappedReader streams file-backed PT_LOAD bytes with NUL separators and an
// aggregate cap. If an unusual ET_DYN has no PT_LOAD, allocated file-backed
// sections are used as a bounded fallback.
func (f *File) MappedReader(limit uint64) io.Reader {
	if f == nil || f.raw == nil || f.size < 0 || limit == 0 {
		return bytes.NewReader(nil)
	}
	limit = min(limit, maxProgramReadBytes)
	remaining := limit
	var readers []io.Reader
	addRange := func(off, size uint64) {
		if remaining == 0 || size == 0 {
			return
		}
		size = min(size, remaining)
		readers = append(readers, io.NewSectionReader(f.raw, int64(off), int64(size)), bytes.NewReader([]byte{0}))
		remaining -= size
	}
	hasLoad := false
	for _, p := range f.LoadSegments() {
		if p.Filesz == 0 {
			continue
		}
		hasLoad = true
		addRange(p.Offset, p.Filesz)
	}
	if !hasLoad {
		for _, s := range f.Sections() {
			if s.Flags&elf.SHF_ALLOC == 0 || s.Type == elf.SHT_NOBITS || s.Size == 0 {
				continue
			}
			addRange(s.Offset, s.FileSize)
		}
	}
	return &stableReader{file: f, reader: io.MultiReader(readers...)}
}

type stableReader struct {
	file    *File
	reader  io.Reader
	started bool
	done    bool
}

func (r *stableReader) Read(p []byte) (int, error) {
	if !r.started {
		r.started = true
		if err := r.file.checkStable(); err != nil {
			return 0, err
		}
	}
	n, err := r.reader.Read(p)
	if errors.Is(err, io.EOF) && !r.done {
		r.done = true
		if stableErr := r.file.checkStable(); stableErr != nil {
			return n, stableErr
		}
	}
	return n, err
}

// DWARF exposes only the structured decoder, not the underlying ELF parser.
// The aggregate logical debug-section budget is enforced here so callers cannot
// accidentally bypass the trust-boundary resource policy.
func (f *File) DWARF() (*dwarf.Data, error) {
	if f == nil || f.elfFile == nil {
		return nil, fmt.Errorf("elfx: unavailable ELF")
	}
	if err := f.checkStable(); err != nil {
		return nil, err
	}
	var logical uint64
	for _, s := range f.elfFile.Sections {
		if s == nil {
			continue
		}
		// Legacy .zdebug_* embeds its uncompressed size inside zlib data rather
		// than an ELF compression header. Section.Size is therefore only the
		// compressed file size at this point, so it cannot bound the allocation
		// debug/elf.DWARF may perform. Refuse this legacy form at the trust
		// boundary; modern SHF_COMPRESSED .debug_* sections expose their logical
		// size in Chdr64 and are safe to budget below.
		if strings.HasPrefix(s.Name, ".zdebug_") {
			return nil, fmt.Errorf("elfx: legacy .zdebug_* DWARF is not accepted")
		}
		if !strings.HasPrefix(s.Name, ".debug_") {
			continue
		}
		if s.Size > maxDWARFBytes || logical > maxDWARFBytes-s.Size {
			return nil, fmt.Errorf("elfx: DWARF logical data exceeds %d-byte budget", maxDWARFBytes)
		}
		logical += s.Size
	}
	d, err := f.elfFile.DWARF()
	if err != nil {
		return nil, err
	}
	if err := f.checkStable(); err != nil {
		return nil, err
	}
	return d, nil
}
