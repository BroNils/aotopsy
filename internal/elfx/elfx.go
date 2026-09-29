// Package elfx provides ELF loading helpers for Dart AOT libapp.so files.
package elfx

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

var (
	ErrNotELF             = errors.New("elfx: not an ELF file")
	ErrUnsupportedMachine = errors.New("elfx: unsupported machine (want EM_AARCH64 or EM_X86_64)")
	ErrNotLittleEndian    = errors.New("elfx: not little-endian ELF")
	ErrNotShared          = errors.New("elfx: not a shared object")
	ErrNot64Bit           = errors.New("elfx: not 64-bit ELF")
	ErrNoSymbol           = errors.New("elfx: symbol not found")
	ErrNoSegment          = errors.New("elfx: no PT_LOAD segment covers address")
)

// File wraps a debug/elf.File with convenience methods for Dart AOT analysis.
type File struct {
	ELF    *elf.File
	raw    io.ReaderAt
	closer io.Closer
	size   int64
}

// Open opens a 64-bit little-endian AArch64/x86_64 ELF shared object.
// Dart's ELF loader rejects non-ELFDATA2LSB files and the snapshot parser reads
// little-endian fields, so accepting big-endian ELF here would create a split
// interpretation of the same bytes downstream.
func Open(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("elfx: open: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("elfx: stat: %w", err)
	}

	ef, err := elf.NewFile(f)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %v", ErrNotELF, err)
	}

	if ef.Class != elf.ELFCLASS64 {
		_ = f.Close()
		return nil, ErrNot64Bit
	}
	if ef.Data != elf.ELFDATA2LSB {
		_ = f.Close()
		return nil, ErrNotLittleEndian
	}
	// AOTopsy supports both AArch64 and x86_64 Dart AOT snapshots. Snapshot
	// cluster/fill data is Dart serialization rather than machine code, while
	// architecture-specific callers select the matching disassembly/decompiler
	// path after Open. Keep this accepted set aligned with the architectures the
	// rest of the repository actually implements.
	if ef.Machine != elf.EM_AARCH64 && ef.Machine != elf.EM_X86_64 {
		_ = f.Close()
		return nil, ErrUnsupportedMachine
	}
	if ef.Type != elf.ET_DYN {
		_ = f.Close()
		return nil, ErrNotShared
	}
	if err := validateFileExtents(ef, info.Size()); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %v", ErrNotELF, err)
	}

	return &File{ELF: ef, raw: f, closer: f, size: info.Size()}, nil
}

// validateFileExtents checks the file-backed ranges that debug/elf records but
// does not itself compare against the actual ReaderAt length. Keeping this at
// Open means every later caller sees one fail-closed view of malformed section
// and program headers instead of discovering truncation only when it happens to
// read a particular range.
func validateFileExtents(ef *elf.File, size int64) error {
	if ef == nil || size < 0 {
		return fmt.Errorf("elfx: invalid backing file size %d", size)
	}
	fileSize := uint64(size)
	for i, p := range ef.Progs {
		if p == nil {
			return fmt.Errorf("elfx: nil program header %d", i)
		}
		if p.Type == elf.PT_LOAD && p.Filesz > p.Memsz {
			return fmt.Errorf("elfx: PT_LOAD %d file size 0x%x exceeds memory size 0x%x", i, p.Filesz, p.Memsz)
		}
		if p.Filesz > 0 && (p.Off > fileSize || p.Filesz > fileSize-p.Off) {
			return fmt.Errorf("elfx: program header %d file extent lies outside backing file", i)
		}
	}
	for i, sec := range ef.Sections {
		if sec == nil {
			return fmt.Errorf("elfx: nil section header %d", i)
		}
		// SHT_NOBITS occupies memory only; sh_offset does not describe a
		// FileSize-byte extent and may legitimately be at the end of the file.
		if sec.Type == elf.SHT_NOBITS || sec.FileSize == 0 {
			continue
		}
		if sec.Offset > fileSize || sec.FileSize > fileSize-sec.Offset {
			return fmt.Errorf("elfx: section %d (%q) file extent lies outside backing file", i, sec.Name)
		}
	}
	return nil
}

// Close releases resources.
func (f *File) Close() error {
	var err error
	if f.ELF != nil {
		err = f.ELF.Close()
	}
	if f.closer != nil {
		err = errors.Join(err, f.closer.Close())
	}
	return err
}

// FileSize returns the size of the underlying file.
func (f *File) FileSize() int64 { return f.size }

// SHA256 hashes the exact file descriptor Open validated and that every ELF/
// snapshot read in this File is backed by. It deliberately does not reopen a
// pathname: a caller may have supplied a replaceable path, and provenance must
// identify the bytes actually analysed rather than whatever inode happens to be
// reachable by that name later.
func (f *File) SHA256() (string, error) {
	if f == nil || f.raw == nil || f.size < 0 {
		return "", fmt.Errorf("elfx: unavailable backing file")
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
	return hex.EncodeToString(h.Sum(nil)), nil
}

// IsARM64 reports whether this file is an AArch64 binary. Open accepts only
// AArch64 and x86_64, so callers can use this to select their architecture-
// specific path without treating an arbitrary unsupported machine as x86_64.
func (f *File) IsARM64() bool { return f.ELF.Machine == elf.EM_AARCH64 }

// Symbol looks up a dynamic symbol by exact name.
// Returns the symbol's virtual address and size.
func (f *File) Symbol(name string) (addr, size uint64, err error) {
	present, err := f.validateSymbolTable(elf.SHT_DYNSYM, ".dynsym")
	if err != nil {
		return 0, 0, err
	}
	if !present {
		return 0, 0, fmt.Errorf("%w: %s", ErrNoSymbol, name)
	}
	syms, err := f.ELF.DynamicSymbols()
	if err != nil {
		return 0, 0, fmt.Errorf("elfx: dynsym: %w", err)
	}
	for _, s := range syms {
		if s.Name == name && s.Section != elf.SHN_UNDEF {
			return s.Value, s.Size, nil
		}
	}
	return 0, 0, fmt.Errorf("%w: %s", ErrNoSymbol, name)
}

// Symbols returns the static ELF symbol table after validating its section
// metadata before handing it to debug/elf. A stripped binary returns (nil,nil).
func (f *File) Symbols() ([]elf.Symbol, error) {
	present, err := f.validateSymbolTable(elf.SHT_SYMTAB, ".symtab")
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, nil
	}
	syms, err := f.ELF.Symbols()
	if err != nil {
		if errors.Is(err, elf.ErrNoSymbols) {
			return nil, nil
		}
		return nil, fmt.Errorf("elfx: symtab: %w", err)
	}
	return syms, nil
}

// DynamicSymbols returns the dynamic ELF symbol table after the same metadata
// validation used by Symbol. A binary without .dynsym returns (nil,nil).
func (f *File) DynamicSymbols() ([]elf.Symbol, error) {
	present, err := f.validateSymbolTable(elf.SHT_DYNSYM, ".dynsym")
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, nil
	}
	syms, err := f.ELF.DynamicSymbols()
	if err != nil {
		if errors.Is(err, elf.ErrNoSymbols) {
			return nil, nil
		}
		return nil, fmt.Errorf("elfx: dynsym: %w", err)
	}
	return syms, nil
}

// validateSymbolTable rejects malformed symbol-table section metadata before
// handing it to debug/elf. Go's debug/elf deliberately assumes mostly trusted
// inputs in several table readers; zero/truncated/non-integral tables must not
// be allowed to reach those paths from an untrusted libapp.so.
func (f *File) validateSymbolTable(typ elf.SectionType, label string) (bool, error) {
	if f == nil || f.ELF == nil {
		return false, fmt.Errorf("elfx: unavailable ELF")
	}
	for _, sec := range f.ELF.Sections {
		if sec.Type != typ {
			continue
		}
		if sec.Size < elf.Sym64Size || sec.Size%elf.Sym64Size != 0 {
			return true, fmt.Errorf("elfx: %s size %d is not a non-empty multiple of ELF64 symbol size %d", label, sec.Size, elf.Sym64Size)
		}
		if sec.Entsize != elf.Sym64Size {
			return true, fmt.Errorf("elfx: %s entry size %d, want %d", label, sec.Entsize, elf.Sym64Size)
		}
		// Section.Size is the logical (uncompressed) size while FileSize is the
		// number of bytes actually present in the ELF file. Bounds checks must use
		// FileSize or a compressed section can be rejected for its expanded size,
		// or worse, a malformed compressed extent can escape the physical file.
		if f.size < 0 || sec.Offset > uint64(f.size) || sec.FileSize > uint64(f.size)-sec.Offset {
			return true, fmt.Errorf("elfx: %s lies outside backing file", label)
		}
		if sec.Link >= uint32(len(f.ELF.Sections)) {
			return true, fmt.Errorf("elfx: %s has invalid string-table link %d", label, sec.Link)
		}
		strs := f.ELF.Sections[sec.Link]
		if strs == nil || strs.Type != elf.SHT_STRTAB {
			return true, fmt.Errorf("elfx: %s link %d is not a string table", label, sec.Link)
		}
		if f.size < 0 || strs.Offset > uint64(f.size) || strs.FileSize > uint64(f.size)-strs.Offset {
			return true, fmt.Errorf("elfx: %s string table lies outside backing file", label)
		}
		return true, nil
	}
	return false, nil
}

// VAToFileOffset converts a virtual address to a file offset using PT_LOAD
// segments. Only file-backed bytes are mappable; BSS/zero-fill tails are not.
func (f *File) VAToFileOffset(va uint64) (uint64, error) {
	off, _, err := f.vaFileMapping(va)
	return off, err
}

// vaFileMapping returns the file offset for va and the exact number of bytes
// remaining in the same file-backed PT_LOAD extent, additionally capped by the
// physical file size. Overlapping PT_LOADs are legal enough to handle
// defensively: a BSS-only match does not prevent a later file-backed match.
func (f *File) vaFileMapping(va uint64) (offset, remaining uint64, err error) {
	bssMatch := false
	for _, p := range f.ELF.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		// Avoid Vaddr+Memsz: malformed program headers can overflow uint64 and
		// make an invalid segment look like it wraps around the address space.
		if va < p.Vaddr {
			continue
		}
		rel := va - p.Vaddr
		if rel >= p.Memsz {
			continue
		}
		// A VA in the Memsz-only tail is BSS/zero-fill and has no bytes in the
		// ELF file. Mapping it through p.Off would read unrelated later content.
		if rel >= p.Filesz {
			bssMatch = true
			continue
		}
		if p.Off > ^uint64(0)-rel {
			return 0, 0, fmt.Errorf("elfx: VA 0x%x file offset overflows uint64", va)
		}
		offset := p.Off + rel
		if f.size < 0 || offset >= uint64(f.size) {
			return 0, 0, fmt.Errorf("elfx: VA 0x%x maps to offset 0x%x beyond file size 0x%x", va, offset, f.size)
		}
		segRemaining := p.Filesz - rel
		fileRemaining := uint64(f.size) - offset
		if fileRemaining < segRemaining {
			segRemaining = fileRemaining
		}
		return offset, segRemaining, nil
	}
	if bssMatch {
		return 0, 0, fmt.Errorf("elfx: VA 0x%x lies in non-file-backed PT_LOAD memory", va)
	}
	return 0, 0, fmt.Errorf("%w: VA 0x%x", ErrNoSegment, va)
}

// ReadAt reads bytes from the underlying file at the given file offset.
func (f *File) ReadAt(buf []byte, off int64) (int, error) {
	return f.raw.ReadAt(buf, off)
}

// ReadBytesAtVA reads n bytes starting at the given virtual address.
func (f *File) ReadBytesAtVA(va uint64, n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("elfx: negative read length %d", n)
	}
	off, remaining, err := f.vaFileMapping(va)
	if err != nil {
		return nil, err
	}
	if uint64(n) > remaining {
		return nil, fmt.Errorf("elfx: exact read of %d bytes at VA 0x%x exceeds file-backed PT_LOAD extent (%d bytes remain)", n, va, remaining)
	}
	buf := make([]byte, n)
	nread, readErr := f.raw.ReadAt(buf, int64(off))
	if nread != n {
		if readErr == nil || errors.Is(readErr, io.EOF) {
			readErr = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("elfx: short read at 0x%x: got %d of %d: %w", off, nread, n, readErr)
	}
	if readErr != nil {
		return nil, fmt.Errorf("elfx: read at 0x%x: %w", off, readErr)
	}
	return buf, nil
}

// SegmentInfo describes a PT_LOAD segment.
type SegmentInfo struct {
	Vaddr  uint64
	Memsz  uint64
	Filesz uint64
	Offset uint64
	Flags  elf.ProgFlag
}

// LoadSegments returns all PT_LOAD segments.
func (f *File) LoadSegments() []SegmentInfo {
	var segs []SegmentInfo
	for _, p := range f.ELF.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		segs = append(segs, SegmentInfo{
			Vaddr:  p.Vaddr,
			Memsz:  p.Memsz,
			Filesz: p.Filesz,
			Offset: p.Off,
			Flags:  p.Flags,
		})
	}
	return segs
}
