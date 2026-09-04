// Package elfx provides ELF loading helpers for Dart AOT libapp.so files.
//
// For Mach-O (iOS) and PE (Windows) container support, see the Container
// interface and OpenContainer function below. The snapshot parsing packages
// (cluster, snapshot, disasm, decompiler) are container-agnostic — they
// operate on raw byte regions, not ELF-specific structures. Only this
// package and the symbol-lookup layer need container awareness.
package elfx

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

var (
	ErrNotELF       = errors.New("elfx: not an ELF file")
	ErrNotARM64     = errors.New("elfx: not ARM64 (EM_AARCH64)")
	ErrNotShared    = errors.New("elfx: not a shared object")
	ErrNot64Bit     = errors.New("elfx: not 64-bit ELF")
	ErrNoSymbol     = errors.New("elfx: symbol not found")
	ErrNoSegment    = errors.New("elfx: no PT_LOAD segment covers address")
	ErrSymbolNoSize = errors.New("elfx: symbol has zero size")
)

// File wraps a debug/elf.File with convenience methods for Dart AOT analysis.
type File struct {
	ELF    *elf.File
	raw    io.ReaderAt
	closer io.Closer
	size   int64
}

// Open opens an ELF file and validates it is an ARM64 shared object.
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
	// Relaxed to also accept EM_X86_64: the snapshot cluster/fill format
	// this package's callers actually parse
	// (internal/cluster, internal/snapshot) is Dart's own serialization
	// format, not machine code -- it does not vary by target CPU beyond a
	// few explicit profile fields (pointer size, compressed-pointers flag)
	// that snapshot.VersionProfile already accounts for. Only
	// internal/disasm (ARM64 instruction decoding) is genuinely
	// architecture-specific, and callers that only need cluster/class/
	// function metadata (e.g. cmd/aotopsy/refinfo.go) never reach it.
	// Untested for other machine types; if snapshot layout assumptions
	// turn out to differ for a given arch, that will surface as a parse
	// error downstream, not a silent wrong answer.
	if ef.Machine != elf.EM_AARCH64 && ef.Machine != elf.EM_X86_64 {
		_ = f.Close()
		return nil, ErrNotARM64
	}
	if ef.Type != elf.ET_DYN {
		_ = f.Close()
		return nil, ErrNotShared
	}

	return &File{ELF: ef, raw: f, closer: f, size: info.Size()}, nil
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

// IsARM64 reports whether this file is an AArch64 binary. Open() accepts
// both EM_AARCH64 and EM_X86_64 (see Open's doc comment) since most of
// this project's snapshot/cluster parsing is architecture-agnostic, but
// internal/disasm (and everything built on it: the ARM64-only
// disassembly/CFG/call-edge/THR-analysis pipeline used by the top-level
// `aotopsy` commands, `dump`, and `thr-audit`) is genuinely ARM64-only.
// Callers on that path should check this and fail with a clear error
// instead of silently decoding x86_64 bytes as ARM64 instructions.
func (f *File) IsARM64() bool { return f.ELF.Machine == elf.EM_AARCH64 }

// Symbol looks up a dynamic symbol by exact name.
// Returns the symbol's virtual address and size.
func (f *File) Symbol(name string) (addr, size uint64, err error) {
	syms, err := f.ELF.DynamicSymbols()
	if err != nil {
		return 0, 0, fmt.Errorf("elfx: dynsym: %w", err)
	}
	for _, s := range syms {
		if s.Name == name {
			return s.Value, s.Size, nil
		}
	}
	return 0, 0, fmt.Errorf("%w: %s", ErrNoSymbol, name)
}

// VAToFileOffset converts a virtual address to a file offset using PT_LOAD segments.
func (f *File) VAToFileOffset(va uint64) (uint64, error) {
	for _, p := range f.ELF.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if va >= p.Vaddr && va < p.Vaddr+p.Memsz {
			offset := va - p.Vaddr + p.Off
			if offset >= uint64(f.size) {
				return 0, fmt.Errorf("elfx: VA 0x%x maps to offset 0x%x beyond file size 0x%x", va, offset, f.size)
			}
			return offset, nil
		}
	}
	return 0, fmt.Errorf("%w: VA 0x%x", ErrNoSegment, va)
}

// ReadAt reads bytes from the underlying file at the given file offset.
func (f *File) ReadAt(buf []byte, off int64) (int, error) {
	return f.raw.ReadAt(buf, off)
}

// ReadBytesAtVA reads n bytes starting at the given virtual address.
func (f *File) ReadBytesAtVA(va uint64, n int) ([]byte, error) {
	off, err := f.VAToFileOffset(va)
	if err != nil {
		return nil, err
	}
	// Clamp to file size.
	avail := f.size - int64(off)
	if avail <= 0 {
		return nil, fmt.Errorf("elfx: offset 0x%x at or past end of file", off)
	}
	if int64(n) > avail {
		n = int(avail)
	}
	buf := make([]byte, n)
	_, err = f.raw.ReadAt(buf, int64(off))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("elfx: read at 0x%x: %w", off, err)
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

// ByteOrder returns the ELF byte order.
func (f *File) ByteOrder() binary.ByteOrder {
	return f.ELF.ByteOrder
}

// --- Container abstraction for Mach-O / PE support ---
//
// The snapshot parsing packages (cluster, snapshot, disasm, decompiler)
// work with raw byte regions and don't care about the container format.
// Only symbol lookup and VA-to-offset translation need container awareness.
// The Container interface abstracts this so Mach-O (iOS) and PE (Windows)
// binaries can be supported without modifying any parsing code.

// ContainerKind identifies the binary container format.
type ContainerKind int

const (
	ContainerELF   ContainerKind = iota // Android, Linux
	ContainerMachO                      // iOS, macOS
	ContainerPE                         // Windows
)

// Container is the abstract interface for loading a Dart AOT binary
// regardless of its container format (ELF, Mach-O, PE).
// Implementations must provide symbol lookup and VA-to-offset translation.
type Container interface {
	// Kind returns the container format.
	Kind() ContainerKind

	// Symbol looks up a dynamic symbol by exact name.
	// Returns the symbol's virtual address and size.
	Symbol(name string) (addr, size uint64, err error)

	// VAToFileOffset converts a virtual address to a file offset.
	VAToFileOffset(va uint64) (uint64, error)

	// ReadAt reads bytes from the underlying file at the given file offset.
	ReadAt(buf []byte, off int64) (int, error)

	// ReadBytesAtVA reads n bytes starting at the given virtual address.
	ReadBytesAtVA(va uint64, n int) ([]byte, error)

	// IsARM64 reports whether this is an AArch64 binary.
	IsARM64() bool

	// Is64bit reports whether this is a 64-bit binary.
	Is64bit() bool

	// ByteOrder returns the byte order.
	ByteOrder() binary.ByteOrder

	// FileSize returns the size of the underlying file.
	FileSize() int64

	// Close releases resources.
	Close() error
}

// ELFContainer wraps elfx.File to implement Container.
type ELFContainer struct {
	*File
}

func (c *ELFContainer) Kind() ContainerKind { return ContainerELF }

// Is64bit reports whether this is a 64-bit binary.
func (f *File) Is64bit() bool { return f.ELF.Class == elf.ELFCLASS64 }

// OpenContainer opens a binary file and returns the appropriate Container
// implementation based on magic bytes. Currently only ELF is supported;
// Mach-O and PE will return an error indicating the format is recognized
// but not yet implemented.
func OpenContainer(path string) (Container, error) {
	// Read first 8 bytes to identify the format.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("elfx: open: %w", err)
	}
	header := make([]byte, 8)
	_, err = f.Read(header)
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("elfx: read header: %w", err)
	}

	// ELF magic: 0x7f 'E' 'L' 'F'
	if header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' {
		ef, err := Open(path)
		if err != nil {
			return nil, err
		}
		return &ELFContainer{File: ef}, nil
	}

	// Mach-O magic: 0xFEEDFACE (32-bit) or 0xFEEDFACF (64-bit)
	if (header[0] == 0xFE && header[1] == 0xED && header[2] == 0xFA &&
		(header[3] == 0xCE || header[3] == 0xCF)) ||
		// Fat binary: 0xCAFEBABE
		(header[0] == 0xCA && header[1] == 0xFE && header[2] == 0xBA && header[3] == 0xBE) {
		mo, err := openMachO(path)
		if err != nil {
			return nil, fmt.Errorf("elfx: Mach-O: %w", err)
		}
		// Dropped the pointless machOAdapter embedding: all methods were
		// declared on *MachOContainer anyway, so the extra struct added an
		// indirection and nothing else.
		return &MachOContainer{mo: mo}, nil
	}

	// PE magic: "MZ" (DOS header) — PE files start with MZ
	if header[0] == 'M' && header[1] == 'Z' {
		return nil, fmt.Errorf("elfx: PE binary detected but PE support is not yet implemented — only ELF and Mach-O are supported")
	}

	return nil, fmt.Errorf("elfx: unrecognized binary format (magic: %x)", header[:4])
}
