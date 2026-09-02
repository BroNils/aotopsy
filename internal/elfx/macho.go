package elfx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// Mach-O constants (from <mach-o/loader.h>).
const (
	MH_MAGIC_64  = 0xFEEDFACF
	MH_CIGAM_64  = 0xCFFAEDFE // byte-swapped
	MH_MAGIC     = 0xFEEDFACE
	MH_CIGAM     = 0xCEFAEDFE // byte-swapped
	MH_FAT_MAGIC = 0xCAFEBABE
	MH_FAT_CIGAM = 0xBEBAFECA // byte-swapped

	LC_SEGMENT_64 = 0x19
	LC_SYMTAB     = 0x02
	LC_DYSYMTAB   = 0x0B
	LC_LOAD_DYLIB = 0x0C
	LC_ID_DYLIB   = 0x0D
	LC_UUID       = 0x1B

	// CPU types
	CPU_TYPE_ARM64  = 0x0100000C
	CPU_TYPE_X86_64 = 0x01000007
)

// MachOHeader is the 64-bit Mach-O header.
type MachOHeader struct {
	Magic      uint32
	CPUType    uint32
	CPUSubtype uint32
	FileType   uint32
	NCmds      uint32
	SizeOfCmds uint32
	Flags      uint32
	Reserved   uint32
}

// MachOSegment64 is a LC_SEGMENT_64 load command.
type MachOSegment64 struct {
	Cmd      uint32
	CmdSize  uint32
	SegName  [16]byte
	VMAddr   uint64
	VMSize   uint64
	FileOff  uint64
	FileSize uint64
	MaxProt  int32
	InitProt int32
	NSects   uint32
	Flags    uint32
}

// MachOSymbol is a nlist_64 entry.
type MachOSymbol struct {
	NStrx  uint32
	NType  uint8
	NSect  uint8
	Desc   uint16
	NValue uint64
}

// MachOFile wraps a Mach-O binary for Dart AOT analysis.
type MachOFile struct {
	file      *os.File
	header    MachOHeader
	segments  []MachOSegment64
	symbols   []MachOSymbol
	strtab    []byte
	byteOrder binary.ByteOrder
	size      int64
}

// MachOContainer implements Container for Mach-O binaries.
//
// STATUS: parsed and unit-reviewable, but NOT wired into any command and NOT
// tested against a real iOS binary -- there is no Mach-O sample in the corpus.
// Every entry point still goes through elfx.Open; OpenContainer is the only
// thing that can produce one of these, and nothing calls OpenContainer yet.
// Treat behaviour beyond header/segment/symtab parsing as unverified.
type MachOContainer struct {
	mo *MachOFile
}

func (c *MachOContainer) Kind() ContainerKind { return ContainerMachO }
func (c *MachOContainer) IsARM64() bool {
	return c.mo.header.CPUType == CPU_TYPE_ARM64
}
func (c *MachOContainer) Is64bit() bool {
	return c.mo.header.Magic == MH_MAGIC_64 || c.mo.header.Magic == MH_CIGAM_64
}
func (c *MachOContainer) ByteOrder() binary.ByteOrder { return c.mo.byteOrder }
func (c *MachOContainer) FileSize() int64             { return c.mo.size }
func (c *MachOContainer) Close() error                { return c.mo.file.Close() }

// nlist_64 n_type bit layout, from <mach-o/nlist.h>:
//
//	N_STAB 0xe0  debug-symbol bits (any set => stab entry, not a real symbol)
//	N_PEXT 0x10  private external
//	N_TYPE 0x0e  symbol type field
//	N_EXT  0x01  external
//
// N_TYPE values: N_UNDF 0x0, N_ABS 0x2, N_SECT 0xe, N_PBUD 0xc, N_INDR 0xa.
const (
	nType = 0x0e
	nStab = 0xe0
	nSect = 0x0e
	nAbs  = 0x02
)

// Symbol looks up a defined symbol by exact name.
//
// The filter here used to be `if sym.NType&0x3E != 0 { continue }`, i.e. keep
// only entries whose N_TYPE is N_UNDF (0) and which are not N_PEXT. That is
// the exact opposite of what is wanted: it accepted only UNDEFINED symbols and
// rejected every defined one, since a symbol defined in a section has
// N_TYPE == N_SECT == 0xe. Looking up _kDartIsolateSnapshotData could never
// have succeeded. Now: skip stabs, and accept N_SECT / N_ABS.
func (c *MachOContainer) Symbol(name string) (addr, size uint64, err error) {
	for _, sym := range c.mo.symbols {
		if sym.NType&nStab != 0 {
			continue // debug (stab) entry, not a linker symbol
		}
		switch sym.NType & nType {
		case nSect, nAbs:
			// defined
		default:
			continue // N_UNDF / N_PBUD / N_INDR: no address of our own
		}
		if c.mo.symbolName(sym) == name {
			// nlist_64 has no size field; callers must derive extents from
			// segment/section bounds or from the snapshot header itself.
			return sym.NValue, 0, nil
		}
	}
	return 0, 0, fmt.Errorf("%w: %s", ErrNoSymbol, name)
}

func (c *MachOContainer) VAToFileOffset(va uint64) (uint64, error) {
	for _, seg := range c.mo.segments {
		if va >= seg.VMAddr && va < seg.VMAddr+seg.VMSize {
			offset := va - seg.VMAddr + seg.FileOff
			if offset >= uint64(c.mo.size) {
				return 0, fmt.Errorf("macho: VA 0x%x maps to offset 0x%x beyond file size 0x%x", va, offset, c.mo.size)
			}
			return offset, nil
		}
	}
	return 0, fmt.Errorf("%w: VA 0x%x", ErrNoSegment, va)
}

func (c *MachOContainer) ReadAt(buf []byte, off int64) (int, error) {
	return c.mo.file.ReadAt(buf, off)
}

func (c *MachOContainer) ReadBytesAtVA(va uint64, n int) ([]byte, error) {
	off, err := c.VAToFileOffset(va)
	if err != nil {
		return nil, err
	}
	avail := c.mo.size - int64(off)
	if avail <= 0 {
		return nil, fmt.Errorf("macho: offset 0x%x at or past end of file", off)
	}
	if int64(n) > avail {
		n = int(avail)
	}
	buf := make([]byte, n)
	_, err = c.mo.file.ReadAt(buf, int64(off))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("macho: read at 0x%x: %w", off, err)
	}
	return buf, nil
}

// openMachO opens and parses a Mach-O binary.
func openMachO(path string) (*MachOFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("macho: open: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("macho: stat: %w", err)
	}

	// Read magic to determine byte order.
	magicBuf := make([]byte, 4)
	_, err = f.ReadAt(magicBuf, 0)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("macho: read magic: %w", err)
	}

	magic := binary.LittleEndian.Uint32(magicBuf)
	var bo binary.ByteOrder

	switch magic {
	case MH_MAGIC_64:
		bo = binary.LittleEndian
	case MH_CIGAM_64:
		bo = binary.BigEndian
	case MH_MAGIC:
		_ = f.Close()
		return nil, fmt.Errorf("macho: 32-bit Mach-O not supported (only 64-bit)")
	case MH_CIGAM:
		_ = f.Close()
		return nil, fmt.Errorf("macho: 32-bit Mach-O not supported (only 64-bit)")
	case MH_FAT_MAGIC, MH_FAT_CIGAM:
		_ = f.Close()
		return nil, fmt.Errorf("macho: fat binary — extract the arm64 slice first (lipo -thin arm64 -output libapp_arm64.so input)")
	default:
		_ = f.Close()
		return nil, fmt.Errorf("macho: bad magic 0x%08x", magic)
	}

	// Read 64-bit header (32 bytes).
	headerBuf := make([]byte, 32)
	_, err = f.ReadAt(headerBuf, 0)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("macho: read header: %w", err)
	}

	mo := &MachOFile{
		file:      f,
		byteOrder: bo,
		size:      info.Size(),
	}
	mo.header.Magic = bo.Uint32(headerBuf[0:4])
	mo.header.CPUType = bo.Uint32(headerBuf[4:8])
	mo.header.CPUSubtype = bo.Uint32(headerBuf[8:12])
	mo.header.FileType = bo.Uint32(headerBuf[12:16])
	mo.header.NCmds = bo.Uint32(headerBuf[16:20])
	mo.header.SizeOfCmds = bo.Uint32(headerBuf[20:24])
	mo.header.Flags = bo.Uint32(headerBuf[24:28])
	mo.header.Reserved = bo.Uint32(headerBuf[28:32])

	// Read load commands.
	offset := int64(32) // after header
	for i := uint32(0); i < mo.header.NCmds; i++ {
		cmdBuf := make([]byte, 8)
		_, err = f.ReadAt(cmdBuf, offset)
		if err != nil {
			break
		}
		cmd := bo.Uint32(cmdBuf[0:4])
		cmdSize := bo.Uint32(cmdBuf[4:8])

		switch cmd {
		case LC_SEGMENT_64:
			if cmdSize < 72 {
				break
			}
			segBuf := make([]byte, cmdSize)
			_, err = f.ReadAt(segBuf, offset)
			if err != nil {
				break
			}
			seg := MachOSegment64{
				Cmd:      cmd,
				CmdSize:  cmdSize,
				VMAddr:   bo.Uint64(segBuf[24:32]),
				VMSize:   bo.Uint64(segBuf[32:40]),
				FileOff:  bo.Uint64(segBuf[40:48]),
				FileSize: bo.Uint64(segBuf[48:56]),
				NSects:   bo.Uint32(segBuf[64:68]),
			}
			copy(seg.SegName[:], segBuf[8:24])
			mo.segments = append(mo.segments, seg)
		case LC_SYMTAB:
			if cmdSize < 24 {
				break
			}
			symBuf := make([]byte, cmdSize)
			_, err = f.ReadAt(symBuf, offset)
			if err != nil {
				break
			}
			symOff := bo.Uint32(symBuf[8:12])
			nSyms := bo.Uint32(symBuf[12:16])
			strOff := bo.Uint32(symBuf[16:20])
			strSize := bo.Uint32(symBuf[20:24])

			// Read symbol table (nlist_64 = 16 bytes each).
			symData := make([]byte, int(nSyms)*16)
			_, err = f.ReadAt(symData, int64(symOff))
			if err != nil {
				break
			}
			for j := uint32(0); j < nSyms; j++ {
				off := int(j) * 16
				mo.symbols = append(mo.symbols, MachOSymbol{
					NStrx:  bo.Uint32(symData[off : off+4]),
					NType:  symData[off+4],
					NSect:  symData[off+5],
					Desc:   bo.Uint16(symData[off+6 : off+8]),
					NValue: bo.Uint64(symData[off+8 : off+16]),
				})
			}

			// Read string table.
			//
			// This used to `break` on failure, as the last statement of the
			// block -- so it exited to exactly where control was already
			// going and the error was simply dropped. The symbol table is
			// parsed by this point; without its string table the names
			// cannot be resolved, so the buffer is dropped rather than left
			// zero-filled and read as a run of empty names.
			mo.strtab = make([]byte, strSize)
			if _, err = f.ReadAt(mo.strtab, int64(strOff)); err != nil {
				mo.strtab = nil
			}
		}

		offset += int64(cmdSize)
	}

	return mo, nil
}

// symbolName returns the name of a Mach-O symbol from the string table.
func (mo *MachOFile) symbolName(sym MachOSymbol) string {
	if sym.NStrx >= uint32(len(mo.strtab)) {
		return ""
	}
	end := sym.NStrx
	for end < uint32(len(mo.strtab)) && mo.strtab[end] != 0 {
		end++
	}
	return string(mo.strtab[sym.NStrx:end])
}
