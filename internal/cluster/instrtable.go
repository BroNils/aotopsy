package cluster

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"

	"aotopsy/internal/snapshot"
)

// InstructionsTable holds the parsed InstructionsTable rodata from the data image.
type InstructionsTable struct {
	Length             uint32 // total number of table entries (stubs + code)
	FirstEntryWithCode uint32 // index of first entry that maps to a Code object
	Entries            []InstrTableEntry

	// CanonicalStackMapOffset is the Data header's first word: the offset of
	// the canonicalized global stack-map table, relative to the Data struct.
	// Entries whose payload uses the table-referencing encoding resolve their
	// bitmaps through it.
	CanonicalStackMapOffset uint32

	// RoData is the table's Data struct and everything after it, so an
	// entry's StackMapOffset can be resolved: the SDK's StackMapAt is
	// `reinterpret_cast<uword>(this) + offset` with `this` being the Data
	// struct, so offsets index into this slice directly.
	//
	// This is where AOT stack maps live from Dart 2.16 onwards. The Code
	// object stopped carrying compressed_stackmaps_ then (app_snapshot.cc
	// guards it with kind() == kFullJIT), and the information moved here --
	// so a snapshot with zero CompressedStackMaps clusters still has a stack
	// map for every entry.
	RoData []byte
}

// InstrTableEntry is one entry in the InstructionsTable.
type InstrTableEntry struct {
	PCOffset uint32 // offset from instructions image base
	// StackMapOffset locates this entry's CompressedStackMaps payload within
	// InstructionsTable.RoData. Zero means the entry has no stack map.
	StackMapOffset uint32
}

// CodeRange describes one Code object's instruction region.
type CodeRange struct {
	RefID    int
	OwnerRef int
	Index    int    // ClusterIndex (slot relative to first_entry_with_code)
	PCOffset uint32 // from instructions image base
	Size     uint32 // bytes
}

// dataImageAlignment returns the data image base alignment for a version.
//
// SDK source (snapshot.h DataImage()):
//
//	≤2.18: RoundUp(length(), kMaxObjectAlignment)  → 16 on 64-bit
//	≥2.19: RoundUp(length(), kObjectStartAlignment) → 64
//
// This is an explicit VersionProfile dimension because a future compatibility
// hash must not inherit an alignment from a semver comparison. Verified from
// local SDK snapshot.h: 2.18 uses kMaxObjectAlignment; 2.19 switches to
// kObjectStartAlignment.
func dataImageAlignment(profile *snapshot.VersionProfile) int64 {
	if profile == nil {
		return 0
	}
	return profile.DataImageAlignment
}

// oneByteStringHeaderSize is the size of a OneByteString object header in the
// image. On arm64, WriteROData writes tags (8 bytes) + length (8 bytes via
// WriteTargetWord) = 16 bytes before the payload data.
const oneByteStringHeaderSize = 16

// instrTableDataHeaderSize is sizeof(UntaggedInstructionsTable::Data):
// {canon_offset u32, length u32, first_entry_with_code u32, padding u32}.
const instrTableDataHeaderSize = 16

// ParseInstructionsTable reads the InstructionsTable rodata from the isolate
// snapshot data. It locates the data image, finds the OneByteString object at
// InstructionTableDataOffset, skips its header, and parses the Data header
// and DataEntry array.
func ParseInstructionsTable(data []byte, hdr *Header, profile *snapshot.VersionProfile, isoHeader *snapshot.Header) (*InstructionsTable, error) {
	if hdr == nil {
		return nil, fmt.Errorf("instrtable: nil cluster header")
	}
	if !snapshot.IsExactSupportedProfile(profile) {
		return nil, fmt.Errorf("instrtable: exact supported Dart profile required")
	}
	if isoHeader == nil || isoHeader.TotalSize <= 0 {
		return nil, fmt.Errorf("instrtable: valid isolate snapshot header required")
	}
	if hdr.InstructionTableDataOffset == 0 {
		return nil, fmt.Errorf("instrtable: no instruction table data offset")
	}

	align := dataImageAlignment(profile)
	if align <= 0 {
		return nil, fmt.Errorf("instrtable: unverified data-image alignment")
	}
	// SDK formula (runtime/vm/snapshot.h, verified at tags 2.12.0 and 3.9.2):
	//
	//   int64_t large_length() const {
	//     return Read<int64_t>(kLengthOffset) + kMagicSize;   // + 4
	//   }
	//   intptr_t length() const { return large_length(); }
	//   const uint8_t* DataImage() const {
	//     uword offset = Utils::RoundUp(length(), <align>);
	//     return Addr() + offset;
	//   }
	//
	// So length() INCLUDES the 4-byte magic: the field stored in the buffer
	// excludes it (set_length writes value - kMagicSize) and length() adds it
	// back. Header.Length here is the stored field; Header.TotalSize is
	// Length + 4 -- i.e. TotalSize is the SDK's length(), and it is what must
	// be rounded up. A previous change swapped these on the opposite reading
	// of the same code and placed the data image `align` bytes too low.
	diStart, ok := roundUpChecked(isoHeader.TotalSize, align)
	if !ok {
		return nil, fmt.Errorf("instrtable: invalid data image start size=%d align=%d", isoHeader.TotalSize, align)
	}
	tableObjOff, ok := checkedAddInt64(diStart, hdr.InstructionTableDataOffset)
	if !ok || tableObjOff < 0 {
		return nil, fmt.Errorf("instrtable: table offset overflow data_image=%d relative=%d", diStart, hdr.InstructionTableDataOffset)
	}

	// Minimum: oneByteStringHeader + Data header + 0 entries
	minSize, ok := checkedAddInt64(tableObjOff, oneByteStringHeaderSize+instrTableDataHeaderSize)
	if !ok || minSize > int64(len(data)) {
		return nil, fmt.Errorf("instrtable: data too short for table at offset %d (need %d, have %d)",
			tableObjOff, minSize, len(data))
	}

	// Skip OneByteString header to reach Data payload.
	payloadOff := int(tableObjOff) + oneByteStringHeaderSize

	// Read Data header: {canon_offset u32, length u32, first_entry_with_code u32, padding u32}
	canonOff := binary.LittleEndian.Uint32(data[payloadOff : payloadOff+4])
	length := binary.LittleEndian.Uint32(data[payloadOff+4 : payloadOff+8])
	firstCode := binary.LittleEndian.Uint32(data[payloadOff+8 : payloadOff+12])

	if length == 0 {
		return &InstructionsTable{}, nil
	}
	if firstCode > length {
		return nil, fmt.Errorf("instrtable: first_entry_with_code %d > length %d", firstCode, length)
	}

	// Read DataEntry array.
	entriesOff := payloadOff + instrTableDataHeaderSize
	if entriesOff < 0 || entriesOff > len(data) || uint64(length) > uint64((len(data)-entriesOff)/8) {
		return nil, fmt.Errorf("instrtable: data too short for %d entries (need %d, have %d)",
			length, uint64(entriesOff)+uint64(length)*8, len(data))
	}

	entries := make([]InstrTableEntry, length)
	for i := range entries {
		off := entriesOff + i*8
		entries[i] = InstrTableEntry{
			PCOffset:       binary.LittleEndian.Uint32(data[off : off+4]),
			StackMapOffset: binary.LittleEndian.Uint32(data[off+4 : off+8]),
		}
	}

	return &InstructionsTable{
		Length:                  length,
		FirstEntryWithCode:      firstCode,
		Entries:                 entries,
		CanonicalStackMapOffset: canonOff,
		RoData:                  data[payloadOff:],
	}, nil
}

// StackMapsAt decodes the CompressedStackMaps payload of table entry i.
//
// Returns nil when the entry has none, or when the table predates the move of
// stack maps into the instructions table (Dart <= 2.15, where they are still
// on the Code object and reached through Code.CompressedStackMapsRef).
//
// Offsets are relative to the Data struct, matching the SDK:
//
//	const Payload* StackMapAt(intptr_t offset) const {
//	  return reinterpret_cast<Payload*>(reinterpret_cast<uword>(this) + offset);
//	}
func (t *InstructionsTable) StackMapsAt(i int) ([]StackMapEntry, error) {
	if t == nil || i < 0 || i >= len(t.Entries) {
		return nil, nil
	}
	off := t.Entries[i].StackMapOffset
	if off == 0 || int(off) >= len(t.RoData) {
		return nil, nil
	}
	var global []byte
	if c := t.CanonicalStackMapOffset; c != 0 && int(c) < len(t.RoData) {
		global = t.RoData[c:]
	}
	return DecodeCompressedStackMaps(t.RoData[off:], global)
}

// HasStackMaps reports whether this table carries stack maps at all, so a
// caller can tell "this build has none" from "we did not look".
func (t *InstructionsTable) HasStackMaps() bool {
	if t == nil || len(t.RoData) == 0 {
		return false
	}
	for i := range t.Entries {
		if t.Entries[i].StackMapOffset != 0 {
			return true
		}
	}
	return false
}

// ResolveCodeRanges maps each CodeEntry to its instruction byte range using the
// InstructionsTable. Returns sorted CodeRange slices (by PCOffset).
func ResolveCodeRanges(codes []CodeEntry, table *InstructionsTable) ([]CodeRange, error) {
	if table == nil || len(table.Entries) == 0 {
		return nil, nil
	}

	// Collect pc_offsets for all main codes.
	var ranges []CodeRange
	for i := range codes {
		c := &codes[i]
		if c.ClusterIndex < 0 {
			continue
		}
		slot := int(table.FirstEntryWithCode) + c.ClusterIndex
		if slot < 0 || slot >= len(table.Entries) {
			return nil, fmt.Errorf("instrtable: code ref %d index %d maps to slot %d (table has %d entries)",
				c.RefID, c.ClusterIndex, slot, len(table.Entries))
		}
		ranges = append(ranges, CodeRange{
			RefID:    c.RefID,
			OwnerRef: c.OwnerRef,
			Index:    c.ClusterIndex,
			PCOffset: table.Entries[slot].PCOffset,
		})
	}

	// Sort by PCOffset.
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].PCOffset < ranges[j].PCOffset
	})

	// Compute sizes by diffing adjacent offsets.
	for i := 0; i < len(ranges)-1; i++ {
		ranges[i].Size = ranges[i+1].PCOffset - ranges[i].PCOffset
	}
	// Last range: size unknown from table alone; caller must provide code region end.

	return ranges, nil
}

// ResolveStubRanges creates CodeRange entries for stub/trampoline entries in
// the instructions table (indices 0 through FirstEntryWithCode-1). These
// entries have valid PCOffsets but are not associated with snapshot Code objects.
// RefID is set to -1 to distinguish them from code-object ranges.
func ResolveStubRanges(table *InstructionsTable) []CodeRange {
	if table == nil || table.FirstEntryWithCode == 0 {
		return nil
	}

	// P5-3 (D-021): Validate FirstEntryWithCode against Entries length
	// to prevent index-out-of-range panic on corrupt snapshot data.
	fec := int(table.FirstEntryWithCode)
	if fec > len(table.Entries) {
		fec = len(table.Entries)
	}
	if fec == 0 {
		return nil
	}

	ranges := make([]CodeRange, 0, fec)
	for i := 0; i < fec; i++ {
		ranges = append(ranges, CodeRange{
			RefID:    -1,
			OwnerRef: -1,
			Index:    i,
			PCOffset: table.Entries[i].PCOffset,
		})
	}

	// Sort by PCOffset.
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].PCOffset < ranges[j].PCOffset
	})

	// Compute sizes by diffing adjacent offsets.
	for i := 0; i < len(ranges)-1; i++ {
		ranges[i].Size = ranges[i+1].PCOffset - ranges[i].PCOffset
	}
	// Last stub: size set by caller (either first code entry or code region end).

	return ranges
}

// MergeRanges merges stub and code ranges into a single sorted slice.
// Sizes are recomputed from adjacent entries after merge. The caller must
// call SetLastRangeSize on the result.
func MergeRanges(stubs, codes []CodeRange) []CodeRange {
	all := make([]CodeRange, 0, len(stubs)+len(codes))
	all = append(all, stubs...)
	all = append(all, codes...)

	sort.Slice(all, func(i, j int) bool {
		return all[i].PCOffset < all[j].PCOffset
	})

	// Recompute sizes from sorted order.
	for i := 0; i < len(all)-1; i++ {
		all[i].Size = all[i+1].PCOffset - all[i].PCOffset
	}
	// Last entry: size 0 until caller sets it.
	if len(all) > 0 {
		all[len(all)-1].Size = 0
	}

	return all
}

// SetLastRangeSize sets the size of the last CodeRange based on the total
// code region end offset. codeEndOffset is relative to the instructions image base.
func SetLastRangeSize(ranges []CodeRange, codeEndOffset uint32) {
	if len(ranges) == 0 {
		return
	}
	last := &ranges[len(ranges)-1]
	if codeEndOffset > last.PCOffset {
		last.Size = codeEndOffset - last.PCOffset
	}
}

// ResolveCodeRangesFromTextOffset builds CodeRange entries directly from
// CodeEntry.TextOffset values (v2.10-v2.15, pre-InstructionsTable era).
// TextOffset is the direct byte offset into the instructions image for each
// Code object's instructions. Returns sorted ranges with sizes computed from
// adjacent offsets. Caller must call SetLastRangeSize on the result.
func ResolveCodeRangesFromTextOffset(codes []CodeEntry) []CodeRange {
	var ranges []CodeRange
	for i := range codes {
		c := &codes[i]
		if c.ClusterIndex < 0 {
			continue // deferred code, no instructions
		}
		ranges = append(ranges, CodeRange{
			RefID:    c.RefID,
			OwnerRef: c.OwnerRef,
			Index:    c.ClusterIndex,
			PCOffset: uint32(c.TextOffset),
		})
	}

	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].PCOffset != ranges[j].PCOffset {
			return ranges[i].PCOffset < ranges[j].PCOffset
		}
		// Stable secondary key so runs of shared offsets come out in the
		// same order on every run.
		return ranges[i].RefID < ranges[j].RefID
	})

	// Compute sizes by diffing against the next DISTINCT offset.
	//
	// Several Code objects legitimately share one instructions payload: the
	// AOT compiler deduplicates identical code, so e.g. 181 Codes in the
	// 2.12 sample all point at text offset 0xc8f4. Diffing strictly adjacent
	// entries gave every one of them except the last a size of 0, and
	// RunDisasmStage skips size-0 ranges -- 852 functions silently vanished
	// even after the text offsets themselves were fixed.
	for i := 0; i < len(ranges); {
		j := i
		for j < len(ranges) && ranges[j].PCOffset == ranges[i].PCOffset {
			j++
		}
		if j < len(ranges) {
			size := ranges[j].PCOffset - ranges[i].PCOffset
			for k := i; k < j; k++ {
				ranges[k].Size = size
			}
		}
		i = j
	}

	return ranges
}

func roundUp(v, align int64) int64 {
	return (v + align - 1) &^ (align - 1)
}

func roundUpChecked(v, align int64) (int64, bool) {
	if v < 0 || align <= 0 || align&(align-1) != 0 || v > math.MaxInt64-(align-1) {
		return 0, false
	}
	return roundUp(v, align), true
}

func checkedAddInt64(a, b int64) (int64, bool) {
	if b > 0 && a > math.MaxInt64-b {
		return 0, false
	}
	if b < 0 && a < math.MinInt64-b {
		return 0, false
	}
	return a + b, true
}
