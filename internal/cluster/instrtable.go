package cluster

import (
	"encoding/binary"
	"fmt"
	"sort"

	"aotopsy/internal/snapshot"
)

// InstructionsTable holds the parsed InstructionsTable rodata from the data image.
type InstructionsTable struct {
	Length             uint32 // total number of table entries (stubs + code)
	FirstEntryWithCode uint32 // index of first entry that maps to a Code object
	Entries            []InstrTableEntry
}

// InstrTableEntry is one entry in the InstructionsTable.
type InstrTableEntry struct {
	PCOffset       uint32 // offset from instructions image base
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

// dataImageAlignment returns the data image alignment for a version.
// Dart ≤2.18 uses kMaxObjectAlignment=16; Dart ≥2.19 uses kObjectStartAlignment=64.
// Uses ObjectAlignment field when explicitly set (>0), otherwise falls back to
// the TopLevelCid16 proxy for backward compatibility with older version profiles.
func dataImageAlignment(profile *snapshot.VersionProfile) int64 {
	if profile.ObjectAlignment > 0 {
		return int64(profile.ObjectAlignment)
	}
	if profile.TopLevelCid16 {
		return 16
	}
	return 64
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
	if hdr.InstructionTableDataOffset == 0 {
		return nil, fmt.Errorf("instrtable: no instruction table data offset")
	}

	align := dataImageAlignment(profile)
	// SDK formula: DataImage = Addr() + RoundUp(length(), align) where length()
	// EXCLUDES the 4-byte magic. TotalSize = Length + 4, so round up Length.
	// Using TotalSize crosses a rounding boundary for ~25% (align=16) / ~6%
	// (align=64) of snapshots, placing the image `align` bytes too high.
	diStart := roundUp(isoHeader.Length, align)
	tableObjOff := diStart + hdr.InstructionTableDataOffset

	// Minimum: oneByteStringHeader + Data header + 0 entries
	minSize := tableObjOff + oneByteStringHeaderSize + instrTableDataHeaderSize
	if int64(len(data)) < minSize {
		return nil, fmt.Errorf("instrtable: data too short for table at offset %d (need %d, have %d)",
			tableObjOff, minSize, len(data))
	}

	// Skip OneByteString header to reach Data payload.
	payloadOff := int(tableObjOff) + oneByteStringHeaderSize

	// Read Data header: {canon_offset u32, length u32, first_entry_with_code u32, padding u32}
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
	entryBytes := int(length) * 8
	if entriesOff+entryBytes > len(data) {
		return nil, fmt.Errorf("instrtable: data too short for %d entries (need %d, have %d)",
			length, entriesOff+entryBytes, len(data))
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
		Length:             length,
		FirstEntryWithCode: firstCode,
		Entries:            entries,
	}, nil
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
		return ranges[i].PCOffset < ranges[j].PCOffset
	})

	// Compute sizes by diffing adjacent offsets.
	for i := 0; i < len(ranges)-1; i++ {
		ranges[i].Size = ranges[i+1].PCOffset - ranges[i].PCOffset
	}

	return ranges
}

func roundUp(v, align int64) int64 {
	return (v + align - 1) &^ (align - 1)
}
