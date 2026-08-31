package cluster

// CompressedStackMaps decoding.
//
// A CompressedStackMaps (CSM) payload is a uint32_t flags_and_size header
// followed by LEB128-encoded entries. Three CSM types determined by bit fields:
//
//   GlobalTableBit (bit 0) | UsesTableBit (bit 1) | Type
//   false                  | false                | Standalone: full stack maps
//   false                  | true                 | Table-referencing: offsets into global table
//   true                   | false                | Global table: shared stack map data
//
// SizeField (bits 2+) = payload length in bytes (excluding the 4-byte header).
//
// Each standalone entry has:
//   - PC offset delta (LEB128 unsigned, accumulated from 0)
//   - spill slot bit count (LEB128 unsigned)
//   - non-spill slot bit count (LEB128 unsigned)
//   - bitmap body: (spill_bits + non_spill_bits) bits, tightly packed
//
// Table-referencing entries have:
//   - PC offset delta (LEB128 unsigned)
//   - global table offset (LEB128 unsigned)
//
// Global table entries have:
//   - spill slot bit count (LEB128 unsigned)
//   - non-spill slot bit count (LEB128 unsigned)
//   - bitmap body
//
// Source: runtime/vm/raw_object.h @3.12.2 — UntaggedCompressedStackMaps::Payload
// Verified via gh api to dart-lang/sdk at tag 3.12.2.

// StackMapEntry is one decoded CSM entry at a specific PC offset.
type StackMapEntry struct {
	PCOffset      uint32 // accumulated PC offset from function entry
	SpillSlotBits []byte // bitmap: bit i = spill slot i holds a live object
	NonSpillBits  []byte // bitmap: bit i = non-spill register i holds a live object
}

// IsSpillObject returns whether spill slot index holds a live tagged object pointer.
func (e StackMapEntry) IsSpillObject(slotIndex int) bool {
	if slotIndex < 0 {
		return false
	}
	byteIdx := slotIndex / 8
	bitIdx := uint(slotIndex % 8)
	if byteIdx >= len(e.SpillSlotBits) {
		return false
	}
	return (e.SpillSlotBits[byteIdx] & (1 << bitIdx)) != 0
}

// IsNonSpillObject returns whether non-spill register index holds a live tagged object pointer.
func (e StackMapEntry) IsNonSpillObject(regIndex int) bool {
	if regIndex < 0 {
		return false
	}
	byteIdx := regIndex / 8
	bitIdx := uint(regIndex % 8)
	if byteIdx >= len(e.NonSpillBits) {
		return false
	}
	return (e.NonSpillBits[byteIdx] & (1 << bitIdx)) != 0
}

// DecodeCompressedStackMaps decodes a CSM payload into per-PC register/spill
// liveness entries. Returns entries sorted by PC offset.
//
// For global-table-referencing CSMs (UsesTableBit=true), globalTable provides
// the payload of the canonicalized global table CSM (whose GlobalTableBit=true)
// to resolve each entry's spill and non-spill bitmaps.
func DecodeCompressedStackMaps(payload, globalTable []byte) ([]StackMapEntry, error) {
	if len(payload) < 4 {
		return nil, nil
	}
	// Read flags_and_size header (uint32_t, little-endian, packed without alignment).
	flagsAndSize := uint32(payload[0]) | uint32(payload[1])<<8 | uint32(payload[2])<<16 | uint32(payload[3])<<24
	globalTableBit := flagsAndSize&1 != 0
	usesTableBit := (flagsAndSize>>1)&1 != 0
	length := flagsAndSize >> 2 // SizeField starts at bit 2

	if int(length)+4 > len(payload) {
		return nil, nil // truncated payload
	}

	data := payload[4 : 4+int(length)]
	pos := 0

	// Global table CSM: entries have no PC offset, just bitmaps.
	if globalTableBit {
		spillBits, nonSpillBits, _, err := readCSMBitmapBody(data, pos)
		if err != nil {
			return nil, err
		}
		return []StackMapEntry{{PCOffset: 0, SpillSlotBits: spillBits, NonSpillBits: nonSpillBits}}, nil
	}

	// Prepare global table data if referenced.
	var gtData []byte
	if usesTableBit && len(globalTable) >= 4 {
		gtFlagsAndSize := uint32(globalTable[0]) | uint32(globalTable[1])<<8 | uint32(globalTable[2])<<16 | uint32(globalTable[3])<<24
		gtLen := gtFlagsAndSize >> 2
		if int(gtLen)+4 <= len(globalTable) {
			gtData = globalTable[4 : 4+int(gtLen)]
		}
	}

	var entries []StackMapEntry
	var currentPC uint32

	for pos < len(data) {
		if usesTableBit {
			// Table-referencing entry: PC delta + global table offset.
			pcDelta, newPos, err := readLEB128(data, pos)
			if err != nil {
				break
			}
			pos = newPos
			gtOffset, newPos2, err := readLEB128(data, pos)
			if err != nil {
				break
			}
			pos = newPos2
			currentPC += uint32(pcDelta)
			var spillBits, nonSpillBits []byte
			if len(gtData) > 0 && int(gtOffset) < len(gtData) {
				spillBits, nonSpillBits, _, _ = readCSMBitmapBody(gtData, int(gtOffset))
			}
			entries = append(entries, StackMapEntry{
				PCOffset:      currentPC,
				SpillSlotBits: spillBits,
				NonSpillBits:  nonSpillBits,
			})
		} else {
			// Standalone entry: PC delta + spill bits + non-spill bits + bitmap.
			pcDelta, newPos, err := readLEB128(data, pos)
			if err != nil {
				break
			}
			pos = newPos
			spillCount, newPos2, err := readLEB128(data, pos)
			if err != nil {
				break
			}
			pos = newPos2
			nonSpillCount, newPos3, err := readLEB128(data, pos)
			if err != nil {
				break
			}
			pos = newPos3
			totalBits := int(spillCount) + int(nonSpillCount)
			totalBytes := (totalBits + 7) / 8
			if pos+totalBytes > len(data) {
				break
			}
			bitmap := data[pos : pos+totalBytes]
			pos += totalBytes
			currentPC += uint32(pcDelta)
			spillBytes := (int(spillCount) + 7) / 8
			nonSpillBytes := (int(nonSpillCount) + 7) / 8
			spillBits := bitmap[:spillBytes]
			nonSpillStart := spillBytes
			nonSpillBits := bitmap[nonSpillStart : nonSpillStart+nonSpillBytes]
			entries = append(entries, StackMapEntry{
				PCOffset:      currentPC,
				SpillSlotBits: append([]byte(nil), spillBits...),
				NonSpillBits:  append([]byte(nil), nonSpillBits...),
			})
		}
	}

	return entries, nil
}

// readLEB128 reads an unsigned LEB128 value from data at position pos.
// Returns the value, the new position, and any error.
func readLEB128(data []byte, pos int) (uint64, int, error) {
	var result uint64
	var shift uint
	for pos < len(data) {
		b := data[pos]
		pos++
		result |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return result, pos, nil
		}
		shift += 7
		if shift >= 64 {
			return 0, pos, nil // overflow guard
		}
	}
	return 0, pos, nil
}

// readCSMBitmapBody reads spill/non-spill bit counts and the bitmap body
// from a global table entry at position pos.
func readCSMBitmapBody(data []byte, pos int) ([]byte, []byte, int, error) {
	spillCount, newPos, err := readLEB128(data, pos)
	if err != nil {
		return nil, nil, pos, err
	}
	pos = newPos
	nonSpillCount, newPos2, err := readLEB128(data, pos)
	if err != nil {
		return nil, nil, pos, err
	}
	pos = newPos2
	totalBits := int(spillCount) + int(nonSpillCount)
	totalBytes := (totalBits + 7) / 8
	if pos+totalBytes > len(data) {
		return nil, nil, pos, nil
	}
	bitmap := data[pos : pos+totalBytes]
	pos += totalBytes
	spillBits := bitmap[:(int(spillCount)+7)/8]
	nonSpillStart := (int(spillCount) + 7) / 8
	nonSpillBits := bitmap[nonSpillStart : nonSpillStart+(int(nonSpillCount)+7)/8]
	return append([]byte(nil), spillBits...), append([]byte(nil), nonSpillBits...), pos, nil
}
