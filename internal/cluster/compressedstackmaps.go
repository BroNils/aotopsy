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
//
// Both bitmaps describe FRAME SLOTS, not registers, and both say "holds a
// tagged pointer" rather than "is live". stack_frame.cc walks them like this:
//
//	intptr_t spill_slot_count = it.SpillSlotBitCount();
//	for (bit = 0; bit < spill_slot_count; ++bit) {
//	  if (it.IsObject(bit)) visitor->VisitPointer(last);
//	  --last;                       // last starts at fp + first_local_from_fp
//	}
//	for (bit = it.Length()-1; bit >= spill_slot_count; --bit) {
//	  if (it.IsObject(bit)) visitor->VisitPointer(first);
//	  ++first;                      // first starts at sp
//	}
//
// So spill bit i is the slot i words below the first local, and the remaining
// bits are the saved-register and slow-path-argument slots at the top of the
// frame, consumed from the END of the bitmap downwards.
//
// The distinction matters: a slot holding an unboxed double has a clear bit
// and is perfectly live, so a clear bit proves nothing about liveness. Only
// SET bits carry information -- "this slot definitely holds a tagged object".
//
// The two bitmaps are ONE tightly packed bit array, not two byte arrays: the
// saved-slot bits begin at bit index SpillSlotCount, which is almost never a
// byte boundary. An earlier version of this decoder split the payload at
// ceil(SpillSlotCount/8) bytes, which misaligned every saved-slot bit whenever
// the spill count was not a multiple of 8, and could slice past the end of the
// payload because ceil(a/8)+ceil(b/8) exceeds ceil((a+b)/8). Keeping the single
// array and the two counts, exactly as the VM does, removes both faults.
type StackMapEntry struct {
	PCOffset       uint32 // accumulated PC offset from function entry
	SpillSlotCount int    // number of leading bits describing spill slots
	SavedSlotCount int    // number of trailing bits describing saved slots
	// Bits is the packed bitmap, LSB-first within each byte, matching
	// UntaggedCompressedStackMaps::Payload. Index it through the accessors.
	Bits []byte
}

// Length is the total bit count, matching CompressedStackMapsIterator::Length.
func (e StackMapEntry) Length() int { return e.SpillSlotCount + e.SavedSlotCount }

// isObject is the VM's IsObject(bit_index): LSB-first within each byte.
func (e StackMapEntry) isObject(bitIndex int) bool {
	if bitIndex < 0 || bitIndex >= e.Length() {
		return false
	}
	byteIdx := bitIndex / 8
	if byteIdx >= len(e.Bits) {
		return false
	}
	return (e.Bits[byteIdx] & (1 << uint(bitIndex%8))) != 0
}

// IsSpillObject reports whether spill slot i definitely holds a tagged object
// pointer at this safepoint. False means "not a pointer", which includes
// unboxed live values -- it does not mean the slot is dead.
func (e StackMapEntry) IsSpillObject(slotIndex int) bool {
	if slotIndex < 0 || slotIndex >= e.SpillSlotCount {
		return false
	}
	return e.isObject(slotIndex)
}

// SavedSlotIsObject reports whether the saved-register slot at `slotsFromSP`
// words above SP holds a tagged object.
//
// The VM reads these bits backwards -- the slot at SP is the LAST bit of the
// whole bitmap, not the first saved-slot bit -- so this is not an index into
// the payload and must not be used as one. An earlier accessor here was named
// IsNonSpillObject and documented as taking a *register index*, which is
// neither the right domain nor the right order; the emitter used it to delete
// register values and was wrong on both counts.
func (e StackMapEntry) SavedSlotIsObject(slotsFromSP int) bool {
	if slotsFromSP < 0 || slotsFromSP >= e.SavedSlotCount {
		return false
	}
	return e.isObject(e.Length() - 1 - slotsFromSP)
}

// ObjectSpillSlotOffsets returns the frame-pointer-relative BYTE offsets of
// the spill slots that definitely hold tagged objects at this safepoint.
//
// Spill slot i sits at fp + (kFirstLocalSlotFromFp - i) * wordSize, with
// kFirstLocalSlotFromFp = -3 on both ARM64 and x64 (stack_frame_arm64.h:42,
// stack_frame_x64.h:45). Only set bits are reported: a clear bit means "not a
// pointer", not "unused".
func (e StackMapEntry) ObjectSpillSlotOffsets(wordSize int64) []int64 {
	var out []int64
	for i := 0; i < e.SpillSlotCount; i++ {
		if e.IsSpillObject(i) {
			out = append(out, (FirstLocalSlotFromFP-int64(i))*wordSize)
		}
	}
	return out
}

// FirstLocalSlotFromFP is kFirstLocalSlotFromFp: the word offset from FP to
// the first local slot. -3 on ARM64 (stack_frame_arm64.h:42) and on x64
// (stack_frame_x64.h:45).
const FirstLocalSlotFromFP int64 = -3

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
		e, _, ok := readCSMBitmapBody(data, pos)
		if !ok {
			return nil, nil
		}
		return []StackMapEntry{e}, nil
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
			var e StackMapEntry
			if len(gtData) > 0 && int(gtOffset) < len(gtData) {
				e, _, _ = readCSMBitmapBody(gtData, int(gtOffset))
			}
			e.PCOffset = currentPC
			entries = append(entries, e)
		} else {
			// Standalone entry: PC delta, then the same body shape the
			// global table uses.
			pcDelta, newPos, err := readLEB128(data, pos)
			if err != nil {
				break
			}
			pos = newPos
			e, newPos2, ok := readCSMBitmapBody(data, pos)
			if !ok {
				break
			}
			pos = newPos2
			currentPC += uint32(pcDelta)
			e.PCOffset = currentPC
			entries = append(entries, e)
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

// readCSMBitmapBody reads the two bit counts and the packed bitmap that follow
// them, which is the body shape shared by standalone entries and global-table
// entries. It returns the entry (without a PC offset), the position just past
// the body, and whether the body was well-formed.
//
// A truncated or absurd body returns ok=false rather than a partial entry:
// these payloads are attacker-influenced binary data, and the previous version
// sliced first and checked later, which panicked on a real 2.16.0 sample.
func readCSMBitmapBody(data []byte, pos int) (StackMapEntry, int, bool) {
	spillCount, newPos, err := readLEB128(data, pos)
	if err != nil {
		return StackMapEntry{}, pos, false
	}
	pos = newPos
	savedCount, newPos2, err := readLEB128(data, pos)
	if err != nil {
		return StackMapEntry{}, pos, false
	}
	pos = newPos2
	// Guard the addition itself: both counts are LEB128 and unvalidated.
	const maxBits = 1 << 20
	if spillCount > maxBits || savedCount > maxBits {
		return StackMapEntry{}, pos, false
	}
	totalBytes := (int(spillCount) + int(savedCount) + 7) / 8
	if pos+totalBytes > len(data) {
		return StackMapEntry{}, pos, false
	}
	e := StackMapEntry{
		SpillSlotCount: int(spillCount),
		SavedSlotCount: int(savedCount),
		Bits:           append([]byte(nil), data[pos:pos+totalBytes]...),
	}
	return e, pos + totalBytes, true
}
