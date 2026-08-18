package cluster

import (
	"fmt"

	"aotopsy/internal/dartfmt"
)

// readFillInstance captures Instance fill data.
// Format: ReadUnsigned64(unboxed_bitmap) ONCE, then per object:
//
//	for each field offset from header to next_field_offset:
//	  if unboxed: ReadWordWith32BitReads (2 × ReadTagged32)
//	  else: ReadRef (ReadRefId)
//
// header_words: 2 for compressed pointers (tags + hash = 2 × 4 bytes = 2 compressed words).
// header_words: 1 for uncompressed (tags = 1 × 8 bytes = 1 word).
func readFillInstance(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned, compressedPointers, preCanonicalSplit bool) ([]InstanceInfo, error) {
	var result []InstanceInfo
	var bitmap int64
	if !preCanonicalSplit {
		var err error
		bitmap, err = s.ReadUnsigned()
		if err != nil {
			return result, fmt.Errorf("instance(%d) bitmap: %w", cm.CID, err)
		}
	}

	nfo := int(cm.NextFieldOffsetInWords)
	if nfo <= 0 {
		return result, nil
	}
	headerWords := 1
	wordSize := 8
	if compressedPointers {
		headerWords = 2
		wordSize = 4
	}
	numFields := nfo - headerWords
	if numFields < 0 {
		numFields = 0
	}

	ref := cm.StartRef
	for i := int64(0); i < cm.Count; i++ {
		if preCanonicalSplit {
			if _, err := s.ReadByte(); err != nil {
				return result, fmt.Errorf("instance(%d) %d/%d is_canonical: %w", cm.CID, i, cm.Count, err)
			}
		}
		inst := InstanceInfo{
			RefID:         ref,
			CID:           cm.CID,
			HeaderWords:   headerWords,
			NumFieldSlots: numFields,
		}
		for j := 0; j < numFields; j++ {
			fieldWordIdx := headerWords + j
			isUnboxed := (bitmap>>uint(fieldWordIdx))&1 != 0
			// Two 32-bit reads per unboxed slot, always -- and NOT for the
			// reason the TODO that used to sit here gave. It claimed the
			// bitmap granularity is the machine word "not the compressed
			// word", and warned this would "need revisiting if bitmap
			// granularity became compressed-word-sized". Checked against
			// the SDK at 3.9.2: it already IS compressed-word-sized, and
			// nothing needs revisiting.
			//
			// app_snapshot.cc, InstanceSerializationCluster::WriteFill:
			//
			//	while (offset < next_field_offset) {
			//	  if (unboxed_fields_bitmap.Get(offset / kCompressedWordSize)) {
			//	    s->WriteWordWith32BitWrites(value);   // one slot
			//	  } else { ... WriteElementRef(...); }
			//	  offset += kCompressedWordSize;
			//	}
			//
			// so the bitmap is indexed per COMPRESSED word and the loop
			// steps by one. What fixes the read at two is datastream.h:
			//
			//	uword ReadWordWith32BitReads() {
			//	  constexpr intptr_t kNumRead32PerWord =
			//	      kBitsPerWord / kBitsPerInt32;      // 64/32 = 2
			//
			// kBitsPerWord is the MACHINE word, which does not change when
			// pointers are compressed. So the count is 2 on every 64-bit
			// target regardless of compression, and it is the machine word
			// -- not the bitmap -- that would have to change for this to
			// need revisiting.
			//
			// Our loop matches the serializer on both axes: numFields and
			// fieldWordIdx are counted in compressed words when
			// compressedPointers is set (headerWords=2, wordSize=4), which
			// is the same indexing the bitmap uses.
			if isUnboxed {
				if _, err := s.ReadTagged32(); err != nil {
					return result, fmt.Errorf("instance(%d) %d/%d unboxed field %d lo: %w", cm.CID, i, cm.Count, j, err)
				}
				if _, err := s.ReadTagged32(); err != nil {
					return result, fmt.Errorf("instance(%d) %d/%d unboxed field %d hi: %w", cm.CID, i, cm.Count, j, err)
				}
				continue
			}
			fieldRef, err := readRef(s, fillRefUnsigned)
			if err != nil {
				return result, fmt.Errorf("instance(%d) %d/%d ref %d: %w", cm.CID, i, cm.Count, j, err)
			}
			// Byte offset in the same coordinate system BuildClassLayouts
			// uses for FieldInfo: word index from the object start times the
			// word size (4 under compressed pointers, else 8).
			inst.Fields = append(inst.Fields, InstanceFieldRef{
				ByteOffset: int32(fieldWordIdx) * int32(wordSize),
				Ref:        int(fieldRef),
			})
		}
		result = append(result, inst)
		ref++
	}
	return result, nil
}

// skipFillRecord skips Record fill.
// Per object: ReadRef(shape) + num_fields × ReadRef(field).
// skipFillRecord skips Record fill.
// Per object: ReadUnsigned(shape) + num_fields × ReadRef(field).
// num_fields = RecordShape.NumFieldsBitField (lower 16 bits of shape).
