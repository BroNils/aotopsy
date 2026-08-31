package cluster

import (
	"fmt"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

// instanceCarriesUnboxedBitmap reports whether the Instance cluster writes its
// own copy of the unboxed-fields bitmap into its fill.
//
// InstanceSerializationCluster::WriteFill gained
//
//	s->WriteUnsigned64(CalculateTargetUnboxedFieldsBitmap(s, cid_).Value());
//
// after 2.10: at that tag clustered_snapshot.cc mentions the bitmap only in
// the Class cluster (write at WriteClass, read/skip in ClassDeserialization-
// Cluster::ReadFill), while 2.12.0, 2.13.0 and 2.14.0 all carry the extra
// Instance-cluster pair as well.
func instanceCarriesUnboxedBitmap(profile *snapshot.VersionProfile) bool {
	return snapshot.VersionAtLeast(profile.DartVersion, "2.12.0")
}

// readFillInstance captures Instance fill data. Per object:
//
//	[2.10 only] Read<bool>(is_canonical)
//	for each field offset from header to next_field_offset:
//	  if unboxed: ReadWordWith32BitReads (2 × ReadTagged32)
//	  else: ReadRef
//
// The unboxed bitmap says which slots are raw machine words instead of refs,
// and WHERE it comes from is version-dependent:
//
//	2.10       the Class cluster's fill, per class id -- the Instance cluster
//	           writes none of its own. Passed in via classBitmaps.
//	>= 2.12    the Instance cluster's own fill, one ReadUnsigned64 up front.
//
// Treating 2.10 like the later versions leaves the bitmap zero, so every
// unboxed slot is read as one ref instead of two 32-bit reads. That silently
// under-runs the fill -- on a real 2.10 sample by 392 bytes, identically on
// arm64 and x64 -- which lands the roots section 392 bytes early and takes the
// whole dispatch table with it.
//
// header_words: 2 for compressed pointers (tags + hash = 2 × 4 bytes = 2 compressed words).
// header_words: 1 for uncompressed (tags = 1 × 8 bytes = 1 word).
func readFillInstance(s *dartfmt.Stream, cm *ClusterMeta, profile *snapshot.VersionProfile, classBitmaps map[int32]uint64) ([]InstanceInfo, error) {
	var result []InstanceInfo
	fillRefUnsigned := profile.FillRefUnsigned
	compressedPointers := profile.CompressedPointers
	preCanonicalSplit := profile.PreCanonicalSplit

	var bitmap uint64
	if instanceCarriesUnboxedBitmap(profile) {
		v, err := s.ReadUnsigned()
		if err != nil {
			return result, fmt.Errorf("instance(%d) bitmap: %w", cm.CID, err)
		}
		bitmap = uint64(v)
	} else {
		bitmap = classBitmaps[int32(cm.CID)]
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
			isUnboxed := fieldWordIdx < 64 && (bitmap>>uint(fieldWordIdx))&1 != 0
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
