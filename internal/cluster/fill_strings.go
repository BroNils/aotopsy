package cluster

import (
	"encoding/binary"
	"fmt"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/sdk"
	"aotopsy/internal/snapshot"
)

// readFillStrings reads the fill data for a String cluster.
// When oldFormat is true (≤2.14), length is plain ReadUnsigned and
// isTwoByte is determined by the cluster CID (ct.TwoByteString).
// When oldFormat is false (≥2.16), length is encoded as (length<<1)|flag.
func readFillStrings(s *dartfmt.Stream, cm *ClusterMeta, oldFormat bool, ct *snapshot.CIDTable) ([]ParsedString, error) {
	count := int(cm.Count)
	if count <= 0 {
		return nil, nil
	}

	// In old format, the CID determines one-byte vs two-byte for the entire cluster.
	cidIsTwoByte := oldFormat && ct != nil && cm.CID == ct.TwoByteString

	strings := make([]ParsedString, 0, count)
	ref := cm.StartRef

	for i := 0; i < count; i++ {
		encoded, err := s.ReadUnsigned()
		if err != nil {
			return strings, fmt.Errorf("string %d/%d encoded: %w", i, count, err)
		}

		var length int
		var isTwoByte bool
		if oldFormat {
			length = int(encoded)
			isTwoByte = cidIsTwoByte
		} else {
			length = int(encoded >> 1)
			isTwoByte = (encoded & 1) != 0
		}

		var value string
		if isTwoByte {
			nbytes := length * 2
			raw, err := s.ReadBytes(nbytes)
			if err != nil {
				return strings, fmt.Errorf("string %d/%d data (%d bytes): %w", i, count, nbytes, err)
			}
			runes := make([]rune, length)
			for j := 0; j < length; j++ {
				runes[j] = rune(uint16(raw[j*2]) | uint16(raw[j*2+1])<<8)
			}
			value = string(runes)
		} else {
			raw, err := s.ReadBytes(length)
			if err != nil {
				return strings, fmt.Errorf("string %d/%d data (%d bytes): %w", i, count, length, err)
			}
			value = string(raw)
		}

		strings = append(strings, ParsedString{
			RefID:     ref,
			Value:     value,
			IsOneByte: !isTwoByte,
		})
		ref++
	}

	return strings, nil
}

// extractRODataStrings reads string data from the data image for ROData string clusters.
// When strings use ROData format (non-compressed-pointers), the string bytes live
// in the data image region of the snapshot, not in the fill stream.
// The alloc phase recorded offset deltas in cm.Lengths.
// dataImageObjStart is the byte offset within data[] where ROData objects begin.
//
// The alignment shift and CID tag decode are version-dependent:
//   - alignment: dataImageAlignment(profile) — 16 for ≤2.18, 64 for ≥2.19
//     (was hardcoded << 5 = 32, matching NEITHER — P0-3/D-001)
//   - CID decode: uses DecodeTags (bits 12-31, 20-bit mask) for v3.x+
//     (was hardcoded >> 16 & 0xFFFF, wrong for CIDs > 65535 — P0-4/D-002)
func extractRODataStrings(data []byte, cm *ClusterMeta, ct *snapshot.CIDTable, dataImageObjStart int64, profile *snapshot.VersionProfile, isVM bool) []ParsedString {
	if len(cm.Lengths) == 0 || dataImageObjStart <= 0 {
		return nil
	}

	// The ROData running_offset delta is encoded in units of kObjectAlignment
	// (RODataDeserializationCluster::ReadAlloc: `running_offset += ReadUnsigned()
	// << kObjectAlignmentLog2`). kObjectAlignment = 2*kWordSize = 16 on 64-bit
	// (kObjectAlignmentLog2 = 4). This is a DIFFERENT, smaller alignment than the
	// data-image BASE alignment (kObjectStartAlignment = 64 for >=2.19, applied in
	// dataImageObjStart) — the two must not be conflated. The ROData path only
	// runs for non-compressed-pointers snapshots, which are 64-bit in practice.
	alignShift := uint(4)

	// No per-snapshot header adjustment: with the correct image-base alignment
	// (kObjectStartAlignment, applied in dataImageObjStart) and the correct delta
	// stride (kObjectAlignment=16, alignShift=4 above), the cumulative
	// running_offset lands exactly on each object header for BOTH the VM and the
	// isolate data images -- verified against real cid=94 OneByteString headers in
	// both. The previous isVM-only +16 fudge only compensated for a wrong stride.
	headerAdjust := int64(0)
	_ = isVM

	runningOffset := int64(0)
	ref := cm.StartRef
	var strings []ParsedString

	for i := 0; i < len(cm.Lengths); i++ {
		// C-3 fix: delta is the offset from DataImage start to this object.
		// Objects begin at DataImage + kHeaderSize (16 bytes image header).
		// GetObjectAt(running_offset) = DataImage + running_offset.
		// But our dataImageObjStart = DataImage offset within data[].
		// The image header (kHeaderSize=16) is at DataImage[0..15].
		// First object is at DataImage+16, but CID there may be 0 (padding).
		// String objects are at DataImage+32, +64, +96, etc. (step 32).
		// Delta sequence: 1, 2, 2, 2... → runningOffset: 16, 48, 80...
		// But strings are at 32, 64, 96... = runningOffset + 16.
		// Fix: add kHeaderSize (= align = 16) to objPos.
		runningOffset += cm.Lengths[i] << alignShift
		objPos := dataImageObjStart + runningOffset + headerAdjust

		// Need at least 16 bytes for header (tags + length).
		if objPos+16 > int64(len(data)) {
			ref++
			continue
		}

		tags := binary.LittleEndian.Uint64(data[objPos : objPos+8])
		// C-3 fix: Object header tags use ClassIdTag bitfield, NOT the
		// cluster stream tag style. The ClassIdTag position differs by
		// version (verified against dart-lang/sdk raw_object.h):
		//   v2.12–v2.17: kClassIdTagPos=16, kClassIdTagSize=16 → bits 16-31
		//   v3.0+:       kClassIdTagPos=12, kClassIdTagSize=20 → bits 12-31
		var cid int
		if profile.PreV32Format {
			cid = int((uint32(tags) >> sdk.ClassIdTagPosV2) & ((1 << sdk.ClassIdTagSizeV2) - 1))
		} else {
			cid = int((uint32(tags) >> sdk.ClassIdTagPosV3) & ((1 << sdk.ClassIdTagSizeV3) - 1))
		}

		// Check if this is a string object.
		isOneByte := cid == ct.OneByteString
		isTwoByte := ct.TwoByteString != 0 && cid == ct.TwoByteString

		if !isOneByte && !isTwoByte {
			// Non-string ROData object (TypeArguments, Array, etc.). Skip it.
			ref++
			continue
		}

		lenSmi := int64(binary.LittleEndian.Uint64(data[objPos+8 : objPos+16]))
		strLen := lenSmi >> 1 // Smi decode (kSmiTagShift=1 on arm64)

		if strLen < 0 || strLen > 1<<20 {
			strings = append(strings, ParsedString{RefID: ref, Value: "", IsOneByte: isOneByte})
			ref++
			continue
		}

		dataStart := objPos + 16 // oneByteStringHeaderSize
		var value string
		if isTwoByte {
			nbytes := strLen * 2
			if dataStart+nbytes > int64(len(data)) {
				strings = append(strings, ParsedString{RefID: ref, Value: "", IsOneByte: false})
				ref++
				continue
			}
			runes := make([]rune, strLen)
			for j := int64(0); j < strLen; j++ {
				off := dataStart + j*2
				runes[j] = rune(uint16(data[off]) | uint16(data[off+1])<<8)
			}
			value = string(runes)
		} else {
			if dataStart+strLen > int64(len(data)) {
				strings = append(strings, ParsedString{RefID: ref, Value: "", IsOneByte: true})
				ref++
				continue
			}
			value = string(data[dataStart : dataStart+strLen])
		}

		strings = append(strings, ParsedString{
			RefID:     ref,
			Value:     value,
			IsOneByte: isOneByte,
		})
		ref++
	}

	return strings
}
