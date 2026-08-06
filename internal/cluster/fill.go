package cluster

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

var debugFill = os.Getenv("DEFLUTTER_DEBUG_FILL") != ""

// NamedObject holds a named object extracted from the fill section.
type NamedObject struct {
	CID            int
	RefID          int
	NameRefID      int // ref ID pointing to name string (-1 if none)
	OwnerRefID     int // ref ID pointing to owner (-1 if none)
	SignatureRefID int // ref ID pointing to FunctionType signature (-1 if none)
	CodeIndex      int // Function's code_index scalar (-1 if not a Function / not captured)
}

// FuncTypeInfo holds parameter count data extracted from a FunctionType object.
type FuncTypeInfo struct {
	RefID       int
	NumFixed    int  // fixed parameters (excludes implicit 'this')
	NumOptional int  // optional parameters
	HasImplicit bool // true if instance method (has implicit 'this' parameter)

	// ParamTypesArrayRefID is the ref ID of this FunctionType's
	// parameter_types Array object, captured only when
	// snapshot.VersionProfile.FuncTypeParamTypesIdx is set for this
	// Dart version (see that field's doc comment for the verified
	// per-version ref-loop index). -1 if not captured/not applicable.
	ParamTypesArrayRefID int
}

// ArrayInfo holds an Array/ImmutableArray object's elements, extracted
// from fill -- needed to resolve a FunctionType's parameter_types
// (itself just an Array ref) into its actual per-parameter Type refs.
type ArrayInfo struct {
	RefID         int
	TypeArgsRefID int
	ElementRefIDs []int
}

// ClassInfo holds class layout data extracted from a Class object's fill.
type ClassInfo struct {
	RefID          int
	NameRefID      int
	ClassID        int32
	InstanceSize   int32
	NextFieldOff   int32 // next_field_offset in bytes
	TypeArgsOff    int32 // type_arguments field offset in bytes
	SuperTypeRefID int   // ref ID of the super_type Type object (-1 if not captured for this spec.NumRefs)
	LibraryRefID   int   // ref ID of the owning Library object (-1 if not captured for this spec.NumRefs)
}

// TypeInfo holds the resolved type_class_id for a Type object -- i.e. which
// class a `super_type`/other Type reference actually names. Only populated
// for the v3.x fill shape (type_class_id packed into the "flags" scalar,
// not a separate ref -- see readFillRefs' IsType handling).
type TypeInfo struct {
	RefID   int
	ClassID int32
}

// FieldInfo holds field layout data extracted from a Field object's fill.
type FieldInfo struct {
	RefID            int
	NameRefID        int
	OwnerRefID       int
	KindBits         int32
	HostOffset       int32 // byte offset within instance; -1 for static fields
	TypeRefID        int   // ref ID of the field's declared Type object (-1 if not captured); used by typetrack to resolve field-load receiver types
	InitializerRefID int   // ref ID of the Function that lazily initializes this field (-1 if none)
}

// readRef reads a fill-phase ref using the correct encoding for the version.
// ≤2.17 (fillRefUnsigned=true): ReadRef() → ReadUnsigned() (marker 128, little-endian).
// ≥2.18 (fillRefUnsigned=false): ReadRef() → ReadRefId() (big-endian, signed-byte).
func readRef(s *dartfmt.Stream, fillRefUnsigned bool) (int64, error) {
	if fillRefUnsigned {
		return s.ReadUnsigned()
	}
	return s.ReadRefId()
}

// DebugFillPositions iterates the fill section and prints the stream position
// before/after each cluster's fill to w. Used to diagnose fill drift.
func DebugFillPositions(data []byte, result *Result, profile *snapshot.VersionProfile, isVM bool, w io.Writer) error {
	if result.FillStart <= 0 || result.FillStart >= len(data) {
		return fmt.Errorf("fill: invalid start offset %d", result.FillStart)
	}
	s := dartfmt.NewStreamAt(data, result.FillStart)
	fillRefUnsigned := profile.FillRefUnsigned
	instrIdx := 0
	for i := range result.Clusters {
		cm := &result.Clusters[i]
		spec := GetFillSpec(cm.CID, cm, profile)
		startPos := s.Position()
		name := CidNameV(cm.CID, profile.CIDs)
		if name == "" {
			name = fmt.Sprintf("CID_%d", cm.CID)
		}
		err := fillOneCluster(s, cm, &spec, fillRefUnsigned, profile, &instrIdx, nil)
		endPos := s.Position()
		delta := endPos - startPos
		status := "OK"
		if err != nil {
			status = fmt.Sprintf("ERR: %v", err)
		}
		nfoStr := ""
		if cm.NextFieldOffsetInWords != 0 {
			nfoStr = fmt.Sprintf(" nfo=%d", cm.NextFieldOffsetInWords)
		}
		_, _ = fmt.Fprintf(w, "FILL[%3d] CID=%-3d %-24s kind=%-2d count=%-5d start=0x%06x end=0x%06x delta=%-6d%s %s\n",
			i, cm.CID, name, spec.Kind, cm.Count, startPos, endPos, delta, nfoStr, status)
		if err != nil {
			return err
		}
	}
	return nil
}

// dataImageObjStart computes the byte offset within data[] where ROData objects begin.
// For non-compressed-pointers mode, the Dart SDK computes the data image as:
//   DataImage() = Addr() + RoundUp(length(), kMaxObjectAlignment)
// where Addr() is the start of the snapshot blob (including magic),
// length() is the stored length (excluding the 4-byte magic), and
// kMaxObjectAlignment = 2 * word_size = 16 on 64-bit.
//
// Objects within the data image start at DataImage + kHeaderSize, where
// kHeaderSize = kMaxObjectAlignment = 16 (verified against dart-lang/sdk
// image_snapshot.h at tag 2.12.0: `object_start() = raw_memory_ + kHeaderSize`).
// The ROData delta encoding uses offsets relative to DataImage (not
// relative to object_start), so the first object is at delta = kHeaderSize/16 = 1.
//
// We return the DataImage offset (not object_start) because extractRODataStrings
// adds runningOffset (which includes the kHeaderSize delta) to this base.
//
// snapshotSize is header.TotalSize = header.Length + 4 (includes magic).
// Returns 0 if ROData string extraction is not applicable.
func dataImageObjStart(dataLen int, snapshotSize int64, profile *snapshot.VersionProfile) int64 {
	if snapshotSize <= 0 || profile.CompressedPointers {
		return 0
	}
	// kMaxObjectAlignment = 2 * word_size = 16 on 64-bit (all supported archs).
	align := int64(16)
	// length() = snapshotSize - 4 (exclude magic bytes).
	lengthVal := snapshotSize - 4
	if lengthVal <= 0 {
		return 0
	}
	// DataImage = Addr() + RoundUp(length(), align).
	diStart := (lengthVal + align - 1) &^ (align - 1)
	if diStart >= int64(dataLen) {
		return 0
	}
	return diStart
}

// ReadFill parses the fill section of the snapshot, extracting strings
// and named objects. It processes ALL clusters in alloc order.
// snapshotSize is the TotalSize from the snapshot header (needed for ROData string extraction).
func ReadFill(data []byte, result *Result, profile *snapshot.VersionProfile, isVM bool, snapshotSize int64) error {
	if result.FillStart <= 0 || result.FillStart >= len(data) {
		return fmt.Errorf("fill: invalid start offset %d", result.FillStart)
	}

	s := dartfmt.NewStreamAt(data, result.FillStart)
	ct := profile.CIDs
	fillRefUnsigned := profile.FillRefUnsigned
	instrIdx := 0 // running instructions_index_ across Code clusters

	if debugFill {
		fmt.Fprintf(os.Stderr, "fill: %d clusters, fillStart=0x%x, dataLen=0x%x\n", len(result.Clusters), result.FillStart, len(data))
		for ci := range result.Clusters {
			cc := &result.Clusters[ci]
			name := CidNameV(cc.CID, ct)
			if name == "" {
				name = fmt.Sprintf("CID_%d", cc.CID)
			}
			fmt.Fprintf(os.Stderr, "  cluster[%d] CID=%d (%s) count=%d canonical=%v refs=%d..%d\n",
				ci, cc.CID, name, cc.Count, cc.IsCanonical, cc.StartRef, cc.StopRef)
		}
	}

	// C-3 fix: collect ROData string clusters for deferred extraction.
	// The data image position depends on FillEnd, which is only known
	// after all clusters have been processed.
	var rodataStringClusters []*ClusterMeta

	for i := range result.Clusters {
		cm := &result.Clusters[i]
		spec := GetFillSpec(cm.CID, cm, profile)
		fillPos := s.Position()
		if debugFill {
			fmt.Fprintf(os.Stderr, "fill[%d] CID=%d kind=%d count=%d pos=0x%x\n", i, cm.CID, spec.Kind, cm.Count, s.Position())
		}

		switch spec.Kind {
		case FillString:
			strings, err := readFillStrings(s, cm, profile.OldStringFormat, profile.CIDs)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (String CID %d): %w", i, cm.CID, err)
			}
			result.Strings = append(result.Strings, strings...)

		case FillNone, FillSentinel, FillInstructionsTable:
			// No fill data to read.

		case FillROData:
			// C-3 fix: defer ROData string extraction to after FillEnd is set.
			isStringCluster := cm.CID == ct.String ||
				(profile.StringRODataPerSubclass && (cm.CID == ct.OneByteString || cm.CID == ct.TwoByteString))
			if isStringCluster && len(cm.Lengths) > 0 {
				rodataStringClusters = append(rodataStringClusters, cm)
			}

		case FillInlineBytes:
			if err := skipFillInlineBytes(s, cm); err != nil {
				return fmt.Errorf("fill: cluster %d (CID %d) pos=0x%x: %w", i, cm.CID, fillPos, err)
			}

		case FillRefs:
			named, funcTypes, fieldInfos, typeInfos, err := readFillRefs(s, cm, &spec, fillRefUnsigned)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (CID %d): %w", i, cm.CID, err)
			}
			result.Named = append(result.Named, named...)
			result.FuncTypes = append(result.FuncTypes, funcTypes...)
			result.Fields = append(result.Fields, fieldInfos...)
			result.Types = append(result.Types, typeInfos...)

		case FillDouble:
			if err := skipFillDouble(s, cm, profile.PreCanonicalSplit); err != nil {
				return fmt.Errorf("fill: cluster %d (Double): %w", i, err)
			}

		case FillCode:
			codes, err := readFillCode(s, cm, profile.CIDs, fillRefUnsigned, instrIdx, profile.CodeNumRefs, profile.CodeTextOffsetDelta, profile.CodeStateBitsAfterRef, profile.CodeStateBitsAtEnd)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (Code): %w", i, err)
			}
			result.Codes = append(result.Codes, codes...)
			// Advance instrIdx by the number of main (non-deferred) codes.
			instrIdx += int(cm.MainCount)

		case FillObjectPool:
			pool, err := readFillObjectPool(s, cm, profile.OldPoolFormat, profile.PoolTypeSwapped, fillRefUnsigned)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (ObjectPool): %w", i, err)
			}
			result.Pool = append(result.Pool, pool...)

		case FillArray:
			arrays, err := readFillArray(s, cm, fillRefUnsigned, profile)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (Array): %w", i, err)
			}
			result.Arrays = append(result.Arrays, arrays...)

		case FillWeakArray:
			if err := skipFillWeakArray(s, cm, fillRefUnsigned); err != nil {
				return fmt.Errorf("fill: cluster %d (WeakArray): %w", i, err)
			}

		case FillTypedData:
			if err := skipFillTypedData(s, cm, profile.CIDs, profile.PreCanonicalSplit); err != nil {
				return fmt.Errorf("fill: cluster %d (TypedData CID %d): %w", i, cm.CID, err)
			}

		case FillExceptionHandlers:
			if err := skipFillExceptionHandlers(s, cm, fillRefUnsigned); err != nil {
				return fmt.Errorf("fill: cluster %d (ExceptionHandlers) pos=0x%x: %w", i, fillPos, err)
			}

		case FillContext:
			if err := skipFillContext(s, cm, fillRefUnsigned); err != nil {
				return fmt.Errorf("fill: cluster %d (Context): %w", i, err)
			}

		case FillTypeArguments:
			if err := skipFillTypeArguments(s, cm, fillRefUnsigned, profile); err != nil {
				return fmt.Errorf("fill: cluster %d (TypeArguments): %w", i, err)
			}

		case FillClass:
			named, classInfos, err := readFillClass(s, cm, &spec, fillRefUnsigned, profile.TopLevelCid16, profile.ClassHasTokenPos)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (Class): %w", i, err)
			}
			result.Named = append(result.Named, named...)
			result.Classes = append(result.Classes, classInfos...)

		case FillField:
			named, fieldInfos, err := readFillField(s, cm, &spec, fillRefUnsigned)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (Field): %w", i, err)
			}
			result.Named = append(result.Named, named...)
			result.Fields = append(result.Fields, fieldInfos...)

		case FillInstance:
			if err := skipFillInstance(s, cm, fillRefUnsigned, profile.CompressedPointers, profile.PreCanonicalSplit); err != nil {
				return fmt.Errorf("fill: cluster %d (Instance CID %d): %w", i, cm.CID, err)
			}

		case FillRecord:
			if err := skipFillRecord(s, cm, fillRefUnsigned); err != nil {
				return fmt.Errorf("fill: cluster %d (Record): %w", i, err)
			}

		case FillContextScope:
			if err := skipFillContextScope(s, cm, fillRefUnsigned); err != nil {
				return fmt.Errorf("fill: cluster %d (ContextScope): %w", i, err)
			}

		default:
			return fmt.Errorf("fill: cluster %d (CID %d): unknown fill kind %d", i, cm.CID, spec.Kind)
		}
	}

	// Byte offset right after the last cluster's fill data -- where the
	// isolate snapshot's "roots" section begins (ObjectStore fields,
	// field tables, DispatchTable). See ParseDispatchTable.
	result.FillEnd = s.Position()

	// C-3 fix: extract ROData strings from the data image region.
	// The data image position is computed from the snapshot header's
	// length field (verified against dart-lang/sdk snapshot.h at 2.12.0).
	if len(rodataStringClusters) > 0 {
		objStart := dataImageObjStart(len(data), snapshotSize, profile)
		if objStart > 0 {
			for _, cm := range rodataStringClusters {
				strs := extractRODataStrings(data, cm, ct, objStart, profile, isVM)
				result.Strings = append(result.Strings, strs...)
			}
		}
	}

	return nil
}

// fillOneCluster advances the stream past one cluster's fill data.
// Used by DebugFillPositions to track stream positions without collecting results.
// instrIdx is updated for Code clusters.
func fillOneCluster(s *dartfmt.Stream, cm *ClusterMeta, spec *FillSpec, fillRefUnsigned bool, profile *snapshot.VersionProfile, instrIdx *int, result *Result) error {
	switch spec.Kind {
	case FillString:
		strings, err := readFillStrings(s, cm, profile.OldStringFormat, profile.CIDs)
		if err != nil {
			return err
		}
		if result != nil {
			result.Strings = append(result.Strings, strings...)
		}
	case FillNone, FillSentinel, FillROData, FillInstructionsTable:
		// No fill data.
	case FillInlineBytes:
		return skipFillInlineBytes(s, cm)
	case FillRefs:
		_, _, _, _, err := readFillRefs(s, cm, spec, fillRefUnsigned)
		return err
	case FillDouble:
		return skipFillDouble(s, cm, profile.PreCanonicalSplit)
	case FillCode:
		_, err := readFillCode(s, cm, profile.CIDs, fillRefUnsigned, *instrIdx, profile.CodeNumRefs, profile.CodeTextOffsetDelta, profile.CodeStateBitsAfterRef, profile.CodeStateBitsAtEnd)
		*instrIdx += int(cm.MainCount)
		return err
	case FillObjectPool:
		_, err := readFillObjectPool(s, cm, profile.OldPoolFormat, profile.PoolTypeSwapped, fillRefUnsigned)
		return err
	case FillArray:
		return skipFillArray(s, cm, fillRefUnsigned, profile)
	case FillWeakArray:
		return skipFillWeakArray(s, cm, fillRefUnsigned)
	case FillTypedData:
		return skipFillTypedData(s, cm, profile.CIDs, profile.PreCanonicalSplit)
	case FillExceptionHandlers:
		return skipFillExceptionHandlers(s, cm, fillRefUnsigned)
	case FillContext:
		return skipFillContext(s, cm, fillRefUnsigned)
	case FillTypeArguments:
		return skipFillTypeArguments(s, cm, fillRefUnsigned, profile)
	case FillClass:
		_, _, err := readFillClass(s, cm, spec, fillRefUnsigned, profile.TopLevelCid16, profile.ClassHasTokenPos)
		return err
	case FillField:
		_, _, err := readFillField(s, cm, spec, fillRefUnsigned)
		return err
	case FillInstance:
		return skipFillInstance(s, cm, fillRefUnsigned, profile.CompressedPointers, profile.PreCanonicalSplit)
	case FillRecord:
		return skipFillRecord(s, cm, fillRefUnsigned)
	case FillContextScope:
		return skipFillContextScope(s, cm, fillRefUnsigned)
	default:
		return fmt.Errorf("unknown fill kind %d", spec.Kind)
	}
	return nil
}

// ReadFillStrings parses the Fill section of the snapshot to extract string
// values. It processes clusters in order, extracting strings from String
// clusters and skipping non-string clusters. Extracted strings are stored
// in result.Strings with their ref IDs for later correlation.
//
// Deprecated: Use ReadFill for full fill parsing including name extraction.
// ReadFillStrings is no longer called by any production code path -- it is
// retained only for backward compatibility. ReadFill already handles strings
// (via the FillString and FillROData cases) and named objects, so callers
// should use it directly instead of the previous ReadFillStrings + ReadFill
// two-step pattern.
func ReadFillStrings(data []byte, result *Result, profile *snapshot.VersionProfile, isVM bool, snapshotSize int64) error {
	if result.FillStart <= 0 || result.FillStart >= len(data) {
		return fmt.Errorf("fill: invalid start offset %d", result.FillStart)
	}

	s := dartfmt.NewStreamAt(data, result.FillStart)
	ct := profile.CIDs

	for i := range result.Clusters {
		cm := &result.Clusters[i]
		kind := ClassifyAlloc(cm.CID, ct)

		if kind == AllocString {
			// ROData strings (non-compressed-pointers or SplitCanonical) have no fill data.
			// Extract string bytes from the data image region instead.
			if profile.SplitCanonical || !profile.CompressedPointers {
				objStart := dataImageObjStart(len(data), snapshotSize, profile)
				// C-3 fix: StringRODataPerSubclass (≤2.12) has no abstract
				// kStringCid cluster — OneByteString/TwoByteString each carry
				// their own real deltas directly. Was hardcoded to only
				// ct.String, missing all strings for Dart 2.12.
				isStringCluster := cm.CID == ct.String ||
					(profile.StringRODataPerSubclass && (cm.CID == ct.OneByteString || cm.CID == ct.TwoByteString))
				if objStart > 0 && len(cm.Lengths) > 0 && isStringCluster {
					strs := extractRODataStrings(data, cm, ct, objStart, profile, isVM)
					result.Strings = append(result.Strings, strs...)
				}
				continue
			}
			strings, err := readFillStrings(s, cm, profile.OldStringFormat, profile.CIDs)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (String): %w", i, err)
			}
			result.Strings = append(result.Strings, strings...)
		} else {
			// C-3 fix: was `break` — stopped at the first non-string cluster,
			// missing string clusters that appear later in the cluster order
			// (e.g., Dart 2.12 has Instance/TypeArguments/etc. before
			// OneByteString). Now skip non-string clusters instead.
			continue
		}
	}

	return nil
}

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

	// Version-dependent alignment shift (was hardcoded 5 = 32 bytes, P0-3).
	alignShift := uint(5) // fallback
	if a := dataImageAlignment(profile); a > 0 {
		alignShift = uint(0)
		for (int64(1) << alignShift) < a {
			alignShift++
		}
	}

	// kHeaderSize = kMaxObjectAlignment = 16 on 64-bit (verified against
	// dart-lang/sdk image_snapshot.h: `kHeaderSize = kMaxObjectAlignment`).
	// VM data image has a 16-byte image header before objects; isolate does not.
	// This is an empirical observation: VM strings need +16 offset, isolate
	// strings do not. The exact reason is likely a difference in how VM vs
	// isolate data images are constructed by the serializer.
	headerAdjust := int64(0)
	if isVM {
		headerAdjust = int64(1) << alignShift // kHeaderSize = 16
	}

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
			cid = int((uint32(tags) >> 16) & 0xFFFF)
		} else {
			cid = int((uint32(tags) >> 12) & ((1 << 20) - 1))
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

// readFillRefs reads fill data for a FillRefs cluster, extracting name/owner/signature refs.
// When spec.IsFuncType is true, also extracts packed_parameter_counts from scalars.
// When spec.IsField is true, also extracts kind_bits and host_offset from scalars.
func readFillRefs(s *dartfmt.Stream, cm *ClusterMeta, spec *FillSpec, fillRefUnsigned bool) ([]NamedObject, []FuncTypeInfo, []FieldInfo, []TypeInfo, error) {
	count := int(cm.Count)
	if count <= 0 {
		return nil, nil, nil, nil, nil
	}

	// Capture into `named` (and thus RefToNamed) whenever there's either a
	// resolvable name OR an owner link worth walking (e.g. PatchClass has
	// no name of its own but its OwnerIdx points to the real wrapped Class).
	hasName := spec.NameIdx >= 0 || spec.OwnerIdx >= 0
	var named []NamedObject
	if hasName {
		named = make([]NamedObject, 0, count)
	}

	var funcTypes []FuncTypeInfo
	if spec.IsFuncType {
		funcTypes = make([]FuncTypeInfo, 0, count)
	}

	var fields []FieldInfo
	if spec.IsField {
		fields = make([]FieldInfo, 0, count)
	}

	var types []TypeInfo
	if spec.IsType {
		types = make([]TypeInfo, 0, count)
	}

	ref := cm.StartRef
	for i := 0; i < count; i++ {
		// v2.10: Read<bool>(is_canonical) — 1 raw byte before refs.
		if spec.LeadingBool {
			if _, err := s.ReadByte(); err != nil {
				return named, funcTypes, fields, types, fmt.Errorf("obj %d/%d is_canonical: %w", i, count, err)
			}
		}

		var nameRef, ownerRef, sigRef, paramTypesRef, fieldTypeRef int
		nameRef = -1
		ownerRef = -1
		sigRef = -1
		paramTypesRef = -1
		fieldTypeRef = -1

		// Read refs using version-appropriate encoding.
		for j := 0; j < spec.NumRefs; j++ {
			r, err := readRef(s, fillRefUnsigned)
			if err != nil {
				return named, funcTypes, fields, types, fmt.Errorf("obj %d/%d ref %d: %w", i, count, j, err)
			}
			if j == spec.NameIdx {
				nameRef = int(r)
			}
			if j == spec.OwnerIdx {
				ownerRef = int(r)
			}
			if spec.SignatureIdx > 0 && j == spec.SignatureIdx {
				sigRef = int(r)
			}
			if spec.IsFuncType && spec.FuncTypeParamTypesIdx > 0 && j == spec.FuncTypeParamTypesIdx {
				paramTypesRef = int(r)
			}
			// Field type ref is at index 2 (refs: name=0, owner=1, type=2, initializer=3).
			if spec.IsField && j == 2 {
				fieldTypeRef = int(r)
			}
		}

		// Read scalars; extract type-specific data for FunctionType and Field clusters.
		var fieldKindBits int32
		funcCodeIndex := -1
		for si, op := range spec.Scalars {
			if spec.IsFunction && si == 0 {
				// code_index is OpUnsigned at scalar index 0.
				ci, err := s.ReadUnsigned()
				if err != nil {
					return named, funcTypes, fields, types, fmt.Errorf("obj %d/%d code_index: %w", i, count, err)
				}
				funcCodeIndex = int(ci)
			} else if spec.IsFuncType && si == 1 {
				// packed_parameter_counts is OpTagged32 at scalar index 1.
				packed, err := s.ReadTagged32()
				if err != nil {
					return named, funcTypes, fields, types, fmt.Errorf("obj %d/%d packed_param_counts: %w", i, count, err)
				}
				hasImplicit := (packed & 1) != 0
				numFixed := int((packed >> 2) & 0x3FFF)
				numOptional := int((packed >> 16) & 0x3FFF)
				if hasImplicit && numFixed > 0 {
					numFixed-- // subtract implicit 'this'
				}
				funcTypes = append(funcTypes, FuncTypeInfo{
					RefID:                ref,
					NumFixed:             numFixed,
					NumOptional:          numOptional,
					HasImplicit:          hasImplicit,
					ParamTypesArrayRefID: paramTypesRef,
				})
			} else if spec.IsField && si == 0 {
				// kind_bits is OpTagged32 at scalar index 0.
				kb, err := s.ReadTagged32()
				if err != nil {
					return named, funcTypes, fields, types, fmt.Errorf("obj %d/%d kind_bits: %w", i, count, err)
				}
				fieldKindBits = int32(kb)
			} else if spec.IsField && si == 1 {
				// host_offset_or_field_id is OpRefId at scalar index 1.
				hostOff, err := s.ReadRefId()
				if err != nil {
					return named, funcTypes, fields, types, fmt.Errorf("obj %d/%d host_offset: %w", i, count, err)
				}
				isStatic := (fieldKindBits>>1)&1 != 0
				offset := int32(hostOff)
				if isStatic {
					offset = -1
				}
				fields = append(fields, FieldInfo{
					RefID:            ref,
					NameRefID:        nameRef,
					OwnerRefID:       ownerRef,
					KindBits:         fieldKindBits,
					HostOffset:       offset,
					InitializerRefID: sigRef,
					TypeRefID:        fieldTypeRef,
				})
			} else if spec.IsType && si == 0 {
				// flags is OpUnsigned at scalar index 0 (v3.x only -- see
				// specType). type_class_id is packed inside it: bit 0 =
				// nullability, bits [1,3) = TypeState, bits [3,23) = the
				// 20-bit ClassIdTag (confirmed against Dart SDK source,
				// runtime/vm/raw_object.h UntaggedType::TypeClassIdBits).
				flags, err := s.ReadUnsigned()
				if err != nil {
					return named, funcTypes, fields, types, fmt.Errorf("obj %d/%d type flags: %w", i, count, err)
				}
				classID := int32((flags >> 3) & 0xFFFFF)
				types = append(types, TypeInfo{RefID: ref, ClassID: classID})
			} else {
				if err := skipScalar(s, op); err != nil {
					return named, funcTypes, fields, types, fmt.Errorf("obj %d/%d scalar: %w", i, count, err)
				}
			}
		}

		if hasName {
			named = append(named, NamedObject{
				CID:            cm.CID,
				RefID:          ref,
				NameRefID:      nameRef,
				OwnerRefID:     ownerRef,
				SignatureRefID: sigRef,
				CodeIndex:      funcCodeIndex,
			})
		}
		ref++
	}

	return named, funcTypes, fields, types, nil
}

// skipScalar reads and discards one scalar value.
func skipScalar(s *dartfmt.Stream, op ScalarOp) error {
	switch op {
	case OpTagged32, OpUint16, OpInt16:
		// Read<int32_t/uint32_t/uint16_t/int16_t>: variable-length, marker 192.
		_, err := s.ReadTagged32()
		return err
	case OpTagged64:
		// Read<int64_t/double/uword>: variable-length, marker 192.
		_, err := s.ReadTagged64()
		return err
	case OpUnsigned:
		// ReadUnsigned: variable-length, marker 128.
		_, err := s.ReadUnsigned()
		return err
	case OpBool, OpUint8, OpInt8:
		// Read<uint8_t/int8_t/bool>: Raw<1,T> = 1 raw byte.
		_, err := s.ReadByte()
		return err
	case OpRefId:
		// ReadRef: big-endian signed-byte accumulation (trailing ref after scalars).
		_, err := s.ReadRefId()
		return err
	default:
		return fmt.Errorf("unknown scalar op %d", op)
	}
}

// readFillClass parses Class fill data with conditional bitmap read.
// Predefined classes (i < mainCount): bitmap always read.
// New classes (i >= mainCount): bitmap only if !IsTopLevelCid(class_id).
// ≤2.18: kTopLevelCidOffset = 1<<16. ≥2.19: kTopLevelCidOffset = 1<<20.
func readFillClass(s *dartfmt.Stream, cm *ClusterMeta, spec *FillSpec, fillRefUnsigned, topLevelCid16, classHasTokenPos bool) ([]NamedObject, []ClassInfo, error) {
	count := int(cm.Count)
	if count <= 0 {
		return nil, nil, nil
	}

	topLevelOffset := int64(1 << 20)
	if topLevelCid16 {
		topLevelOffset = 1 << 16
	}

	named := make([]NamedObject, 0, count)
	classes := make([]ClassInfo, 0, count)
	ref := cm.StartRef

	// super_type's ref index within the ReadFromTo range. Confirmed against
	// Dart SDK source (runtime/vm/raw_object.h UntaggedClass field
	// declaration order + to_snapshot(kFullAOT) under PRODUCT).
	//
	// v3.x (13 refs, no user_name, no signature_function):
	//   name(0), functions(1), functions_hash_table(2), fields(3),
	//   offset_in_words_to_field(4), interfaces(5), script(6),
	//   library(7), type_parameters(8), super_type(9), constants(10),
	//   declaration_type(11), invocation_dispatcher_cache(12)
	//
	// v2.13 (15 refs, has user_name, no signature_function):
	//   name(0), user_name(1), functions(2), functions_hash_table(3),
	//   fields(4), offset_in_words_to_field(5), interfaces(6), script(7),
	//   library(8), type_parameters(9), super_type(10), constants(11),
	//   declaration_type(12), invocation_dispatcher_cache(13),
	//   allocation_stub(14)
	//
	// v2.10 (16 refs, has user_name AND signature_function):
	//   name(0), user_name(1), functions(2), functions_hash_table(3),
	//   fields(4), offset_in_words_to_field(5), interfaces(6), script(7),
	//   library(8), type_parameters(9), super_type(10),
	//   signature_function(11), constants(12), declaration_type(13),
	//   invocation_dispatcher_cache(14), allocation_stub(15)
	const superTypeIdxV13 = 9
	const libraryIdxV13 = 7
	const superTypeIdxV2 = 10 // v2.10 and v2.13
	const libraryIdxV2 = 8    // v2.10 and v2.13

	for i := 0; i < count; i++ {
		var nameRef = -1
		superTypeRef := -1
		libraryRef := -1

		// ReadFromTo: 13 refs.
		for j := 0; j < spec.NumRefs; j++ {
			r, err := readRef(s, fillRefUnsigned)
			if err != nil {
				return named, classes, fmt.Errorf("obj %d/%d ref %d/%d: %w", i, count, j, spec.NumRefs, err)
			}
			if j == spec.NameIdx {
				nameRef = int(r)
			}
			// Capture super_type and library refs for all supported versions.
			// v3.x (13 refs): super_type at 9, library at 7.
			// v2.10 (16 refs) / v2.13 (15 refs): super_type at 10, library at 8.
			// (P1-8: previously only v3.x was handled, v2.10/v2.13 always got -1)
			if spec.NumRefs == 13 && j == superTypeIdxV13 {
				superTypeRef = int(r)
			} else if (spec.NumRefs == 15 || spec.NumRefs == 16) && j == superTypeIdxV2 {
				superTypeRef = int(r)
			}
			if spec.NumRefs == 13 && j == libraryIdxV13 {
				libraryRef = int(r)
			} else if (spec.NumRefs == 15 || spec.NumRefs == 16) && j == libraryIdxV2 {
				libraryRef = int(r)
			}
		}

		// ReadCid (class_id) — Read<int32_t> = ReadTagged32.
		classID, err := s.ReadTagged32()
		if err != nil {
			return named, classes, fmt.Errorf("obj %d/%d class_id: %w", i, count, err)
		}

		// Read<int32_t>(instance_size) + Read<int32_t>(next_field_offset).
		instanceSize, err := s.ReadTagged32()
		if err != nil {
			return named, classes, fmt.Errorf("obj %d/%d instance_size: %w", i, count, err)
		}
		nextFieldOff, err := s.ReadTagged32()
		if err != nil {
			return named, classes, fmt.Errorf("obj %d/%d next_field_offset: %w", i, count, err)
		}
		// Read<int32_t>(type_args_offset).
		typeArgsOff, err := s.ReadTagged32()
		if err != nil {
			return named, classes, fmt.Errorf("obj %d/%d type_args_offset: %w", i, count, err)
		}
		// Read<int16_t>(num_type_arguments) — Read16 marker 192.
		if _, err := s.ReadTagged32(); err != nil {
			return named, classes, fmt.Errorf("obj %d/%d num_type_args: %w", i, count, err)
		}
		// Read<uint16_t>(num_native_fields) — Read16 marker 192.
		if _, err := s.ReadTagged32(); err != nil {
			return named, classes, fmt.Errorf("obj %d/%d num_native_fields: %w", i, count, err)
		}
		// v2.10/v2.13: ReadTokenPosition(token_pos) + ReadTokenPosition(end_token_pos).
		// These are Read<int32_t> each; not present in v2.14+ AOT.
		if classHasTokenPos {
			if _, err := s.ReadTagged32(); err != nil {
				return named, classes, fmt.Errorf("obj %d/%d token_pos: %w", i, count, err)
			}
			if _, err := s.ReadTagged32(); err != nil {
				return named, classes, fmt.Errorf("obj %d/%d end_token_pos: %w", i, count, err)
			}
		}
		// Read<uint32_t>(state_bits) — Read32 marker 192.
		if _, err := s.ReadTagged32(); err != nil {
			return named, classes, fmt.Errorf("obj %d/%d state_bits: %w", i, count, err)
		}

		// ReadUnsigned64 (bitmap) — conditional for new classes.
		isPredefined := int64(i) < cm.MainCount
		isTopLevel := int64(int32(classID)) >= topLevelOffset
		if isPredefined || !isTopLevel {
			if _, err := s.ReadUnsigned(); err != nil {
				return named, classes, fmt.Errorf("obj %d/%d bitmap: %w", i, count, err)
			}
		}

		named = append(named, NamedObject{
			CID:        cm.CID,
			RefID:      ref,
			NameRefID:  nameRef,
			OwnerRefID: -1,
		})
		classes = append(classes, ClassInfo{
			RefID:          ref,
			NameRefID:      nameRef,
			ClassID:        int32(classID),
			InstanceSize:   int32(instanceSize),
			NextFieldOff:   int32(nextFieldOff),
			TypeArgsOff:    int32(typeArgsOff),
			SuperTypeRefID: superTypeRef,
			LibraryRefID:   libraryRef,
		})
		ref++
	}
	return named, classes, nil
}

// readFillField parses v2.17.6 Field fill with conditional ReadUnsigned for static fields.
// v2.17.6 AOT: ReadFromTo(4 refs) + Read<uint16_t>(kind_bits) + ReadRef(value_or_offset) +
// [if static: ReadUnsigned(field_id)].
// kStaticBit = 1 in v2.17.6 kind_bits.
func readFillField(s *dartfmt.Stream, cm *ClusterMeta, spec *FillSpec, fillRefUnsigned bool) ([]NamedObject, []FieldInfo, error) {
	count := int(cm.Count)
	if count <= 0 {
		return nil, nil, nil
	}

	named := make([]NamedObject, 0, count)
	fields := make([]FieldInfo, 0, count)
	ref := cm.StartRef

	for i := 0; i < count; i++ {
		var nameRef, ownerRef, fieldTypeRef int
		nameRef = -1
		ownerRef = -1
		fieldTypeRef = -1

		// ReadFromTo: 4 refs (name, owner, type, initializer_function).
		for j := 0; j < spec.NumRefs; j++ {
			r, err := readRef(s, fillRefUnsigned)
			if err != nil {
				return named, fields, fmt.Errorf("field %d/%d ref %d: %w", i, count, j, err)
			}
			if j == spec.NameIdx {
				nameRef = int(r)
			}
			if j == spec.OwnerIdx {
				ownerRef = int(r)
			}
			// Field type ref is at index 2 (refs: name=0, owner=1, type=2, initializer=3).
			if j == 2 {
				fieldTypeRef = int(r)
			}
		}

		// Read<uint16_t>(kind_bits) — Read16(marker 192).
		kindBits, err := s.ReadTagged32()
		if err != nil {
			return named, fields, fmt.Errorf("field %d/%d kind_bits: %w", i, count, err)
		}

		// ReadRef(value_or_offset).
		valOrOff, err := readRef(s, fillRefUnsigned)
		if err != nil {
			return named, fields, fmt.Errorf("field %d/%d value_or_offset: %w", i, count, err)
		}

		// Conditional: if static field, read field_id.
		isStatic := (kindBits>>1)&1 != 0
		if isStatic {
			if _, err := s.ReadUnsigned(); err != nil {
				return named, fields, fmt.Errorf("field %d/%d field_id: %w", i, count, err)
			}
		}

		offset := int32(valOrOff)
		if isStatic {
			offset = -1
		}
		fields = append(fields, FieldInfo{
			RefID:      ref,
			NameRefID:  nameRef,
			OwnerRefID: ownerRef,
			KindBits:   int32(kindBits),
			TypeRefID:  fieldTypeRef,
			HostOffset: offset,
		})

		named = append(named, NamedObject{
			CID:        cm.CID,
			RefID:      ref,
			NameRefID:  nameRef,
			OwnerRefID: ownerRef,
		})
		ref++
	}
	return named, fields, nil
}

// skipFillDouble skips Double fill.
// Read<double>() → Raw<8,double>::Read() → Read64(kEndByteMarker=192) = variable-length.
// v2.10: Read<bool>(is_canonical) before the double.
func skipFillDouble(s *dartfmt.Stream, cm *ClusterMeta, preCanonicalSplit bool) error {
	for i := int64(0); i < cm.Count; i++ {
		if preCanonicalSplit {
			if _, err := s.ReadByte(); err != nil {
				return fmt.Errorf("double %d/%d is_canonical: %w", i, cm.Count, err)
			}
		}
		if _, err := s.ReadTagged64(); err != nil {
			return fmt.Errorf("double %d/%d: %w", i, cm.Count, err)
		}
	}
	return nil
}

// readFillCode reads Code fill data, extracting owner refs and instruction metadata.
// AOT PRODUCT: ReadInstructions + N ReadRef per code.
// v2.16+: ReadInstructions = 1 ReadUnsigned (payload_info). 6 refs.
// v2.10-v2.15: ReadInstructions = 2 ReadUnsigned (text_offset_delta + payload_info). 7 refs.
// Deferred codes skip ReadInstructions (no stream read).
// Ref 0 = owner (Function/Closure/FfiTrampolineData).
// instrIdxBase is the running instructions_index_ counter from previous Code clusters.
//
// stateBitsAfterRef: 0 = no state_bits in fill (v2.10, v2.14+).
// N>0 = state_bits is read after first N refs (v2.13: N=1). DiscardedBit (bit 3)
// of state_bits determines whether remaining refs are skipped.
func readFillCode(s *dartfmt.Stream, cm *ClusterMeta, ct *snapshot.CIDTable, fillRefUnsigned bool, instrIdxBase int, codeNumRefs int, textOffsetDelta bool, stateBitsAfterRef int, stateBitsAtEnd bool) ([]CodeEntry, error) {
	numRefs := codeNumRefs
	if numRefs == 0 {
		numRefs = 6 // default: owner, exception_handlers, pc_descriptors, catch_entry, inlined_id_to_function, code_source_map
	}
	codes := make([]CodeEntry, 0, cm.Count)
	ref := cm.StartRef
	instrIdx := instrIdxBase
	discardedCount := 0
	for i := int64(0); i < cm.Count; i++ {
		var payloadInfo int64
		var textOff int64
		clusterIndex := -1
		traceCode := debugFill && i < 5

		// v2.14+: discarded status from alloc phase. v2.13: determined from state_bits below.
		discarded := cm.DiscardedCodes[i]

		posStart := s.Position()

		// Dump raw bytes for first 3, last 3, and codes near known failure points.
		if debugFill && (i < 3 || i >= cm.Count-3 || (i >= 21600 && i <= 21610)) {
			saved := s.Position()
			hexBytes, _ := s.ReadBytes(30)
			s.SetPosition(saved)
			fmt.Fprintf(os.Stderr, "  code[%d] RAW@0x%x: %x\n", i, posStart, hexBytes)
		}

		// Main (non-deferred) codes: ReadInstructions reads payload data.
		// v2.10-v2.15: ReadUnsigned(text_offset_delta) + ReadUnsigned(payload_info).
		//   v2.14+: discarded codes also read compressed_stackmaps(ReadRef) in ReadInstructions.
		// v2.16+: ReadUnsigned(payload_info) only.
		// Deferred codes: ReadInstructions does nothing (early return).
		if i < cm.MainCount {
			if textOffsetDelta {
				tod, err := s.ReadUnsigned()
				if err != nil {
					return codes, fmt.Errorf("code %d/%d text_offset_delta: %w", i, cm.Count, err)
				}
				textOff = tod
			}
			pi, err := s.ReadUnsigned()
			if err != nil {
				return codes, fmt.Errorf("code %d/%d payload_info: %w", i, cm.Count, err)
			}
			payloadInfo = pi
			clusterIndex = instrIdx
			instrIdx++

			// v2.14+: discarded codes read compressed_stackmaps ref inside ReadInstructions,
			// then return without reading any other refs or state_bits.
			if discarded && stateBitsAfterRef == 0 {
				if _, err := readRef(s, fillRefUnsigned); err != nil {
					return codes, fmt.Errorf("code %d/%d discarded compressed_stackmaps: %w", i, cm.Count, err)
				}
			}
		}

		// v2.13 (stateBitsAfterRef > 0): compressed_stackmaps → state_bits → [if discarded: stop] → 6 refs.
		// All codes read compressed_stackmaps and state_bits. DiscardedBit (bit 3) of state_bits
		// determines whether remaining refs are read. This is different from v2.14+ where
		// discarded status comes from the alloc phase.
		var ownerRef int
		if stateBitsAfterRef > 0 {
			// Read first N refs (before state_bits) — all codes, including discarded.
			for j := 0; j < stateBitsAfterRef; j++ {
				if _, err := readRef(s, fillRefUnsigned); err != nil {
					return codes, fmt.Errorf("code %d/%d ref %d: %w", i, cm.Count, j, err)
				}
			}
			// Read state_bits (Read<int32_t> VLE).
			sbPos := s.Position()
			sb, err := s.ReadTagged32()
			if err != nil {
				// Dump context for diagnosis.
				if debugFill {
					fmt.Fprintf(os.Stderr, "  code[%d] state_bits ERR at pos=0x%x (code start=0x%x)\n", i, sbPos, posStart)
					// Dump raw bytes from code start.
					saved := s.Position()
					s.SetPosition(posStart)
					hexBytes, _ := s.ReadBytes(40)
					s.SetPosition(saved)
					fmt.Fprintf(os.Stderr, "  hex@0x%x=%x\n", posStart, hexBytes)
				}
				return codes, fmt.Errorf("code %d/%d state_bits: %w", i, cm.Count, err)
			}
			if debugFill && (i%1000 == 0 || (i >= 21595 && i <= 21610)) {
				fmt.Fprintf(os.Stderr, "  code[%d] pos=0x%x sb=0x%x discarded=%v cumDisc=%d\n",
					i, posStart, sb, (sb>>3)&1 != 0, discardedCount)
			}
			// DiscardedBit = bit 3 of state_bits.
			discarded = (sb>>3)&1 != 0
			if discarded {
				discardedCount++
				if traceCode {
					fmt.Fprintf(os.Stderr, "  code[%d] pos=0x%x state_bits=0x%x DISCARDED\n", i, posStart, sb)
				}
				goto done
			}
			// Read remaining refs after state_bits.
			for j := stateBitsAfterRef; j < numRefs; j++ {
				r, err := readRef(s, fillRefUnsigned)
				if err != nil {
					return codes, fmt.Errorf("code %d/%d ref %d: %w", i, cm.Count, j, err)
				}
				// Owner is the first ref after state_bits (e.g., ref[1] for v2.13).
				if j == stateBitsAfterRef {
					ownerRef = int(r)
				}
			}
		} else if !discarded {
			// v2.10, v2.14+: read all refs in order (no interleaved state_bits).
			for j := 0; j < numRefs; j++ {
				r, err := readRef(s, fillRefUnsigned)
				if err != nil {
					return codes, fmt.Errorf("code %d/%d ref %d: %w", i, cm.Count, j, err)
				}
				if j == 0 {
					ownerRef = int(r)
				}
			}
		}

		// v2.10: state_bits_ = Read<int32_t>() after ALL refs, unconditionally (no discarded check).
		if stateBitsAtEnd {
			if _, err := s.ReadTagged32(); err != nil {
				return codes, fmt.Errorf("code %d/%d state_bits_at_end: %w", i, cm.Count, err)
			}
		}

	done:
		if traceCode {
			fmt.Fprintf(os.Stderr, "  code[%d] pos=0x%x total=%d discarded=%v\n",
				i, posStart, s.Position()-posStart, discarded)
		}
		if debugFill && (i < 5 || i >= cm.Count-3 || i == cm.MainCount-1 || i == cm.MainCount || i%5000 == 0) {
			fmt.Fprintf(os.Stderr, "  code[%d/%d] main=%d owner=%d discarded=%v endPos=0x%x\n", i, cm.Count, cm.MainCount, ownerRef, discarded, s.Position())
		}
		codes = append(codes, CodeEntry{
			RefID:        ref,
			OwnerRef:     ownerRef,
			ClusterIndex: clusterIndex,
			PayloadInfo:  payloadInfo,
			TextOffset:   textOff,
		})
		ref++
	}
	if debugFill && discardedCount > 0 {
		fmt.Fprintf(os.Stderr, "  code: %d/%d discarded (from state_bits)\n", discardedCount, cm.Count)
	}
	return codes, nil
}

// readFillObjectPool reads ObjectPool fill data and captures entries.
// Per pool: ReadUnsigned(length) + length × (ReadByte(entry_bits) + type-dependent data).
//
// v2.17.6: TypeBits[0:7] (7 bits), PatchableBit[7].
//
//	0=kTaggedObject→ReadRef, 1=kImmediate→Read<intptr_t>, 2+=nothing.
//
// v3.x: TypeBits[0:4], PatchableBit[4], SnapshotBehaviorBits[5:8].
//
//	behavior 0: 0=kImmediate→Read<intptr_t>, 1=kTaggedObject→ReadRef, 2=kNativeFunction→nothing.
//	behavior 1,2,3: nothing.
func readFillObjectPool(s *dartfmt.Stream, cm *ClusterMeta, oldPoolFormat, poolTypeSwapped, fillRefUnsigned bool) ([]PoolEntry, error) {
	if debugFill {
		saved := s.Position()
		rawBytes, _ := s.ReadBytes(40)
		s.SetPosition(saved)
		fmt.Fprintf(os.Stderr, "  ObjectPool fill start @0x%x raw=%x\n", saved, rawBytes)
	}
	var entries []PoolEntry
	idx := 0
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return nil, fmt.Errorf("pool %d/%d length: %w", i, cm.Count, err)
		}
		for j := int64(0); j < length; j++ {
			entryBits, err := s.ReadByte()
			if err != nil {
				return nil, fmt.Errorf("pool %d entry %d bits: %w", i, j, err)
			}

			pe := PoolEntry{Index: idx}
			idx++

			if oldPoolFormat {
				// ≤3.2: TypeBits = entryBits & 0x7F (7 bits).
				typeBits := entryBits & 0x7F
				// v3.2 swapped kImmediate(0) and kTaggedObject(1). Normalize to pre-3.2 ordering.
				if poolTypeSwapped && typeBits <= 1 {
					typeBits ^= 1
				}
				switch typeBits {
				case 0: // kTaggedObject → ReadRef
					ref, err := readRef(s, fillRefUnsigned)
					if err != nil {
						return nil, fmt.Errorf("pool %d entry %d ref (bits=0x%02x pos=0x%x): %w", i, j, entryBits, s.Position(), err)
					}
					pe.Kind = PoolTagged
					pe.RefID = int(ref)
				case 1: // kImmediate → Read<intptr_t> = Read64
					imm, err := s.ReadTagged64()
					if err != nil {
						return nil, fmt.Errorf("pool %d entry %d imm (bits=0x%02x pos=0x%x): %w", i, j, entryBits, s.Position(), err)
					}
					pe.Kind = PoolImmediate
					pe.Imm = imm
				case 2, 3: // kNativeFunction, kNativeFunctionWrapper → nothing
					pe.Kind = PoolNative
				case 4: // kNativeEntryData → ReadRef (same as kTaggedObject)
					ref, err := readRef(s, fillRefUnsigned)
					if err != nil {
						return nil, fmt.Errorf("pool %d entry %d native_entry_data ref (bits=0x%02x pos=0x%x): %w", i, j, entryBits, s.Position(), err)
					}
					pe.Kind = PoolTagged
					pe.RefID = int(ref)
				default:
					return nil, fmt.Errorf("pool %d entry %d: unknown type %d (bits=0x%02x pos=0x%x)", i, j, typeBits, entryBits, s.Position())
				}
			} else {
				// v3.x: SnapshotBehaviorBits = entryBits >> 5 (3 bits).
				behaviorBits := entryBits >> 5
				typeBits := entryBits & 0x0F
				switch behaviorBits {
				case 0: // kSnapshotable
					switch typeBits {
					case 0: // kImmediate → Read<intptr_t>
						imm, err := s.ReadTagged64()
						if err != nil {
							return nil, fmt.Errorf("pool %d entry %d imm: %w", i, j, err)
						}
						pe.Kind = PoolImmediate
						pe.Imm = imm
					case 1: // kTaggedObject → ReadRef
						ref, err := readRef(s, fillRefUnsigned)
						if err != nil {
							return nil, fmt.Errorf("pool %d entry %d ref: %w", i, j, err)
						}
						pe.Kind = PoolTagged
						pe.RefID = int(ref)
					case 2: // kNativeFunction → nothing
						pe.Kind = PoolNative
					default:
						return nil, fmt.Errorf("pool %d entry %d: unknown type %d", i, j, typeBits)
					}
				case 1, 2, 3, 4: // kResetToBootstrapNative, kResetToSwitchableCallMissEntryPoint, kSetToZero, kResetToMegamorphicCallEntryPoint
					pe.Kind = PoolEmpty
				default:
					return nil, fmt.Errorf("pool %d entry %d: unknown snapshot behavior %d", i, j, behaviorBits)
				}
			}
			entries = append(entries, pe)
		}
	}
	return entries, nil
}

// skipFillInlineBytes skips clusters that store inline byte data.
// Per object: ReadUnsigned(length) + ReadBytes(length).
// Used for PcDescriptors, CodeSourceMap, CompressedStackMaps with compressed pointers.
func skipFillInlineBytes(s *dartfmt.Stream, cm *ClusterMeta) error {
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("inline_bytes %d/%d length: %w", i, cm.Count, err)
		}
		if err := s.Skip(int(length)); err != nil {
			return fmt.Errorf("inline_bytes %d/%d data (%d bytes): %w", i, cm.Count, length, err)
		}
	}
	return nil
}

// skipFillArray parses Array/ImmutableArray fill and discards the result,
// for the debug-only fillOneCluster path that just needs to advance the
// stream. Real callers (ReadFill) use readFillArray directly to keep the
// captured elements.
func skipFillArray(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool, profile *snapshot.VersionProfile) error {
	_, err := readFillArray(s, cm, fillRefUnsigned, profile)
	return err
}

// readFillArray reads Array/ImmutableArray fill and returns each object's
// elements, needed to resolve a FunctionType's parameter_types (itself
// just an Array ref) into its real per-parameter Type refs.
//
// New format (v2.16+):
//
//	Per object: ReadUnsigned(length) + ReadRef(type_args) + length × ReadRef(element).
//
// Old format (v2.13, v2.15 — OldArrayFill):
//
//	Per object: ReadRef(type_args) + N × ReadRef(element) where N = cm.Lengths[i] from alloc.
func readFillArray(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool, profile *snapshot.VersionProfile) ([]ArrayInfo, error) {
	if profile.OldArrayFill {
		return readFillArrayOld(s, cm, fillRefUnsigned)
	}
	arrays := make([]ArrayInfo, 0, cm.Count)
	ref := cm.StartRef
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return arrays, fmt.Errorf("array %d/%d length: %w", i, cm.Count, err)
		}
		// v2.10: Read<bool>(is_canonical) after length.
		if profile.PreCanonicalSplit {
			if _, err := s.ReadByte(); err != nil {
				return arrays, fmt.Errorf("array %d is_canonical: %w", i, err)
			}
		}
		// ReadRef(type_arguments).
		typeArgsRef, err := readRef(s, fillRefUnsigned)
		if err != nil {
			return arrays, fmt.Errorf("array %d type_args: %w", i, err)
		}
		elems := make([]int, 0, length)
		for j := int64(0); j < length; j++ {
			r, err := readRef(s, fillRefUnsigned)
			if err != nil {
				return arrays, fmt.Errorf("array %d elem %d/%d: %w", i, j, length, err)
			}
			elems = append(elems, int(r))
		}
		arrays = append(arrays, ArrayInfo{RefID: ref, TypeArgsRefID: int(typeArgsRef), ElementRefIDs: elems})
		ref++
	}
	return arrays, nil
}

// readFillArrayOld handles the pre-v2.16 Array fill format.
// Per object: ReadRef(type_args) + N × ReadRef(element) where N = cm.Lengths[i] from alloc.
func readFillArrayOld(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool) ([]ArrayInfo, error) {
	arrays := make([]ArrayInfo, 0, cm.Count)
	ref := cm.StartRef
	for i := int64(0); i < cm.Count; i++ {
		allocLen := int64(0)
		if int(i) < len(cm.Lengths) {
			allocLen = cm.Lengths[i]
		}
		// ReadRef(type_arguments).
		typeArgsRef, err := readRef(s, fillRefUnsigned)
		if err != nil {
			return arrays, fmt.Errorf("array_old %d/%d type_args: %w", i, cm.Count, err)
		}
		elems := make([]int, 0, allocLen)
		for j := int64(0); j < allocLen; j++ {
			r, err := readRef(s, fillRefUnsigned)
			if err != nil {
				return arrays, fmt.Errorf("array_old %d elem %d/%d: %w", i, j, allocLen, err)
			}
			elems = append(elems, int(r))
		}
		arrays = append(arrays, ArrayInfo{RefID: ref, TypeArgsRefID: int(typeArgsRef), ElementRefIDs: elems})
		ref++
	}
	return arrays, nil
}

// skipFillWeakArray skips WeakArray fill.
// Per object: ReadUnsigned(length) + length × ReadRef(element).
func skipFillWeakArray(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool) error {
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("weak_array %d/%d length: %w", i, cm.Count, err)
		}
		for j := int64(0); j < length; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("weak_array %d elem %d/%d: %w", i, j, length, err)
			}
		}
	}
	return nil
}

// skipFillTypedData skips TypedData fill.
// Per object: ReadUnsigned(length) + length × element_size raw bytes.
// v2.10: Read<bool>(is_canonical) after length.
func skipFillTypedData(s *dartfmt.Stream, cm *ClusterMeta, ct *snapshot.CIDTable, preCanonicalSplit bool) error {
	elemSize := typedDataElementSize(cm.CID, ct)
	for i := int64(0); i < cm.Count; i++ {
		// Fill reads: ReadUnsigned(length), then length * element_size raw bytes.
		length, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("typed_data %d/%d length: %w", i, cm.Count, err)
		}
		if preCanonicalSplit {
			if _, err := s.ReadByte(); err != nil {
				return fmt.Errorf("typed_data %d is_canonical: %w", i, err)
			}
		}
		nbytes := int(length) * elemSize
		if err := s.Skip(nbytes); err != nil {
			return fmt.Errorf("typed_data %d/%d data (%d bytes): %w", i, cm.Count, nbytes, err)
		}
	}
	return nil
}

// skipFillExceptionHandlers skips ExceptionHandlers fill.
// v2.17.6: ReadUnsigned(length) directly.
// v3.x: ReadUnsigned(packed_fields), length = packed_fields >> 1 (AsyncHandlerBit at bit 0).
// Then: ReadRef(handled_types_data) + per-handler: Read<uint32_t>(pc_offset) +
// Read<int16_t>(outer_try_index) + Read<int8_t>(needs_stacktrace) +
// Read<int8_t>(has_catch_all) + Read<int8_t>(is_generated).
func skipFillExceptionHandlers(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool) error {
	for i := int64(0); i < cm.Count; i++ {
		raw, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("exc_handlers %d length/packed: %w", i, err)
		}
		// v2.17.6: value IS the length. v3.x: length = packed_fields >> 1.
		length := raw
		if !fillRefUnsigned {
			length = raw >> 1
		}
		// ReadRef(handled_types_data).
		if _, err := readRef(s, fillRefUnsigned); err != nil {
			return fmt.Errorf("exc_handlers %d handled_types: %w", i, err)
		}
		for j := int64(0); j < length; j++ {
			// Read<uint32_t>(handler_pc_offset) — marker 192.
			if _, err := s.ReadTagged32(); err != nil {
				return fmt.Errorf("exc_handlers %d handler %d pc: %w", i, j, err)
			}
			// Read<int16_t>(outer_try_index) — marker 192 (Read16).
			if _, err := s.ReadTagged32(); err != nil {
				return fmt.Errorf("exc_handlers %d handler %d try_idx: %w", i, j, err)
			}
			// Read<int8_t>(needs_stacktrace) — Raw<1,T> = ReadByte.
			if _, err := s.ReadByte(); err != nil {
				return fmt.Errorf("exc_handlers %d handler %d stacktrace: %w", i, j, err)
			}
			// Read<int8_t>(has_catch_all) — Raw<1,T> = ReadByte.
			if _, err := s.ReadByte(); err != nil {
				return fmt.Errorf("exc_handlers %d handler %d catch_all: %w", i, j, err)
			}
			// Read<int8_t>(is_generated) — Raw<1,T> = ReadByte.
			if _, err := s.ReadByte(); err != nil {
				return fmt.Errorf("exc_handlers %d handler %d generated: %w", i, j, err)
			}
		}
	}
	return nil
}

// skipFillContext skips Context fill.
// Per object: ReadRef(parent) + num_variables × ReadRef(variable).
// skipFillContext skips Context fill.
// Per object: ReadUnsigned(length) + ReadRef(parent) + length × ReadRef(variable).
func skipFillContext(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool) error {
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("context %d/%d length: %w", i, cm.Count, err)
		}
		// ReadRef(parent).
		if _, err := readRef(s, fillRefUnsigned); err != nil {
			return fmt.Errorf("context %d parent: %w", i, err)
		}
		for j := int64(0); j < length; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("context %d var %d/%d: %w", i, j, length, err)
			}
		}
	}
	return nil
}

// skipFillTypeArguments skips TypeArguments fill.
//
// New format (v2.14, v2.16+):
//
//	Per object: ReadUnsigned(length) + Read<int32_t>(hash) + ReadUnsigned(nullability) +
//	  ReadRef(instantiations) + length × ReadRef(type).
//
// Old format (v2.13, v2.15 — OldTypeArgsFill):
//
//	Per object: ReadRef(instantiations) + N × ReadRef(type) + Read<int32_t>(hash)
//	  where N = cm.Lengths[i] from alloc phase (no length/nullability in stream).
func skipFillTypeArguments(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool, profile *snapshot.VersionProfile) error {
	if profile.OldTypeArgsFill {
		return skipFillTypeArgumentsOld(s, cm, fillRefUnsigned)
	}
	if debugFill {
		pos := s.Position()
		peek, _ := s.ReadBytes(32)
		s.SetPosition(pos)
		fmt.Fprintf(os.Stderr, "  TypeArgs fill start pos=0x%x raw=%x\n", pos, peek)
		if len(cm.Lengths) > 0 {
			n := 5
			if len(cm.Lengths) < n {
				n = len(cm.Lengths)
			}
			fmt.Fprintf(os.Stderr, "  TypeArgs alloc lengths[0:%d]=%v\n", n, cm.Lengths[:n])
		}
	}
	for i := int64(0); i < cm.Count; i++ {
		itemPos := s.Position()
		// Fill reads length from stream (not from alloc).
		length, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("type_args %d/%d length: %w", i, cm.Count, err)
		}
		if debugFill && (i < 3 || i >= 45 && i <= 50) {
			fmt.Fprintf(os.Stderr, "  typeargs[%d] pos=0x%x length=%d\n", i, itemPos, length)
		}
		// v2.10: Read<bool>(is_canonical) — 1 raw byte.
		if profile.PreCanonicalSplit {
			if _, err := s.ReadByte(); err != nil {
				return fmt.Errorf("type_args %d is_canonical: %w", i, err)
			}
		}
		// Read<int32_t>(hash) — marker 192.
		hash, err := s.ReadTagged32()
		if err != nil {
			return fmt.Errorf("type_args %d hash: %w", i, err)
		}
		// ReadUnsigned(nullability) — marker 128.
		nullab, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("type_args %d nullability: %w", i, err)
		}
		// ReadRef(instantiations).
		inst, err := readRef(s, fillRefUnsigned)
		if err != nil {
			return fmt.Errorf("type_args %d instantiations: %w", i, err)
		}
		if debugFill && i < 3 {
			fmt.Fprintf(os.Stderr, "    hash=%d nullab=%d inst=%d\n", hash, nullab, inst)
		}
		for j := int64(0); j < length; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("type_args %d type %d/%d: %w", i, j, length, err)
			}
		}
	}
	return nil
}

// skipFillTypeArgumentsOld handles the pre-v2.14 TypeArguments fill format.
// Per object: ReadRef(instantiations) + N × ReadRef(type) + Read<int32_t>(hash)
// where N = cm.Lengths[i] from the alloc phase.
func skipFillTypeArgumentsOld(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool) error {
	for i := int64(0); i < cm.Count; i++ {
		allocLen := int64(1)
		if int(i) < len(cm.Lengths) {
			allocLen = cm.Lengths[i]
		}
		// ReadRef(instantiations).
		if _, err := readRef(s, fillRefUnsigned); err != nil {
			return fmt.Errorf("type_args_old %d/%d instantiations: %w", i, cm.Count, err)
		}
		// N × ReadRef(type) where N = alloc length.
		for j := int64(0); j < allocLen; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("type_args_old %d type %d/%d: %w", i, j, allocLen, err)
			}
		}
		// Read<int32_t>(hash).
		if _, err := s.ReadTagged32(); err != nil {
			return fmt.Errorf("type_args_old %d hash: %w", i, err)
		}
	}
	return nil
}

// skipFillInstance skips Instance fill.
// Format: ReadUnsigned64(unboxed_bitmap) ONCE, then per object:
//
//	for each field offset from header to next_field_offset:
//	  if unboxed: ReadWordWith32BitReads (2 × ReadTagged32)
//	  else: ReadRef (ReadRefId)
//
// header_words: 2 for compressed pointers (tags + hash = 2 × 4 bytes = 2 compressed words).
// header_words: 1 for uncompressed (tags = 1 × 8 bytes = 1 word).
func skipFillInstance(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned, compressedPointers, preCanonicalSplit bool) error {
	// v2.13+: ReadUnsigned64(unboxed_fields_bitmap) read once before all objects.
	// v2.10 (PreCanonicalSplit): bitmap from class table (not in stream); assume 0.
	var bitmap int64
	if !preCanonicalSplit {
		var err error
		bitmap, err = s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("instance(%d) bitmap: %w", cm.CID, err)
		}
	}

	nfo := int(cm.NextFieldOffsetInWords)
	if nfo <= 0 {
		return nil
	}
	// Compressed pointers: header = 2 compressed words (tags 4B + hash 4B).
	// Uncompressed: header = 1 word (tags 8B).
	headerWords := 1
	if compressedPointers {
		headerWords = 2
	}
	numFields := nfo - headerWords
	if numFields < 0 {
		numFields = 0
	}

	for i := int64(0); i < cm.Count; i++ {
		// v2.10: Read<bool>(is_canonical) per object — 1 raw byte.
		if preCanonicalSplit {
			if _, err := s.ReadByte(); err != nil {
				return fmt.Errorf("instance(%d) %d/%d is_canonical: %w", cm.CID, i, cm.Count, err)
			}
		}
		for j := 0; j < numFields; j++ {
			fieldWordIdx := headerWords + j
			isUnboxed := (bitmap>>uint(fieldWordIdx))&1 != 0
			if isUnboxed {
				// ReadWordWith32BitReads: 2 × Read<uint32_t> (marker 192).
				if _, err := s.ReadTagged32(); err != nil {
					return fmt.Errorf("instance(%d) %d/%d unboxed field %d lo: %w", cm.CID, i, cm.Count, j, err)
				}
				if _, err := s.ReadTagged32(); err != nil {
					return fmt.Errorf("instance(%d) %d/%d unboxed field %d hi: %w", cm.CID, i, cm.Count, j, err)
				}
			} else {
				if _, err := readRef(s, fillRefUnsigned); err != nil {
					return fmt.Errorf("instance(%d) %d/%d ref %d: %w", cm.CID, i, cm.Count, j, err)
				}
			}
		}
	}
	return nil
}

// skipFillRecord skips Record fill.
// Per object: ReadRef(shape) + num_fields × ReadRef(field).
// skipFillRecord skips Record fill.
// Per object: ReadUnsigned(shape) + num_fields × ReadRef(field).
// num_fields = RecordShape.NumFieldsBitField (lower 16 bits of shape).
func skipFillRecord(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool) error {
	for i := int64(0); i < cm.Count; i++ {
		// Fill reads shape from stream; num_fields decoded from lower 16 bits.
		shape, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("record %d/%d shape: %w", i, cm.Count, err)
		}
		numFields := shape & 0xFFFF
		for j := int64(0); j < numFields; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("record %d field %d/%d: %w", i, j, numFields, err)
			}
		}
	}
	return nil
}

// skipFillContextScope skips ContextScope fill.
// Per scope: num_variables entries, each with multiple refs and scalars.
// ContextScope is non-AOT only (context_scope_ = null in AOT ClosureData).
// In practice this cluster type should not appear in AOT snapshots,
// but we handle it for completeness.
// skipFillContextScope skips ContextScope fill.
// ContextScope is non-AOT only. Should not appear in AOT PRODUCT snapshots.
// Per object: ReadUnsigned(length) + ReadByte(is_implicit) + ReadFromTo(scope, length).
// ReadFromTo reads all pointer fields per variable entry as ReadRef.
func skipFillContextScope(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool) error {
	// ContextScope shouldn't appear in AOT. If it does, we'll attempt to skip
	// using the known structure: ReadUnsigned(length) + ReadByte(is_implicit) +
	// then ReadFromTo which reads pointer fields per variable.
	// Each variable in ContextScope has ~7 pointer fields.
	const refsPerVariable = 7
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("context_scope %d/%d length: %w", i, cm.Count, err)
		}
		// Read<bool>(is_implicit) = ReadByte.
		if _, err := s.ReadByte(); err != nil {
			return fmt.Errorf("context_scope %d is_implicit: %w", i, err)
		}
		// ReadFromTo reads all pointer fields for this scope.
		// Each variable entry has ~7 pointer fields.
		totalRefs := int64(refsPerVariable) * length
		for j := int64(0); j < totalRefs; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("context_scope %d ref %d/%d: %w", i, j, totalRefs, err)
			}
		}
	}
	return nil
}

// typedDataElementSize returns the element size in bytes for a TypedData CID.
func typedDataElementSize(cid int, ct *snapshot.CIDTable) int {
	// DeltaEncodedTypedData (NativePointer) uses element size 1.
	if ct.NativePointerCid != 0 && cid == ct.NativePointerCid {
		return 1
	}

	// Generic TypedData CID (the base class) — element size 1.
	if cid == ct.TypedData {
		return 1
	}

	// Internal TypedData CIDs: stride-based lookup.
	if ct.TypedDataInt8ArrayCid == 0 || ct.TypedDataCidStride == 0 {
		return 1
	}
	idx := (cid - ct.TypedDataInt8ArrayCid) / ct.TypedDataCidStride
	// Element sizes by TypedData type index:
	// 0=Int8(1), 1=Uint8(1), 2=Uint8Clamped(1),
	// 3=Int16(2), 4=Uint16(2), 5=Int32(4), 6=Uint32(4),
	// 7=Int64(8), 8=Uint64(8), 9=Float32(4), 10=Float64(8),
	// 11=Float32x4(16), 12=Int32x4(16), 13=Float64x2(16)
	sizes := [14]int{1, 1, 1, 2, 2, 4, 4, 8, 8, 4, 8, 16, 16, 16}
	if idx >= 0 && idx < 14 {
		return sizes[idx]
	}
	return 1
}
