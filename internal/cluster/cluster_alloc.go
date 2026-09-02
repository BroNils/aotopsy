package cluster

import (
	"fmt"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

func skipAllocV(s *dartfmt.Stream, cm *ClusterMeta, isCanonical bool, ct *snapshot.CIDTable, isVM bool, profile *snapshot.VersionProfile, diags *dartfmt.Diags, maxSteps int) (int64, error) {
	cid := cm.CID
	kind := ClassifyAlloc(cid, ct)
	// v2.12 and earlier (NoCanonicalSetData): canonical sets are rebuilt in memory
	// during PostLoad, never written to the stream. CanonicalSetDeserializationCluster
	// (BuildCanonicalSetFromLayout) was introduced in 2.13 — verified absent from
	// dart-lang/sdk runtime/vm/clustered_snapshot.cc at the 2.12.0 tag. Treat every
	// cluster as non-canonical for alloc-stream purposes on such profiles, even
	// though the tag's canonical bit/position is still meaningful for InitializeHeader.
	canonicalSetInStream := isCanonical && !profile.NoCanonicalSetData

	// Dart 3.13.0+ Closure alloc reads a per-object length after the count
	// (Closure::InstanceSize(length)), where 3.12.2 used ReadAllocFixedSize
	// and read only the count. Handled here rather than in ClassifyAlloc
	// because the shape is version-dependent and ClassifyAlloc sees no
	// profile. Same stream shape as skipRODataAlloc: count + one ReadUnsigned
	// per object, no canonical-set data.
	if profile.ClosureAllocHasLength && ct != nil && ct.Closure != 0 && cid == ct.Closure {
		return skipRODataAlloc(s, cm, false, false, maxSteps)
	}

	switch kind {
	case AllocSimple:
		return skipFixedAllocSimple(s, maxSteps)
	case AllocCanonicalSet:
		if profile.PreCanonicalSplit {
			// v2.10: Type and TypeParameter have internal canonical/non-canonical
			// split: two counts (canonical_count, non_canonical_count) with no
			// canonical set hash table data.
			return skipDualCountAlloc(s, maxSteps)
		}
		// In Dart 2.13 (SplitCanonical), BuildCanonicalSetFromLayout only writes
		// first_element for Type (kAllCanonicalObjectsAreIncludedIntoSet=false).
		// All other canonical set types have first_element hardcoded to 0 and NOT
		// in the stream. In 2.14+, first_element is always in the stream.
		readFirstElement := true
		if profile.SplitCanonical {
			readFirstElement = (cid == ct.Type)
		}
		return skipFixedWithCanonicalSet(s, canonicalSetInStream, readFirstElement, maxSteps)
	case AllocString:
		// In AOT without compressed-pointers, strings use ROData format:
		// count + per-item offset delta (not per-string length).
		// SplitCanonical (2.13) always uses ROData for strings.
		// For other versions, check CompressedPointers flag.
		if profile.SplitCanonical || !profile.CompressedPointers {
			// Only the abstract kStringCid has canonical set data in ROData.
			// OneByteString/TwoByteString via ROData have no canonical set,
			// even when the cluster is canonical (cid_ != kStringCid in C++).
			hasCanonicalSet := canonicalSetInStream && cid == ct.String
			// Pass cm to record offset deltas for later string extraction.
			return skipRODataAlloc(s, cm, hasCanonicalSet, !profile.SplitCanonical, maxSteps)
		}
		// VM snapshot strings never have canonical set data.
		return skipStringAlloc(s, isCanonical && !isVM, maxSteps)
	case AllocMint:
		// Handled in the alloc loop via readMintAlloc (captures ref→value mapping).
		// This path should not be reached.
		return 0, fmt.Errorf("AllocMint should be handled before skipAllocV")
	case AllocArray:
		return skipCountedLengthAlloc(s, cm, maxSteps, "array")
	case AllocWeakArray:
		return skipCountedLengthAlloc(s, cm, maxSteps, "weak_array")
	case AllocTypeArguments:
		// TypeArguments uses kAllCanonicalObjectsAreIncludedIntoSet=true.
		// In 2.13 (SplitCanonical), first_element is NOT in stream.
		// In 2.14+, first_element is always in stream.
		return skipTypeArgumentsAlloc(s, cm, canonicalSetInStream, !profile.SplitCanonical, maxSteps)
	case AllocClass:
		return skipClassAlloc(s, cm, ct, profile.ClassAllocFixedSize, maxSteps)
	case AllocCode:
		// In Dart ≤2.13, Code alloc has no per-object state_bits (they are in fill).
		// In 2.14+, state_bits moved to alloc phase.
		stateBitsInAlloc := profile.Tags != snapshot.TagStyleCidInt32
		return skipCodeAlloc(s, cm, stateBitsInAlloc, maxSteps)
	case AllocObjectPool:
		return skipCountedLengthAlloc(s, cm, maxSteps, "object_pool")
	case AllocROData:
		// ROData for PcDescriptors/CodeSourceMap/CompressedStackMaps is never
		// canonical, so the readFirstElement value doesn't matter.
		//
		// cm is passed (it used to be nil, "no string extraction") purely to
		// RECORD the per-object offset deltas in cm.Lengths. Without them
		// extractRODataPcDescriptors has no way to locate objects in the data
		// image, which is why PcDescriptors decoded to nothing on
		// non-compressed-pointer builds. Recording deltas does not change how
		// much of the stream is consumed.
		return skipRODataAlloc(s, cm, canonicalSetInStream, !profile.SplitCanonical, maxSteps)
	case AllocExceptionHandlers:
		return skipCountedLengthAlloc(s, cm, maxSteps, "exception_handlers")
	case AllocContext:
		return skipCountedLengthAlloc(s, cm, maxSteps, "context")
	case AllocContextScope:
		return skipCountedLengthAlloc(s, cm, maxSteps, "context_scope")
	case AllocRecord:
		return skipCountedLengthAlloc(s, cm, maxSteps, "record")
	case AllocTypedData:
		return skipCountedLengthAlloc(s, cm, maxSteps, "typed_data")
	case AllocInstance:
		return skipInstanceAllocV(s, cm, maxSteps)
	case AllocEmpty:
		// WeakSerializationReference in v2.13+: WriteAlloc writes only the CID tag,
		// ReadAlloc reads nothing. In v2.10 (PreCanonicalSplit), WSR has a count.
		if profile.PreCanonicalSplit {
			return skipFixedAllocSimple(s, maxSteps)
		}
		return 0, nil
	default:
		return 0, fmt.Errorf("unknown CID %d", cid)
	}
}

// skipDualCountAlloc handles v2.10 PreCanonicalSplit clusters (Type, TypeParameter)
// where canonical and non-canonical objects are counted separately within one cluster:
// canonical_count = ReadUnsigned(), non_canonical_count = ReadUnsigned().
// No canonical set hash table data.
func skipDualCountAlloc(s *dartfmt.Stream, maxSteps int) (int64, error) {
	canonical, err := s.ReadUnsigned()
	if err != nil {
		return 0, fmt.Errorf("canonical count: %w", err)
	}
	if canonical < 0 || int(canonical) > maxSteps {
		return 0, fmt.Errorf("canonical count %d out of range", canonical)
	}
	nonCanonical, err := s.ReadUnsigned()
	if err != nil {
		return canonical, fmt.Errorf("non-canonical count: %w", err)
	}
	if nonCanonical < 0 || int(nonCanonical) > maxSteps {
		return canonical, fmt.Errorf("non-canonical count %d out of range", nonCanonical)
	}
	return canonical + nonCanonical, nil
}

// skipFixedAllocSimple skips a cluster whose alloc is just: count = ReadUnsigned().
func skipFixedAllocSimple(s *dartfmt.Stream, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("count %d out of range", count)
	}
	return count, nil
}

// skipFixedWithCanonicalSet skips a fixed-size cluster that may have canonical set data.
// Used for Type, FunctionType, RecordType, TypeParameter, ConstMap, ConstSet.
// readFirstElement controls whether BuildCanonicalSetFromLayout reads first_element
// from the stream (true for ≥2.17, true only for Type in ≤2.16).
func skipFixedWithCanonicalSet(s *dartfmt.Stream, isCanonical bool, readFirstElement bool, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("count %d out of range", count)
	}
	if isCanonical {
		if err := skipCanonicalSet(s, int(count), readFirstElement, maxSteps); err != nil {
			return count, fmt.Errorf("canonical set: %w", err)
		}
	}
	return count, nil
}

// skipCanonicalSet reads the BuildCanonicalSetFromLayout data:
//
//	table_length: ReadUnsigned()
//	first_element: ReadUnsigned()   (only if readFirstElement is true)
//	for i in 0..(count - first_element): gap = ReadUnsigned()
//
// readFirstElement controls whether first_element is present in the stream.
// In Dart ≤2.16, only Type sets kAllCanonicalObjectsAreIncludedIntoSet=false,
// meaning first_element is written/read. All other types (TypeParameter,
// FunctionType, TypeArguments, etc.) use the default true, so first_element
// is hardcoded to 0 and NOT in the stream. In Dart ≥2.17, the format was
// simplified: first_element is always in the stream for all types.
func skipCanonicalSet(s *dartfmt.Stream, count int, readFirstElement bool, maxSteps int) error {
	// Table length (hash table backing array size).
	tableLen, err := s.ReadUnsigned()
	if err != nil {
		return fmt.Errorf("table_length: %w", err)
	}
	if tableLen < 0 || int(tableLen) > maxSteps*16 {
		return fmt.Errorf("table_length %d out of range", tableLen)
	}
	// first_element: number of objects that precede the first gap.
	// Only present in stream when readFirstElement is true.
	var firstElement int64
	if readFirstElement {
		firstElement, err = s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("first_element: %w", err)
		}
		if firstElement < 0 || int(firstElement) > count {
			return fmt.Errorf("first_element %d out of range (count=%d)", firstElement, count)
		}
	}
	// Number of gap values = count - first_element.
	numGaps := count - int(firstElement)
	for i := 0; i < numGaps; i++ {
		if _, err := s.ReadUnsigned(); err != nil {
			return fmt.Errorf("gap %d/%d: %w", i, numGaps, err)
		}
	}
	return nil
}

// skipStringAlloc skips String cluster alloc:
//
//	count + per-string encoded length + canonical set (if canonical).
func skipStringAlloc(s *dartfmt.Stream, isCanonical bool, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("string count %d out of range", count)
	}
	for i := int64(0); i < count; i++ {
		// Each string alloc reads: encoded = ReadUnsigned() (length<<1 | cid_flag)
		if _, err := s.ReadUnsigned(); err != nil {
			return count, fmt.Errorf("string %d/%d alloc: %w", i, count, err)
		}
	}
	if isCanonical {
		// String canonical sets in ≥2.17 always write first_element (kAllCanonical=true
		// but format always includes it). This path is only used for non-SplitCanonical (≥2.17).
		if err := skipCanonicalSet(s, int(count), true, maxSteps); err != nil {
			return count, fmt.Errorf("string canonical set: %w", err)
		}
	}
	return count, nil
}

// readMintAlloc reads Mint cluster alloc, capturing ref→value pairs.
//
// All versions: count + per-mint Read<int64_t>() value.
// v2.10 PreCanonicalSplit: per-mint also has Read<bool>(is_canonical) before value.
func readMintAlloc(s *dartfmt.Stream, preCanonicalSplit bool, maxSteps int) (int64, []int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, nil, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, nil, fmt.Errorf("mint count %d out of range", count)
	}
	// Each mint reads its value during alloc (to determine Smi vs heap Mint).
	values := make([]int64, count)
	for i := int64(0); i < count; i++ {
		if preCanonicalSplit {
			// v2.10: Read<bool>(is_canonical) = 1 raw byte.
			if _, err := s.ReadByte(); err != nil {
				return count, values, fmt.Errorf("mint %d/%d canonical: %w", i, count, err)
			}
		}
		v, err := s.ReadTagged64()
		if err != nil {
			return count, values, fmt.Errorf("mint %d/%d value: %w", i, count, err)
		}
		values[i] = v
	}
	return count, values, nil
}

// skipArrayAlloc was an eighth copy of skipCountedLengthAlloc, missed on
// the first consolidation pass and caught by re-running the similarity
// scan afterwards -- which is the argument for re-running it rather than
// assuming one pass finished the job.

// skipTypeArgumentsAlloc skips TypeArguments alloc:
//
//	count + per-item length + canonical set (if canonical).
//
// readFirstElement: whether canonical set has first_element in stream (≥2.17: true, ≤2.16: false).
func skipTypeArgumentsAlloc(s *dartfmt.Stream, cm *ClusterMeta, isCanonical bool, readFirstElement bool, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("type_arguments count %d out of range", count)
	}
	cm.Lengths = make([]int64, count)
	for i := int64(0); i < count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return count, fmt.Errorf("type_arguments %d/%d alloc: %w", i, count, err)
		}
		cm.Lengths[i] = length
	}
	if isCanonical {
		if err := skipCanonicalSet(s, int(count), readFirstElement, maxSteps); err != nil {
			return count, fmt.Errorf("type_arguments canonical set: %w", err)
		}
	}
	return count, nil
}

// skipClassAlloc skips Class alloc:
//
//	predefined_count + per-class ReadCid(), then new_count.
//
// Some Dart SDK builds (observed in Dart 3.5.1 / Flutter forks) write an extra
// WriteUnsigned(total_class_count) before the standard predefined_count field.
// We detect this by checking whether the first value exceeds NumPredefinedCids;
// if so, we consume it and read the next value as the actual predefined_count.
//
// Stores predefined count in cm.MainCount for fill-phase use.
func skipClassAlloc(s *dartfmt.Stream, cm *ClusterMeta, ct *snapshot.CIDTable, fixedSize bool, maxSteps int) (int64, error) {
	// Dart 3.13.0+: ClassDeserializationCluster::ReadAlloc is just
	// ReadAllocFixedSize(d, Class::InstanceSize()), i.e. ONE ReadUnsigned and
	// no per-class ReadCid() list and no second count. Reading the old shape
	// here consumes far more of the alloc stream than the writer produced, so
	// every subsequent cluster -- and FillStart with them -- lands at the
	// wrong offset. That is what made a real 3.13.0 snapshot fail in fill with
	// "cluster 1 (Array): value too large" even though alloc appeared to
	// succeed: the counts it read were plausible, just not the file's.
	//
	// cm.MainCount is deliberately left at zero. readFillClass uses it to tell
	// predefined classes from new ones, a split that no longer exists here;
	// leaving it zero makes the unboxed-bitmap condition reduce to
	// !IsTopLevelCid(class_id), which is exactly what the 3.13.0 fill does.
	if fixedSize {
		count, err := s.ReadUnsigned()
		if err != nil {
			return 0, err
		}
		if count < 0 || int(count) > maxSteps {
			return 0, fmt.Errorf("class count %d out of range", count)
		}
		return count, nil
	}
	predefined, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	// Heuristic: predefined_count must be ≤ NumPredefinedCids (174 for v3.4.3+).
	// If the value is larger, it's an extra "total class count" prefix; skip it
	// and read the real predefined_count.
	if ct != nil && int(predefined) > ct.NumPredefinedCids {
		predefined, err = s.ReadUnsigned()
		if err != nil {
			return 0, err
		}
	}
	if predefined < 0 || int(predefined) > maxSteps {
		return 0, fmt.Errorf("predefined class count %d out of range", predefined)
	}
	cm.PredefCIDs = make([]int64, predefined)
	for i := int64(0); i < predefined; i++ {
		// ReadCid() = Read<int32_t>() with kEndByteMarker=192.
		cid, err := s.ReadTagged32()
		if err != nil {
			return 0, fmt.Errorf("predefined class %d/%d cid: %w", i, predefined, err)
		}
		cm.PredefCIDs[i] = int64(cid)
	}
	newCount, err := s.ReadUnsigned()
	if err != nil {
		return predefined, err
	}
	if newCount < 0 || int(newCount) > maxSteps {
		return predefined, fmt.Errorf("new class count %d out of range", newCount)
	}
	cm.MainCount = predefined
	return predefined + newCount, nil
}

// skipCodeAlloc skips Code cluster alloc.
//
// Format depends on Dart version:
//   - 2.14+: count + per-code state_bits(int32_t), deferred_count + per-deferred state_bits(int32_t)
//   - ≤2.13: count, deferred_count (no per-object data; state_bits read during fill)
func skipCodeAlloc(s *dartfmt.Stream, cm *ClusterMeta, stateBitsInAlloc bool, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("code count %d out of range", count)
	}
	if stateBitsInAlloc {
		for i := int64(0); i < count; i++ {
			sb, err := s.ReadTagged32()
			if err != nil {
				return count, fmt.Errorf("code %d/%d state_bits: %w", i, count, err)
			}
			// DiscardedBit is bit 3 of state_bits (Dart 2.14+).
			if (sb>>3)&1 != 0 {
				if cm.DiscardedCodes == nil {
					cm.DiscardedCodes = make(map[int64]bool)
				}
				cm.DiscardedCodes[i] = true
			}
		}
	}
	cm.MainCount = count
	// Deferred code section.
	deferred, err := s.ReadUnsigned()
	if err != nil {
		return count, fmt.Errorf("deferred code count: %w", err)
	}
	if deferred < 0 || int(deferred) > maxSteps {
		return count, fmt.Errorf("deferred code count %d out of range", deferred)
	}
	if stateBitsInAlloc {
		for i := int64(0); i < deferred; i++ {
			sb, err := s.ReadTagged32()
			if err != nil {
				return count + deferred, fmt.Errorf("deferred code %d/%d state_bits: %w", i, deferred, err)
			}
			// Deferred codes should not be discarded (Dart asserts this).
			if (sb>>3)&1 != 0 {
				if cm.DiscardedCodes == nil {
					cm.DiscardedCodes = make(map[int64]bool)
				}
				cm.DiscardedCodes[count+i] = true
			}
		}
	}
	return count + deferred, nil
}

// skipCountedLengthAlloc reads the alloc section shared by every cluster
// whose format is "count, then one length per object": ObjectPool,
// ExceptionHandlers, Context, ContextScope, WeakArray, Record and
// TypedData. label names the cluster in error messages.
//
// These were seven separate functions, byte-identical apart from that
// label -- ~112 lines encoding one rule seven times. The hazard is not
// the line count: a correction to the count bound or the error wrapping
// had to be made in seven places, and missing one would leave a cluster
// silently parsing differently from its siblings.
func skipCountedLengthAlloc(s *dartfmt.Stream, cm *ClusterMeta, maxSteps int, label string) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("%s count %d out of range", label, count)
	}
	cm.Lengths = make([]int64, count)
	for i := int64(0); i < count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return count, fmt.Errorf("%s %d/%d alloc: %w", label, i, count, err)
		}
		cm.Lengths[i] = length
	}
	return count, nil
}

// skipRODataAlloc skips ROData cluster alloc (used in AOT for PcDescriptors,
// CodeSourceMap, CompressedStackMaps, and sometimes String).
//
//	count + per-item ReadUnsigned() (running offset delta).
//	If CID is String and canonical, also reads canonical set data.
//
// readFirstElement: whether canonical set has first_element in stream.
// If cm is non-nil, records the offset deltas in cm.Lengths for later extraction.
func skipRODataAlloc(s *dartfmt.Stream, cm *ClusterMeta, isCanonical bool, readFirstElement bool, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("rodata count %d out of range", count)
	}
	if cm != nil {
		cm.Lengths = make([]int64, count)
	}
	for i := int64(0); i < count; i++ {
		delta, err := s.ReadUnsigned()
		if err != nil {
			return count, fmt.Errorf("rodata %d/%d offset: %w", i, count, err)
		}
		if cm != nil {
			cm.Lengths[i] = delta
		}
	}
	// ROData canonical set is only for String CID, but we pass isCanonical
	// for safety — the caller knows the CID.
	if isCanonical {
		if err := skipCanonicalSet(s, int(count), readFirstElement, maxSteps); err != nil {
			return count, fmt.Errorf("rodata canonical set: %w", err)
		}
	}
	return count, nil
}

// skipInstanceAllocV skips a generic Instance alloc and stores layout in cm:
//
//	count = ReadUnsigned()
//	next_field_offset = Read<int32_t>()
//	instance_size = Read<int32_t>()
func skipInstanceAllocV(s *dartfmt.Stream, cm *ClusterMeta, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("instance(%d) count %d out of range", cm.CID, count)
	}
	// Instance alloc reads two layout values using Read<int32_t>() (marker 192).
	nfo, err := s.ReadTagged32()
	if err != nil {
		return count, fmt.Errorf("instance(%d) next_field_offset: %w", cm.CID, err)
	}
	cm.NextFieldOffsetInWords = int32(nfo)
	if _, err := s.ReadTagged32(); err != nil {
		return count, fmt.Errorf("instance(%d) instance_size: %w", cm.CID, err)
	}
	return count, nil
}
