package cluster

import (
	"fmt"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

// skipFillInlineBytes skips clusters that store inline byte data.
// Per object: ReadUnsigned(length) + ReadBytes(length).
// Used for PcDescriptors, CodeSourceMap, CompressedStackMaps with compressed pointers.
func skipFillInlineBytes(s *dartfmt.Stream, cm *ClusterMeta, lengthShift uint) error {
	_, err := readFillInlineBytes(s, cm, false, lengthShift)
	return err
}

// readFillInlineBytes reads an inline-bytes cluster, optionally keeping each
// object's payload.
//
// Format per object: ReadUnsigned(length) + length raw bytes.
//
// This is how PcDescriptors / CodeSourceMap / CompressedStackMaps are stored
// when the snapshot uses compressed pointers, i.e. every Dart 2.18+ build --
// the payload sits inline in the fill stream, not in the ROData image. Only
// non-compressed (2.x) builds route these through ROData. Both paths matter and
// getting them mixed up is why an earlier attempt to read PcDescriptors from
// ROData found nothing on a 3.9.2 arm64 sample.
// lengthShift is FillSpec.InlineBytesLengthShift: 0 when the leading unsigned
// IS the length, 2 for CompressedStackMaps on Dart 2.15.0+ where it is
// flags_and_size with the size starting at bit 2.
func readFillInlineBytes(s *dartfmt.Stream, cm *ClusterMeta, capture bool, lengthShift uint) ([][]byte, error) {
	var payloads [][]byte
	if capture {
		payloads = make([][]byte, 0, cm.Count)
	}
	for i := int64(0); i < cm.Count; i++ {
		raw, err := s.ReadUnsigned()
		if err != nil {
			return payloads, fmt.Errorf("inline_bytes %d/%d length: %w", i, cm.Count, err)
		}
		length := raw >> lengthShift
		if !capture {
			if err := s.Skip(int(length)); err != nil {
				return payloads, fmt.Errorf("inline_bytes %d/%d data (%d bytes): %w", i, cm.Count, length, err)
			}
			continue
		}
		buf, err := s.ReadBytes(int(length))
		if err != nil {
			return payloads, fmt.Errorf("inline_bytes %d/%d data (%d bytes): %w", i, cm.Count, length, err)
		}
		// Copy: ReadBytes may alias the underlying snapshot buffer, and these
		// payloads outlive the parse.
		cp := make([]byte, len(buf))
		copy(cp, buf)
		payloads = append(payloads, cp)
	}
	return payloads, nil
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
// Format (verified against dart-lang/sdk ArrayDeserializationCluster::ReadFill
// at tags 2.10.0, 2.13.0, 2.15.0 — all use the same shape, with v2.10 adding
// an extra Read<bool>(is_canonical) handled via PreCanonicalSplit):
//
//	Per object: ReadUnsigned(length) + ReadRef(type_args) + length × ReadRef(element).
//
// (A previous revision documented an "Old format" for v2.13/v2.15 and kept a
// dead OldArrayFill branch + readFillArrayOld for it; no SDK version actually
// used that format, so both were removed.)
func readFillArray(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool, profile *snapshot.VersionProfile) ([]ArrayInfo, error) {
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

// readFillExceptionHandlers captures ExceptionHandlers fill data.
// v2.17.6: ReadUnsigned(length) directly.
// v3.x: ReadUnsigned(packed_fields), length = packed_fields >> 1 (AsyncHandlerBit at bit 0).
// Then: ReadRef(handled_types_data) + per-handler: Read<uint32_t>(pc_offset) +
// Read<int16_t>(outer_try_index) + Read<int8_t>(needs_stacktrace) +
// Read<int8_t>(has_catch_all) + Read<int8_t>(is_generated).
func readFillExceptionHandlers(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool) ([]ExceptionHandlerInfo, error) {
	var result []ExceptionHandlerInfo
	ref := cm.StartRef
	for i := int64(0); i < cm.Count; i++ {
		raw, err := s.ReadUnsigned()
		if err != nil {
			return result, fmt.Errorf("exc_handlers %d length/packed: %w", i, err)
		}
		length := raw
		if !fillRefUnsigned {
			length = raw >> 1
		}
		handledTypesRef, err := readRef(s, fillRefUnsigned)
		if err != nil {
			return result, fmt.Errorf("exc_handlers %d handled_types: %w", i, err)
		}
		eh := ExceptionHandlerInfo{
			RefID:           ref,
			HandledTypesRef: int(handledTypesRef),
		}
		for j := int64(0); j < length; j++ {
			pcOffset, err := s.ReadTagged32()
			if err != nil {
				return result, fmt.Errorf("exc_handlers %d handler %d pc: %w", i, j, err)
			}
			outerTry, err := s.ReadTagged32()
			if err != nil {
				return result, fmt.Errorf("exc_handlers %d handler %d try_idx: %w", i, j, err)
			}
			needsStack, err := s.ReadByte()
			if err != nil {
				return result, fmt.Errorf("exc_handlers %d handler %d stacktrace: %w", i, j, err)
			}
			hasCatchAll, err := s.ReadByte()
			if err != nil {
				return result, fmt.Errorf("exc_handlers %d handler %d catch_all: %w", i, j, err)
			}
			isGenerated, err := s.ReadByte()
			if err != nil {
				return result, fmt.Errorf("exc_handlers %d handler %d generated: %w", i, j, err)
			}
			eh.Handlers = append(eh.Handlers, ExceptionHandlerEntry{
				PCOffset:        int32(pcOffset),
				OuterTryIndex:   int16(outerTry),
				NeedsStacktrace: needsStack != 0,
				HasCatchAll:     hasCatchAll != 0,
				IsGenerated:     isGenerated != 0,
			})
		}
		result = append(result, eh)
		ref++
	}
	return result, nil
}

// readFillContext captures Context fill data.
// Per object: ReadUnsigned(length) + ReadRef(parent) + length × ReadRef(variable).
func readFillContext(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool) ([]ContextInfo, error) {
	var result []ContextInfo
	ref := cm.StartRef
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return result, fmt.Errorf("context %d/%d length: %w", i, cm.Count, err)
		}
		parentRef, err := readRef(s, fillRefUnsigned)
		if err != nil {
			return result, fmt.Errorf("context %d parent: %w", i, err)
		}
		ctx := ContextInfo{
			RefID:     ref,
			ParentRef: int(parentRef),
		}
		for j := int64(0); j < length; j++ {
			varRef, err := readRef(s, fillRefUnsigned)
			if err != nil {
				return result, fmt.Errorf("context %d var %d/%d: %w", i, j, length, err)
			}
			ctx.VarRefs = append(ctx.VarRefs, int(varRef))
		}
		result = append(result, ctx)
		ref++
	}
	return result, nil
}

// readFillTypeArguments captures TypeArguments fill data.
//
// Format (verified against dart-lang/sdk TypeArgumentsDeserializationCluster
// ::ReadFill at tags 2.13.0, 2.15.0 — same shape, with v2.10 adding an extra
// Read<bool>(is_canonical) handled via PreCanonicalSplit):
//
//	Per object: ReadUnsigned(length) + Read<int32_t>(hash) + ReadUnsigned(nullability) +
//	  ReadRef(instantiations) + length × ReadRef(type).
//
// (A previous revision documented an "Old format" for v2.13/v2.15 and kept a
// dead OldTypeArgsFill branch + readFillTypeArgumentsOld for it; no SDK version
// actually used that format, so both were removed.)
func readFillTypeArguments(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool, profile *snapshot.VersionProfile) ([]TypeArgumentsInfo, error) {
	var result []TypeArgumentsInfo
	ref := cm.StartRef
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return result, fmt.Errorf("type_args %d/%d length: %w", i, cm.Count, err)
		}
		if profile.PreCanonicalSplit {
			if _, err := s.ReadByte(); err != nil {
				return result, fmt.Errorf("type_args %d is_canonical: %w", i, err)
			}
		}
		hash, err := s.ReadTagged32()
		if err != nil {
			return result, fmt.Errorf("type_args %d hash: %w", i, err)
		}
		nullab, err := s.ReadUnsigned()
		if err != nil {
			return result, fmt.Errorf("type_args %d nullability: %w", i, err)
		}
		inst, err := readRef(s, fillRefUnsigned)
		if err != nil {
			return result, fmt.Errorf("type_args %d instantiations: %w", i, err)
		}
		ta := TypeArgumentsInfo{
			RefID:          ref,
			Length:         int(length),
			Instantiations: int(inst),
			Hash:           int32(hash),
			Nullability:    int(nullab),
		}
		for j := int64(0); j < length; j++ {
			typeRef, err := readRef(s, fillRefUnsigned)
			if err != nil {
				return result, fmt.Errorf("type_args %d type %d/%d: %w", i, j, length, err)
			}
			ta.TypeRefs = append(ta.TypeRefs, int(typeRef))
		}
		result = append(result, ta)
		ref++
	}
	return result, nil
}

// skipFillRecord skips Record fill.
// Per object: ReadUnsigned(shape) + num_fields × ReadRef(field).
// num_fields is the low 16 bits of shape.
//
// RecordDeserializationCluster::ReadFill @3.12.2 reads exactly that:
//
//	const intptr_t shape = d.ReadUnsigned();
//	const intptr_t num_fields = RecordShape(shape).num_fields();
//	for (intptr_t j = 0; j < num_fields; ++j) { ... = d.ReadRef(); }
//
// and object.h@3.12.2 has RecordShape::NumFieldsBitField =
// BitField<intptr_t, intptr_t, 0, 16>, hence the 0xFFFF mask.
//
// The comment restored here drops a contradictory first line that said
// ReadRef(shape); the shape is ReadUnsigned, per the SDK above.
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
// Per object: ReadUnsigned(length) + ReadByte(is_implicit) + ReadFromTo(scope, length).
// ReadFromTo reads all pointer fields per variable entry as ReadRef.
//
// ContextScope is non-AOT only (context_scope_ is null in AOT ClosureData),
// so this cluster should not appear in an AOT PRODUCT snapshot at all; it is
// handled for completeness.
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
