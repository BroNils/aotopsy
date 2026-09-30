package cluster

import (
	"encoding/binary"
	"fmt"
	"math"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

// readFillCompressedStackMaps reads the dedicated CompressedStackMaps fill
// format used when the object is not emitted through ROData. Unlike the other
// inline-byte objects, its leading unsigned is semantically part of the object:
// flags_and_size contains both the two table flags and the payload byte count.
// Keep that uint32 header in front of the raw bytes because
// DecodeCompressedStackMaps consumes the in-memory object payload shape.
func readFillCompressedStackMaps(s *dartfmt.Stream, cm *ClusterMeta, lengthShift uint) ([][]byte, error) {
	payloads := make([][]byte, 0, initialCaptureCap(cm.Count, s.Remaining()))
	for i := int64(0); i < cm.Count; i++ {
		raw, err := s.ReadUnsigned()
		if err != nil {
			return payloads, fmt.Errorf("compressed_stack_maps %d/%d flags_and_size: %w", i, cm.Count, err)
		}
		if raw < 0 || raw > math.MaxUint32 {
			return payloads, fmt.Errorf("compressed_stack_maps %d/%d flags_and_size %d out of uint32 range", i, cm.Count, raw)
		}
		length := raw >> lengthShift
		if length < 0 || length > int64(s.Remaining()) {
			return payloads, fmt.Errorf("compressed_stack_maps %d/%d data length %d exceeds remaining %d", i, cm.Count, length, s.Remaining())
		}
		buf, err := s.ReadBytes(int(length))
		if err != nil {
			return payloads, fmt.Errorf("compressed_stack_maps %d/%d data (%d bytes): %w", i, cm.Count, length, err)
		}
		p := make([]byte, 4+len(buf))
		binary.LittleEndian.PutUint32(p[:4], uint32(raw))
		copy(p[4:], buf)
		payloads = append(payloads, p)
	}
	return payloads, nil
}

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
		payloads = make([][]byte, 0, initialCaptureCap(cm.Count, s.Remaining()))
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
		// ReadBytes already returns an owned copy; retaining it does not pin the
		// snapshot buffer and copying it again only doubles peak memory.
		payloads = append(payloads, buf)
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
	arrays := make([]ArrayInfo, 0, initialCaptureCap(cm.Count, s.Remaining()))
	ref := cm.StartRef
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return arrays, fmt.Errorf("array %d/%d length: %w", i, cm.Count, err)
		}
		if err := validateFillLength(cm, i, length, "array"); err != nil {
			return arrays, err
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
		elems := make([]int, 0, initialCaptureCap(length, s.Remaining()))
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
		if err := validateFillLength(cm, i, length, "weak_array"); err != nil {
			return err
		}
		for j := int64(0); j < length; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("weak_array %d elem %d/%d: %w", i, j, length, err)
			}
		}
	}
	return nil
}

// readFillTypedData reads TypedData fill, capturing Int32Array payloads.
// Per object: ReadUnsigned(length) + length × element_size raw bytes.
// v2.10: Read<bool>(is_canonical) after length.
//
// Only Int32Arrays are kept, and only their bytes. That is not a size
// compromise -- it is the one TypedData the static analyzer can read a
// meaning out of: a switch's jump table. IndirectGotoInstr holds its targets
// in `const TypedData& offsets_` of kTypedDataInt32ArrayCid, one int32 per
// case, each the byte offset from the Code's entry to that case's block.
// Every other TypedData in a snapshot is program data whose bytes mean
// nothing without the program.
func readFillTypedData(s *dartfmt.Stream, cm *ClusterMeta, ct *snapshot.CIDTable, preCanonicalSplit bool, out map[int][]byte) error {
	elemSize := typedDataElementSize(cm.CID, ct)
	keep := cm.CID == typedDataInt32ArrayCid(ct)
	ref := cm.StartRef
	for i := int64(0); i < cm.Count; i++ {
		// Fill reads: ReadUnsigned(length), then length * element_size raw bytes.
		length, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("typed_data %d/%d length: %w", i, cm.Count, err)
		}
		if err := validateFillLength(cm, i, length, "typed_data"); err != nil {
			return err
		}
		if preCanonicalSplit {
			if _, err := s.ReadByte(); err != nil {
				return fmt.Errorf("typed_data %d is_canonical: %w", i, err)
			}
		}
		if length < 0 || elemSize <= 0 || length > int64(s.Remaining()/elemSize) {
			return fmt.Errorf("typed_data %d/%d byte length out of range: length=%d elem_size=%d remaining=%d",
				i, cm.Count, length, elemSize, s.Remaining())
		}
		nbytes := int(length) * elemSize
		if keep && out != nil && nbytes > 0 {
			payload, err := s.ReadBytes(nbytes)
			if err != nil {
				return fmt.Errorf("typed_data %d/%d data (%d bytes): %w", i, cm.Count, nbytes, err)
			}
			// ReadBytes already returns an owned copy; store it directly.
			out[ref+int(i)] = payload
		} else if err := s.Skip(nbytes); err != nil {
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
		if err := validateFillLength(cm, i, length, "exception_handlers"); err != nil {
			return result, err
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
			outerTry, err := s.ReadTagged16()
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
		if err := validateFillLength(cm, i, length, "context"); err != nil {
			return result, err
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
		if err := validateFillLength(cm, i, length, "type_args"); err != nil {
			return result, err
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
func skipFillRecord(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool, profile *snapshot.VersionProfile) error {
	for i := int64(0); i < cm.Count; i++ {
		raw, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("record %d/%d shape/num_fields: %w", i, cm.Count, err)
		}

		// Dart 2.19 is the first supported SDK with Record and uses a one-release
		// legacy shape: fill writes num_fields, then a separate field_names ref,
		// then one ref per field. Dart 3.0.5 replaces num_fields+field_names with
		// the packed RecordShape scalar and stores names in that shape, so only the
		// field refs follow. Treating 2.19's num_fields as a RecordShape leaves the
		// field_names ref unread and shifts every subsequent fill record.
		numFields := raw
		legacy219 := profile != nil && profile.DartVersion == "2.19.0"
		if !legacy219 {
			// RecordShape::NumFieldsBitField is the low 16 bits in 3.0+.
			numFields = raw & 0xFFFF
		}
		if err := validateFillLength(cm, i, numFields, "record"); err != nil {
			return err
		}
		if legacy219 {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("record %d field_names: %w", i, err)
			}
		}
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
func skipFillContextScope(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool, profile *snapshot.VersionProfile) error {
	refsPerVariable := contextScopeRefsPerVariable(profile)
	if refsPerVariable <= 0 {
		return fmt.Errorf("context_scope: unsupported variable layout for Dart %q", profile.DartVersion)
	}
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("context_scope %d/%d length: %w", i, cm.Count, err)
		}
		if err := validateFillLength(cm, i, length, "context_scope"); err != nil {
			return err
		}
		// Read<bool>(is_implicit) = ReadByte.
		if _, err := s.ReadByte(); err != nil {
			return fmt.Errorf("context_scope %d is_implicit: %w", i, err)
		}
		// WriteFromTo(scope, length) walks exactly the pointer-storage slots of
		// VariableDesc. The count changed twice: 8 through 2.19, 9 in 3.0/3.1
		// (kernel_offset added), then 10 from 3.2.5 (the type/value union split
		// into independent type and cid fields).
		if length > math.MaxInt64/int64(refsPerVariable) {
			return fmt.Errorf("context_scope %d ref count overflow: length=%d refs_per_variable=%d", i, length, refsPerVariable)
		}
		totalRefs := int64(refsPerVariable) * length
		if totalRefs > int64(s.Remaining()) {
			return fmt.Errorf("context_scope %d needs at least %d ref bytes, only %d remain", i, totalRefs, s.Remaining())
		}
		for j := int64(0); j < totalRefs; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("context_scope %d ref %d/%d: %w", i, j, totalRefs, err)
			}
		}
	}
	return nil
}

func contextScopeRefsPerVariable(profile *snapshot.VersionProfile) int {
	if profile == nil || profile.DartVersion == "" {
		return 0
	}
	switch {
	case snapshot.VersionAtLeast(profile.DartVersion, "3.2.5"):
		return 10
	case snapshot.VersionAtLeast(profile.DartVersion, "3.0.5"):
		return 9
	default:
		return 8
	}
}

// skipFillExternalTypedData mirrors ExternalTypedDataDeserializationCluster:
// ReadUnsigned(length), align to kDataSerializationAlignment (8 on every
// supported SDK), then advance length*element_size bytes. No object refs are
// present in this fill shape.
func skipFillExternalTypedData(s *dartfmt.Stream, cm *ClusterMeta, ct *snapshot.CIDTable) error {
	const dataAlignment = 8
	elementSize := typedDataElementSize(cm.CID, ct)
	if elementSize <= 0 {
		return fmt.Errorf("external_typed_data CID %d has invalid element size %d", cm.CID, elementSize)
	}
	maxInt := int64(^uint(0) >> 1)
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("external_typed_data %d/%d length: %w", i, cm.Count, err)
		}
		if length < 0 || length > maxInt/int64(elementSize) {
			return fmt.Errorf("external_typed_data %d/%d byte length overflow: length=%d element_size=%d", i, cm.Count, length, elementSize)
		}
		pad := (dataAlignment - s.Position()%dataAlignment) % dataAlignment
		if pad > s.Remaining() {
			return fmt.Errorf("external_typed_data %d/%d alignment needs %d bytes, only %d remain", i, cm.Count, pad, s.Remaining())
		}
		if err := s.Align(dataAlignment, 0); err != nil {
			return fmt.Errorf("external_typed_data %d/%d alignment: %w", i, cm.Count, err)
		}
		byteLen := length * int64(elementSize)
		if byteLen > int64(s.Remaining()) {
			return fmt.Errorf("external_typed_data %d/%d payload %d bytes exceeds remaining %d", i, cm.Count, byteLen, s.Remaining())
		}
		if err := s.Skip(int(byteLen)); err != nil {
			return fmt.Errorf("external_typed_data %d/%d payload: %w", i, cm.Count, err)
		}
	}
	return nil
}

func skipFillSimd128(s *dartfmt.Stream, cm *ClusterMeta) error {
	const payloadSize = 16
	for i := int64(0); i < cm.Count; i++ {
		if s.Remaining() < payloadSize {
			return fmt.Errorf("simd128 %d/%d needs %d bytes, only %d remain", i, cm.Count, payloadSize, s.Remaining())
		}
		if err := s.Skip(payloadSize); err != nil {
			return fmt.Errorf("simd128 %d/%d payload: %w", i, cm.Count, err)
		}
	}
	return nil
}

// skipFillDeltaEncodedTypedData mirrors DeltaEncodedTypedDataDeserializationCluster.
// Alloc stores length_in_bytes; fill stores (element_count<<1 | cid_flag), where
// flag 0 means Uint16 and 1 means Uint32, followed by one unsigned delta per
// element. The byte length encoded by both phases must agree.
func skipFillDeltaEncodedTypedData(s *dartfmt.Stream, cm *ClusterMeta, maxSteps int) error {
	for i := int64(0); i < cm.Count; i++ {
		encoded, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("delta_typed_data %d/%d encoded_length: %w", i, cm.Count, err)
		}
		if encoded < 0 {
			return fmt.Errorf("delta_typed_data %d/%d negative encoded length %d", i, cm.Count, encoded)
		}
		length := encoded >> 1
		elementSize := int64(2)
		if encoded&1 != 0 {
			elementSize = 4
		}
		if length > int64(maxSteps) {
			return fmt.Errorf("delta_typed_data %d/%d element count %d exceeds max_steps %d", i, cm.Count, length, maxSteps)
		}
		if length > math.MaxInt64/elementSize {
			return fmt.Errorf("delta_typed_data %d/%d byte length overflow: length=%d element_size=%d", i, cm.Count, length, elementSize)
		}
		if err := validateFillLength(cm, i, length*elementSize, "delta_typed_data"); err != nil {
			return err
		}
		if length > int64(s.Remaining()) {
			return fmt.Errorf("delta_typed_data %d/%d needs at least %d delta bytes, only %d remain", i, cm.Count, length, s.Remaining())
		}
		for j := int64(0); j < length; j++ {
			if _, err := s.ReadUnsigned(); err != nil {
				return fmt.Errorf("delta_typed_data %d/%d delta %d/%d: %w", i, cm.Count, j, length, err)
			}
		}
	}
	return nil
}

// skipFillLocalVarDescriptors mirrors Dart 3.13's exact descriptor layout.
// ReadFromTo(desc, length) reads one name ref per entry; each VarInfo then
// carries index_kind, three token positions and scope_id.
func skipFillLocalVarDescriptors(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned bool, maxSteps int) error {
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("local_var_descriptors %d/%d length: %w", i, cm.Count, err)
		}
		if err := validateFillLength(cm, i, length, "local_var_descriptors"); err != nil {
			return err
		}
		if length < 0 || length > int64(maxSteps) {
			return fmt.Errorf("local_var_descriptors %d/%d length %d exceeds max_steps %d", i, cm.Count, length, maxSteps)
		}
		if length > int64(s.Remaining()) {
			return fmt.Errorf("local_var_descriptors %d/%d needs at least %d name-ref bytes, only %d remain", i, cm.Count, length, s.Remaining())
		}
		for j := int64(0); j < length; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("local_var_descriptors %d/%d name %d/%d: %w", i, cm.Count, j, length, err)
			}
		}
		for j := int64(0); j < length; j++ {
			if _, err := s.ReadTagged32(); err != nil {
				return fmt.Errorf("local_var_descriptors %d/%d entry %d index_kind: %w", i, cm.Count, j, err)
			}
			for k := 0; k < 3; k++ {
				if _, err := s.ReadTagged32(); err != nil {
					return fmt.Errorf("local_var_descriptors %d/%d entry %d token_pos %d: %w", i, cm.Count, j, k, err)
				}
			}
			if _, err := s.ReadTagged64(); err != nil {
				return fmt.Errorf("local_var_descriptors %d/%d entry %d scope_id: %w", i, cm.Count, j, err)
			}
		}
	}
	return nil
}

// skipFillLegacyMap mirrors LinkedHashMapDeserializationCluster through Dart
// 2.13. The compact format serializes only live entries rather than the backing
// table fields used by the 2.14+ ReadFromTo layout:
//
//	[2.10 only] Read<bool>(is_canonical)
//	ReadRef(type_arguments)
//	Read<int32_t>(pairs)
//	pairs * (ReadRef(key), ReadRef(value))
//
// `pairs` is untrusted and controls a parser loop, so cap it with MaxSteps and
// reject impossible minimum byte counts before entering the loop.
func skipFillLegacyMap(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned, leadingBool bool, maxSteps int) error {
	for i := int64(0); i < cm.Count; i++ {
		if leadingBool {
			if _, err := s.ReadByte(); err != nil {
				return fmt.Errorf("legacy_map %d/%d is_canonical: %w", i, cm.Count, err)
			}
		}
		if _, err := readRef(s, fillRefUnsigned); err != nil {
			return fmt.Errorf("legacy_map %d/%d type_arguments: %w", i, cm.Count, err)
		}
		pairs32, err := s.ReadTagged32()
		if err != nil {
			return fmt.Errorf("legacy_map %d/%d pairs: %w", i, cm.Count, err)
		}
		pairs := int64(int32(pairs32))
		if pairs < 0 || pairs > int64(maxSteps) {
			return fmt.Errorf("legacy_map %d/%d pair count %d exceeds max_steps %d", i, cm.Count, pairs, maxSteps)
		}
		if pairs > math.MaxInt64/2 {
			return fmt.Errorf("legacy_map %d/%d ref count overflow: pairs=%d", i, cm.Count, pairs)
		}
		refs := pairs * 2
		// Every encoded ref consumes at least one byte, irrespective of the
		// version's ref encoding. This rejects obviously truncated huge counts
		// without relying on a guessed average varint width.
		if refs > int64(s.Remaining()) {
			return fmt.Errorf("legacy_map %d/%d needs at least %d ref bytes, only %d remain", i, cm.Count, refs, s.Remaining())
		}
		for j := int64(0); j < refs; j++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return fmt.Errorf("legacy_map %d/%d entry ref %d/%d: %w", i, cm.Count, j, refs, err)
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
