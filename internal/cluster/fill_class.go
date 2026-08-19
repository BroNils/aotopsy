package cluster

import (
	"fmt"

	"aotopsy/internal/dartfmt"
)

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
		//
		// The predefined loop reads it and throws it away ("Skip unboxed
		// fields bitmap"); only the second loop calls SetUnboxedFieldsMapAt.
		// Capturing it only for non-predefined classes mirrors that, and it is
		// what makes the kInstanceCid (42) cluster come out with an empty
		// bitmap rather than a predefined class's -- which is correct, since
		// the SDK never stored one for it either.
		isPredefined := int64(i) < cm.MainCount
		isTopLevel := int64(int32(classID)) >= topLevelOffset
		var unboxed uint64
		if isPredefined || !isTopLevel {
			v, err := s.ReadUnsigned()
			if err != nil {
				return named, classes, fmt.Errorf("obj %d/%d bitmap: %w", i, count, err)
			}
			if !isPredefined {
				unboxed = uint64(v)
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

			UnboxedFieldBitmap: unboxed,
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
