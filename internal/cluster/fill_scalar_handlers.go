package cluster

import (
	"fmt"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

// This file holds the per-CID-type scalar handlers that readFillRefs
// (fill.go) dispatches to. Each handler reads one scalar value from the
// stream and updates the per-object capture state.
//
// The scalar loop in readFillRefs iterates spec.Scalars and dispatches to
// the appropriate handler based on spec.IsFunction, spec.IsFuncType,
// spec.IsField, spec.IsType, or CID-specific flags (isScript, isLoadingUnit).

// scalarState holds the per-object capture state that scalar handlers
// update. It is reset to zero at the start of each object in the loop.
type scalarState struct {
	// Function
	codeIndex   int
	numFixed    int
	numOptional int
	isStatic    bool
	hasKindTag  bool
	funcKind    FunctionKind
	// Field
	fieldKindBits int32
	// Script
	scriptLine      int32
	scriptCol       int32
	scriptKernelIdx int32
	scriptFlags     byte
	// LoadingUnit
	loadingUnitID int32
}

// readFunctionScalar reads one scalar for a Function cluster.
// si is the scalar index, numScalars is len(spec.Scalars).
func readFunctionScalar(s *dartfmt.Stream, si int, numScalars int, state *scalarState, i, count int, profile *snapshot.VersionProfile, op ScalarOp) error {
	if si == 0 {
		// code_index is OpUnsigned at scalar index 0.
		ci, err := s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("obj %d/%d code_index: %w", i, count, err)
		}
		state.codeIndex = int(ci)
		return nil
	}
	if si == 1 && numScalars == 3 {
		// Dart 2.x only: Read<uint32_t>(packed_fields_).
		packed, err := s.ReadTagged32()
		if err != nil {
			return fmt.Errorf("obj %d/%d packed_fields: %w", i, count, err)
		}
		state.numFixed = int((packed >> 10) & 0x3FF)
		state.numOptional = int((packed >> 20) & 0x3FF)
		return nil
	}
	if si == 2 && numScalars == 3 {
		// Dart 2.x: Read<uint32_t>(kind_tag_).
		kindTag, err := s.ReadTagged32()
		if err != nil {
			return fmt.Errorf("obj %d/%d kind_tag: %w", i, count, err)
		}
		state.isStatic = (kindTag>>16)&1 == 1
		state.hasKindTag = true
		state.funcKind = decodeFunctionKind(kindTag, profile)
		return nil
	}
	if si == 1 && numScalars == 2 {
		// Dart 3.x: Read<uint32_t>(kind_tag_).
		kindTag, err := s.ReadTagged32()
		if err != nil {
			return fmt.Errorf("obj %d/%d kind_tag: %w", i, count, err)
		}
		state.funcKind = decodeFunctionKind(kindTag, profile)
		state.hasKindTag = true
		return nil
	}
	// Fallback: skip this scalar to keep stream aligned.
	return skipScalar(s, op)
}

// readFuncTypeScalar reads one scalar for a FunctionType cluster.
// si is the scalar index. Returns the FuncTypeInfo if this scalar
// completes the object (si == 1), or nil otherwise.
func readFuncTypeScalar(s *dartfmt.Stream, si int, ref int, paramTypesRef, typeParamsRef, resultTypeRef, namedParamNamesRef int, i, count int, op ScalarOp) (*FuncTypeInfo, error) {
	if si == 1 {
		// packed_parameter_counts is OpTagged32 at scalar index 1.
		packed, err := s.ReadTagged32()
		if err != nil {
			return nil, fmt.Errorf("obj %d/%d packed_param_counts: %w", i, count, err)
		}
		// raw_object.h @3.12.2, UntaggedFunctionType:
		//   bit 0      PackedNumImplicitParameters   (1 bit)
		//   bit 1      PackedHasNamedOptionalParameters
		//   bits 2-15  PackedNumFixedParameters      (14 bits)
		//   bits 16-29 PackedNumOptionalParameters   (14 bits)
		hasImplicit := (packed & 1) != 0
		hasNamedOptional := (packed & 2) != 0
		numFixed := int((packed >> 2) & 0x3FFF)
		numOptional := int((packed >> 16) & 0x3FFF)
		if hasImplicit && numFixed > 0 {
			numFixed-- // subtract implicit 'this'
		}
		return &FuncTypeInfo{
			RefID:                     ref,
			NumFixed:                  numFixed,
			NumOptional:               numOptional,
			HasImplicit:               hasImplicit,
			HasNamedOptional:          hasNamedOptional,
			ParamTypesArrayRefID:      paramTypesRef,
			TypeParamsRefID:           typeParamsRef,
			ResultTypeRefID:           resultTypeRef,
			NamedParamNamesArrayRefID: namedParamNamesRef,
		}, nil
	}
	// Fallback: skip this scalar to keep stream aligned.
	if err := skipScalar(s, op); err != nil {
		return nil, err
	}
	return nil, nil
}

// readFieldScalar reads one scalar for a Field cluster.
// si is the scalar index. Returns the FieldInfo if this scalar
// completes the object (si == 1), or nil otherwise.
func readFieldScalar(s *dartfmt.Stream, si int, ref int, nameRef, ownerRef, sigRef, fieldTypeRef int, state *scalarState, i, count int, op ScalarOp) (*FieldInfo, error) {
	if si == 0 {
		// kind_bits is OpTagged32 at scalar index 0.
		kb, err := s.ReadTagged32()
		if err != nil {
			return nil, fmt.Errorf("obj %d/%d kind_bits: %w", i, count, err)
		}
		state.fieldKindBits = int32(kb)
		return nil, nil
	}
	if si == 1 {
		// host_offset_or_field_id is OpRefId at scalar index 1.
		hostOff, err := s.ReadRefId()
		if err != nil {
			return nil, fmt.Errorf("obj %d/%d host_offset: %w", i, count, err)
		}
		isStatic := (state.fieldKindBits>>1)&1 != 0
		offset := int32(hostOff)
		if isStatic {
			offset = -1
		}
		return &FieldInfo{
			RefID:            ref,
			NameRefID:        nameRef,
			OwnerRefID:       ownerRef,
			KindBits:         state.fieldKindBits,
			HostOffset:       offset,
			InitializerRefID: sigRef,
			TypeRefID:        fieldTypeRef,
		}, nil
	}
	// Fallback: skip this scalar to keep stream aligned.
	if err := skipScalar(s, op); err != nil {
		return nil, err
	}
	return nil, nil
}

// readTypeScalar reads one scalar for a Type cluster (v3.x).
// si is the scalar index. Returns the TypeInfo if this scalar
// completes the object (si == 0), or nil otherwise.
func readTypeScalar(s *dartfmt.Stream, si int, ref int, i, count int, op ScalarOp) (*TypeInfo, error) {
	if si == 0 {
		// flags is OpUnsigned at scalar index 0 (v3.x only).
		// type_class_id is packed inside: bit 0 = nullability,
		// bits [1,3) = TypeState, bits [3,23) = 20-bit ClassIdTag.
		flags, err := s.ReadUnsigned()
		if err != nil {
			return nil, fmt.Errorf("obj %d/%d type flags: %w", i, count, err)
		}
		classID := int32((flags >> 3) & 0xFFFFF)
		return &TypeInfo{RefID: ref, ClassID: classID}, nil
	}
	// Fallback: skip this scalar to keep stream aligned.
	if err := skipScalar(s, op); err != nil {
		return nil, err
	}
	return nil, nil
}

// readScriptScalar reads one scalar for a Script cluster.
// si is the scalar index. Updates state with the captured value.
func readScriptScalar(s *dartfmt.Stream, si int, profile *snapshot.VersionProfile, state *scalarState, i, count int) error {
	if profile.ScriptHasLineCol {
		if si == 0 {
			v, err := s.ReadTagged32()
			if err != nil {
				return fmt.Errorf("obj %d/%d script line: %w", i, count, err)
			}
			state.scriptLine = int32(v)
			return nil
		}
		if si == 1 {
			v, err := s.ReadTagged32()
			if err != nil {
				return fmt.Errorf("obj %d/%d script col: %w", i, count, err)
			}
			state.scriptCol = int32(v)
			return nil
		}
		if profile.ScriptHasFlags && si == 2 {
			v, err := s.ReadByte()
			if err != nil {
				return fmt.Errorf("obj %d/%d script flags: %w", i, count, err)
			}
			state.scriptFlags = v
			return nil
		}
		// kernel_script_index
		v, err := s.ReadTagged32()
		if err != nil {
			return fmt.Errorf("obj %d/%d script kernel_idx: %w", i, count, err)
		}
		state.scriptKernelIdx = int32(v)
		return nil
	}
	if profile.ScriptHasFlags {
		if si == 0 {
			v, err := s.ReadByte()
			if err != nil {
				return fmt.Errorf("obj %d/%d script flags: %w", i, count, err)
			}
			state.scriptFlags = v
			return nil
		}
		v, err := s.ReadTagged32()
		if err != nil {
			return fmt.Errorf("obj %d/%d script kernel_idx: %w", i, count, err)
		}
		state.scriptKernelIdx = int32(v)
		return nil
	}
	// Only kernel_script_index.
	v, err := s.ReadTagged32()
	if err != nil {
		return fmt.Errorf("obj %d/%d script kernel_idx: %w", i, count, err)
	}
	state.scriptKernelIdx = int32(v)
	return nil
}

// readLoadingUnitScalar reads one scalar for a LoadingUnit cluster.
func readLoadingUnitScalar(s *dartfmt.Stream, state *scalarState, i, count int) error {
	v, err := s.ReadTagged32()
	if err != nil {
		return fmt.Errorf("obj %d/%d loading_unit id: %w", i, count, err)
	}
	state.loadingUnitID = int32(v)
	return nil
}
