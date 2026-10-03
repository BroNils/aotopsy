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
	codeIndex     int
	numFixed      int
	numOptional   int
	isStatic      bool
	isNative      bool
	isExternal    bool
	isSuspendable bool
	funcModifier  FunctionModifier
	hasKindTag    bool
	funcKind      FunctionKind
	// Field
	fieldKindBits int32
	// Type
	typeClassID     int32
	typeNullability TypeNullability
	// TypeParameter
	typeParamClassID     int32
	typeParamBase        int
	typeParamIndex       int
	typeParamIsFunction  bool
	typeParamNullability TypeNullability
	typeParamCaptured    bool
	// Script
	scriptLine      int32
	scriptCol       int32
	scriptKernelIdx int32
	scriptFlags     byte
	// LoadingUnit
	loadingUnitID int64
	// FfiTrampolineData
	callbackID int32
	ffiKind    uint8
}

// readFfiTrampolineScalar reads one scalar for an FfiTrampolineData cluster.
func readFfiTrampolineScalar(s *dartfmt.Stream, si int, ss *scalarState, op ScalarOp) error {
	switch op {
	case OpTagged32:
		v, err := s.ReadTagged32()
		if err != nil {
			return err
		}
		if si == 0 {
			ss.callbackID = int32(v)
		}
		return nil
	case OpUint16, OpInt16:
		v, err := s.ReadTagged16()
		if err != nil {
			return err
		}
		if si == 0 {
			ss.callbackID = int32(int16(v))
		}
		return nil
	case OpTagged64:
		v, err := s.ReadTagged64()
		if err != nil {
			return err
		}
		if si == 0 {
			ss.callbackID = int32(v)
		}
		return nil
	case OpUnsigned:
		v, err := s.ReadUnsigned()
		if err != nil {
			return err
		}
		if si == 0 {
			ss.callbackID = int32(v)
		}
		return nil
	case OpBool, OpUint8, OpInt8:
		b, err := s.ReadByte()
		if err != nil {
			return err
		}
		if si == 1 {
			ss.ffiKind = uint8(b)
		}
		return nil
	default:
		return nil
	}
}

// readFunctionScalar reads one scalar for a Function cluster.
// si is the scalar index, numScalars is len(spec.Scalars).
func readFunctionScalar(s *dartfmt.Stream, si int, numScalars int, state *scalarState, i, count int, profile *snapshot.VersionProfile, op ScalarOp, layout FuncPackedFieldsLayout) error {
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
		// Dart 2.x only: Read<uint32_t>(packed_fields_). The bit positions
		// moved at 2.12; see FuncPackedFieldsLayout.
		packed, err := s.ReadTagged32()
		if err != nil {
			return fmt.Errorf("obj %d/%d packed_fields: %w", i, count, err)
		}
		u := uint64(packed)
		state.numFixed = int((u >> layout.FixedShift) & layout.FixedMask)
		state.numOptional = int((u >> layout.OptionalShift) & layout.OptionalMask)
		return nil
	}
	if si == 2 && numScalars == 3 {
		// Dart 2.x: Read<uint32_t>(kind_tag_).
		kindTag, err := s.ReadTagged32()
		if err != nil {
			return fmt.Errorf("obj %d/%d kind_tag: %w", i, count, err)
		}
		captureFunctionKindTag(uint32(kindTag), state, profile)
		return nil
	}
	if si == 1 && numScalars == 2 {
		// Dart 3.x: Read<uint32_t>(kind_tag_).
		kindTag, err := s.ReadTagged32()
		if err != nil {
			return fmt.Errorf("obj %d/%d kind_tag: %w", i, count, err)
		}
		captureFunctionKindTag(uint32(kindTag), state, profile)
		return nil
	}
	// Fallback: skip this scalar to keep stream aligned.
	return skipScalar(s, op)
}

func captureFunctionKindTag(kindTag uint32, state *scalarState, profile *snapshot.VersionProfile) {
	state.funcKind = decodeFunctionKind(kindTag, profile)
	state.funcModifier = decodeFunctionModifier(kindTag)
	state.isSuspendable = state.funcModifier != FunctionModifierNone
	if flags, ok := functionKindTagFlagLayoutFor(profile); ok {
		state.isStatic = kindTag&(uint32(1)<<flags.staticBit) != 0
		state.isNative = kindTag&(uint32(1)<<flags.nativeBit) != 0
		state.isExternal = kindTag&(uint32(1)<<flags.externalBit) != 0
	}
	state.hasKindTag = true
}

// readFuncTypeScalar reads one scalar for a FunctionType cluster.
// si is the scalar index. Returns the FuncTypeInfo if this scalar
// completes the object (si == 1), or nil otherwise.
func readFuncTypeScalar(s *dartfmt.Stream, si int, ref int, paramTypesRef, typeParamsRef, resultTypeRef, namedParamNamesRef int, i, count int, op ScalarOp, layout PackedParamLayout) (*FuncTypeInfo, error) {
	if si == 1 {
		// packed_parameter_counts is OpTagged32 at scalar index 1.
		packed, err := s.ReadTagged32()
		if err != nil {
			return nil, fmt.Errorf("obj %d/%d packed_param_counts: %w", i, count, err)
		}
		// The bit positions are version-dependent; see PackedParamLayout.
		u := uint64(packed)
		hasImplicit := (u>>layout.ImplicitShift)&1 != 0
		hasNamedOptional := (u>>layout.NamedShift)&1 != 0
		numFixed := int((u >> layout.FixedShift) & layout.FixedMask)
		numOptional := int((u >> layout.OptionalShift) & layout.OptionalMask)
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
		// kind_bits is uint16 through Dart 3.9 and uint32 from 3.10.0.
		// Honor the spec's scalar width instead of always using Read32: the
		// encodings overlap for small values, but their accepted domains do not.
		switch op {
		case OpUint16, OpInt16:
			kb, err := s.ReadTagged16()
			if err != nil {
				return nil, fmt.Errorf("obj %d/%d kind_bits: %w", i, count, err)
			}
			state.fieldKindBits = int32(kb)
		case OpTagged32:
			kb, err := s.ReadTagged32()
			if err != nil {
				return nil, fmt.Errorf("obj %d/%d kind_bits: %w", i, count, err)
			}
			state.fieldKindBits = int32(kb)
		default:
			return nil, fmt.Errorf("obj %d/%d unsupported field kind_bits scalar op %d", i, count, op)
		}
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

// readTypeScalar reads one scalar for a Type cluster. It returns TypeInfo once
// the version-specific fields needed for both class id and nullability have
// been consumed: scalar 1 in the 2.15-2.18 split layout, scalar 0 in the packed
// 2.19+ layout.
func readTypeScalar(s *dartfmt.Stream, si int, ref int, state *scalarState, i, count int, op ScalarOp, classIDIsScalar0 bool, classIDShift uint, dartVersion string) (*TypeInfo, error) {
	if classIDShift == 0 {
		classIDShift = 3
	}
	if classIDIsScalar0 {
		// 2.15-2.18: scalar 0 is type_class_id; scalar 1 is the
		// `combined` byte whose low bits are Nullability.
		if si == 0 {
			v, err := s.ReadUnsigned()
			if err != nil {
				return nil, fmt.Errorf("obj %d/%d type class id: %w", i, count, err)
			}
			state.typeClassID = int32(v)
			return nil, nil
		}
		if si == 1 && op == OpUint8 {
			v, err := s.ReadByte()
			if err != nil {
				return nil, fmt.Errorf("obj %d/%d type combined: %w", i, count, err)
			}
			return &TypeInfo{
				RefID:       ref,
				ClassID:     state.typeClassID,
				Nullability: decodeTypeNullability(uint64(v), classIDShift),
			}, nil
		}
	} else if si == 0 {
		// 2.19.0+: the scalar is the packed flags word. type_class_id and
		// nullability are independent bit fields in the same value.
		v, err := s.ReadUnsigned()
			if err != nil {
				return nil, fmt.Errorf("obj %d/%d type flags: %w", i, count, err)
			}
			_, classIDWidth, ok := snapshot.ClassIdTagLayout(dartVersion)
			if !ok {
				return nil, fmt.Errorf("unsupported class-id tag layout for Dart %s", dartVersion)
			}
			return &TypeInfo{
				RefID:       ref,
				ClassID:     int32((v >> classIDShift) & ((1 << classIDWidth) - 1)),
			Nullability: decodeTypeNullability(uint64(v), classIDShift),
		}, nil
	}
	if err := skipScalar(s, op); err != nil {
		return nil, err
	}
	return nil, nil
}

func decodeTypeNullability(raw uint64, classIDShift uint) TypeNullability {
	// TypeState is two bits wide. Therefore the bits below TypeState are
	// exactly the Nullability field: two bits through Dart 3.4, one bit from
	// Dart 3.5 onward. The semantic enum values themselves remain nullable=0,
	// non-nullable=1; the two-bit era also has legacy=2.
	if classIDShift < 3 {
		return TypeNullabilityUnknown
	}
	width := classIDShift - 2
	mask := uint64((1 << width) - 1)
	switch raw & mask {
	case 0:
		return TypeNullabilityNullable
	case 1:
		return TypeNullabilityNonNullable
	case 2:
		return TypeNullabilityLegacy
	default:
		return TypeNullabilityUnknown
	}
}

func readOldTypeScalar(s *dartfmt.Stream, si, numScalars int, state *scalarState, op ScalarOp, classIDShift uint) error {
	if si == numScalars-1 && op == OpUint8 {
		v, err := s.ReadByte()
		if err != nil {
			return err
		}
		state.typeNullability = decodeTypeNullability(uint64(v), classIDShift)
		return nil
	}
	return skipScalar(s, op)
}

func readTypeParameterScalar(s *dartfmt.Stream, si int, state *scalarState, profile *snapshot.VersionProfile, op ScalarOp) error {
	if profile == nil || profile.CIDs == nil {
		return skipScalar(s, op)
	}
	readU16 := func() (int, error) {
		v, err := s.ReadTagged16()
		return int(v), err
	}
	readByte := func() (int, error) {
		v, err := s.ReadByte()
		return int(v), err
	}

	if profile.TypeHasTokenPos {
		switch si {
		case 0:
			v, err := s.ReadTagged32()
			state.typeParamClassID = int32(v)
			return err
		case 1:
			_, err := s.ReadTagged32() // token_pos
			return err
		case 2:
			v, err := s.ReadTagged16()
			state.typeParamIndex = int(int16(v))
			return err
		case 3:
			v, err := s.ReadByte()
			if err != nil {
				return err
			}
			state.typeParamNullability = decodeTypeNullability(uint64(v), typeClassIDShift(profile.DartVersion))
			state.typeParamIsFunction = state.typeParamClassID == int32(profile.CIDs.Function)
			state.typeParamCaptured = true
			return nil
		}
	}

	baseScalar := 0
	if profile.HasTypeParamClassId {
		if si == 0 {
			v, err := s.ReadTagged32()
			state.typeParamClassID = int32(v)
			return err
		}
		baseScalar = 1
	}
	if si == baseScalar {
		var v int
		var err error
		if profile.TypeParamByteScalars && !profile.TypeParamWideScalars {
			v, err = readByte()
		} else {
			v, err = readU16()
		}
		state.typeParamBase = v
		return err
	}
	if si == baseScalar+1 {
		var v int
		var err error
		if profile.TypeParamByteScalars && !profile.TypeParamWideScalars {
			v, err = readByte()
		} else {
			v, err = readU16()
		}
		state.typeParamIndex = v
		return err
	}
	if si == baseScalar+2 && op == OpUint8 {
		v, err := s.ReadByte()
		if err != nil {
			return err
		}
		shift := typeClassIDShift(profile.DartVersion)
		state.typeParamNullability = decodeTypeNullability(uint64(v), shift)
		if profile.HasTypeParamClassId {
			state.typeParamIsFunction = state.typeParamClassID == int32(profile.CIDs.Function)
		} else {
			// Dart 3.1+ moved the class/function discriminator into flags,
			// immediately above TypeState, i.e. at TypeStateBits::kNextBit.
			state.typeParamIsFunction = (uint64(v)>>shift)&1 != 0
		}
		state.typeParamCaptured = true
		return nil
	}
	return skipScalar(s, op)
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
func readLoadingUnitScalar(s *dartfmt.Stream, state *scalarState, i, count int, op ScalarOp) error {
	switch op {
	case OpTagged32:
		v, err := s.ReadTagged32()
		if err != nil {
			return fmt.Errorf("obj %d/%d loading_unit id: %w", i, count, err)
		}
		state.loadingUnitID = int64(int32(v))
		return nil
	case OpTagged64:
		v, err := s.ReadTagged64()
		if err != nil {
			return fmt.Errorf("obj %d/%d loading_unit id: %w", i, count, err)
		}
		state.loadingUnitID = v
		return nil
	default:
		return fmt.Errorf("obj %d/%d loading_unit id: unexpected scalar op %d", i, count, op)
	}
}
