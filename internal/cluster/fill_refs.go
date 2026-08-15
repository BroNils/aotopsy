package cluster

import (
	"fmt"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

// readFillRefs reads fill data for a FillRefs cluster, extracting name/owner/signature refs.
// When spec.IsFuncType is true, also extracts packed_parameter_counts from scalars.
// When spec.IsField is true, also extracts kind_bits and host_offset from scalars.
// For ICData, Script, LoadingUnit, KernelProgramInfo: captures all refs and
// scalars into CID-specific structured types.
func readFillRefs(s *dartfmt.Stream, cm *ClusterMeta, spec *FillSpec, fillRefUnsigned bool, profile *snapshot.VersionProfile) ([]NamedObject, []FuncTypeInfo, []FieldInfo, []TypeInfo, []ICDataInfo, []ScriptInfo, []LoadingUnitInfo, []KernelProgramInfoRef, []ClosureDataInfo, []TypeParametersInfo, error) {
	count := int(cm.Count)
	if count <= 0 {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil
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

	// CID-specific capture slices.
	var icDataInfos []ICDataInfo
	var scriptInfos []ScriptInfo
	var loadingUnitInfos []LoadingUnitInfo
	var kpiRefs []KernelProgramInfoRef
	var closureDataInfos []ClosureDataInfo
	var typeParamInfos []TypeParametersInfo
	// Second line of defence for the nil-profile crash fixed in
	// fillOneCluster: a nil profile (or nil CID table) now disables
	// CID-specific capture instead of panicking. The scalar/ref *stream
	// reads* below are driven by spec, not by profile, so skipping capture
	// keeps the stream aligned.
	var isICData, isScript, isLoadingUnit, isKPI, isClosureData, isTypeParameters bool
	// isOldType marks the Dart 2.10-2.15 Type layout, where type_class_id is
	// a REF (a Smi) inside ReadFromTo rather than a scalar. Capturing it
	// needs allRefs, so it has to be in the set below -- it was not, so the
	// capture block further down ("v2.x TypeClassIdIsRef") always saw an
	// empty allRefs and never ran: clResult.Types came out EMPTY for every
	// 2.x snapshot (2187 Type objects in the 2.12 sample, 0 captured).
	//
	// Everything typed hangs off that: FieldTypes (declared field types),
	// BuildClassHierarchy (superclasses, hence LCA and CHA), and the pool's
	// Type -> class resolution. With it empty, 2.x had no field types at all
	// and dispatch resolution had almost nothing to work from.
	var isOldType bool
	if profile != nil && profile.CIDs != nil {
		isICData = cm.CID == profile.CIDs.ICData
		isScript = cm.CID == profile.CIDs.Script
		isLoadingUnit = cm.CID == profile.CIDs.LoadingUnit
		isKPI = cm.CID == profile.CIDs.KernelProgramInfo
		isClosureData = cm.CID == profile.CIDs.ClosureData
		isTypeParameters = profile.CIDs.TypeParameters != 0 && cm.CID == profile.CIDs.TypeParameters
		isOldType = profile.TypeClassIdIsRef && cm.CID == profile.CIDs.Type
	}

	ref := cm.StartRef
	for i := 0; i < count; i++ {
		// v2.10: Read<bool>(is_canonical) — 1 raw byte before refs.
		if spec.LeadingBool {
			if _, err := s.ReadByte(); err != nil {
				return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, fmt.Errorf("obj %d/%d is_canonical: %w", i, count, err)
			}
		}

		var nameRef, ownerRef, sigRef, paramTypesRef, fieldTypeRef, typeParamsRef int
		nameRef = -1
		ownerRef = -1
		sigRef = -1
		paramTypesRef = -1
		fieldTypeRef = -1
		typeParamsRef = -1
		dataRef := -1

		// For CID-specific capture, save all refs in order.
		var allRefs []int

		// Read refs using version-appropriate encoding.
		for j := 0; j < spec.NumRefs; j++ {
			r, err := readRef(s, fillRefUnsigned)
			if err != nil {
				return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, fmt.Errorf("obj %d/%d ref %d: %w", i, count, j, err)
			}
			if isICData || isScript || isLoadingUnit || isKPI || isClosureData || isTypeParameters || isOldType {
				allRefs = append(allRefs, int(r))
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
			// type_parameters sits two slots before parameter_types; see
			// FuncTypeInfo.TypeParamsRefID for the raw_object.h evidence.
			if spec.IsFuncType && spec.FuncTypeParamTypesIdx >= 2 && j == spec.FuncTypeParamTypesIdx-2 {
				typeParamsRef = int(r)
			}
			// Field type ref is at index 2 (refs: name=0, owner=1, type=2, initializer=3).
			if spec.IsField && j == 2 {
				fieldTypeRef = int(r)
			}
			// Function.data is ref 3; for closures it is the ClosureData.
			if spec.IsFunction && j == 3 {
				dataRef = int(r)
			}
		}

		// Read scalars; extract type-specific data for FunctionType and Field clusters.
		var ss scalarState
		for si, op := range spec.Scalars {
			switch {
			case spec.IsFunction:
				if err := readFunctionScalar(s, si, len(spec.Scalars), &ss, i, count, profile, op); err != nil {
					return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, err
				}
			case spec.IsFuncType:
				fti, err := readFuncTypeScalar(s, si, ref, paramTypesRef, typeParamsRef, i, count, op)
				if err != nil {
					return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, err
				}
				if fti != nil {
					funcTypes = append(funcTypes, *fti)
				}
			case spec.IsField:
				fi, err := readFieldScalar(s, si, ref, nameRef, ownerRef, sigRef, fieldTypeRef, &ss, i, count, op)
				if err != nil {
					return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, err
				}
				if fi != nil {
					fields = append(fields, *fi)
				}
			case spec.IsType:
				ti, err := readTypeScalar(s, si, ref, i, count, op)
				if err != nil {
					return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, err
				}
				if ti != nil {
					types = append(types, *ti)
				}
			case isScript:
				if err := readScriptScalar(s, si, profile, &ss, i, count); err != nil {
					return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, err
				}
			case isLoadingUnit:
				if err := readLoadingUnitScalar(s, &ss, i, count); err != nil {
					return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, err
				}
			default:
				if err := skipScalar(s, op); err != nil {
					return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, fmt.Errorf("obj %d/%d scalar: %w", i, count, err)
				}
			}
		}

		// CID-specific capture: build structured types from allRefs + scalars.
		if isICData && len(allRefs) >= 3 {
			// ICData ReadFromTo order (ICDataDeserializationCluster::ReadFill,
			// UntaggedICData): target_name(0), args_descriptor(1), entries(2).
			//
			// UNVERIFIED AGAINST A REAL BINARY, and expected to stay that way:
			// no AOT snapshot in the corpus contains an ICData cluster (0 in
			// all 16 samples across Dart 2.12/3.7/3.9/3.10/3.11/3.12). ICData
			// is a JIT inline cache; the AOT precompiler drops ic_data_array_.
			// So this branch is a capture-if-it-ever-appears path only. Do NOT
			// build analysis features on it -- an earlier revision did (BLR
			// resolution keyed on ICData) and it resolved exactly zero call
			// sites while reporting the *owner's* name as the call target.
			icDataInfos = append(icDataInfos, ICDataInfo{
				RefID:         ref,
				TargetNameRef: allRefs[0],
				ArgsDescRef:   allRefs[1],
				EntriesRef:    allRefs[2],
			})
		}
		if isScript && len(allRefs) >= 1 {
			si := ScriptInfo{
				RefID:             ref,
				URLRef:            allRefs[0],
				LineOffset:        ss.scriptLine,
				ColOffset:         ss.scriptCol,
				KernelScriptIndex: ss.scriptKernelIdx,
			}
			_ = ss.scriptFlags // captured but not stored in struct (rarely needed)
			scriptInfos = append(scriptInfos, si)
		}
		if isLoadingUnit && len(allRefs) >= 1 {
			// LoadingUnit refs: parent(0). Scalar: id.
			lui := LoadingUnitInfo{
				RefID:     ref,
				ParentRef: allRefs[0],
				UnitID:    ss.loadingUnitID,
			}
			loadingUnitInfos = append(loadingUnitInfos, lui)
		}
		if isKPI && len(allRefs) >= 9 {
			// KPI refs: kernel_component(0), string_offsets(1), string_data(2),
			// canonical_names(3), metadata_payloads(4), metadata_mappings(5),
			// scripts(6), constants(7), constants_table(8).
			kpiRefs = append(kpiRefs, KernelProgramInfoRef{
				RefID:              ref,
				KernelComponentRef: allRefs[0],
				StringOffsetsRef:   allRefs[1],
				StringDataRef:      allRefs[2],
				CanonicalNamesRef:  allRefs[3],
				ConstantsRef:       allRefs[7],
				ConstantsTableRef:  allRefs[8],
			})
		}
		if isClosureData && len(allRefs) >= 2 {
			// ClosureData refs in AOT: parent_function(0), closure(1).
			// context_scope_ is null in AOT (not read from stream).
			cd := ClosureDataInfo{
				RefID:             ref,
				ParentFunctionRef: allRefs[0],
				ClosureRef:        allRefs[1],
			}
			closureDataInfos = append(closureDataInfos, cd)
		}
		// v2.x TypeClassIdIsRef: Type.type_class_id is a Smi ref.
		// Capture it so BuildTypeContext can resolve it via MintValues.
		// Ref index depends on version:
		//   v2.10 (NumRefs=5): type_test_stub(0), type_class_id(1), arguments(2), hash(3), signature(4)
		//   v2.12-v2.13 (NumRefs=4): type_test_stub(0), type_class_id(1), arguments(2), hash(3)
		//   v2.14-v2.15 (NumRefs=3): type_class_id(0), arguments(1), hash(2)
		if profile.TypeClassIdIsRef && profile.CIDs != nil && cm.CID == profile.CIDs.Type && len(allRefs) > 0 {
			typeClassIdIdx := 1 // default for v2.10-v2.13 (NumRefs >= 4)
			if spec.NumRefs == 3 {
				typeClassIdIdx = 0 // v2.14-v2.15: type_class_id at index 0
			}
			if typeClassIdIdx < len(allRefs) {
				types = append(types, TypeInfo{
					RefID:          ref,
					ClassID:        0, // resolved later via MintValues
					TypeClassIdRef: allRefs[typeClassIdIdx],
				})
			}
		}
		if isTypeParameters && len(allRefs) >= 4 {
			// UntaggedTypeParameters ReadFromTo: names(0), flags(1),
			// bounds(2), defaults(3).
			typeParamInfos = append(typeParamInfos, TypeParametersInfo{
				RefID:         ref,
				NamesArrayRef: allRefs[0],
				FlagsRef:      allRefs[1],
				BoundsRef:     allRefs[2],
				DefaultsRef:   allRefs[3],
			})
		}

		if hasName {
			named = append(named, NamedObject{
				CID:               cm.CID,
				RefID:             ref,
				NameRefID:         nameRef,
				OwnerRefID:        ownerRef,
				SignatureRefID:    sigRef,
				DataRefID:         dataRef,
				CodeIndex:         ss.codeIndex,
				NumFixedParams:    ss.numFixed,
				NumOptionalParams: ss.numOptional,
				IsStatic:          ss.isStatic,
				HasKindTag:        ss.hasKindTag,
				FuncKind:          ss.funcKind,
			})
		}
		ref++
	}

	return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, nil
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
