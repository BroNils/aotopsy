// Fill format specifications for Dart AOT PRODUCT snapshot clusters.
//
// Each FillKind describes the sequence of reads per object in the fill section.
// The fill parser uses these to skip or extract data from each cluster.

package cluster

import "aotopsy/internal/snapshot"

// FillKind classifies how a cluster's fill data should be parsed.
type FillKind int

const (
	// FillRefs reads N refs (ReadUnsigned each). N is fixed per CID.
	FillRefs FillKind = iota

	// FillString reads (length<<1|twobyte) + raw bytes. Already implemented.
	FillString

	// FillMint has no fill data (value read during alloc).
	FillNone

	// FillDouble reads one raw float64 (8 bytes LE).
	FillDouble

	// FillCode is custom: instructions + refs + scalars.
	FillCode

	// FillObjectPool is custom: per-entry type dispatch.
	FillObjectPool

	// FillArray reads type_args ref + N element refs (N from alloc).
	FillArray

	// FillWeakArray reads N element refs (N from alloc).
	FillWeakArray

	// FillTypedData reads length + raw bytes (length * element_size).
	FillTypedData

	// FillExceptionHandlers reads packed_fields + refs + per-handler scalars.
	FillExceptionHandlers

	// FillContext reads length + parent ref + N variable refs.
	FillContext

	// FillTypeArguments reads length + hash + nullability + instantiations ref + N type refs.
	FillTypeArguments

	// FillROData has no fill data (data lives in read-only image).
	FillROData

	// FillInstance reads N refs where N = (next_field_offset_in_words - header_words).
	FillInstance

	// FillRecord reads N+1 refs: shape ref + N field refs (N from alloc).
	FillRecord

	// FillContextScope is custom: per-scope variable-length data.
	FillContextScope

	// FillSentinel has no fill data.
	FillSentinel

	// FillInstructionsTable has no fill data (handled in alloc/image).
	FillInstructionsTable

	// FillClass is custom: per-object conditional bitmap read.
	FillClass

	// FillField is custom: v2.17.6 has conditional ReadUnsigned for static fields.
	FillField

	// FillInlineBytes reads ReadUnsigned(length) + ReadBytes(length) per object.
	// Used for PcDescriptors/CodeSourceMap/CompressedStackMaps with compressed pointers.
	FillInlineBytes

	// FillUnknown means we don't know the format.
	FillUnknown
)

// FillSpec describes how to parse one cluster's fill section.
type FillSpec struct {
	Kind         FillKind
	NumRefs      int // for FillRefs: number of ReadRef (ReadUnsigned) per object
	Scalars      []ScalarOp
	NameIdx      int  // index in refs of the "name" field (-1 = none)
	OwnerIdx     int  // index in refs of the "owner" field (-1 = none)
	SignatureIdx int  // index in refs of the "signature" field (-1 = none; used for Function→FunctionType link)
	LeadingBool  bool // v2.10: Read<bool>(is_canonical) before refs (1 raw byte per object)
	IsFuncType   bool // true for FunctionType clusters (extract packed_parameter_counts)
	IsField      bool // true for Field clusters (extract kind_bits + host_offset)
	IsFunction   bool // true for Function clusters (extract code_index, scalar 0)
	IsType       bool // true for Type clusters (extract type_class_id, packed into the v3.x "flags" scalar)
	// FuncTypeParamTypesIdx is the ref-loop index of parameter_types,
	// propagated from snapshot.VersionProfile.FuncTypeParamTypesIdx.
	// 0 = not verified for this version, don't extract.
	FuncTypeParamTypesIdx int
}

// ScalarOp describes one scalar read after the refs.
type ScalarOp int

const (
	OpTagged32 ScalarOp = iota // Read<int32_t/uint32_t>: variable-length, marker 192 (via ReadStream::Read32)
	OpTagged64                 // Read<int64_t/double/uword>: variable-length, marker 192 (via ReadStream::Read64)
	OpUnsigned                 // ReadUnsigned: variable-length, marker 128
	OpBool                     // Read<bool>: Raw<1,T> = ReadByte (1 raw byte)
	OpUint8                    // Read<uint8_t>: Raw<1,T> = ReadByte (1 raw byte)
	OpUint16                   // Read<uint16_t>: variable-length, marker 192 (via ReadStream::Read16)
	OpInt16                    // Read<int16_t>: variable-length, marker 192 (via ReadStream::Read16)
	OpInt8                     // Read<int8_t>: Raw<1,T> = ReadByte (1 raw byte)
	OpRefId                    // ReadRef: big-endian signed-byte accumulation (same as refs, but as trailing scalar)
)

// Fill specs for AOT PRODUCT clusters.
//
// Encoding in fill phase (Deserializer::Local):
//   Read<T>() for sizeof(T)==1: Raw<1,T>::Read() = ReadByte (1 raw byte)
//   Read<T>() for sizeof(T)==2: Raw<2,T>::Read() = Read16(kEndByteMarker=192)
//   Read<T>() for sizeof(T)==4: Raw<4,T>::Read() = Read32(kEndByteMarker=192)
//   Read<T>() for sizeof(T)==8: Raw<8,T>::Read() = Read64(kEndByteMarker=192)
//   ReadRef()  = ReadRefId() (big-endian signed-byte accumulation)
//   ReadUnsigned() = variable-length, marker 128

// specFunction returns FillSpec for Function clusters.
// v2.10:   7 refs + ReadRef(code) + Read<uint32_t>(packed_fields) + Read<uint32_t>(kind_tag)
// v2.13:   5 refs + ReadRef(code) + Read<uint32_t>(packed_fields) + Read<uint32_t>(kind_tag)
// v2.14-2.17: 4 refs + ReadUnsigned(code) + Read<uint32_t>(packed_fields) + Read<uint32_t>(kind_tag)
// v3.x:    4 refs + ReadUnsigned(code) + Read<uint32_t>(kind_tag)
func specFunction(fillRefUnsigned bool, numRefs int) FillSpec {
	if numRefs <= 0 {
		numRefs = 4 // default: name, owner, signature, data
	}
	scalars := []ScalarOp{OpUnsigned} // code_index (or code ref for ≤2.13)
	if fillRefUnsigned {
		scalars = append(scalars, OpTagged32) // packed_fields (v2.x only)
	}
	scalars = append(scalars, OpTagged32) // kind_tag
	return FillSpec{
		Kind:         FillRefs,
		NumRefs:      numRefs,
		Scalars:      scalars,
		NameIdx:      0,
		OwnerIdx:     1,
		SignatureIdx: 2, // Function refs: name(0), owner(1), signature(2), data(3)
		IsFunction:   true,
	}
}

// specClass returns FillSpec for Class clusters (AOT PRODUCT).
// Custom handler needed because ReadUnsigned64(bitmap) is conditional:
// - Predefined classes: always read bitmap
// - New classes: only read bitmap if !IsTopLevelCid(class_id)
// v2.10: 16 refs (name through allocation_stub, no PRODUCT guards)
// v2.13: 15 refs (name through allocation_stub, no signature_function)
// v2.14+: 13 refs (name through invocation_dispatcher_cache, PRODUCT)
func specClass(numRefs int) FillSpec {
	if numRefs <= 0 {
		numRefs = 13
	}
	return FillSpec{
		Kind:     FillClass,
		NumRefs:  numRefs,
		NameIdx:  0,
		OwnerIdx: -1,
	}
}

func specPatchClass(preV32 bool) FillSpec {
	// ≤3.1: 3 refs (patched_class, origin_class, script). to_snapshot = &script_.
	// ≥3.2: 2 refs (wrapped_class, script). origin_class removed.
	nrefs := 2
	if preV32 {
		nrefs = 3
	}
	// wrapped_class (ref 0) is the actual Class this PatchClass wraps.
	// Captured via OwnerIdx so a Function/Field whose owner is a PatchClass
	// (common for functions declared in a source-patched/mixin-applied
	// class) can be walked one more hop to the real Class -- otherwise
	// PatchClass refs are invisible to RefToNamed and owner resolution
	// silently stops here.
	return FillSpec{Kind: FillRefs, NumRefs: nrefs, NameIdx: -1, OwnerIdx: 0}
}

func specClosureData(numRefs int) FillSpec {
	// AOT: context_scope=null (not read from stream).
	// v2.14+: parent_function, closure = 2 refs + ReadUnsigned(default_type_arguments_kind)
	// v2.13:  parent_function, closure, default_type_arguments = 3 refs + ReadUnsigned(default_type_arguments_kind)
	if numRefs == 0 {
		numRefs = 2
	}
	return FillSpec{
		Kind:     FillRefs,
		NumRefs:  numRefs,
		Scalars:  []ScalarOp{OpUnsigned},
		NameIdx:  -1,
		OwnerIdx: -1,
	}
}

func specField(fillRefUnsigned bool) FillSpec {
	if fillRefUnsigned {
		// v2.17.6 AOT: ReadFromTo = 4 refs + Read<uint16_t>(kind_bits) +
		// ReadRef(value_or_offset) + CONDITIONAL ReadUnsigned(field_id) for static fields.
		// Needs custom handler due to conditional read.
		return FillSpec{
			Kind:     FillField,
			NumRefs:  4, // name, owner, type, initializer_function
			NameIdx:  0,
			OwnerIdx: 1,
		}
	}
	// v3.10.7 AOT: ReadFromTo = 4 refs + Read<uint32_t>(kind_bits) + ReadRef(host_offset_or_field_id)
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 4, // name, owner, type, initializer_function
		Scalars: []ScalarOp{
			OpTagged32, // kind_bits (uint32)
			OpRefId,    // host_offset_or_field_id (ReadRef)
		},
		NameIdx:      0,
		OwnerIdx:     1,
		SignatureIdx: 3, // initializer_function -- was read from the stream (necessary for correct parsing) but discarded until now; captured into FieldInfo.InitializerRefID
		IsField:      true,
	}
}

func specScript(hasLineCol, hasFlags bool) FillSpec {
	// AOT: 1 ref (url). Then version-dependent scalars.
	// v2.14+:   kernel_script_index only.
	// v2.13:    line_offset + col_offset + kernel_script_index.
	// v2.10:    line_offset + col_offset + flags(uint8) + kernel_script_index.
	var scalars []ScalarOp
	if hasLineCol {
		scalars = append(scalars, OpTagged32, OpTagged32) // line_offset, col_offset
	}
	if hasFlags {
		scalars = append(scalars, OpUint8) // flags
	}
	scalars = append(scalars, OpTagged32) // kernel_script_index
	return FillSpec{
		Kind:     FillRefs,
		NumRefs:  1, // url
		Scalars:  scalars,
		NameIdx:  0, // url is the "name"
		OwnerIdx: -1,
	}
}

func specLibrary() FillSpec {
	// AOT: 10 refs (name through exports). Then scalars. Field order
	// confirmed against dart-lang/sdk's runtime/vm/raw_object.h
	// UntaggedLibrary declaration + to_snapshot(kFullAOT) (ends at
	// exports_): name(0), url(1), private_key(2), dictionary(3),
	// metadata(4), toplevel_class(5), used_scripts(6), loading_unit(7),
	// imports(8), exports(9). kernel_library_index NOT read in AOT.
	//
	// NameIdx deliberately points at url (1), not name (0): Dart's
	// `library` name directive is deprecated/rarely used, so `name` is
	// almost always an empty string in a real compiled app, while `url`
	// (e.g. "dart:core", "package:flutter/widgets.dart",
	// "package:my_app/main.dart") is always populated and is the only
	// field useful for classifying a function's owning library as
	// framework/SDK vs. application code.
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 10, // name through exports
		Scalars: []ScalarOp{
			OpTagged32, // index (int32_t)
			OpTagged32, // num_imports (uint16_t via Read16)
			OpInt8,     // load_state (int8_t → ReadByte)
			OpUint8,    // flags (uint8_t → ReadByte)
		},
		NameIdx:  1,
		OwnerIdx: -1,
	}
}

func specNamespace() FillSpec {
	// AOT: 1 ref (target only). No scalars.
	return FillSpec{Kind: FillRefs, NumRefs: 1, NameIdx: -1, OwnerIdx: -1}
}

func specClosure() FillSpec {
	// ReadFromTo = 6 refs. No scalars in AOT PRODUCT.
	return FillSpec{Kind: FillRefs, NumRefs: 6, NameIdx: -1, OwnerIdx: -1}
}

func specUnlinkedCall() FillSpec {
	// ReadFromTo = 2 refs (target_name, args_descriptor). Read<bool>(can_patch).
	return FillSpec{
		Kind:     FillRefs,
		NumRefs:  2,
		Scalars:  []ScalarOp{OpBool},
		NameIdx:  0, // target_name
		OwnerIdx: -1,
	}
}

func specSubtypeTestCache(fillRefUnsigned, noSTCScalars bool) FillSpec {
	// v2.17.6: ReadRef(cache) only. No scalars.
	// v3.0.x: ReadRef(cache) only. No scalars (num_inputs/num_occupied not yet added).
	// v3.1.0+: ReadRef(cache) + Read<uint32_t>(num_inputs) + Read<uint32_t>(num_occupied).
	var scalars []ScalarOp
	if !fillRefUnsigned && !noSTCScalars {
		scalars = []ScalarOp{OpTagged32, OpTagged32}
	}
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 1,
		Scalars: scalars,
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specLoadingUnit() FillSpec {
	// ReadRef(parent) + Read<int32_t>(id).
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 1,
		Scalars: []ScalarOp{OpTagged32},
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specType(fillRefUnsigned, oldTypeScalars, typeClassIdIsRef, typeHasTokenPos bool, numRefs int) FillSpec {
	// v3.x:       ReadFromTo = 3 refs (type_test_stub, hash, arguments). ReadUnsigned(flags).
	// v2.17-2.19: ReadFromTo = 3 refs. ReadUnsigned(type_class_id) + Read<uint8_t>(combined).
	// v2.14-2.15: ReadFromTo = 3 refs (type_class_id, arguments, hash). Read<uint8_t>(combined).
	// v2.13:      ReadFromTo = 4 refs (type_test_stub, type_class_id, arguments, hash). Read<uint8_t>(combined).
	// v2.10:      ReadFromTo = 5 refs (type_test_stub, type_class_id, arguments, hash, signature).
	//             ReadTokenPosition(token_pos) + Read<uint8_t>(combined).
	if numRefs == 0 {
		numRefs = 3
	}
	var scalars []ScalarOp
	if typeClassIdIsRef && typeHasTokenPos {
		// v2.10: type_class_id in ReadFromTo + token_pos(int32) + combined(uint8)
		scalars = []ScalarOp{OpTagged32, OpUint8}
	} else if typeClassIdIsRef {
		// v2.13-v2.15: type_class_id is a pointer in ReadFromTo, only combined scalar.
		scalars = []ScalarOp{OpUint8}
	} else if oldTypeScalars {
		// v2.17/v2.18: type_class_id(Unsigned) + combined(uint8)
		scalars = []ScalarOp{OpUnsigned, OpUint8}
	} else {
		// v3.x: flags(Unsigned) only. type_class_id is NOT a ref here -- it's
		// packed into this same flags word (confirmed against Dart SDK
		// source, runtime/vm/raw_object.h UntaggedType::TypeClassIdBits):
		// bit 0 = nullability, bits [1,3) = TypeState, bits [3,23) = class id
		// (20-bit ClassIdTag). See readFillRefs' IsType handling.
		scalars = []ScalarOp{OpUnsigned}
	}
	isV3Type := !typeClassIdIsRef && !oldTypeScalars
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: numRefs,
		Scalars: scalars,
		IsType:  isV3Type,
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specFunctionType(numRefs int, oldScalars bool, paramTypesIdx int) FillSpec {
	// v2.17+/v3.x: ReadFromTo = 6 refs. Read<uint8_t>(combined) + Read<uint32_t>(packed_parameter_counts) + Read<uint16_t>(packed_type_parameter_counts).
	// v2.14-2.15:  ReadFromTo = 5 refs (no type_test_stub). Same 3 scalars.
	// v2.13:       ReadFromTo = 6 refs. Read<uint8_t>(combined) + Read<uint32_t>(packed_fields). Only 2 scalars.
	if numRefs == 0 {
		numRefs = 6
	}
	scalars := []ScalarOp{OpUint8, OpTagged32, OpTagged32}
	if oldScalars {
		// v2.13: only combined + packed_fields (no packed_type_parameter_counts)
		scalars = []ScalarOp{OpUint8, OpTagged32}
	}
	return FillSpec{
		Kind:                  FillRefs,
		NumRefs:               numRefs,
		Scalars:               scalars,
		NameIdx:               -1,
		OwnerIdx:              -1,
		IsFuncType:            true,
		FuncTypeParamTypesIdx: paramTypesIdx,
	}
}

func specRecordType() FillSpec {
	// ReadFromTo: type_test_stub, hash, shape, field_types = 4 refs.
	// shape is COMPRESSED_SMI_FIELD (compressed pointer, included in ReadFromTo).
	// Read<uint8_t>(flags).
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 4,
		Scalars: []ScalarOp{OpUint8},
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specTypeParameter(hasParamClassId, typeParamByteScalars, typeParamWideScalars, typeHasTokenPos bool, numRefs int) FillSpec {
	// v3.1.0+: ReadFromTo = 3 refs (type_test_stub, hash, owner).
	//   Read<uint16_t>(base) + Read<uint16_t>(index) + Read<uint8_t>(flags)
	// v3.0.x: ReadFromTo = 3 refs (type_test_stub, hash, bound).
	//   Read<int32_t>(parameterized_class_id) + Read<uint16_t>(base) + Read<uint16_t>(index) + Read<uint8_t>(flags)
	// v2.17-v2.19: ReadFromTo = 3 refs (type_test_stub, hash, bound).
	//   Read<int32_t>(parameterized_class_id) + Read<uint8_t>(base) + Read<uint8_t>(index) + Read<uint8_t>(combined)
	// v2.14-v2.15: ReadFromTo = 2 refs (hash, bound). Same scalars as v2.17.
	// v2.13: ReadFromTo = 5 refs (type_test_stub, name, hash, bound, default_argument).
	//   Read<int32_t>(parameterized_class_id) + Read<uint16_t>(base) + Read<uint16_t>(index) + Read<uint8_t>(combined)
	// v2.10: ReadFromTo = 5 refs (type_test_stub, name, hash, bound, parameterized_function).
	//   Read<int32_t>(parameterized_class_id) + ReadTokenPosition(token_pos) + Read<int16_t>(index) + Read<uint8_t>(combined)
	if numRefs == 0 {
		numRefs = 3
	}
	var scalars []ScalarOp
	switch {
	case typeHasTokenPos:
		// v2.10: parameterized_class_id(int32) + token_pos(int32) + index(int16) + combined(uint8)
		scalars = []ScalarOp{OpTagged32, OpTagged32, OpInt16, OpUint8}
	case typeParamWideScalars:
		// v2.13: parameterized_class_id(int32) + base(uint16) + index(uint16) + combined(uint8)
		scalars = []ScalarOp{OpTagged32, OpTagged32, OpTagged32, OpUint8}
	case hasParamClassId && typeParamByteScalars:
		// v2.14-v2.19: parameterized_class_id(int32) + base(uint8) + index(uint8) + combined(uint8)
		scalars = []ScalarOp{OpTagged32, OpUint8, OpUint8, OpUint8}
	case hasParamClassId:
		// v3.0.x: parameterized_class_id(int32) + base(uint16) + index(uint16) + flags(uint8)
		scalars = []ScalarOp{OpTagged32, OpTagged32, OpTagged32, OpUint8}
	default:
		// v3.1.0+: base(uint16) + index(uint16) + flags(uint8)
		scalars = []ScalarOp{OpTagged32, OpTagged32, OpUint8}
	}
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: numRefs,
		Scalars: scalars,
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specTypeRef(numRefs int) FillSpec {
	// TypeRef serialization: WriteFromTo serializes from type_test_stub
	// (inherited from UntaggedAbstractType) to type (TypeRef's own field).
	// All versions (v2.13, v2.14, v2.15, v2.17.6, v3.x) have 2 refs.
	// Verified against dart-lang/sdk raw_object.h at tags 2.13.0, 2.14.0,
	// 2.15.0, 2.17.6 — all have VISIT_FROM(type_test_stub) + VISIT_TO(type).
	if numRefs == 0 {
		numRefs = 2
	}
	return FillSpec{Kind: FillRefs, NumRefs: numRefs, NameIdx: -1, OwnerIdx: -1}
}

func specGrowableObjectArray() FillSpec {
	// ReadFromTo = 3 refs (type_arguments, length, data). No scalars.
	return FillSpec{Kind: FillRefs, NumRefs: 3, NameIdx: -1, OwnerIdx: -1}
}

func specMap() FillSpec {
	// Map/ConstMap: ReadFromTo(to_snapshot) = 5 refs.
	// Fields: type_arguments, hash_mask, data, used_data, deleted_keys.
	// Field "index" is NOT serialized (null-initialized via to_snapshot()).
	return FillSpec{Kind: FillRefs, NumRefs: 5, NameIdx: -1, OwnerIdx: -1}
}

func specSet() FillSpec {
	// Set/ConstSet: ReadFromTo(to_snapshot) = 5 refs.
	// Fields: type_arguments, hash_mask, data, used_data, deleted_keys.
	// Field "index" is NOT serialized (null-initialized via to_snapshot()).
	// Same layout as Map — both inherit UntaggedLinkedHashBase.
	return FillSpec{Kind: FillRefs, NumRefs: 5, NameIdx: -1, OwnerIdx: -1}
}

func specRegExp(hasExternalFields bool) FillSpec {
	// ≤3.3.0: ReadFromTo = 10 refs (capture_name_map, pattern, one_byte, two_byte,
	//   external_one_byte, external_two_byte, one_byte_sticky, two_byte_sticky,
	//   external_one_byte_sticky, external_two_byte_sticky).
	// ≥3.4.3: ReadFromTo = 6 refs (external_* fields removed).
	// Scalars: Read<int32_t>(num_one_byte_registers) + Read<int32_t>(num_two_byte_registers) + Read<int8_t>(type_flags).
	numRefs := 6
	if hasExternalFields {
		numRefs = 10
	}
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: numRefs,
		Scalars: []ScalarOp{OpTagged32, OpTagged32, OpInt8},
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specWeakProperty() FillSpec {
	// ReadFromTo = 2 refs (key, value). No scalars.
	return FillSpec{Kind: FillRefs, NumRefs: 2, NameIdx: -1, OwnerIdx: -1}
}

func specWeakReference() FillSpec {
	// ReadFromTo = 2 refs (target, type_arguments). No scalars in AOT.
	return FillSpec{Kind: FillRefs, NumRefs: 2, NameIdx: -1, OwnerIdx: -1}
}

func specLibraryPrefix() FillSpec {
	// AOT: to_snapshot(kFullAOT) = &imports_. ReadFromTo = 2 refs (name, imports).
	// importer NOT serialized in AOT.
	// Read<uint16_t>(num_imports) + Read<bool>(is_deferred_load).
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 2,
		Scalars: []ScalarOp{OpTagged32, OpBool},
		NameIdx: 0, OwnerIdx: -1,
	}
}

func specLanguageError() FillSpec {
	// ReadFromTo = 4 refs (previous_error, script, message, formatted_message).
	// ReadTokenPosition = Read<int32_t>(token_pos).
	// Read<bool>(report_after_token).
	// Read<int8_t>(kind).
	// All scalar reads are unconditional (no DART_PRECOMPILED_RUNTIME guard).
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 4,
		Scalars: []ScalarOp{OpTagged32, OpBool, OpInt8},
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specUnhandledException() FillSpec {
	// ReadFromTo = 2 refs (exception, stacktrace). No scalars.
	return FillSpec{Kind: FillRefs, NumRefs: 2, NameIdx: -1, OwnerIdx: -1}
}

func specICData() FillSpec {
	// AOT PRODUCT: ReadFromTo reads CallSiteData fields + ICData entries.
	// CallSiteData: target_name, args_descriptor; ICData: entries = 3 refs total.
	// deopt_id is NOT_IN_PRECOMPILED (skipped in AOT).
	// Read<int32_t>(state_bits) only.
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 3,
		Scalars: []ScalarOp{OpTagged32},
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specMegamorphicCache() FillSpec {
	// ReadFromTo reads CallSiteData (target_name, args_descriptor) + MegamorphicCache (buckets, mask) = 4 refs.
	// Read<int32_t>(filled_entry_count).
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 4,
		Scalars: []ScalarOp{OpTagged32},
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specSingleTargetCache() FillSpec {
	// ReadFromTo: target = 1 ref.
	// Read<uword>(lower_limit) + Read<uword>(upper_limit). uword = 8 bytes on arm64.
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 1,
		Scalars: []ScalarOp{OpTagged64, OpTagged64},
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specKernelProgramInfo() FillSpec {
	// ReadFromTo only. to_snapshot → &constants_table_.
	// Fields: kernel_component, string_offsets, string_data, canonical_names,
	//         metadata_payloads, metadata_mappings, scripts, constants, constants_table = 9 refs.
	// No scalars (ReadFill only does ReadFromTo).
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 9,
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specFfiTrampolineData(fillRefUnsigned, noFfiKind bool) FillSpec {
	// ReadFromTo: signature_type, c_signature, callback_target, callback_exceptional_return = 4 refs.
	// v2.17.6: ReadUnsigned(callback_id) only. No ffi_function_kind.
	// v3.0.x: Read<int32_t>(callback_id) only. ffi_function_kind not yet added.
	// v3.1.0+: Read<int32_t>(callback_id) + Read<uint8_t>(ffi_function_kind).
	var scalars []ScalarOp
	switch {
	case fillRefUnsigned:
		scalars = []ScalarOp{OpUnsigned}
	case noFfiKind:
		scalars = []ScalarOp{OpTagged32}
	default:
		scalars = []ScalarOp{OpTagged32, OpUint8}
	}
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 4,
		Scalars: scalars,
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specSignatureData() FillSpec {
	// v2.10 only. ReadFromTo: parent_function, signature_type = 2 refs.
	return FillSpec{Kind: FillRefs, NumRefs: 2, NameIdx: -1, OwnerIdx: -1}
}

func specTypeParameters() FillSpec {
	// ReadFromTo: names, flags, bounds, defaults = 4 refs. No scalars.
	return FillSpec{Kind: FillRefs, NumRefs: 4, NameIdx: -1, OwnerIdx: -1}
}

func specMonomorphicSmiableCall() FillSpec {
	// Read<uword>(expected_cid) + Read<uword>(entry_point).
	// No refs in fill. uword = 8 bytes on arm64 → Read64(marker 192).
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 0,
		Scalars: []ScalarOp{OpTagged64, OpTagged64},
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specTypedDataView() FillSpec {
	// ReadFromTo: typed_data, offset_in_bytes, length = 3 refs. No scalars.
	return FillSpec{Kind: FillRefs, NumRefs: 3, NameIdx: -1, OwnerIdx: -1}
}

func specExternalTypedData() FillSpec {
	// ReadFromTo: length = 1 ref. Read raw data pointer handling.
	// Actually in AOT, ExternalTypedData not typically serialized. Treat as simple refs.
	return FillSpec{Kind: FillRefs, NumRefs: 1, NameIdx: -1, OwnerIdx: -1}
}

func specStackTrace() FillSpec {
	// ReadFromTo = 2 refs. No scalars in AOT PRODUCT.
	return FillSpec{Kind: FillRefs, NumRefs: 2, NameIdx: -1, OwnerIdx: -1}
}

func specSendPort() FillSpec {
	// SendPort: ReadRef(id) + ReadUnsigned(origin_id).
	// Actually: no ReadFromTo, custom: Read<Dart_Port>(id) + Read<Dart_Port>(origin_id) = 2 × ReadTagged64.
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 0,
		Scalars: []ScalarOp{OpTagged64, OpTagged64},
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specCapability() FillSpec {
	// Read<uint64_t>(id) = ReadTagged64.
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 0,
		Scalars: []ScalarOp{OpTagged64},
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specReceivePort() FillSpec {
	// AOT: ReadRef(send_port) + Read<Dart_Port>(id) = 1 ref + Tagged64.
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 1,
		Scalars: []ScalarOp{OpTagged64},
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specSuspendState() FillSpec {
	// AOT: ReadFromTo = 2 refs (then_callback, error_callback).
	// Read<int32_t>(frame_size).
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 2,
		Scalars: []ScalarOp{OpTagged32},
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specTransferableTypedData() FillSpec {
	// No fill data in AOT typically. Treat as 0 refs.
	return FillSpec{Kind: FillNone, NameIdx: -1, OwnerIdx: -1}
}

func specUserTag() FillSpec {
	// ReadFromTo = 1 ref (label). Read<uword>(tag). uword = 8 bytes on arm64.
	return FillSpec{
		Kind:     FillRefs,
		NumRefs:  1,
		Scalars:  []ScalarOp{OpTagged64},
		NameIdx:  0, // label
		OwnerIdx: -1,
	}
}

func specFutureOr() FillSpec {
	// ReadFromTo = 2 refs (type_test_stub, type_arguments). No scalars.
	return FillSpec{Kind: FillRefs, NumRefs: 2, NameIdx: -1, OwnerIdx: -1}
}

func specWeakSerializationReference() FillSpec {
	// ReadRef(target) = 1 ref. No scalars.
	return FillSpec{Kind: FillRefs, NumRefs: 1, NameIdx: -1, OwnerIdx: -1}
}

// GetFillSpec returns the fill format for a cluster, dispatching by CID.
// Takes the full VersionProfile to access CIDs, version, and compressed pointer flag.
func GetFillSpec(cid int, cm *ClusterMeta, profile *snapshot.VersionProfile) FillSpec {
	ct := profile.CIDs
	fillRefUnsigned := profile.FillRefUnsigned
	preV32 := profile.PreV32Format
	switch {
	case cid == ct.Function:
		return specFunction(fillRefUnsigned, profile.FuncNumRefs)
	case cid == ct.Class:
		return specClass(profile.ClassNumRefs)
	case cid == ct.PatchClass:
		return specPatchClass(preV32)
	case cid == ct.ClosureData:
		return specClosureData(profile.ClosureDataNumRefs)
	case cid == ct.Field:
		return specField(fillRefUnsigned)
	case cid == ct.Script:
		return specScript(profile.ScriptHasLineCol, profile.ScriptHasFlags)
	case cid == ct.Library:
		return specLibrary()
	case cid == ct.Namespace:
		return specNamespace()
	case cid == ct.Closure:
		s := specClosure()
		if profile.PreCanonicalSplit {
			s.LeadingBool = true
		}
		return s
	case cid == ct.UnlinkedCall:
		return specUnlinkedCall()
	case cid == ct.SubtypeTestCache:
		return specSubtypeTestCache(fillRefUnsigned, profile.HasTypeParamClassId)
	case cid == ct.LoadingUnit:
		return specLoadingUnit()
	case cid == ct.Type:
		return specType(fillRefUnsigned, profile.OldTypeScalars, profile.TypeClassIdIsRef, profile.TypeHasTokenPos, profile.TypeNumRefs)
	case cid == ct.FunctionType:
		return specFunctionType(profile.FuncTypeNumRefs, profile.FuncTypeOldScalars, profile.FuncTypeParamTypesIdx)
	case ct.RecordType != 0 && cid == ct.RecordType:
		return specRecordType()
	case cid == ct.TypeParameter:
		return specTypeParameter(profile.HasTypeParamClassId, profile.TypeParamByteScalars, profile.TypeParamWideScalars, profile.TypeHasTokenPos, profile.TypeParamNumRefs)
	case ct.TypeRef != 0 && cid == ct.TypeRef:
		return specTypeRef(profile.TypeRefNumRefs)
	case cid == ct.GrowableObjectArray:
		s := specGrowableObjectArray()
		if profile.PreCanonicalSplit {
			s.LeadingBool = true
		}
		return s
	case cid == ct.Map, cid == ct.ConstMap:
		s := specMap()
		if profile.PreCanonicalSplit {
			s.LeadingBool = true
		}
		return s
	case cid == ct.Set, cid == ct.ConstSet:
		s := specSet()
		if profile.PreCanonicalSplit {
			s.LeadingBool = true
		}
		return s
	case cid == ct.RegExp:
		// ≤3.3.0 (CidShift1): 10 refs (external_* fields present).
		// ≥3.4.3 (ObjectHeader): 6 refs (external_* fields removed).
		hasExternal := profile.Tags == snapshot.TagStyleCidShift1
		return specRegExp(hasExternal)
	case cid == ct.WeakProperty:
		return specWeakProperty()
	case ct.WeakReference != 0 && cid == ct.WeakReference:
		return specWeakReference()
	case cid == ct.LibraryPrefix:
		return specLibraryPrefix()
	case cid == ct.LanguageError:
		return specLanguageError()
	case cid == ct.UnhandledException:
		return specUnhandledException()
	case cid == ct.ICData:
		return specICData()
	case cid == ct.MegamorphicCache:
		return specMegamorphicCache()
	case cid == ct.SingleTargetCache:
		return specSingleTargetCache()
	case ct.MonomorphicSmiableCall != 0 && cid == ct.MonomorphicSmiableCall:
		return specMonomorphicSmiableCall()
	case cid == ct.KernelProgramInfo:
		return specKernelProgramInfo()
	case ct.FfiTrampolineData != 0 && cid == ct.FfiTrampolineData:
		return specFfiTrampolineData(fillRefUnsigned, profile.HasTypeParamClassId)
	case ct.SignatureData != 0 && cid == ct.SignatureData:
		return specSignatureData()
	case ct.TypeParameters != 0 && cid == ct.TypeParameters:
		return specTypeParameters()
	case cid == ct.TypedDataView:
		s := specTypedDataView()
		if profile.PreCanonicalSplit {
			s.LeadingBool = true
		}
		return s
	case cid == ct.ExternalTypedData:
		return specExternalTypedData()
	case cid == ct.StackTrace:
		return specStackTrace()
	case cid == ct.SendPort:
		return specSendPort()
	case ct.Capability != 0 && cid == ct.Capability:
		return specCapability()
	case ct.ReceivePort != 0 && cid == ct.ReceivePort:
		return specReceivePort()
	case ct.SuspendState != 0 && cid == ct.SuspendState:
		return specSuspendState()
	case ct.TransferableTypedData != 0 && cid == ct.TransferableTypedData:
		return specTransferableTypedData()
	case ct.UserTag != 0 && cid == ct.UserTag:
		return specUserTag()
	case ct.FutureOr != 0 && cid == ct.FutureOr:
		return specFutureOr()
	case ct.WeakSerializationReference != 0 && cid == ct.WeakSerializationReference:
		return specWeakSerializationReference()
	case ct.Sentinel != 0 && cid == ct.Sentinel:
		return FillSpec{Kind: FillSentinel, NameIdx: -1, OwnerIdx: -1}

	// Special fill formats (not FillRefs)
	case cid == ct.String, cid == ct.OneByteString, cid == ct.TwoByteString:
		// In AOT without compressed pointers (or SplitCanonical/2.13), strings use
		// ROData format: alloc embeds the data inline, fill has nothing.
		// With compressed pointers, strings have per-string fill data.
		if profile.SplitCanonical || !profile.CompressedPointers {
			return FillSpec{Kind: FillROData, NameIdx: -1, OwnerIdx: -1}
		}
		return FillSpec{Kind: FillString, NameIdx: -1, OwnerIdx: -1}
	case cid == ct.Mint:
		return FillSpec{Kind: FillNone, NameIdx: -1, OwnerIdx: -1}
	case cid == ct.Double:
		return FillSpec{Kind: FillDouble, NameIdx: -1, OwnerIdx: -1}
	case cid == ct.Float32x4:
		return FillSpec{Kind: FillRefs, NumRefs: 0,
			Scalars: []ScalarOp{OpTagged32, OpTagged32, OpTagged32, OpTagged32},
			NameIdx: -1, OwnerIdx: -1}
	case cid == ct.Int32x4:
		return FillSpec{Kind: FillRefs, NumRefs: 0,
			Scalars: []ScalarOp{OpTagged32, OpTagged32, OpTagged32, OpTagged32},
			NameIdx: -1, OwnerIdx: -1}
	case cid == ct.Float64x2:
		return FillSpec{Kind: FillRefs, NumRefs: 0,
			Scalars: []ScalarOp{OpTagged64, OpTagged64},
			NameIdx: -1, OwnerIdx: -1}
	case cid == ct.Code:
		return FillSpec{Kind: FillCode, NameIdx: -1, OwnerIdx: -1}
	case cid == ct.ObjectPool:
		return FillSpec{Kind: FillObjectPool, NameIdx: -1, OwnerIdx: -1}
	case cid == ct.Array, cid == ct.ImmutableArray:
		return FillSpec{Kind: FillArray, NameIdx: -1, OwnerIdx: -1}
	case ct.WeakArray != 0 && cid == ct.WeakArray:
		return FillSpec{Kind: FillWeakArray, NameIdx: -1, OwnerIdx: -1}
	case cid == ct.TypeArguments:
		return FillSpec{Kind: FillTypeArguments, NameIdx: -1, OwnerIdx: -1}
	case cid == ct.ExceptionHandlers:
		return FillSpec{Kind: FillExceptionHandlers, NameIdx: -1, OwnerIdx: -1}
	case cid == ct.Context:
		return FillSpec{Kind: FillContext, NameIdx: -1, OwnerIdx: -1}
	case cid == ct.ContextScope:
		return FillSpec{Kind: FillContextScope, NameIdx: -1, OwnerIdx: -1}
	case cid == ct.PcDescriptors, cid == ct.CodeSourceMap, cid == ct.CompressedStackMaps:
		// With compressed pointers, these use individual clusters with inline data:
		// ReadUnsigned(length) + ReadBytes(length) per object.
		// Without compressed pointers, they use ROData (no fill).
		if profile.CompressedPointers {
			return FillSpec{Kind: FillInlineBytes, NameIdx: -1, OwnerIdx: -1}
		}
		return FillSpec{Kind: FillROData, NameIdx: -1, OwnerIdx: -1}
	case ct.LocalVarDescriptors != 0 && cid == ct.LocalVarDescriptors:
		// Dart 3.13.0+. LocalVarDescriptorsDeserializationCluster::ReadFill is
		// ReadUnsigned(length) then ReadFromTo(desc, length) per object, i.e.
		// the same length-prefixed shape the inline-bytes reader consumes.
		// Guarded on non-zero so older tables, where the field is 0, are not
		// matched by cid 0.
		return FillSpec{Kind: FillInlineBytes, NameIdx: -1, OwnerIdx: -1}
	case cid == ct.TypedData:
		return FillSpec{Kind: FillTypedData, NameIdx: -1, OwnerIdx: -1}
	case ct.Record != 0 && cid == ct.Record:
		return FillSpec{Kind: FillRecord, NameIdx: -1, OwnerIdx: -1}
	}

	// TypedData internal CIDs.
	if ct.TypedDataInt8ArrayCid != 0 && ct.ByteDataViewCid != 0 &&
		cid >= ct.TypedDataInt8ArrayCid && cid < ct.ByteDataViewCid {
		rem := (cid - ct.TypedDataInt8ArrayCid) % ct.TypedDataCidStride
		if rem == 0 {
			// Internal TypedData: same as TypedData fill.
			return FillSpec{Kind: FillTypedData, NameIdx: -1, OwnerIdx: -1}
		}
		if rem == 1 {
			// TypedDataView: 3 refs (typed_data, offset_in_bytes, length).
			return specTypedDataView()
		}
		// External or UnmodifiableView: treat as simple refs.
		return specExternalTypedData()
	}

	// DeltaEncodedTypedData (NativePointer CID).
	if ct.NativePointerCid != 0 && cid == ct.NativePointerCid {
		return FillSpec{Kind: FillTypedData, NameIdx: -1, OwnerIdx: -1}
	}

	// Instance subclasses (CID >= Instance).
	if ct.Instance != 0 && cid >= ct.Instance {
		return FillSpec{Kind: FillInstance, NameIdx: -1, OwnerIdx: -1}
	}

	return FillSpec{Kind: FillUnknown, NameIdx: -1, OwnerIdx: -1}
}
