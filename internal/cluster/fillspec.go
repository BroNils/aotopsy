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

	// FillDouble reads Read<double>, which is Raw<8,double>::Read -> Read64()
	// -- a VARIABLE-length varint, not 8 raw LE bytes (datastream.h). Plus a
	// leading is_canonical byte before 2.12.
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

	// FillExternalTypedData reads length, aligns the stream to 8 bytes, then
	// skips length*element_size external bytes. Unlike ordinary TypedData its
	// alloc phase is fixed-size and does not repeat the length there.
	FillExternalTypedData

	// FillSimd128 reads the raw 16-byte simd128_value_t payload used by
	// Int32x4/Float32x4/Float64x2 from Dart 3.4.0 onward (SDK: the serializer case
	// exists in 3.4.0..3.4.4 and never in 3.3.x; Simd128DeserializationCluster
	// ReadFill is ReadBytes(sizeof(simd128_value_t))).
	FillSimd128

	// FillDeltaEncodedTypedData is the special CID-1 cluster introduced in
	// Dart 2.19: encoded length/cid flag followed by one unsigned delta per
	// Uint16/Uint32 element.
	FillDeltaEncodedTypedData

	// FillLocalVarDescriptors is Dart 3.13's variable-length local descriptor
	// table: length, one String ref per entry, then five scalar fields per entry.
	FillLocalVarDescriptors

	// FillLegacyMap is the Dart <=2.13 LinkedHashMap compact form: optional
	// v2.10 canonical byte, type-arguments ref, int32 live-pair count, then two
	// refs per live pair. Dart 2.14 switched the same CID family to ReadFromTo.
	FillLegacyMap

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
	Kind    FillKind
	NumRefs int // for FillRefs: number of ReadRef (ReadUnsigned) per object
	// LeadingScalars are scalar fields serialized before ReadFromTo/refs. Most
	// clusters put scalars after refs, but Dart 2.10 ParameterTypeCheck writes
	// its intptr_t index first. Keeping the ordering explicit prevents a
	// correct field count with the wrong byte-stream order.
	LeadingScalars []ScalarOp
	Scalars        []ScalarOp
	NameIdx        int  // index in refs of the "name" field (-1 = none)
	OwnerIdx       int  // index in refs of the "owner" field (-1 = none)
	SignatureIdx   int  // index in refs of the "signature" field (-1 = none; used for Function→FunctionType link)
	LeadingBool    bool // v2.10: Read<bool>(is_canonical) before refs (1 raw byte per object)

	// VarLenRefs marks an object whose ref count is not fixed: the fill reads
	// ReadUnsigned(length) first, then NumRefs fixed refs plus `length`
	// variable ones.
	//
	// Dart 3.13.0's Closure is the first such object here. ReadFromTo(obj,
	// params...) walks from()..to_snapshot(kind, params...), and
	// UntaggedClosure::to_snapshot just forwards to to(num_elements), so the
	// whole range including the variable tail is read.
	VarLenRefs bool
	IsFuncType bool // true for FunctionType clusters (extract packed_parameter_counts)
	IsField    bool // true for Field clusters (extract kind_bits + host_offset)
	IsFunction bool // true for Function clusters (extract code_index, scalar 0)
	// IsTypeParameter captures base/index/kind/nullability for the nameless
	// TypeParameter objects that appear inside TypeArguments. Those scalars are
	// required to reproduce the VM's canonical X0/Y0/C1X0/F1Y0 spelling.
	IsTypeParameter bool
	// DataIdx is the ref-loop index of Function.data; see specFunction.
	DataIdx int

	// ResultTypeIdx/ParamTypesIdx are the ref-loop indices of
	// Function.result_type and Function.parameter_types, which exist only
	// before FunctionType did. -1 from 2.12 on, where the same information
	// hangs off the signature instead. See FunctionRefLayout.
	ResultTypeIdx int
	ParamTypesIdx int
	IsType        bool // true for Type clusters (extract type_class_id)
	IsRecordType  bool // true for RecordType clusters (capture shape/field types/nullability)
	// TypeClassIDIsScalar0 marks the Dart 2.16-2.18 Type layout, where
	// scalar 0 is the raw type_class_id rather than the packed "flags" word
	// that 2.19.0+ uses:
	//
	//	2.16-2.18  type->untag()->type_class_id_ = d.ReadUnsigned();
	//	           const uint8_t combined = d.Read<uint8_t>();
	//	2.19.0+    type->untag()->set_flags(d.ReadUnsigned());
	//
	// (TypeDeserializationCluster::ReadFill, verified at 2.16.0, 2.17.6,
	// 2.18.0, 2.19.0 and 3.1.0.) The stream shape was always read correctly;
	// what was missing is that IsType stayed false for this era, so nothing
	// was captured and Result.Types came out empty on every 2.16-2.18
	// snapshot -- 0 of the 2.17.6 sample's Type objects, against 2506 on a
	// 3.9.2 build of the same program.
	TypeClassIDIsScalar0 bool

	// TypeClassIDShift is where type_class_id starts inside the packed
	// "flags" word on 2.19.0+ (TypeClassIdBits, whose shift is
	// TypeStateBits::kNextBit). It is NOT constant across versions:
	//
	//	2.19.0-3.4.3  NullabilityBits is 2 bits wide -> TypeState at 2..3 -> shift 4
	//	3.5.0+        NullabilityBit  is 1 bit  wide -> TypeState at 1..2 -> shift 3
	//
	// (raw_object.h UntaggedAbstractType, checked at 2.19.0, 3.0.5, 3.1.0,
	// 3.2.5, 3.3.0, 3.4.3, 3.5.0, 3.6.2, 3.7.0, 3.9.2 and 3.13.0.) The width
	// is kClassIdTagSize = 20 throughout.
	//
	// A hardcoded 3 made every Type on 2.19.0 through 3.4.3 decode to a
	// class id shifted one bit left: on the 3.1.0 sample only 936 of 2419
	// landed on a real class, the other 1483 on ids like 3800 that no class
	// in the snapshot has.
	TypeClassIDShift uint

	// InlineBytesLengthShift is how far right to shift the leading unsigned to
	// get an inline-bytes payload length.
	//
	// It is 0 for PcDescriptors and CodeSourceMap, whose ReadFill writes a
	// plain length, and 2 for CompressedStackMaps, whose dedicated ReadFill
	// the leading value is flags_and_size and the length is
	// SizeField::decode(flags_and_size) -- GlobalTableBit at bit 0,
	// UsesTableBit at bit 1, SizeField from bit 2
	// (raw_object.h UntaggedCompressedStackMaps).
	//
	// The apparent pre-2.15 plain length is the ALLOC stream field, not the
	// FILL field. Exact 2.14.0 source already reads flags_and_size in
	// CompressedStackMapsDeserializationCluster::ReadFill. Those older Full AOT
	// builds normally take the non-compressed ROData route, which hid this mixup.
	InlineBytesLengthShift uint

	// PackedParams describes how to decode the parameter-count word of a
	// FunctionType. The layout changed at 2.14.0 and decoding one with the
	// other's rule yields plausible-looking but wrong arity for every
	// function -- see PackedParamLayout.
	PackedParams PackedParamLayout
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

// FunctionRefLayout is where each interesting ref sits in a Function's
// ReadFromTo run. -1 means the field does not exist at that version.
//
// UntaggedFunction was reshaped twice, and the two reshapes are NOT the same
// kind of change (raw_object.h at 2.10.0, 2.12.0, 2.14.0):
//
//	2.10   name, owner, result_type, parameter_types, parameter_names,
//	       type_parameters, data                                    (7 refs)
//	2.12   name, owner, parameter_names, signature, data            (5 refs)
//	2.14   name, owner, signature, data                             (4 refs)
//
// At 2.10 there is no FunctionType at all: the signature is spread across the
// Function itself, so result_type and parameter_types are read straight off it.
// From 2.12 they move onto the FunctionType that `signature` points at, which
// is why SignatureIdx and ResultTypeIdx are never both set.
//
// Treating 2.10 like 2.12 does not merely lose the return type -- it also puts
// `data` at index 4, which at 2.10 is parameter_names, so closure resolution
// follows a ref to an Array of parameter name strings.
type FunctionRefLayout struct {
	SignatureIdx  int
	DataIdx       int
	ResultTypeIdx int
	ParamTypesIdx int
}

var (
	functionRefs210 = FunctionRefLayout{SignatureIdx: -1, DataIdx: 6, ResultTypeIdx: 2, ParamTypesIdx: 3}
	functionRefs212 = FunctionRefLayout{SignatureIdx: 3, DataIdx: 4, ResultTypeIdx: -1, ParamTypesIdx: -1}
	functionRefs214 = FunctionRefLayout{SignatureIdx: 2, DataIdx: 3, ResultTypeIdx: -1, ParamTypesIdx: -1}
)

// specFunction returns FillSpec for Function clusters.
// v2.10:   7 refs + ReadRef(code) + Read<uint32_t>(packed_fields) + Read<uint32_t>(kind_tag)
// v2.13:   5 refs + ReadRef(code) + Read<uint32_t>(packed_fields) + Read<uint32_t>(kind_tag)
// v2.14-2.17: 4 refs + ReadUnsigned(code) + Read<uint32_t>(packed_fields) + Read<uint32_t>(kind_tag)
// v3.x:    4 refs + ReadUnsigned(code) + Read<uint32_t>(kind_tag)
// layout gives the ref-loop positions of the fields worth capturing; see
// FunctionRefLayout for how they move across versions and what breaks when the
// wrong one is used.
func specFunction(fillRefUnsigned bool, numRefs int, layout FunctionRefLayout) FillSpec {
	if numRefs <= 0 {
		numRefs = 4 // default: name, owner, signature, data
	}
	scalars := []ScalarOp{OpUnsigned} // code_index (or code ref for ≤2.13)
	if fillRefUnsigned {
		scalars = append(scalars, OpTagged32) // packed_fields (v2.x only)
	}
	scalars = append(scalars, OpTagged32) // kind_tag
	return FillSpec{
		Kind:          FillRefs,
		NumRefs:       numRefs,
		Scalars:       scalars,
		NameIdx:       0,
		OwnerIdx:      1,
		SignatureIdx:  layout.SignatureIdx,
		DataIdx:       layout.DataIdx,
		ResultTypeIdx: layout.ResultTypeIdx,
		ParamTypesIdx: layout.ParamTypesIdx,
		IsFunction:    true,
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

func specClosureData(dartVersion string, numRefs int) FillSpec {
	// Full AOT always omits context_scope, but the remaining ClosureData fields
	// changed repeatedly before settling at 2.14:
	//   2.10: parent_function, signature_type, closure = 3 refs, no scalar
	//   2.12: parent_function, closure, default_type_arguments,
	//         default_type_arguments_info = 4 refs, no scalar
	//   2.13: parent_function, closure, default_type_arguments = 3 refs,
	//         then ReadUnsigned(default_type_arguments_kind)
	//   2.14+: parent_function, closure = 2 refs, then the same unsigned kind.
	var scalars []ScalarOp
	switch {
	case !snapshot.VersionAtLeast(dartVersion, "2.12.0"):
		numRefs = 3
	case !snapshot.VersionAtLeast(dartVersion, "2.13.0"):
		numRefs = 4
	case !snapshot.VersionAtLeast(dartVersion, "2.14.0"):
		numRefs = 3
		scalars = []ScalarOp{OpUnsigned}
	default:
		if numRefs == 0 {
			numRefs = 2
		}
		scalars = []ScalarOp{OpUnsigned}
	}
	return FillSpec{
		Kind:     FillRefs,
		NumRefs:  numRefs,
		Scalars:  scalars,
		NameIdx:  -1,
		OwnerIdx: -1,
	}
}

func specField(fillRefUnsigned bool, dartVersion string) FillSpec {
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
	// 2.18-3.9 AOT: ReadFromTo = 4 refs + Read<uint16_t>(kind_bits) +
	// ReadRef(host_offset_or_field_id). The conditional trailing field_id from
	// the older layout is gone here: static fields serialize the Smi field id as
	// value_or_offset itself.
	// 3.10.0+ widens kind_bits to uint32_t; the rest of the shape is unchanged.
	// SDK: FieldSerializationCluster::WriteFill is Write<uint16_t>(kind_bits_)
	// through 3.9.4 and Write<uint32_t> from 3.10.0.
	kindBitsOp := OpUint16
	if snapshot.VersionAtLeast(dartVersion, "3.10.0") {
		kindBitsOp = OpTagged32
	}
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 4, // name, owner, type, initializer_function
		Scalars: []ScalarOp{
			kindBitsOp, // kind_bits
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
			OpUint16,   // num_imports (uint16_t via Read16)
			OpInt8,     // load_state (int8_t → ReadByte)
			OpUint8,    // flags (uint8_t → ReadByte)
		},
		NameIdx:  1,
		OwnerIdx: -1,
	}
}

func specNamespace(dartVersion string) FillSpec {
	// 2.10/2.12 serialize the full pointer range (to_snapshot returns to()): 2.10
	// has library, show_names, hide_names, metadata_field; 2.12 has target,
	// show_names, hide_names, owner -- 4 refs either way. Dart 2.13 changes
	// to_snapshot(kFullAOT) to stop at target only; every later supported release
	// keeps 1 ref. TestFillLayoutsMatchSDK derives this from raw_object.h per tag.
	numRefs := 1
	if !snapshot.VersionAtLeast(dartVersion, "2.13.0") {
		numRefs = 4
	}
	return FillSpec{Kind: FillRefs, NumRefs: numRefs, NameIdx: -1, OwnerIdx: -1}
}

func specClosure() FillSpec {
	// ReadFromTo = 6 refs. No scalars in AOT PRODUCT.
	// FP-9: Closure function ref capture is done via a dedicated ClosureInfo
	// path in readFillRefs (see isClosure case), NOT via OwnerIdx/SignatureIdx
	// here, because setting those would create NamedObject entries and change
	// the corpus `named` count.
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

func specLoadingUnit(dartVersion string) FillSpec {
	// ReadRef(parent) + loading-unit id. The scalar widened at 3.5.0 when the
	// VM moved id into AtomicBitFieldContainer<intptr_t>::IdBits:
	//   <=3.4.3 Read<int32_t>
	//   >=3.5.0 Read<intptr_t> (64-bit on AOTopsy's supported targets)
	op := OpTagged32
	if snapshot.VersionAtLeast(dartVersion, "3.5.0") {
		op = OpTagged64
	}
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 1,
		Scalars: []ScalarOp{op},
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specType(fillRefUnsigned, oldTypeScalars, typeClassIdIsRef, typeHasTokenPos bool, numRefs int, classIDShift uint) FillSpec {
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
		// v2.16-v2.18: type_class_id(Unsigned) + combined(uint8)
		scalars = []ScalarOp{OpUnsigned, OpUint8}
	} else {
		// v3.x: flags(Unsigned) only. type_class_id is NOT a ref here -- it's
		// packed into this same flags word (confirmed against Dart SDK
		// source, runtime/vm/raw_object.h UntaggedType::TypeClassIdBits):
		// bit 0 = nullability, bits [1,3) = TypeState, bits [3,23) = class id
		// (20-bit ClassIdTag). See readFillRefs' IsType handling.
		scalars = []ScalarOp{OpUnsigned}
	}
	// Both the packed (2.19.0+) and the separate-scalar (2.16-2.18) layouts
	// carry type_class_id in a scalar, so both are capturable. Only the
	// 2.10-2.15 layout keeps it as a ref, and that one is captured from
	// allRefs in readFillRefs instead.
	oldScalarType := oldTypeScalars && !typeClassIdIsRef
	packedType := !typeClassIdIsRef && !oldTypeScalars
	return FillSpec{
		Kind:                 FillRefs,
		NumRefs:              numRefs,
		Scalars:              scalars,
		IsType:               packedType || oldScalarType,
		TypeClassIDIsScalar0: oldScalarType,
		TypeClassIDShift:     classIDShift,
		NameIdx:              -1, OwnerIdx: -1,
	}
}

func specFunctionType(numRefs int, oldScalars bool, paramTypesIdx int, layout PackedParamLayout) FillSpec {
	// v2.17+/v3.x: ReadFromTo = 6 refs. Read<uint8_t>(combined) + Read<uint32_t>(packed_parameter_counts) + Read<uint16_t>(packed_type_parameter_counts).
	// v2.14-2.15:  ReadFromTo = 5 refs (no type_test_stub). Same 3 scalars.
	// v2.13:       ReadFromTo = 6 refs. Read<uint8_t>(combined) + Read<uint32_t>(packed_fields). Only 2 scalars.
	if numRefs == 0 {
		numRefs = 6
	}
	scalars := []ScalarOp{OpUint8, OpTagged32, OpUint16}
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
		PackedParams:          layout,
	}
}

func specRecordType() FillSpec {
	// ReadFromTo: type_test_stub, hash, shape, field_types = 4 refs.
	// shape is COMPRESSED_SMI_FIELD (compressed pointer, included in ReadFromTo).
	// Read<uint8_t>(flags).
	return FillSpec{
		Kind:         FillRefs,
		NumRefs:      4,
		Scalars:      []ScalarOp{OpUint8},
		NameIdx:      -1,
		OwnerIdx:     -1,
		IsRecordType: true,
	}
}

func specTypeParameter(hasParamClassId, typeParamByteScalars, typeParamWideScalars, typeHasTokenPos bool, numRefs int) FillSpec {
	// v3.1.0+: ReadFromTo = 3 refs (type_test_stub, hash, owner).
	//   Read<uint16_t>(base) + Read<uint16_t>(index) + Read<uint8_t>(flags)
	// v3.0.x: ReadFromTo = 3 refs (type_test_stub, hash, bound).
	//   Read<int32_t>(parameterized_class_id) + Read<uint16_t>(base) + Read<uint16_t>(index) + Read<uint8_t>(flags)
	// v2.14-v2.19: ReadFromTo = 3 refs. Scalars are
	//   Read<int32_t>(parameterized_class_id) + Read<uint8_t>(base) + Read<uint8_t>(index) + Read<uint8_t>(combined).
	// v2.12-v2.13: ReadFromTo = 5 refs.
	//   Read<int32_t>(parameterized_class_id) + Read<uint16_t>(base) + Read<uint16_t>(index) + Read<uint8_t>(combined)
	// v2.10: ReadFromTo = 5 refs (type_test_stub, name, hash, bound, parameterized_function).
	//   Read<int32_t>(parameterized_class_id) + ReadTokenPosition(token_pos) + Read<int16_t>(index) + Read<uint8_t>(combined)
	if numRefs == 0 {
		numRefs = 3
	}
	nameIdx := -1
	if numRefs == 5 {
		// SDK @2.12.0 runtime/vm/raw_object.h: UntaggedTypeParameter visits
		// type_test_stub(0), name(1), hash(2), bound(3), default_argument(4).
		// @2.13.0 keeps that layout and TypeTestingStubNamer still spells a
		// TypeParameter with TypeParameter::name(). @2.14.0 moves names into the
		// new TypeParameters object, shrinks TypeParameter to 3 visited refs and
		// switches the TTS namer to CanonicalNameCString. Capture the old name at
		// the serialization boundary instead of trying to reconstruct it later.
		nameIdx = 1
	}
	var scalars []ScalarOp
	switch {
	case typeHasTokenPos:
		// v2.10: parameterized_class_id(int32) + token_pos(int32) + index(int16) + combined(uint8)
		scalars = []ScalarOp{OpTagged32, OpTagged32, OpInt16, OpUint8}
	case typeParamWideScalars:
		// v2.12-v2.13: parameterized_class_id(int32) + base(uint16) + index(uint16) + combined(uint8)
		scalars = []ScalarOp{OpTagged32, OpUint16, OpUint16, OpUint8}
	case hasParamClassId && typeParamByteScalars:
		// v2.14-v2.19: parameterized_class_id(int32) + base(uint8) + index(uint8) + combined(uint8)
		scalars = []ScalarOp{OpTagged32, OpUint8, OpUint8, OpUint8}
	case hasParamClassId:
		// v3.0.x: parameterized_class_id(int32) + base(uint16) + index(uint16) + flags(uint8)
		scalars = []ScalarOp{OpTagged32, OpUint16, OpUint16, OpUint8}
	default:
		// v3.1.0+: base(uint16) + index(uint16) + flags(uint8)
		scalars = []ScalarOp{OpUint16, OpUint16, OpUint8}
	}
	return FillSpec{
		Kind:            FillRefs,
		NumRefs:         numRefs,
		Scalars:         scalars,
		NameIdx:         nameIdx,
		OwnerIdx:        -1,
		IsTypeParameter: true,
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

func specRegExp(dartVersion string) FillSpec {
	// ≤2.12: ReadFromTo = 11 refs because num_bracket_expressions is still a
	// Smi pointer at the start of the visited range.
	// 2.13-3.3.0: ReadFromTo = 10 refs (capture_name_map, pattern, one_byte, two_byte,
	//   external_one_byte, external_two_byte, one_byte_sticky, two_byte_sticky,
	//   external_one_byte_sticky, external_two_byte_sticky).
	// ≥3.4.0: ReadFromTo = 6 refs (external_* fields removed).
	// Scalars are two int32 register counts followed by RegExp flags. The flags
	// field itself changed width at 3.12.0: through 3.11 it is Read<int8_t>(),
	// while 3.12.0+ uses Read<uint32_t>() (new flag bits no longer fit in the old
	// byte representation).
	//
	// SDK (UntaggedRegExp VISIT_FROM..VISIT_TO): 2.12.0 num_bracket_expressions..
	// external_two_byte_sticky (11); 2.13.0..3.3.4 capture_name_map..
	// external_two_byte_sticky (10); 3.4.0 onward capture_name_map..two_byte_sticky
	// (6). RegExpSerializationCluster::WriteFill: Write<int8_t>(type_flags_) in
	// 3.10.7/3.11.x, Write<uint32_t>(flags_) in 3.12.0/3.12.1/3.12.2/3.13.
	numRefs := 11
	if snapshot.VersionAtLeast(dartVersion, "3.4.0") {
		numRefs = 6
	} else if snapshot.VersionAtLeast(dartVersion, "2.13.0") {
		numRefs = 10
	}
	flagOp := OpInt8
	if snapshot.VersionAtLeast(dartVersion, "3.12.0") {
		flagOp = OpTagged32
	}
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: numRefs,
		Scalars: []ScalarOp{OpTagged32, OpTagged32, flagOp},
		NameIdx: -1, OwnerIdx: -1,
	}
}

func specWeakProperty() FillSpec {
	// ReadFromTo = 2 refs (key, value). No scalars.
	return FillSpec{Kind: FillRefs, NumRefs: 2, NameIdx: -1, OwnerIdx: -1}
}

func specLibraryPrefix() FillSpec {
	// AOT: to_snapshot(kFullAOT) = &imports_. ReadFromTo = 2 refs (name, imports).
	// importer NOT serialized in AOT.
	// Read<uint16_t>(num_imports) + Read<bool>(is_deferred_load).
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 2,
		Scalars: []ScalarOp{OpUint16, OpBool},
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
	// target_name is ref 0, exactly as for UnlinkedCall, so the object is named
	// by its selector.
	return FillSpec{
		Kind:    FillRefs,
		NumRefs: 4,
		Scalars: []ScalarOp{OpTagged32},
		NameIdx: 0, OwnerIdx: -1,
	}
}

func specFfiTrampolineData(dartVersion string) FillSpec {
	// ReadFromTo: signature_type, c_signature, callback_target, callback_exceptional_return = 4 refs.
	// <=2.18: ReadUnsigned(callback_id) only. No ffi_function_kind.
	// 2.19-3.0.x: Read<int32_t>(callback_id) only. ffi_function_kind not yet added.
	// v3.1.0+: Read<int32_t>(callback_id) + Read<uint8_t>(ffi_function_kind).
	var scalars []ScalarOp
	switch {
	case !snapshot.VersionAtLeast(dartVersion, "2.19.0"):
		scalars = []ScalarOp{OpUnsigned}
	case !snapshot.VersionAtLeast(dartVersion, "3.1.0"):
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

func specTypedDataView() FillSpec {
	// ReadFromTo: typed_data, offset_in_bytes, length = 3 refs. No scalars.
	return FillSpec{Kind: FillRefs, NumRefs: 3, NameIdx: -1, OwnerIdx: -1}
}

func specExternalTypedData() FillSpec {
	return FillSpec{Kind: FillExternalTypedData, NameIdx: -1, OwnerIdx: -1}
}

func specStackTrace() FillSpec {
	// ReadFromTo = 3 refs throughout the supported range:
	// async_link, code_array, pc_offset_array. No scalars.
	return FillSpec{Kind: FillRefs, NumRefs: 3, NameIdx: -1, OwnerIdx: -1}
}

// specUnsupported is the fill spec of every CID that Serializer::NewClusterForClass
// never serializes into a Full-AOT snapshot (runtime-only, cache, KernelProgramInfo,
// abstract typed-data bases, mutable Map/Set ...). A cluster under such a CID is
// malformed; guessing a shape would move every later fill boundary while looking
// superficially valid, so it fails closed.
func specUnsupported() FillSpec {
	return FillSpec{Kind: FillUnknown, NameIdx: -1, OwnerIdx: -1}
}

func specRedirectionData() FillSpec {
	// Dart 2.10 only: type, identifier, target.
	return FillSpec{Kind: FillRefs, NumRefs: 3, NameIdx: -1, OwnerIdx: -1}
}

func specParameterTypeCheck() FillSpec {
	// Dart 2.10 only: Write<intptr_t>(index_) precedes WriteFromTo over
	// param_, type_or_bound_, name_, cache_. AOTopsy supports 64-bit AOT
	// architectures, so intptr_t follows the Read64/marker-192 stream path.
	return FillSpec{
		Kind:           FillRefs,
		NumRefs:        4,
		LeadingScalars: []ScalarOp{OpTagged64},
		NameIdx:        -1,
		OwnerIdx:       -1,
	}
}

func specWeakSerializationReference(dartVersion string) FillSpec {
	// 2.10/2.12 Full AOT canonicalize WSRs by target class and serialize only
	// that target CID in fill (`WriteCid` / `ReadCid`, i.e. tagged int32).
	// 2.13+ forwards each WSR reference to its target/replacement and writes no
	// alloc/fill payload for the cluster itself.
	if !snapshot.VersionAtLeast(dartVersion, "2.13.0") {
		return FillSpec{Kind: FillRefs, NumRefs: 0, Scalars: []ScalarOp{OpTagged32}, NameIdx: -1, OwnerIdx: -1}
	}
	return FillSpec{Kind: FillNone, NameIdx: -1, OwnerIdx: -1}
}

// GetFillSpec returns the fill format for a cluster, dispatching by CID.
// Takes the full VersionProfile to access CIDs, version, and compressed pointer flag.
func GetFillSpec(cid int, cm *ClusterMeta, profile *snapshot.VersionProfile) FillSpec {
	ct := profile.CIDs
	fillRefUnsigned := profile.FillRefUnsigned
	preV32 := profile.PreV32Format
	switch {
	case notSerializedInFullAOT(cid, ct):
		return specUnsupported()
	case cid == ct.Function:
		return specFunction(fillRefUnsigned, profile.FuncNumRefs, functionRefLayoutFor(profile.DartVersion))
	case cid == ct.Class:
		return specClass(profile.ClassNumRefs)
	case cid == ct.PatchClass:
		return specPatchClass(preV32)
	case cid == ct.ClosureData:
		return specClosureData(profile.DartVersion, profile.ClosureDataNumRefs)
	case cid == ct.Field:
		return specField(fillRefUnsigned, profile.DartVersion)
	case cid == ct.Script:
		return specScript(profile.ScriptHasLineCol, profile.ScriptHasFlags)
	case cid == ct.Library:
		return specLibrary()
	case cid == ct.Namespace:
		return specNamespace(profile.DartVersion)
	case cid == ct.Closure:
		s := specClosure()
		if profile.ClosureAllocHasLength {
			// Dart 3.13.0 reshaped Closure. raw_object.h:
			//
			//   3.12.2  VISIT_FROM(instantiator_type_arguments),
			//           function_type_arguments, delayed_type_arguments,
			//           function, context, VISIT_TO(hash)   = 6 fixed refs
			//
			//   3.13.0  COMPRESSED_SMI_FIELD(length_and_flags)  <- VISIT_FROM
			//           COMPRESSED_SMI_FIELD(hash)
			//           COMPRESSED_POINTER_FIELD(function)
			//           COMPRESSED_VARIABLE_POINTER_FIELDS(.., data, function)
			//                                                = 3 fixed + length
			//
			// The type-argument and context fields moved into the variable
			// `data` tail. The fill reads that length itself, per object.
			//
			// Count the fixed refs from the field list, not from VISIT_FROM
			// alone: `hash` sits between length_and_flags and function and is
			// easy to miss, and getting 2 instead of 3 here moves the fill
			// failure earlier rather than fixing it.
			s.NumRefs = 3
			s.VarLenRefs = true
		}
		if profile.PreCanonicalSplit {
			s.LeadingBool = true
		}
		return s
	case cid == ct.UnlinkedCall:
		return specUnlinkedCall()
	case cid == ct.SubtypeTestCache:
		return specSubtypeTestCache(fillRefUnsigned, profile.HasTypeParamClassId)
	case cid == ct.LoadingUnit:
		return specLoadingUnit(profile.DartVersion)
	case cid == ct.Type:
		return specType(fillRefUnsigned, profile.OldTypeScalars, profile.TypeClassIdIsRef, profile.TypeHasTokenPos, profile.TypeNumRefs, typeClassIDShift(profile.DartVersion))
	case cid == ct.FunctionType:
		return specFunctionType(profile.FuncTypeNumRefs, profile.FuncTypeOldScalars, profile.FuncTypeParamTypesIdx, packedParamLayoutFor(profile.DartVersion))
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
	case ct.Map != 0 && cid == ct.Map:
		if !snapshot.VersionAtLeast(profile.DartVersion, "2.14.0") {
			return FillSpec{Kind: FillLegacyMap, NameIdx: -1, OwnerIdx: -1, LeadingBool: profile.PreCanonicalSplit}
		}
		return specUnsupported()
	case ct.ConstMap != 0 && cid == ct.ConstMap:
		return specMap()
	case ct.ConstSet != 0 && cid == ct.ConstSet:
		return specSet()
	case cid == ct.RegExp:
		return specRegExp(profile.DartVersion)
	case cid == ct.WeakProperty:
		return specWeakProperty()
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
	case ct.FfiTrampolineData != 0 && cid == ct.FfiTrampolineData:
		return specFfiTrampolineData(profile.DartVersion)
	case ct.SignatureData != 0 && cid == ct.SignatureData:
		return specSignatureData()
	case ct.RedirectionData != 0 && cid == ct.RedirectionData:
		return specRedirectionData()
	case ct.ParameterTypeCheck != 0 && cid == ct.ParameterTypeCheck:
		return specParameterTypeCheck()
	case ct.TypeParameters != 0 && cid == ct.TypeParameters:
		return specTypeParameters()
	case cid == ct.StackTrace:
		return specStackTrace()
	case ct.WeakSerializationReference != 0 && cid == ct.WeakSerializationReference:
		return specWeakSerializationReference(profile.DartVersion)

		// Special fill formats (not FillRefs)
	case cid == ct.String:
		// Exact SDK NewClusterForClass/ReadOnlyObjectType does not route the
		// abstract kStringCid in 2.10/2.12. It becomes a Full-AOT ROData route
		// in 2.13; the concrete one-/two-byte string CIDs are older routes.
		if !snapshot.VersionAtLeast(profile.DartVersion, "2.13.0") {
			return specUnsupported()
		}
		if profile.SplitCanonical || !profile.CompressedPointers {
			return FillSpec{Kind: FillROData, NameIdx: -1, OwnerIdx: -1}
		}
		return FillSpec{Kind: FillString, NameIdx: -1, OwnerIdx: -1}
	case cid == ct.OneByteString, cid == ct.TwoByteString:
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
	case cid == ct.Float32x4, cid == ct.Int32x4, cid == ct.Float64x2:
		if !snapshot.VersionAtLeast(profile.DartVersion, "3.4.0") {
			// These CIDs existed earlier, but NewClusterForClass had no SIMD case
			// through 3.3.4, so a Full-AOT cluster under them is invalid.
			return specUnsupported()
		}
		return FillSpec{Kind: FillSimd128, NameIdx: -1, OwnerIdx: -1}
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
			spec := FillSpec{Kind: FillInlineBytes, NameIdx: -1, OwnerIdx: -1}
			if cid == ct.CompressedStackMaps {
				spec.InlineBytesLengthShift = 2
			}
			return spec
		}
		return FillSpec{Kind: FillROData, NameIdx: -1, OwnerIdx: -1}
	case ct.ApiError != 0 && cid == ct.ApiError:
		// Dart 3.13.0+. UntaggedApiError: VISIT_FROM(message)..VISIT_TO(message)
		// = 1 ref, no scalars.
		return FillSpec{Kind: FillRefs, NumRefs: 1, NameIdx: -1, OwnerIdx: -1}
	case ct.UnwindError != 0 && cid == ct.UnwindError:
		// Dart 3.13.0+. Same single `message` ref, plus
		// Read<bool>(is_user_initiated) -- one raw byte.
		return FillSpec{Kind: FillRefs, NumRefs: 1, Scalars: []ScalarOp{OpBool}, NameIdx: -1, OwnerIdx: -1}
	case ct.LocalVarDescriptors != 0 && cid == ct.LocalVarDescriptors:
		return FillSpec{Kind: FillLocalVarDescriptors, NameIdx: -1, OwnerIdx: -1}
	case ct.Record != 0 && cid == ct.Record:
		return FillSpec{Kind: FillRecord, NameIdx: -1, OwnerIdx: -1}
	}

	// TypedData internal CIDs.
	if ct.TypedDataInt8ArrayCid != 0 && ct.ByteDataViewCid != 0 && ct.TypedDataCidStride > 0 &&
		cid >= ct.TypedDataInt8ArrayCid && cid < ct.ByteDataViewCid {
		rem := (cid - ct.TypedDataInt8ArrayCid) % ct.TypedDataCidStride
		switch rem {
		case 0:
			// Internal TypedData: same as TypedData fill.
			return FillSpec{Kind: FillTypedData, NameIdx: -1, OwnerIdx: -1}
		case 1:
			// TypedDataView: 3 refs (typed_data, offset_in_bytes, length).
			s := specTypedDataView()
			if profile.PreCanonicalSplit {
				s.LeadingBool = true
			}
			return s
		case 2:
			return specExternalTypedData()
		default:
			// Newer SDKs use remainder 3 for unmodifiable views, but the
			// Full-AOT cluster factory does not route those through the ordinary
			// view/external clusters. Refuse a synthetic cluster instead of
			// consuming it with the wrong shape.
			return specUnsupported()
		}
	}
	if ct.ByteDataViewCid != 0 && cid == ct.ByteDataViewCid {
		// IsTypedDataViewClassId has a dedicated kByteDataViewCid clause in the
		// SDK. Its cluster is otherwise identical to the typed-data view remainder:
		// fixed-size alloc and three refs in fill.
		s := specTypedDataView()
		if profile.PreCanonicalSplit {
			s.LeadingBool = true
		}
		return s
	}

	// DeltaEncodedTypedData (NativePointer CID).
	if ct.NativePointerCid != 0 && cid == ct.NativePointerCid {
		if !snapshot.VersionAtLeast(profile.DartVersion, "2.19.0") {
			return specUnsupported()
		}
		return FillSpec{Kind: FillDeltaEncodedTypedData, NameIdx: -1, OwnerIdx: -1}
	}

	// Mirror Serializer::NewClusterForClass exactly: kInstanceCid itself,
	// explicit FFI type-marker cases, and app-defined classes. Other predefined
	// CIDs must not silently fall through to Instance fill.
	if ct.Instance != 0 && cid == ct.Instance {
		return FillSpec{Kind: FillInstance, NameIdx: -1, OwnerIdx: -1}
	}
	if ct.FfiMarkerFirstCid != 0 && cid >= ct.FfiMarkerFirstCid && cid <= ct.FfiMarkerLastCid {
		return FillSpec{Kind: FillInstance, NameIdx: -1, OwnerIdx: -1}
	}
	if ct.NumPredefinedCids > 0 && cid >= ct.NumPredefinedCids {
		return FillSpec{Kind: FillInstance, NameIdx: -1, OwnerIdx: -1}
	}

	return specUnsupported()
}

// typeClassIDShift returns where type_class_id starts in UntaggedType's packed
// flags word for a given Dart version. See FillSpec.TypeClassIDShift.
func typeClassIDShift(dartVersion string) uint {
	if snapshot.VersionAtLeast(dartVersion, "3.5.0") {
		return 3
	}
	return 4
}

// PackedParamLayout is where the implicit/named/fixed/optional counts sit
// inside a FunctionType's packed parameter word.
//
// Dart split that word in two at 2.14.0. Before then a single packed_fields_
// held the parent type-argument count as well, pushing everything else up by
// eight bits:
//
//	<= 2.13.0  packed_fields_            parentTypeArgs 0..7, implicit 8,
//	                                     hasNamedOptional 9,
//	                                     fixed 10..19 (10 bits),
//	                                     optional 20..29 (10 bits)
//	>= 2.14.0  packed_parameter_counts_  implicit 0, hasNamedOptional 1,
//	                                     fixed 2..15 (14 bits),
//	                                     optional 16..29 (14 bits)
//	                                     (parent type args moved to
//	                                      packed_type_parameter_counts_)
//
// Verified in raw_object.h at 2.12.0, 2.13.0, 2.14.0, 2.15.0 and 3.12.2.
// UntaggedFunction.packed_fields_ keeps the <= 2.13 shape throughout, which is
// why readFunctionScalar already shifts by 10 and 20 and only the FunctionType
// path was reading the wrong bits.
type PackedParamLayout struct {
	ImplicitShift uint
	NamedShift    uint
	FixedShift    uint
	FixedMask     uint64
	OptionalShift uint
	OptionalMask  uint64
}

// packedParamsPre214 is the Dart <= 2.13.0 layout; packedParams214 is 2.14.0+.
var (
	packedParamsPre214 = PackedParamLayout{
		ImplicitShift: 8, NamedShift: 9,
		FixedShift: 10, FixedMask: 0x3FF,
		OptionalShift: 20, OptionalMask: 0x3FF,
	}
	packedParams214 = PackedParamLayout{
		ImplicitShift: 0, NamedShift: 1,
		FixedShift: 2, FixedMask: 0x3FFF,
		OptionalShift: 16, OptionalMask: 0x3FFF,
	}
)

// packedParamLayoutFor picks the layout for a Dart version.
func packedParamLayoutFor(dartVersion string) PackedParamLayout {
	if snapshot.VersionAtLeast(dartVersion, "2.14.0") {
		return packedParams214
	}
	return packedParamsPre214
}

// FuncPackedFieldsLayout is the bit layout of UntaggedFunction.packed_fields_,
// which is NOT the same word as FunctionType's (see PackedParamLayout).
//
// It was reshaped at 2.12, when the type-parameter count moved into it
// (raw_object.h):
//
//	2.10  hasNamedOptional(0,1) optimizable(1,1) backgroundOptimizable(2,1)
//	      numFixed(3,14) numOptional(17,13)
//	2.12  optimizable(0,1) backgroundOptimizable(1,1) numTypeParameters(2,7)
//	      hasNamedOptional(9,1) numFixed(10,10) numOptional(20,10)
//
// The 2.12 row applies to 2.12.0 and 2.13.0 ONLY. At 2.14.0 the field became
// `AtomicBitFieldContainer<uint8_t> packed_fields_` holding just the
// optimizable flags -- the arity moved to FunctionType. The serializer still
// writes the word as `s->Write<uint32_t>(packed_fields_)`, so the scalar
// stream stays aligned and this is NOT a desync; the value simply has nothing
// above bit 7, so numFixed and numOptional read 0 rather than garbage. That is
// luck, not design: it holds only because a uint8 cannot reach bits 10 and 20.
//
// Measured consequence: arity from packed_fields_ is 7083 functions on
// dart-2.12.0-arm64 and exactly 0 on 2.17.6, 3.1.0 and 3.3.0. From 2.14 the
// only source is FunctionType, reachable through a WeakSerializationReference
// the AOT serializer does not write, so ~80% of functions have no arity at
// all. See docs/findings-repo/010.
//
// Reading 2.10 with the 2.12 shifts does not merely garble a reported arity:
// num_fixed_parameters is what CodeNameInfo.FixedParamsWithReceiver turns into
// the frame slot the receiver arrives at on every version before the register
// calling convention (SDK 3.4.0; first supported profile 3.4.3). A wrong
// count seeds `this` at the wrong stack offset, so the seed is never read back,
// and the receiver's class is unknown at every field load that follows -- on
// the 2.10 x64 sample the declared-field-type source knew the owning class 57
// times out of 16000 calls, against 31476 out of 156000 on 2.12.
type FuncPackedFieldsLayout struct {
	NamedShift    uint
	FixedShift    uint
	FixedMask     uint64
	OptionalShift uint
	OptionalMask  uint64
}

var (
	funcPackedFields210 = FuncPackedFieldsLayout{
		NamedShift: 0,
		FixedShift: 3, FixedMask: 1<<14 - 1,
		OptionalShift: 17, OptionalMask: 1<<13 - 1,
	}
	funcPackedFields212 = FuncPackedFieldsLayout{
		NamedShift: 9,
		FixedShift: 10, FixedMask: 0x3FF,
		OptionalShift: 20, OptionalMask: 0x3FF,
	}
)

// funcPackedFieldsFor picks the layout for a Dart version.
func funcPackedFieldsFor(dartVersion string) FuncPackedFieldsLayout {
	if snapshot.VersionAtLeast(dartVersion, "2.12.0") {
		return funcPackedFields212
	}
	return funcPackedFields210
}

// functionRefIdx returns the ref-loop indices of Function.signature and
// Function.data for a Dart version. See specFunction.
func functionRefLayoutFor(dartVersion string) FunctionRefLayout {
	switch {
	case snapshot.VersionAtLeast(dartVersion, "2.14.0"):
		return functionRefs214
	case snapshot.VersionAtLeast(dartVersion, "2.12.0"):
		return functionRefs212
	default:
		return functionRefs210
	}
}
