// CID constants and tag decoding for Dart VM class IDs.

package cluster

import (
	"aotopsy/internal/sdk"
	"aotopsy/internal/snapshot"
)

// CID constants for Dart VM v3.9.2 (kept for backward compatibility and CidName).
const (
	CidIllegal                    = 0
	CidObject                     = 4
	CidClass                      = 5
	CidPatchClass                 = 6
	CidFunction                   = 7
	CidTypeParameters             = 8
	CidClosureData                = 9
	CidFfiTrampolineData          = 10
	CidField                      = 11
	CidScript                     = 12
	CidLibrary                    = 13
	CidNamespace                  = 14
	CidKernelProgramInfo          = 15
	CidWeakSerializationReference = 16
	CidWeakArray                  = 17
	CidCode                       = 18
	CidBytecode                   = 19
	CidInstructions               = 20
	CidInstructionsSection        = 21
	CidInstructionsTable          = 22
	CidObjectPool                 = 23
	CidPcDescriptors              = 24
	CidCodeSourceMap              = 25
	CidCompressedStackMaps        = 26
	CidLocalVarDescriptors        = 27
	CidExceptionHandlers          = 28
	CidContext                    = 29
	CidContextScope               = 30
	CidSentinel                   = 31
	CidSingleTargetCache          = 32
	CidMonomorphicSmiableCall     = 33
	CidCallSiteData               = 34
	CidUnlinkedCall               = 35
	CidICData                     = 36
	CidMegamorphicCache           = 37
	CidSubtypeTestCache           = 38
	CidLoadingUnit                = 39
	CidError                      = 40
	CidApiError                   = 41
	CidLanguageError              = 42
	CidUnhandledException         = 43
	CidUnwindError                = 44

	CidInstance              = 45
	CidLibraryPrefix         = 46
	CidTypeArguments         = 47
	CidAbstractType          = 48
	CidType                  = 49
	CidFunctionType          = 50
	CidRecordType            = 51
	CidTypeParameter         = 52
	CidFinalizerBase         = 53
	CidFinalizer             = 54
	CidNativeFinalizer       = 55
	CidFinalizerEntry        = 56
	CidClosure               = 57
	CidNumber                = 58
	CidInteger               = 59
	CidSmi                   = 60
	CidMint                  = 61
	CidDouble                = 62
	CidBool                  = 63
	CidFloat32x4             = 64
	CidInt32x4               = 65
	CidFloat64x2             = 66
	CidRecord                = 67
	CidTypedDataBase         = 68
	CidTypedData             = 69
	CidExternalTypedData     = 70
	CidTypedDataView         = 71
	CidPointer               = 72
	CidDynamicLibrary        = 73
	CidCapability            = 74
	CidReceivePort           = 75
	CidSendPort              = 76
	CidStackTrace            = 77
	CidSuspendState          = 78
	CidRegExp                = 79
	CidWeakProperty          = 80
	CidWeakReference         = 81
	CidMirrorReference       = 82
	CidFutureOr              = 83
	CidUserTag               = 84
	CidTransferableTypedData = 85

	CidMap      = 86
	CidConstMap = 87
	CidSet      = 88
	CidConstSet = 89

	CidArray               = 90
	CidImmutableArray      = 91
	CidGrowableObjectArray = 92

	CidString        = 93
	CidOneByteString = 94
	CidTwoByteString = 95
)

// Tag bit positions for v3.4.3+ object header tag encoding.
const (
	tagCanonicalBit = 1
	tagImmutableBit = 6
	tagClassIdShift = sdk.ClassIdTagPosV3
	tagClassIdMask  = (1 << sdk.ClassIdTagSizeV3) - 1
)

// DecodeTags extracts CID, canonical, and immutable flags from v3.4.3+
// object header tag encoding. For old-style encoding, use DecodeTagsOld.
func DecodeTags(tags uint32) (cid int, isCanonical, isImmutable bool) {
	cid = int((tags >> tagClassIdShift) & tagClassIdMask)
	isCanonical = (tags>>tagCanonicalBit)&1 != 0
	isImmutable = (tags>>tagImmutableBit)&1 != 0
	return
}

// DecodeTagsOld extracts CID and canonical flag from v2.x / early v3.x
// cluster tags. Format: (cid << 1) | canonical, stored as uint64_t.
// The CID is masked to 32 bits to match Dart's (cid >> 1) & kMaxUint32.
func DecodeTagsOld(cidAndCanonical int64) (cid int, isCanonical bool) {
	cid = int(uint32(cidAndCanonical >> 1))
	isCanonical = cidAndCanonical&1 != 0
	return
}

// AllocKind classifies how a cluster's alloc data should be parsed.
type AllocKind int

const (
	AllocSimple              AllocKind = iota // count = ReadUnsigned()
	AllocCanonicalSet                         // count + optional canonical set
	AllocString                               // count + per-string length + optional canonical set
	AllocMint                                 // count + per-mint int64
	AllocArray                                // count + per-element length
	AllocWeakArray                            // count + per-element length
	AllocTypeArguments                        // count + per-item length + optional canonical set
	AllocClass                                // predefined_count + per-class cid + new_count
	AllocCode                                 // count + per-code state_bits + deferred
	AllocObjectPool                           // count + per-pool length
	AllocROData                               // count + per-item offset + optional canonical set
	AllocExceptionHandlers                    // count + per-handler length
	AllocContext                              // count + per-context num_variables
	AllocContextScope                         // count + per-scope length
	AllocRecord                               // count + per-record num_fields
	AllocTypedData                            // count + per-item length
	AllocLocalVarDescriptors                  // count + per-descriptor entry count
	AllocInstance                             // count + next_field_offset + instance_size
	AllocEmpty                                // no alloc data at all (WeakSerializationReference)
	AllocUnknown                              // unrecognized CID
)

// ClassifyAlloc determines the alloc kind for a CID given a CID table.
func ClassifyAlloc(cid int, ct *snapshot.CIDTable) AllocKind {
	// LocalVarDescriptors, new in Dart 3.13.0. Its ReadAlloc is byte-for-byte
	// the same shape as CompressedStackMaps' -- count = ReadUnsigned(), then
	// one ReadUnsigned(length) per object -- so it takes the same path.
	//
	// Checked before the switch and guarded on non-zero, because the field is
	// 0 in every older CID table and a bare `case ct.LocalVarDescriptors:`
	// would then silently claim cid 0.
	if ct.LocalVarDescriptors != 0 && cid == ct.LocalVarDescriptors {
		return AllocLocalVarDescriptors
	}
	switch cid {
	case ct.String, ct.OneByteString, ct.TwoByteString:
		return AllocString
	case ct.Mint:
		return AllocMint
	case ct.Double, ct.Float32x4, ct.Int32x4, ct.Float64x2:
		return AllocSimple
	case ct.Array, ct.ImmutableArray:
		return AllocArray
	case ct.WeakArray:
		if ct.WeakArray == 0 {
			return AllocUnknown
		}
		return AllocWeakArray
	case ct.TypeArguments:
		return AllocTypeArguments
	case ct.Type, ct.FunctionType, ct.TypeParameter:
		return AllocCanonicalSet
	case ct.Class:
		return AllocClass
	case ct.Code:
		return AllocCode
	case ct.ObjectPool:
		return AllocObjectPool
	case ct.PcDescriptors, ct.CodeSourceMap, ct.CompressedStackMaps:
		return AllocROData
	case ct.ExceptionHandlers:
		return AllocExceptionHandlers
	case ct.Context:
		return AllocContext
	case ct.ContextScope:
		return AllocContextScope
	case ct.Map:
		// LinkedHashMap itself is serializable only through 2.13. Starting
		// at 2.14 the mutable map case is explicitly UNREACHABLE; 2.15 adds
		// a separate immutable/const CID. Presence of Set (2.14+) cleanly
		// distinguishes the old era without needing a VersionProfile here.
		if ct.Set != 0 || ct.ConstMap != 0 {
			return AllocUnknown
		}
		return AllocSimple
	case ct.ConstMap:
		if ct.ConstMap != 0 {
			return AllocSimple
		}
	case ct.Set:
		// Mutable set is UNREACHABLE from its introduction onward.
		if ct.Set != 0 {
			return AllocUnknown
		}
	case ct.ConstSet:
		if ct.ConstSet != 0 {
			return AllocSimple
		}
	case ct.TypedData, ct.TypedDataView, ct.ExternalTypedData:
		// These are abstract/base CIDs, not the concrete typed-data family.
		// NewClusterForClass has no switch case for them in any supported SDK;
		// 3.13 also lists all three in IsAbsentCid. Concrete internal/view/
		// external CIDs are handled by the stride family below.
		return AllocUnknown
	case ct.GrowableObjectArray:
		return AllocSimple
	}

	// RecordType and Record may be 0 in v2.17.6.
	if ct.RecordType != 0 && cid == ct.RecordType {
		return AllocCanonicalSet
	}
	if ct.Record != 0 && cid == ct.Record {
		return AllocRecord
	}

	// WeakSerializationReference: exists only in Dart 2.x. Format varies by version:
	// - v2.10 (PreCanonicalSplit): AllocSimple (has count)
	// - v2.13+ (SplitCanonical/CidShift1): AllocEmpty (no alloc data at all)
	// Handled in skipAllocV which checks the version flags.
	if ct.WeakSerializationReference != 0 && cid == ct.WeakSerializationReference {
		return AllocEmpty
	}

	// Simple alloc types: just count = ReadUnsigned().
	simples := []int{
		ct.Function, ct.ClosureData, ct.Field, ct.Script, ct.Library,
		ct.Namespace, ct.Closure,
		ct.UnlinkedCall, ct.ICData, ct.MegamorphicCache,
		ct.SubtypeTestCache, ct.LoadingUnit, ct.WeakProperty,
		ct.LibraryPrefix, ct.LanguageError,
		ct.UnhandledException, ct.RegExp, ct.PatchClass,
		ct.FfiTrampolineData, ct.TypeParameters, ct.SignatureData,
		ct.RedirectionData, ct.ParameterTypeCheck,
		ct.StackTrace,
	}
	if ct.ApiError != 0 {
		simples = append(simples, ct.ApiError)
	}
	if ct.UnwindError != 0 {
		simples = append(simples, ct.UnwindError)
	}
	// Every supported SDK states next to KernelProgramInfoDeserializationCluster
	// that KernelProgramInfo objects are not written into full AOT snapshots.
	// Its dormant deserializer layout also changes across releases, so accepting
	// a forged KPI cluster with a guessed/simple shape is a silent-desync risk.
	if ct.KernelProgramInfo != 0 && cid == ct.KernelProgramInfo {
		return AllocUnknown
	}
	// These predefined runtime-only/cache/meta CIDs have no serialization case
	// in Serializer::NewClusterForClass in any supported Full-AOT SDK. Because
	// predefined CIDs do not take the generic InstanceSerializationCluster path,
	// a cluster under any of them is malformed and must fail closed.
	runtimeOnly := []int{
		ct.Capability, ct.ReceivePort, ct.SendPort, ct.SuspendState,
		ct.WeakReference, ct.FutureOr, ct.UserTag, ct.TransferableTypedData,
		ct.SingleTargetCache, ct.MonomorphicSmiableCall, ct.CallSiteData,
		ct.Sentinel,
	}
	for _, c := range runtimeOnly {
		if c != 0 && cid == c {
			return AllocUnknown
		}
	}
	if ct.TypeRef != 0 {
		simples = append(simples, ct.TypeRef)
	}
	for _, s := range simples {
		if s != 0 && cid == s {
			return AllocSimple
		}
	}

	// DeltaEncodedTypedData: CID = kNativePointer (1). Same alloc as TypedData.
	if ct.NativePointerCid != 0 && cid == ct.NativePointerCid {
		return AllocTypedData
	}

	// Concrete TypedData-family CIDs. Dart's snapshot factory dispatches the
	// first three remainders separately: internal -> TypedData, view ->
	// TypedDataView, external -> ExternalTypedData. Internal objects carry a
	// length in alloc; views/external objects are fixed-size and alloc is only a
	// count. Newer SDKs add a fourth remainder for unmodifiable views, but the
	// Full-AOT snapshot factory does not serialize those through any of these
	// clusters, so fail closed rather than falling through to generic Instance.
	if ct.TypedDataInt8ArrayCid != 0 && ct.ByteDataViewCid != 0 &&
		ct.TypedDataCidStride > 0 && cid >= ct.TypedDataInt8ArrayCid && cid < ct.ByteDataViewCid {
		rem := (cid - ct.TypedDataInt8ArrayCid) % ct.TypedDataCidStride
		switch rem {
		case 0:
			return AllocTypedData
		case 1, 2:
			return AllocSimple
		default:
			return AllocUnknown
		}
	}
	// ByteDataView sits just after the stride-based typed-data family but
	// IsTypedDataViewClassId() handles it explicitly in every supported SDK.
	// It therefore uses the same fixed-size alloc as the remainder-1 views.
	if ct.ByteDataViewCid != 0 && cid == ct.ByteDataViewCid {
		return AllocSimple
	}

	// Generic InstanceSerializationCluster is exact, not a blanket fallback for
	// every predefined class after kInstanceCid. The SDK routes only:
	//   * kInstanceCid itself,
	//   * app-defined classes (cid >= kNumPredefinedCids), and
	//   * CLASS_LIST_FFI_TYPE_MARKER cids (explicit switch cases).
	// Accepting every predefined cid >= Instance made malformed Smi/Bool/Null/
	// ByteBuffer/etc. clusters look like plausible Instance clusters.
	if ct.Instance != 0 && cid == ct.Instance {
		return AllocInstance
	}
	if ct.FfiMarkerFirstCid != 0 && cid >= ct.FfiMarkerFirstCid && cid <= ct.FfiMarkerLastCid {
		return AllocInstance
	}
	if ct.NumPredefinedCids > 0 && cid >= ct.NumPredefinedCids {
		return AllocInstance
	}

	// Do not guess for an unrecognized predefined CID. Predefined classes do not
	// fall through to InstanceSerializationCluster; every valid Full-AOT case is
	// selected explicitly by NewClusterForClass (or the typed-data/ROData gates
	// mirrored above). Treating an unknown predefined CID as count-only made
	// unsupported families such as 2.10 Bytecode/Instructions look plausible
	// while shifting every following alloc tag.
	return AllocUnknown
}

// CidNameV returns a human-readable name for a CID using version-specific table.
func CidNameV(cid int, ct *snapshot.CIDTable) string {
	return cidNameFromTable(cid, ct)
}

// typedDataInternalNames maps TypedData type index to name.
var typedDataInternalNames = [14]string{
	"TypedDataInt8Array", "TypedDataUint8Array", "TypedDataUint8ClampedArray",
	"TypedDataInt16Array", "TypedDataUint16Array", "TypedDataInt32Array",
	"TypedDataUint32Array", "TypedDataInt64Array", "TypedDataUint64Array",
	"TypedDataFloat32Array", "TypedDataFloat64Array", "TypedDataFloat32x4Array",
	"TypedDataInt32x4Array", "TypedDataFloat64x2Array",
}

// typedDataInt32ArrayCid returns kTypedDataInt32ArrayCid for this version, or
// 0 when the CID table has no TypedData range.
//
// Derived from the committed base + stride rather than stored as its own
// profile field: the internal TypedData CIDs are one contiguous strided run in
// the order typedDataInternalNames spells out, so a separate field would be a
// second copy of the same fact with its own way of going stale.
func typedDataInt32ArrayCid(ct *snapshot.CIDTable) int {
	if ct.TypedDataInt8ArrayCid == 0 || ct.TypedDataCidStride == 0 {
		return 0
	}
	return ct.TypedDataInt8ArrayCid + typedDataInt32ArrayIndex*ct.TypedDataCidStride
}

// typedDataInt32ArrayIndex is Int32Array's position in typedDataInternalNames.
const typedDataInt32ArrayIndex = 5

func typedDataInternalName(cid int, ct *snapshot.CIDTable) string {
	if ct.TypedDataCidStride == 0 {
		return ""
	}
	idx := (cid - ct.TypedDataInt8ArrayCid) / ct.TypedDataCidStride
	rem := (cid - ct.TypedDataInt8ArrayCid) % ct.TypedDataCidStride
	if idx < 0 || idx >= 14 {
		return ""
	}
	base := typedDataInternalNames[idx]
	switch rem {
	case 0:
		return base
	case 1:
		return base + "View"
	case 2:
		return "External" + base
	case 3:
		return "Unmodifiable" + base + "View"
	}
	return ""
}

func cidNameFromTable(cid int, ct *snapshot.CIDTable) string {
	// Defensive nil check: callers reach here with a table taken from a
	// VersionProfile, and an unsupported/placeholder profile has historically
	// been able to carry a nil CIDs pointer. Returning "" makes the caller
	// fall back to its "CID_%d" rendering instead of panicking.
	if ct == nil {
		return ""
	}
	switch {
	case cid == ct.Class:
		return "Class"
	case cid == ct.PatchClass:
		return "PatchClass"
	case cid == ct.Function:
		return "Function"
	case cid == ct.TypeParameters:
		return "TypeParameters"
	case cid == ct.ClosureData:
		return "ClosureData"
	case ct.SignatureData != 0 && cid == ct.SignatureData:
		return "SignatureData"
	case ct.FfiTrampolineData != 0 && cid == ct.FfiTrampolineData:
		return "FfiTrampolineData"
	case cid == ct.Field:
		return "Field"
	case cid == ct.Script:
		return "Script"
	case cid == ct.Library:
		return "Library"
	case cid == ct.Namespace:
		return "Namespace"
	case cid == ct.Code:
		return "Code"
	case cid == ct.ObjectPool:
		return "ObjectPool"
	case cid == ct.PcDescriptors:
		return "PcDescriptors"
	case cid == ct.CodeSourceMap:
		return "CodeSourceMap"
	case cid == ct.CompressedStackMaps:
		return "CompressedStackMaps"
	case cid == ct.ExceptionHandlers:
		return "ExceptionHandlers"
	case cid == ct.Context:
		return "Context"
	case cid == ct.ContextScope:
		return "ContextScope"
	case cid == ct.UnlinkedCall:
		return "UnlinkedCall"
	case cid == ct.ICData:
		return "ICData"
	case cid == ct.MegamorphicCache:
		return "MegamorphicCache"
	case cid == ct.SubtypeTestCache:
		return "SubtypeTestCache"
	case cid == ct.LoadingUnit:
		return "LoadingUnit"
	case cid == ct.LanguageError:
		return "LanguageError"
	case cid == ct.UnhandledException:
		return "UnhandledException"
	case cid == ct.Instance:
		return "Instance"
	case cid == ct.LibraryPrefix:
		return "LibraryPrefix"
	case cid == ct.TypeArguments:
		return "TypeArguments"
	case cid == ct.Type:
		return "Type"
	case cid == ct.FunctionType:
		return "FunctionType"
	case ct.RecordType != 0 && cid == ct.RecordType:
		return "RecordType"
	case ct.TypeRef != 0 && cid == ct.TypeRef:
		return "TypeRef"
	case cid == ct.TypeParameter:
		return "TypeParameter"
	case cid == ct.Closure:
		return "Closure"
	case cid == ct.Mint:
		return "Mint"
	case cid == ct.Double:
		return "Double"
	case cid == ct.GrowableObjectArray:
		return "GrowableObjectArray"
	case ct.Record != 0 && cid == ct.Record:
		return "Record"
	case cid == ct.Array:
		return "Array"
	case cid == ct.ImmutableArray:
		return "ImmutableArray"
	case ct.WeakArray != 0 && cid == ct.WeakArray:
		return "WeakArray"
	case cid == ct.String:
		return "String"
	case cid == ct.OneByteString:
		return "OneByteString"
	case cid == ct.TwoByteString:
		return "TwoByteString"
	case cid == ct.Map:
		return "Map"
	case cid == ct.ConstMap:
		return "ConstMap"
	case cid == ct.Set:
		return "Set"
	case cid == ct.ConstSet:
		return "ConstSet"
	case cid == ct.RegExp:
		return "RegExp"
	case cid == ct.WeakProperty:
		return "WeakProperty"
	case cid == ct.StackTrace:
		return "StackTrace"
	case cid == ct.SendPort:
		return "SendPort"
	case ct.NativePointerCid != 0 && cid == ct.NativePointerCid:
		return "DeltaEncodedTypedData"
	case ct.TypedDataInt8ArrayCid != 0 && ct.ByteDataViewCid != 0 &&
		cid >= ct.TypedDataInt8ArrayCid && cid < ct.ByteDataViewCid:
		return typedDataInternalName(cid, ct)
	default:
		return ""
	}
}
