// CID constants and tag decoding for Dart VM class IDs.

package cluster

import "aotopsy/internal/snapshot"

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
	tagCanonicalBit = 1  // bit 1
	tagImmutableBit = 6  // bit 6
	tagClassIdShift = 12 // bits 12-31
	tagClassIdMask  = (1 << 20) - 1
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
	AllocSimple            AllocKind = iota // count = ReadUnsigned()
	AllocCanonicalSet                       // count + optional canonical set
	AllocString                             // count + per-string length + optional canonical set
	AllocMint                               // count + per-mint int64
	AllocArray                              // count + per-element length
	AllocWeakArray                          // count + per-element length
	AllocTypeArguments                      // count + per-item length + optional canonical set
	AllocClass                              // predefined_count + per-class cid + new_count
	AllocCode                               // count + per-code state_bits + deferred
	AllocObjectPool                         // count + per-pool length
	AllocROData                             // count + per-item offset + optional canonical set
	AllocExceptionHandlers                  // count + per-handler length
	AllocContext                            // count + per-context num_variables
	AllocContextScope                       // count + per-scope length
	AllocRecord                             // count + per-record num_fields
	AllocTypedData                          // count + per-item length
	AllocInstance                           // count + next_field_offset + instance_size
	AllocEmpty                              // no alloc data at all (WeakSerializationReference)
	AllocUnknown                            // unrecognized CID
)

// ClassifyAlloc determines the alloc kind for a CID given a CID table.
func ClassifyAlloc(cid int, ct *snapshot.CIDTable) AllocKind {
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
	case ct.Map, ct.ConstMap, ct.Set, ct.ConstSet:
		// Map/Set clusters use plain SerializationCluster, not
		// CanonicalSetSerializationCluster. Alloc is just count.
		return AllocSimple
	case ct.TypedData:
		return AllocTypedData
	case ct.TypedDataView, ct.ExternalTypedData:
		return AllocSimple
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
		ct.Namespace, ct.KernelProgramInfo, ct.Closure,
		ct.UnlinkedCall, ct.ICData, ct.MegamorphicCache,
		ct.SubtypeTestCache, ct.LoadingUnit, ct.WeakProperty,
		ct.WeakReference, ct.LibraryPrefix, ct.LanguageError,
		ct.UnhandledException, ct.RegExp, ct.PatchClass,
		ct.FfiTrampolineData, ct.TypeParameters, ct.Sentinel, ct.SignatureData,
		ct.SingleTargetCache, ct.MonomorphicSmiableCall,
		ct.CallSiteData,
		ct.SendPort, ct.StackTrace, ct.Capability, ct.ReceivePort,
		ct.FutureOr, ct.TransferableTypedData, ct.UserTag,
	}
	if ct.SuspendState != 0 {
		simples = append(simples, ct.SuspendState)
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

	// TypedData internal CIDs (kTypedDataInt8ArrayCid through kByteDataViewCid-1).
	// IsTypedDataClassId: cid in range AND (cid - base) % stride == 0.
	if ct.TypedDataInt8ArrayCid != 0 && ct.ByteDataViewCid != 0 &&
		cid >= ct.TypedDataInt8ArrayCid && cid < ct.ByteDataViewCid &&
		(cid-ct.TypedDataInt8ArrayCid)%ct.TypedDataCidStride == 0 {
		return AllocTypedData
	}

	// Instance: CID >= Instance and not otherwise matched.
	// App-defined classes (>= NumPredefinedCids) always use Instance alloc.
	// Predefined CIDs that reach here also use Instance alloc unless they
	// have their own serialization cluster (handled above or as special cases).
	if ct.Instance != 0 && cid >= ct.Instance {
		return AllocInstance
	}

	// Unrecognized predefined CIDs (e.g. SignatureData, RedirectionData, Bytecode
	// in v2.10.0 that were removed in later versions) default to AllocSimple.
	// All predefined types with non-simple alloc are matched above.
	if ct.NumPredefinedCids != 0 && cid > 0 && cid < ct.NumPredefinedCids {
		return AllocSimple
	}

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
