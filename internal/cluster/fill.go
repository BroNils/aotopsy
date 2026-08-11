package cluster

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

var debugFill = os.Getenv("DEFLUTTER_DEBUG_FILL") != ""

// NamedObject holds a named object extracted from the fill section.
type NamedObject struct {
	CID            int
	RefID          int
	NameRefID      int // ref ID pointing to name string (-1 if none)
	OwnerRefID     int // ref ID pointing to owner (-1 if none)
	SignatureRefID int // ref ID pointing to FunctionType signature (-1 if none)
	// DataRefID is Function.data (ref index 3). For a closure function this is
	// its ClosureData, whose parent_function names the enclosing function --
	// strictly more precise than OwnerRefID, which only gives the owning class.
	// -1 if not a Function or not captured.
	DataRefID int
	CodeIndex int // Function's code_index scalar (-1 if not a Function / not captured)
}

// FuncTypeInfo holds parameter count data extracted from a FunctionType object.
type FuncTypeInfo struct {
	RefID       int
	NumFixed    int  // fixed parameters (excludes implicit 'this')
	NumOptional int  // optional parameters
	HasImplicit bool // true if instance method (has implicit 'this' parameter)

	// ParamTypesArrayRefID is the ref ID of this FunctionType's
	// parameter_types Array object, captured only when
	// snapshot.VersionProfile.FuncTypeParamTypesIdx is set for this
	// Dart version (see that field's doc comment for the verified
	// per-version ref-loop index). -1 if not captured/not applicable.
	ParamTypesArrayRefID int

	// TypeParamsRefID is the ref ID of this FunctionType's type_parameters
	// (a TypeParameters object): the function's OWN generic parameters, i.e.
	// the `<T>` in `void runUnaryGuarded<T>(...)`. -1 when absent or not
	// captured for this Dart version.
	//
	// Its ref-loop index is DERIVED as FuncTypeParamTypesIdx-2 rather than
	// tabulated separately, because UntaggedFunctionType lays out
	// type_parameters, result_type, parameter_types consecutively in every
	// supported version. Verified in runtime/vm/raw_object.h:
	//
	//	3.9.2  leading refs type_test_stub, hash  => type_parameters idx 2,
	//	                                             parameter_types  idx 4
	//	2.17.6 leading ref  type_test_stub (hash moved to the end)
	//	                                          => type_parameters idx 1,
	//	                                             parameter_types  idx 3
	//
	// Deriving it also means the capture is enabled exactly where
	// FuncTypeParamTypesIdx has been verified for a version, and nowhere
	// else -- no new unverified per-version constant.
	TypeParamsRefID int
}

// TypeParametersInfo holds a TypeParameters object's refs.
//
// ReadFromTo order per UntaggedTypeParameters (raw_object.h @ 3.9.2):
// names(0), flags(1), bounds(2), defaults(3), matching specTypeParameters'
// NumRefs: 4. `names` is an Array of Strings holding the declared parameter
// names ("T", "K", "V", ...) -- that Array's elements are captured in
// Result.Arrays, so resolving a name list is
// TypeParameters -> NamesArrayRef -> ArrayInfo.ElementRefIDs -> Strings.
type TypeParametersInfo struct {
	RefID         int
	NamesArrayRef int
	FlagsRef      int
	BoundsRef     int
	DefaultsRef   int
}

// ArrayInfo holds an Array/ImmutableArray object's elements, extracted
// from fill -- needed to resolve a FunctionType's parameter_types
// (itself just an Array ref) into its actual per-parameter Type refs.
type ArrayInfo struct {
	RefID         int
	TypeArgsRefID int
	ElementRefIDs []int
}

// ClassInfo holds class layout data extracted from a Class object's fill.
type ClassInfo struct {
	RefID          int
	NameRefID      int
	ClassID        int32
	InstanceSize   int32
	NextFieldOff   int32 // next_field_offset in bytes
	TypeArgsOff    int32 // type_arguments field offset in bytes
	SuperTypeRefID int   // ref ID of the super_type Type object (-1 if not captured for this spec.NumRefs)
	LibraryRefID   int   // ref ID of the owning Library object (-1 if not captured for this spec.NumRefs)
}

// TypeInfo holds the resolved type_class_id for a Type object -- i.e. which
// class a `super_type`/other Type reference actually names.
//
// v3.x: type_class_id is packed into the "flags" scalar (IsType=true path).
// v2.x with TypeClassIdIsRef: type_class_id is a Smi ref at a specific index
// in ReadFromTo. The ref is captured in TypeClassIdRef and resolved to a
// class ID later via MintValues (Smi encoding: classID = smiValue >> 1).
type TypeInfo struct {
	RefID          int
	ClassID        int32
	TypeClassIdRef int // ref ID of type_class_id Smi (v2.x TypeClassIdIsRef only); -1 otherwise
}

// --- New capture types (previously skipped) ---

// RefNull is the ref ID of the snapshot's null object.
//
// Deserializer::AddBaseObjects installs Object::null() as the very first base
// object and reference numbering starts at kFirstReference == 1, so ref 1 is
// always null. Verified against runtime/vm/app_snapshot.cc @ 3.9.2
// ("s->AddBaseObject(Object::null(), \"Null\", \"null\")") and empirically: 866
// of 925 ClosureData records in compare_sample carry closure_ref == 1, which is
// the null closure_ field.
const RefNull = 1

// InstanceFieldRef is one captured pointer field of an Instance, tagged with
// the byte offset it occupies inside the object.
//
// Recording the offset at capture time is not a convenience -- it is the only
// correct way to do it. An Instance's fill stream walks every field SLOT from
// the header to next_field_offset_in_words, and each slot is either an unboxed
// raw value or a ref. Unboxed slots produce no ref, so the position of a ref
// within a bare []int ref list does NOT equal its slot index: every ref after
// the first unboxed field is shifted. An earlier revision tried to recover the
// mapping afterwards by sorting the class's own declared field offsets and
// zipping them against the ref list, which is wrong twice over -- it drops the
// shift above, and it ignores inherited fields, which occupy the LEADING slots
// (Class.next_field_offset_in_words counts superclass fields too).
type InstanceFieldRef struct {
	ByteOffset int32 // offset from the start of the object, in bytes
	Ref        int   // ref ID of the stored value
}

// InstanceInfo holds an Instance object's pointer field values, captured from
// fill. Unboxed (raw) fields are read to keep the stream aligned but carry no
// ref, so they are absent from Fields; NumFieldSlots records how many slots
// existed in total so callers can tell "no ref here" from "not captured".
type InstanceInfo struct {
	RefID int
	CID   int // class ID of this instance == its cluster's CID
	// HeaderWords is 2 under compressed pointers (tags + hash, 4 bytes each)
	// and 1 otherwise (tags, 8 bytes).
	HeaderWords int
	// NumFieldSlots is next_field_offset_in_words - HeaderWords.
	NumFieldSlots int
	Fields        []InstanceFieldRef
}

// ContextInfo holds a Context object's captured variables.
// Contexts store closure-captured variables (parent context + variable refs).
type ContextInfo struct {
	RefID     int
	ParentRef int   // ref ID of parent context (-1 if none)
	VarRefs   []int // ref IDs of captured variables
}

// TypeArgumentsInfo holds a TypeArguments object's type refs.
// These represent generic type instantiations (e.g., List<int> → [int]).
type TypeArgumentsInfo struct {
	RefID          int
	Length         int   // number of type refs
	TypeRefs       []int // ref IDs of Type objects
	Instantiations int   // ref ID of instantiations array (-1 if none)
	Hash           int32
	Nullability    int
}

// ExceptionHandlerEntry describes one exception handler.
type ExceptionHandlerEntry struct {
	PCOffset        int32 // PC offset of the handler entry
	OuterTryIndex   int16 // outer try index (-1 if none)
	NeedsStacktrace bool
	HasCatchAll     bool
	IsGenerated     bool
}

// ExceptionHandlerInfo holds an ExceptionHandlers object's handler entries.
// This enables try/catch structure recovery in the decompiler.
type ExceptionHandlerInfo struct {
	RefID           int
	HandledTypesRef int // ref ID of handled types data (-1 if none)
	Handlers        []ExceptionHandlerEntry
}

// ICDataInfo holds an ICData object's refs, in ReadFromTo order.
//
// ICData is a JIT-only inline cache. The AOT precompiler does not retain
// ic_data_array_, so no AOT snapshot in this project's corpus contains an
// ICData cluster (verified: 0 entries across 16 samples spanning Dart 2.12,
// 3.7, 3.9, 3.10, 3.11 and 3.12, both arm64 and x64). This type exists so
// that IF such a cluster ever appears (e.g. a kFullJIT snapshot) the refs
// are captured rather than skipped -- it is NOT a basis for call-target
// resolution, and the fields below are unverified against a real binary.
type ICDataInfo struct {
	RefID         int
	TargetNameRef int // ref 0: CallSiteData.target_name
	ArgsDescRef   int // ref 1: CallSiteData.args_descriptor
	EntriesRef    int // ref 2: ICData.entries (Array of class_id/target pairs)
}

// ScriptInfo holds a Script object's URL and optional line/col metadata.
type ScriptInfo struct {
	RefID             int
	URLRef            int   // ref ID of URL string
	LineOffset        int32 // v2.10/v2.13 only
	ColOffset         int32 // v2.10/v2.13 only
	KernelScriptIndex int32
}

// LoadingUnitInfo holds a LoadingUnit object's metadata.
// Loading units represent deferred libraries (split AOT).
type LoadingUnitInfo struct {
	RefID     int
	ParentRef int   // ref ID of parent loading unit (-1 if root)
	UnitID    int32 // loading unit ID
}

// KernelProgramInfoRef holds a KernelProgramInfo object's refs.
// KPI contains references to the kernel binary (dill) data, which
// could theoretically enable Dart source reconstruction.
// Note: KPI is NOT serialized in AOT PRODUCT snapshots — this will
// always be empty for AOT binaries.
type KernelProgramInfoRef struct {
	RefID              int
	KernelComponentRef int // ref ID of kernel component
	StringOffsetsRef   int // ref ID of string offsets
	StringDataRef      int // ref ID of string data
	CanonicalNamesRef  int // ref ID of canonical names
	ConstantsRef       int // ref ID of constants
	ConstantsTableRef  int // ref ID of constants table
}

// ClosureDataInfo holds a ClosureData object's refs.
// In AOT, ClosureData has: parent_function (ref 0), closure (ref 1),
// and packed_fields (scalar). context_scope_ is null in AOT.
// This enables closure → parent function resolution without Context objects.
type ClosureDataInfo struct {
	RefID             int
	ParentFunctionRef int // ref ID of parent function (-1 if none)
	ClosureRef        int // ref ID of closure object (-1 if none)
	PackedFields      uint32
}

// CompressedStackMapsInfo holds a raw CompressedStackMaps payload.
// Not decoded yet — the payload is a compressed bitmap of which registers
// are live at each safepoint. No consumer exists currently, but the data
// is captured so future decompilation quality improvements can access it.
type CompressedStackMapsInfo struct {
	RefID   int
	Payload []byte
}

// FieldInfo holds field layout data extracted from a Field object's fill.
type FieldInfo struct {
	RefID            int
	NameRefID        int
	OwnerRefID       int
	KindBits         int32
	HostOffset       int32 // byte offset within instance; -1 for static fields
	TypeRefID        int   // ref ID of the field's declared Type object (-1 if not captured); used by typetrack to resolve field-load receiver types
	InitializerRefID int   // ref ID of the Function that lazily initializes this field (-1 if none)
}

// readRef reads a fill-phase ref using the correct encoding for the version.
// ≤2.17 (fillRefUnsigned=true): ReadRef() → ReadUnsigned() (marker 128, little-endian).
// ≥2.18 (fillRefUnsigned=false): ReadRef() → ReadRefId() (big-endian, signed-byte).
func readRef(s *dartfmt.Stream, fillRefUnsigned bool) (int64, error) {
	if fillRefUnsigned {
		return s.ReadUnsigned()
	}
	return s.ReadRefId()
}

// DebugFillPositions iterates the fill section and prints the stream position
// before/after each cluster's fill to w. Used to diagnose fill drift.
func DebugFillPositions(data []byte, result *Result, profile *snapshot.VersionProfile, isVM bool, w io.Writer) error {
	if result.FillStart <= 0 || result.FillStart >= len(data) {
		return fmt.Errorf("fill: invalid start offset %d", result.FillStart)
	}
	s := dartfmt.NewStreamAt(data, result.FillStart)
	fillRefUnsigned := profile.FillRefUnsigned
	instrIdx := 0
	for i := range result.Clusters {
		cm := &result.Clusters[i]
		spec := GetFillSpec(cm.CID, cm, profile)
		startPos := s.Position()
		name := CidNameV(cm.CID, profile.CIDs)
		if name == "" {
			name = fmt.Sprintf("CID_%d", cm.CID)
		}
		err := fillOneCluster(s, cm, &spec, fillRefUnsigned, profile, &instrIdx, nil)
		endPos := s.Position()
		delta := endPos - startPos
		status := "OK"
		if err != nil {
			status = fmt.Sprintf("ERR: %v", err)
		}
		nfoStr := ""
		if cm.NextFieldOffsetInWords != 0 {
			nfoStr = fmt.Sprintf(" nfo=%d", cm.NextFieldOffsetInWords)
		}
		_, _ = fmt.Fprintf(w, "FILL[%3d] CID=%-3d %-24s kind=%-2d count=%-5d start=0x%06x end=0x%06x delta=%-6d%s %s\n",
			i, cm.CID, name, spec.Kind, cm.Count, startPos, endPos, delta, nfoStr, status)
		if err != nil {
			return err
		}
	}
	return nil
}

// dataImageObjStart computes the byte offset within data[] where ROData objects begin.
// For non-compressed-pointers mode, the Dart SDK computes the data image as:
//
//	DataImage() = Addr() + RoundUp(length(), kMaxObjectAlignment)
//
// where Addr() is the start of the snapshot blob (including magic),
// length() is the size of that whole blob -- the stored length field plus the
// 4-byte magic, see large_length() -- and kMaxObjectAlignment = 2 * word_size
// = 16 on 64-bit (kObjectStartAlignment = 64 from 2.19.0 on).
//
// Objects within the data image start at DataImage + kHeaderSize, where
// kHeaderSize = kMaxObjectAlignment = 16 (verified against dart-lang/sdk
// image_snapshot.h at tag 2.12.0: `object_start() = raw_memory_ + kHeaderSize`).
// The ROData delta encoding uses offsets relative to DataImage (not
// relative to object_start), so the first object is at delta = kHeaderSize/16 = 1.
//
// We return the DataImage offset (not object_start) because extractRODataStrings
// adds runningOffset (which includes the kHeaderSize delta) to this base.
//
// snapshotSize is header.TotalSize = header.Length + 4 (includes magic).
// Returns 0 if ROData string extraction is not applicable.
func dataImageObjStart(dataLen int, snapshotSize int64, profile *snapshot.VersionProfile) int64 {
	if snapshotSize <= 0 || profile.CompressedPointers {
		return 0
	}
	// The data image BASE is placed at RoundUp(length(), alignment).
	// SDK ≤2.18: kMaxObjectAlignment=16; SDK ≥2.19: kObjectStartAlignment=64.
	// dataImageAlignment() derives this from the DartVersion string (single
	// cutoff at 2.19.0), verified via gh api against SDK source.
	// This is the LARGER of the two ROData alignments; the per-object delta
	// stride uses kObjectAlignment (16) instead — see extractRODataStrings.
	// Using 16 here (the old hardcoded value) placed the image base too low
	// on >=2.19 snapshots, so every string object header landed mid-data and
	// string extraction silently returned nothing.
	align := dataImageAlignment(profile)
	if align <= 0 {
		align = 16
	}
	// The SDK's length() INCLUDES the magic (runtime/vm/snapshot.h):
	//
	//   int64_t large_length() const {
	//     return Read<int64_t>(kLengthOffset) + kMagicSize;   // + 4
	//   }
	//
	// set_length writes `value - kMagicSize`, so the stored field excludes
	// the magic and length() adds it back: length() == the whole snapshot
	// blob's size == Header.TotalSize here. Rounding up TotalSize-4 instead
	// lands `align` bytes too low whenever the two straddle an alignment
	// boundary (~6% of snapshots at align=64).
	lengthVal := snapshotSize
	if lengthVal <= 0 {
		return 0
	}
	// DataImage = Addr() + RoundUp(length(), align).
	diStart := (lengthVal + align - 1) &^ (align - 1)
	if diStart >= int64(dataLen) {
		return 0
	}
	return diStart
}

// ReadFill parses the fill section of the snapshot, extracting strings
// and named objects. It processes ALL clusters in alloc order.
// snapshotSize is the TotalSize from the snapshot header (needed for ROData string extraction).
func ReadFill(data []byte, result *Result, profile *snapshot.VersionProfile, isVM bool, snapshotSize int64) error {
	if result.FillStart <= 0 || result.FillStart >= len(data) {
		return fmt.Errorf("fill: invalid start offset %d", result.FillStart)
	}

	s := dartfmt.NewStreamAt(data, result.FillStart)
	ct := profile.CIDs
	fillRefUnsigned := profile.FillRefUnsigned
	instrIdx := 0 // running instructions_index_ across Code clusters

	if debugFill {
		fmt.Fprintf(os.Stderr, "fill: %d clusters, fillStart=0x%x, dataLen=0x%x\n", len(result.Clusters), result.FillStart, len(data))
		for ci := range result.Clusters {
			cc := &result.Clusters[ci]
			name := CidNameV(cc.CID, ct)
			if name == "" {
				name = fmt.Sprintf("CID_%d", cc.CID)
			}
			fmt.Fprintf(os.Stderr, "  cluster[%d] CID=%d (%s) count=%d canonical=%v refs=%d..%d\n",
				ci, cc.CID, name, cc.Count, cc.IsCanonical, cc.StartRef, cc.StopRef)
		}
	}

	// C-3 fix: collect ROData string clusters for deferred extraction.
	// The data image position depends on FillEnd, which is only known
	// after all clusters have been processed.
	var rodataStringClusters []*ClusterMeta
	var rodataPcDescClusters []*ClusterMeta
	var rodataCSMClusters []*ClusterMeta
	var rodataCSM2Clusters []*ClusterMeta

	for i := range result.Clusters {
		cm := &result.Clusters[i]
		spec := GetFillSpec(cm.CID, cm, profile)
		fillPos := s.Position()
		if debugFill {
			fmt.Fprintf(os.Stderr, "fill[%d] CID=%d kind=%d count=%d pos=0x%x\n", i, cm.CID, spec.Kind, cm.Count, s.Position())
		}

		switch spec.Kind {
		case FillString:
			strings, err := readFillStrings(s, cm, profile.OldStringFormat, profile.CIDs)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (String CID %d): %w", i, cm.CID, err)
			}
			result.Strings = append(result.Strings, strings...)

		case FillNone, FillSentinel, FillInstructionsTable:
			// No fill data to read.

		case FillROData:
			// C-3 fix: defer ROData string extraction to after FillEnd is set.
			isStringCluster := cm.CID == ct.String ||
				(profile.StringRODataPerSubclass && (cm.CID == ct.OneByteString || cm.CID == ct.TwoByteString))
			if isStringCluster && len(cm.Lengths) > 0 {
				rodataStringClusters = append(rodataStringClusters, cm)
			}
			// PcDescriptors also live in ROData. Their payload carries the
			// try_index per PC, which is the only source for try/catch region
			// extents (ExceptionHandlers gives handler entries but no ranges).
			if ct != nil && ct.PcDescriptors != 0 && cm.CID == ct.PcDescriptors && len(cm.Lengths) > 0 {
				rodataPcDescClusters = append(rodataPcDescClusters, cm)
			}
			// CodeSourceMap takes the same ROData route on non-compressed
			// builds. Capturing it only on the inline-bytes path left Dart
			// < 2.18 with zero CodeSourceMaps despite PcDescriptors working
			// right beside it.
			if ct != nil && ct.CodeSourceMap != 0 && cm.CID == ct.CodeSourceMap && len(cm.Lengths) > 0 {
				rodataCSMClusters = append(rodataCSMClusters, cm)
			}
			// CompressedStackMaps also lives in ROData on non-compressed builds.
			// Same asymmetry fix as PcDescriptors/CSM above.
			if ct != nil && ct.CompressedStackMaps != 0 && cm.CID == ct.CompressedStackMaps && len(cm.Lengths) > 0 {
				rodataCSM2Clusters = append(rodataCSM2Clusters, cm)
			}

		case FillInlineBytes:
			// Capture PcDescriptors, CodeSourceMap, and CompressedStackMaps
			// payloads. PcDescriptors and CSM have consumers (try/catch
			// recovery, inline frame markers). CompressedStackMaps is captured
			// for completeness — it records which registers are live at
			// safepoints, useful for future decompilation quality improvements.
			capturePcDesc := ct != nil && ct.PcDescriptors != 0 && cm.CID == ct.PcDescriptors
			captureCSM := ct != nil && ct.CodeSourceMap != 0 && cm.CID == ct.CodeSourceMap
			captureCSM2 := ct != nil && ct.CompressedStackMaps != 0 && cm.CID == ct.CompressedStackMaps
			payloads, err := readFillInlineBytes(s, cm, capturePcDesc || captureCSM || captureCSM2)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (CID %d) pos=0x%x: %w", i, cm.CID, fillPos, err)
			}
			// Keep partial results in both cases: these are streams of
			// independent records, so a malformed tail still leaves usable
			// information for the earlier PCs.
			if capturePcDesc {
				ref := cm.StartRef
				for _, p := range payloads {
					entries, decErr := DecodePcDescriptors(p)
					if len(entries) > 0 || decErr == nil {
						result.PcDescriptors = append(result.PcDescriptors,
							PcDescriptorsInfo{RefID: ref, Entries: entries})
					}
					ref++
				}
			}
			if captureCSM {
				ref := cm.StartRef
				for _, p := range payloads {
					entries, decErr := DecodeCodeSourceMap(p)
					if len(entries) > 0 || decErr == nil {
						result.CodeSourceMaps = append(result.CodeSourceMaps,
							CodeSourceMapInfo{RefID: ref, Entries: entries})
					}
					ref++
				}
			}
			if captureCSM2 {
				ref := cm.StartRef
				for _, p := range payloads {
					result.CompressedStackMaps = append(result.CompressedStackMaps,
						CompressedStackMapsInfo{RefID: ref, Payload: p})
					ref++
				}
			}

		case FillRefs:
			named, funcTypes, fieldInfos, typeInfos, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, err := readFillRefs(s, cm, &spec, fillRefUnsigned, profile)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (CID %d): %w", i, cm.CID, err)
			}
			result.Named = append(result.Named, named...)
			result.FuncTypes = append(result.FuncTypes, funcTypes...)
			result.Fields = append(result.Fields, fieldInfos...)
			result.Types = append(result.Types, typeInfos...)
			result.ICData = append(result.ICData, icDataInfos...)
			result.Scripts = append(result.Scripts, scriptInfos...)
			result.LoadingUnits = append(result.LoadingUnits, loadingUnitInfos...)
			result.KernelProgramInfo = append(result.KernelProgramInfo, kpiRefs...)
			result.ClosureData = append(result.ClosureData, closureDataInfos...)
			result.TypeParameters = append(result.TypeParameters, typeParamInfos...)

		case FillDouble:
			if err := skipFillDouble(s, cm, profile.PreCanonicalSplit); err != nil {
				return fmt.Errorf("fill: cluster %d (Double): %w", i, err)
			}

		case FillCode:
			codes, err := readFillCode(s, cm, profile.CIDs, fillRefUnsigned, instrIdx, profile.CodeNumRefs, profile.CodeTextOffsetDelta, profile.CodeStateBitsAfterRef, profile.CodeStateBitsAtEnd)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (Code): %w", i, err)
			}
			result.Codes = append(result.Codes, codes...)
			// Advance instrIdx by the number of main (non-deferred) codes.
			instrIdx += int(cm.MainCount)

		case FillObjectPool:
			pool, err := readFillObjectPool(s, cm, profile.OldPoolFormat, profile.PoolTypeSwapped, fillRefUnsigned)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (ObjectPool): %w", i, err)
			}
			result.Pool = append(result.Pool, pool...)

		case FillArray:
			arrays, err := readFillArray(s, cm, fillRefUnsigned, profile)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (Array): %w", i, err)
			}
			result.Arrays = append(result.Arrays, arrays...)

		case FillWeakArray:
			if err := skipFillWeakArray(s, cm, fillRefUnsigned); err != nil {
				return fmt.Errorf("fill: cluster %d (WeakArray): %w", i, err)
			}

		case FillTypedData:
			if err := skipFillTypedData(s, cm, profile.CIDs, profile.PreCanonicalSplit); err != nil {
				return fmt.Errorf("fill: cluster %d (TypedData CID %d): %w", i, cm.CID, err)
			}

		case FillExceptionHandlers:
			ehInfos, err := readFillExceptionHandlers(s, cm, fillRefUnsigned)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (ExceptionHandlers) pos=0x%x: %w", i, fillPos, err)
			}
			result.ExceptionHandlers = append(result.ExceptionHandlers, ehInfos...)

		case FillContext:
			ctxInfos, err := readFillContext(s, cm, fillRefUnsigned)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (Context): %w", i, err)
			}
			result.Contexts = append(result.Contexts, ctxInfos...)

		case FillTypeArguments:
			taInfos, err := readFillTypeArguments(s, cm, fillRefUnsigned, profile)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (TypeArguments): %w", i, err)
			}
			result.TypeArguments = append(result.TypeArguments, taInfos...)

		case FillClass:
			named, classInfos, err := readFillClass(s, cm, &spec, fillRefUnsigned, profile.TopLevelCid16, profile.ClassHasTokenPos)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (Class): %w", i, err)
			}
			result.Named = append(result.Named, named...)
			result.Classes = append(result.Classes, classInfos...)

		case FillField:
			named, fieldInfos, err := readFillField(s, cm, &spec, fillRefUnsigned)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (Field): %w", i, err)
			}
			result.Named = append(result.Named, named...)
			result.Fields = append(result.Fields, fieldInfos...)

		case FillInstance:
			instInfos, err := readFillInstance(s, cm, fillRefUnsigned, profile.CompressedPointers, profile.PreCanonicalSplit)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (Instance CID %d): %w", i, cm.CID, err)
			}
			result.Instances = append(result.Instances, instInfos...)

		case FillRecord:
			if err := skipFillRecord(s, cm, fillRefUnsigned); err != nil {
				return fmt.Errorf("fill: cluster %d (Record): %w", i, err)
			}

		case FillContextScope:
			if err := skipFillContextScope(s, cm, fillRefUnsigned); err != nil {
				return fmt.Errorf("fill: cluster %d (ContextScope): %w", i, err)
			}

		default:
			return fmt.Errorf("fill: cluster %d (CID %d): unknown fill kind %d", i, cm.CID, spec.Kind)
		}
	}

	// Byte offset right after the last cluster's fill data -- where the
	// isolate snapshot's "roots" section begins (ObjectStore fields,
	// field tables, DispatchTable). See ParseDispatchTable.
	result.FillEnd = s.Position()

	// C-3 fix: extract ROData strings from the data image region.
	// The data image position is computed from the snapshot header's
	// length field (verified against dart-lang/sdk snapshot.h at 2.12.0).
	if len(rodataStringClusters) > 0 {
		objStart := dataImageObjStart(len(data), snapshotSize, profile)
		if objStart > 0 {
			for _, cm := range rodataStringClusters {
				strs := extractRODataStrings(data, cm, ct, objStart, profile, isVM)
				result.Strings = append(result.Strings, strs...)
			}
		}
	}

	// Extract PcDescriptors / CodeSourceMap payloads (same ROData addressing
	// as strings; used by non-compressed-pointer builds).
	if len(rodataPcDescClusters) > 0 || len(rodataCSMClusters) > 0 || len(rodataCSM2Clusters) > 0 {
		objStart := dataImageObjStart(len(data), snapshotSize, profile)
		if objStart > 0 {
			for _, cm := range rodataPcDescClusters {
				result.PcDescriptors = append(result.PcDescriptors,
					extractRODataPcDescriptors(data, cm, objStart, profile, isVM)...)
			}
			for _, cm := range rodataCSMClusters {
				result.CodeSourceMaps = append(result.CodeSourceMaps,
					extractRODataCodeSourceMaps(data, cm, objStart, profile, isVM)...)
			}
			// CompressedStackMaps ROData extraction (non-compressed builds).
			for _, cm := range rodataCSM2Clusters {
				for _, p := range extractRODataPayloads(data, cm, profile.CIDs.CompressedStackMaps, objStart, profile, isVM) {
					result.CompressedStackMaps = append(result.CompressedStackMaps,
						CompressedStackMapsInfo{RefID: p.RefID, Payload: p.Payload})
				}
			}
		}
	}

	return nil
}

// fillOneCluster advances the stream past one cluster's fill data.
// Used by DebugFillPositions to track stream positions without collecting results.
// instrIdx is updated for Code clusters.
func fillOneCluster(s *dartfmt.Stream, cm *ClusterMeta, spec *FillSpec, fillRefUnsigned bool, profile *snapshot.VersionProfile, instrIdx *int, result *Result) error {
	switch spec.Kind {
	case FillString:
		strings, err := readFillStrings(s, cm, profile.OldStringFormat, profile.CIDs)
		if err != nil {
			return err
		}
		if result != nil {
			result.Strings = append(result.Strings, strings...)
		}
	case FillNone, FillSentinel, FillROData, FillInstructionsTable:
		// No fill data.
	case FillInlineBytes:
		return skipFillInlineBytes(s, cm)
	case FillRefs:
		// Pass the real profile through. Passing nil here used to panic:
		// readFillRefs dereferences profile.CIDs to decide which CID-specific
		// capture applies, so every FillRefs cluster reached from
		// DebugFillPositions (aotopsy _debug clusters / _debug objects) hit a
		// nil-pointer dereference.
		_, _, _, _, _, _, _, _, _, _, err := readFillRefs(s, cm, spec, fillRefUnsigned, profile)
		return err
	case FillDouble:
		return skipFillDouble(s, cm, profile.PreCanonicalSplit)
	case FillCode:
		_, err := readFillCode(s, cm, profile.CIDs, fillRefUnsigned, *instrIdx, profile.CodeNumRefs, profile.CodeTextOffsetDelta, profile.CodeStateBitsAfterRef, profile.CodeStateBitsAtEnd)
		*instrIdx += int(cm.MainCount)
		return err
	case FillObjectPool:
		_, err := readFillObjectPool(s, cm, profile.OldPoolFormat, profile.PoolTypeSwapped, fillRefUnsigned)
		return err
	case FillArray:
		return skipFillArray(s, cm, fillRefUnsigned, profile)
	case FillWeakArray:
		return skipFillWeakArray(s, cm, fillRefUnsigned)
	case FillTypedData:
		return skipFillTypedData(s, cm, profile.CIDs, profile.PreCanonicalSplit)
	case FillExceptionHandlers:
		_, err := readFillExceptionHandlers(s, cm, fillRefUnsigned)
		return err
	case FillContext:
		_, err := readFillContext(s, cm, fillRefUnsigned)
		return err
	case FillTypeArguments:
		_, err := readFillTypeArguments(s, cm, fillRefUnsigned, profile)
		return err
	case FillClass:
		_, _, err := readFillClass(s, cm, spec, fillRefUnsigned, profile.TopLevelCid16, profile.ClassHasTokenPos)
		return err
	case FillField:
		_, _, err := readFillField(s, cm, spec, fillRefUnsigned)
		return err
	case FillInstance:
		_, err := readFillInstance(s, cm, fillRefUnsigned, profile.CompressedPointers, profile.PreCanonicalSplit)
		return err
	case FillRecord:
		return skipFillRecord(s, cm, fillRefUnsigned)
	case FillContextScope:
		return skipFillContextScope(s, cm, fillRefUnsigned)
	default:
		return fmt.Errorf("unknown fill kind %d", spec.Kind)
	}
	return nil
}

// ReadFillStrings parses the Fill section of the snapshot to extract string
// values. It processes clusters in order, extracting strings from String
// clusters and skipping non-string clusters. Extracted strings are stored
// in result.Strings with their ref IDs for later correlation.
//
// Deprecated: Use ReadFill for full fill parsing including name extraction.
// ReadFillStrings is no longer called by any production code path -- it is
// retained only for backward compatibility. ReadFill already handles strings
// (via the FillString and FillROData cases) and named objects, so callers
// should use it directly instead of the previous ReadFillStrings + ReadFill
// two-step pattern.
func ReadFillStrings(data []byte, result *Result, profile *snapshot.VersionProfile, isVM bool, snapshotSize int64) error {
	if result.FillStart <= 0 || result.FillStart >= len(data) {
		return fmt.Errorf("fill: invalid start offset %d", result.FillStart)
	}

	s := dartfmt.NewStreamAt(data, result.FillStart)
	ct := profile.CIDs

	for i := range result.Clusters {
		cm := &result.Clusters[i]
		kind := ClassifyAlloc(cm.CID, ct)

		if kind == AllocString {
			// ROData strings (non-compressed-pointers or SplitCanonical) have no fill data.
			// Extract string bytes from the data image region instead.
			if profile.SplitCanonical || !profile.CompressedPointers {
				objStart := dataImageObjStart(len(data), snapshotSize, profile)
				// C-3 fix: StringRODataPerSubclass (≤2.12) has no abstract
				// kStringCid cluster — OneByteString/TwoByteString each carry
				// their own real deltas directly. Was hardcoded to only
				// ct.String, missing all strings for Dart 2.12.
				isStringCluster := cm.CID == ct.String ||
					(profile.StringRODataPerSubclass && (cm.CID == ct.OneByteString || cm.CID == ct.TwoByteString))
				if objStart > 0 && len(cm.Lengths) > 0 && isStringCluster {
					strs := extractRODataStrings(data, cm, ct, objStart, profile, isVM)
					result.Strings = append(result.Strings, strs...)
				}
				continue
			}
			strings, err := readFillStrings(s, cm, profile.OldStringFormat, profile.CIDs)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (String): %w", i, err)
			}
			result.Strings = append(result.Strings, strings...)
		} else {
			// C-3 fix: was `break` — stopped at the first non-string cluster,
			// missing string clusters that appear later in the cluster order
			// (e.g., Dart 2.12 has Instance/TypeArguments/etc. before
			// OneByteString). Now skip non-string clusters instead.
			continue
		}
	}

	return nil
}

// readFillStrings reads the fill data for a String cluster.
// When oldFormat is true (≤2.14), length is plain ReadUnsigned and
// isTwoByte is determined by the cluster CID (ct.TwoByteString).
// When oldFormat is false (≥2.16), length is encoded as (length<<1)|flag.
func readFillStrings(s *dartfmt.Stream, cm *ClusterMeta, oldFormat bool, ct *snapshot.CIDTable) ([]ParsedString, error) {
	count := int(cm.Count)
	if count <= 0 {
		return nil, nil
	}

	// In old format, the CID determines one-byte vs two-byte for the entire cluster.
	cidIsTwoByte := oldFormat && ct != nil && cm.CID == ct.TwoByteString

	strings := make([]ParsedString, 0, count)
	ref := cm.StartRef

	for i := 0; i < count; i++ {
		encoded, err := s.ReadUnsigned()
		if err != nil {
			return strings, fmt.Errorf("string %d/%d encoded: %w", i, count, err)
		}

		var length int
		var isTwoByte bool
		if oldFormat {
			length = int(encoded)
			isTwoByte = cidIsTwoByte
		} else {
			length = int(encoded >> 1)
			isTwoByte = (encoded & 1) != 0
		}

		var value string
		if isTwoByte {
			nbytes := length * 2
			raw, err := s.ReadBytes(nbytes)
			if err != nil {
				return strings, fmt.Errorf("string %d/%d data (%d bytes): %w", i, count, nbytes, err)
			}
			runes := make([]rune, length)
			for j := 0; j < length; j++ {
				runes[j] = rune(uint16(raw[j*2]) | uint16(raw[j*2+1])<<8)
			}
			value = string(runes)
		} else {
			raw, err := s.ReadBytes(length)
			if err != nil {
				return strings, fmt.Errorf("string %d/%d data (%d bytes): %w", i, count, length, err)
			}
			value = string(raw)
		}

		strings = append(strings, ParsedString{
			RefID:     ref,
			Value:     value,
			IsOneByte: !isTwoByte,
		})
		ref++
	}

	return strings, nil
}

// extractRODataStrings reads string data from the data image for ROData string clusters.
// When strings use ROData format (non-compressed-pointers), the string bytes live
// in the data image region of the snapshot, not in the fill stream.
// The alloc phase recorded offset deltas in cm.Lengths.
// dataImageObjStart is the byte offset within data[] where ROData objects begin.
//
// The alignment shift and CID tag decode are version-dependent:
//   - alignment: dataImageAlignment(profile) — 16 for ≤2.18, 64 for ≥2.19
//     (was hardcoded << 5 = 32, matching NEITHER — P0-3/D-001)
//   - CID decode: uses DecodeTags (bits 12-31, 20-bit mask) for v3.x+
//     (was hardcoded >> 16 & 0xFFFF, wrong for CIDs > 65535 — P0-4/D-002)
func extractRODataStrings(data []byte, cm *ClusterMeta, ct *snapshot.CIDTable, dataImageObjStart int64, profile *snapshot.VersionProfile, isVM bool) []ParsedString {
	if len(cm.Lengths) == 0 || dataImageObjStart <= 0 {
		return nil
	}

	// The ROData running_offset delta is encoded in units of kObjectAlignment
	// (RODataDeserializationCluster::ReadAlloc: `running_offset += ReadUnsigned()
	// << kObjectAlignmentLog2`). kObjectAlignment = 2*kWordSize = 16 on 64-bit
	// (kObjectAlignmentLog2 = 4). This is a DIFFERENT, smaller alignment than the
	// data-image BASE alignment (kObjectStartAlignment = 64 for >=2.19, applied in
	// dataImageObjStart) — the two must not be conflated. The ROData path only
	// runs for non-compressed-pointers snapshots, which are 64-bit in practice.
	alignShift := uint(4)

	// No per-snapshot header adjustment: with the correct image-base alignment
	// (kObjectStartAlignment, applied in dataImageObjStart) and the correct delta
	// stride (kObjectAlignment=16, alignShift=4 above), the cumulative
	// running_offset lands exactly on each object header for BOTH the VM and the
	// isolate data images -- verified against real cid=94 OneByteString headers in
	// both. The previous isVM-only +16 fudge only compensated for a wrong stride.
	headerAdjust := int64(0)
	_ = isVM

	runningOffset := int64(0)
	ref := cm.StartRef
	var strings []ParsedString

	for i := 0; i < len(cm.Lengths); i++ {
		// C-3 fix: delta is the offset from DataImage start to this object.
		// Objects begin at DataImage + kHeaderSize (16 bytes image header).
		// GetObjectAt(running_offset) = DataImage + running_offset.
		// But our dataImageObjStart = DataImage offset within data[].
		// The image header (kHeaderSize=16) is at DataImage[0..15].
		// First object is at DataImage+16, but CID there may be 0 (padding).
		// String objects are at DataImage+32, +64, +96, etc. (step 32).
		// Delta sequence: 1, 2, 2, 2... → runningOffset: 16, 48, 80...
		// But strings are at 32, 64, 96... = runningOffset + 16.
		// Fix: add kHeaderSize (= align = 16) to objPos.
		runningOffset += cm.Lengths[i] << alignShift
		objPos := dataImageObjStart + runningOffset + headerAdjust

		// Need at least 16 bytes for header (tags + length).
		if objPos+16 > int64(len(data)) {
			ref++
			continue
		}

		tags := binary.LittleEndian.Uint64(data[objPos : objPos+8])
		// C-3 fix: Object header tags use ClassIdTag bitfield, NOT the
		// cluster stream tag style. The ClassIdTag position differs by
		// version (verified against dart-lang/sdk raw_object.h):
		//   v2.12–v2.17: kClassIdTagPos=16, kClassIdTagSize=16 → bits 16-31
		//   v3.0+:       kClassIdTagPos=12, kClassIdTagSize=20 → bits 12-31
		var cid int
		if profile.PreV32Format {
			cid = int((uint32(tags) >> 16) & 0xFFFF)
		} else {
			cid = int((uint32(tags) >> 12) & ((1 << 20) - 1))
		}

		// Check if this is a string object.
		isOneByte := cid == ct.OneByteString
		isTwoByte := ct.TwoByteString != 0 && cid == ct.TwoByteString

		if !isOneByte && !isTwoByte {
			// Non-string ROData object (TypeArguments, Array, etc.). Skip it.
			ref++
			continue
		}

		lenSmi := int64(binary.LittleEndian.Uint64(data[objPos+8 : objPos+16]))
		strLen := lenSmi >> 1 // Smi decode (kSmiTagShift=1 on arm64)

		if strLen < 0 || strLen > 1<<20 {
			strings = append(strings, ParsedString{RefID: ref, Value: "", IsOneByte: isOneByte})
			ref++
			continue
		}

		dataStart := objPos + 16 // oneByteStringHeaderSize
		var value string
		if isTwoByte {
			nbytes := strLen * 2
			if dataStart+nbytes > int64(len(data)) {
				strings = append(strings, ParsedString{RefID: ref, Value: "", IsOneByte: false})
				ref++
				continue
			}
			runes := make([]rune, strLen)
			for j := int64(0); j < strLen; j++ {
				off := dataStart + j*2
				runes[j] = rune(uint16(data[off]) | uint16(data[off+1])<<8)
			}
			value = string(runes)
		} else {
			if dataStart+strLen > int64(len(data)) {
				strings = append(strings, ParsedString{RefID: ref, Value: "", IsOneByte: true})
				ref++
				continue
			}
			value = string(data[dataStart : dataStart+strLen])
		}

		strings = append(strings, ParsedString{
			RefID:     ref,
			Value:     value,
			IsOneByte: isOneByte,
		})
		ref++
	}

	return strings
}

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
	if profile != nil && profile.CIDs != nil {
		isICData = cm.CID == profile.CIDs.ICData
		isScript = cm.CID == profile.CIDs.Script
		isLoadingUnit = cm.CID == profile.CIDs.LoadingUnit
		isKPI = cm.CID == profile.CIDs.KernelProgramInfo
		isClosureData = cm.CID == profile.CIDs.ClosureData
		isTypeParameters = profile.CIDs.TypeParameters != 0 && cm.CID == profile.CIDs.TypeParameters
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
			if isICData || isScript || isLoadingUnit || isKPI || isClosureData || isTypeParameters {
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
		var fieldKindBits int32
		funcCodeIndex := -1
		// Script scalar capture: line_offset, col_offset, [flags], kernel_script_index.
		var scriptLine, scriptCol, scriptKernelIdx int32
		var scriptFlags byte
		// LoadingUnit scalar capture: the loading-unit id.
		var loadingUnitID int32
		for si, op := range spec.Scalars {
			if spec.IsFunction && si == 0 {
				// code_index is OpUnsigned at scalar index 0.
				ci, err := s.ReadUnsigned()
				if err != nil {
					return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, fmt.Errorf("obj %d/%d code_index: %w", i, count, err)
				}
				funcCodeIndex = int(ci)
			} else if spec.IsFuncType && si == 1 {
				// packed_parameter_counts is OpTagged32 at scalar index 1.
				packed, err := s.ReadTagged32()
				if err != nil {
					return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, fmt.Errorf("obj %d/%d packed_param_counts: %w", i, count, err)
				}
				hasImplicit := (packed & 1) != 0
				numFixed := int((packed >> 2) & 0x3FFF)
				numOptional := int((packed >> 16) & 0x3FFF)
				if hasImplicit && numFixed > 0 {
					numFixed-- // subtract implicit 'this'
				}
				funcTypes = append(funcTypes, FuncTypeInfo{
					RefID:                ref,
					NumFixed:             numFixed,
					NumOptional:          numOptional,
					HasImplicit:          hasImplicit,
					ParamTypesArrayRefID: paramTypesRef,
					TypeParamsRefID:      typeParamsRef,
				})
			} else if spec.IsField && si == 0 {
				// kind_bits is OpTagged32 at scalar index 0.
				kb, err := s.ReadTagged32()
				if err != nil {
					return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, fmt.Errorf("obj %d/%d kind_bits: %w", i, count, err)
				}
				fieldKindBits = int32(kb)
			} else if spec.IsField && si == 1 {
				// host_offset_or_field_id is OpRefId at scalar index 1.
				hostOff, err := s.ReadRefId()
				if err != nil {
					return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, fmt.Errorf("obj %d/%d host_offset: %w", i, count, err)
				}
				isStatic := (fieldKindBits>>1)&1 != 0
				offset := int32(hostOff)
				if isStatic {
					offset = -1
				}
				fields = append(fields, FieldInfo{
					RefID:            ref,
					NameRefID:        nameRef,
					OwnerRefID:       ownerRef,
					KindBits:         fieldKindBits,
					HostOffset:       offset,
					InitializerRefID: sigRef,
					TypeRefID:        fieldTypeRef,
				})
			} else if spec.IsType && si == 0 {
				// flags is OpUnsigned at scalar index 0 (v3.x only -- see
				// specType). type_class_id is packed inside it: bit 0 =
				// nullability, bits [1,3) = TypeState, bits [3,23) = the
				// 20-bit ClassIdTag (confirmed against Dart SDK source,
				// runtime/vm/raw_object.h UntaggedType::TypeClassIdBits).
				flags, err := s.ReadUnsigned()
				if err != nil {
					return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, fmt.Errorf("obj %d/%d type flags: %w", i, count, err)
				}
				classID := int32((flags >> 3) & 0xFFFFF)
				types = append(types, TypeInfo{RefID: ref, ClassID: classID})
			} else if isScript {
				// Script scalars: [line_offset, col_offset, [flags],] kernel_script_index.
				if profile.ScriptHasLineCol {
					if si == 0 {
						v, err := s.ReadTagged32()
						if err != nil {
							return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, fmt.Errorf("obj %d/%d script line: %w", i, count, err)
						}
						scriptLine = int32(v)
					} else if si == 1 {
						v, err := s.ReadTagged32()
						if err != nil {
							return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, fmt.Errorf("obj %d/%d script col: %w", i, count, err)
						}
						scriptCol = int32(v)
					} else if profile.ScriptHasFlags && si == 2 {
						v, err := s.ReadByte()
						if err != nil {
							return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, fmt.Errorf("obj %d/%d script flags: %w", i, count, err)
						}
						scriptFlags = v
					} else {
						v, err := s.ReadTagged32()
						if err != nil {
							return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, fmt.Errorf("obj %d/%d script kernel_idx: %w", i, count, err)
						}
						scriptKernelIdx = int32(v)
					}
				} else if profile.ScriptHasFlags {
					if si == 0 {
						v, err := s.ReadByte()
						if err != nil {
							return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, fmt.Errorf("obj %d/%d script flags: %w", i, count, err)
						}
						scriptFlags = v
					} else {
						v, err := s.ReadTagged32()
						if err != nil {
							return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, fmt.Errorf("obj %d/%d script kernel_idx: %w", i, count, err)
						}
						scriptKernelIdx = int32(v)
					}
				} else {
					v, err := s.ReadTagged32()
					if err != nil {
						return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, fmt.Errorf("obj %d/%d script kernel_idx: %w", i, count, err)
					}
					scriptKernelIdx = int32(v)
				}
			} else if isLoadingUnit {
				// LoadingUnit scalar: id, from
				// LoadingUnitDeserializationCluster::ReadFill ->
				// IdBits::encode(d.Read<intptr_t>()).
				v, err := s.ReadTagged32()
				if err != nil {
					return named, funcTypes, fields, types, icDataInfos, scriptInfos, loadingUnitInfos, kpiRefs, closureDataInfos, typeParamInfos, fmt.Errorf("obj %d/%d loading_unit id: %w", i, count, err)
				}
				// Was `_ = v`, which silently dropped the id and made every
				// loading_units.jsonl record report unit_id=0.
				loadingUnitID = int32(v)
			} else {
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
				LineOffset:        scriptLine,
				ColOffset:         scriptCol,
				KernelScriptIndex: scriptKernelIdx,
			}
			_ = scriptFlags // captured but not stored in struct (rarely needed)
			scriptInfos = append(scriptInfos, si)
		}
		if isLoadingUnit && len(allRefs) >= 1 {
			// LoadingUnit refs: parent(0). Scalar: id.
			lui := LoadingUnitInfo{
				RefID:     ref,
				ParentRef: allRefs[0],
				UnitID:    loadingUnitID,
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
				CID:            cm.CID,
				RefID:          ref,
				NameRefID:      nameRef,
				OwnerRefID:     ownerRef,
				SignatureRefID: sigRef,
				DataRefID:      dataRef,
				CodeIndex:      funcCodeIndex,
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
		isPredefined := int64(i) < cm.MainCount
		isTopLevel := int64(int32(classID)) >= topLevelOffset
		if isPredefined || !isTopLevel {
			if _, err := s.ReadUnsigned(); err != nil {
				return named, classes, fmt.Errorf("obj %d/%d bitmap: %w", i, count, err)
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

// readFillCode reads Code fill data, extracting owner refs and instruction metadata.
// AOT PRODUCT: ReadInstructions + N ReadRef per code.
// v2.16+: ReadInstructions = 1 ReadUnsigned (payload_info). 6 refs.
// v2.10-v2.15: ReadInstructions = 2 ReadUnsigned (text_offset_delta + payload_info). 7 refs.
// Deferred codes skip ReadInstructions (no stream read).
// Ref 0 = owner (Function/Closure/FfiTrampolineData).
// instrIdxBase is the running instructions_index_ counter from previous Code clusters.
//
// stateBitsAfterRef: 0 = no state_bits in fill (v2.10, v2.14+).
// N>0 = state_bits is read after first N refs (v2.13: N=1). DiscardedBit (bit 3)
// of state_bits determines whether remaining refs are skipped.
func readFillCode(s *dartfmt.Stream, cm *ClusterMeta, ct *snapshot.CIDTable, fillRefUnsigned bool, instrIdxBase int, codeNumRefs int, textOffsetDelta bool, stateBitsAfterRef int, stateBitsAtEnd bool) ([]CodeEntry, error) {
	numRefs := codeNumRefs
	if numRefs == 0 {
		numRefs = 6 // default: owner, exception_handlers, pc_descriptors, catch_entry, inlined_id_to_function, code_source_map
	}
	codes := make([]CodeEntry, 0, cm.Count)
	ref := cm.StartRef
	instrIdx := instrIdxBase
	discardedCount := 0
	for i := int64(0); i < cm.Count; i++ {
		var payloadInfo int64
		var textOff int64
		clusterIndex := -1
		traceCode := debugFill && i < 5

		// v2.14+: discarded status from alloc phase. v2.13: determined from state_bits below.
		discarded := cm.DiscardedCodes[i]

		posStart := s.Position()

		// Dump raw bytes for first 3, last 3, and codes near known failure points.
		if debugFill && (i < 3 || i >= cm.Count-3 || (i >= 21600 && i <= 21610)) {
			saved := s.Position()
			hexBytes, _ := s.ReadBytes(30)
			s.SetPosition(saved)
			fmt.Fprintf(os.Stderr, "  code[%d] RAW@0x%x: %x\n", i, posStart, hexBytes)
		}

		// Main (non-deferred) codes: ReadInstructions reads payload data.
		// v2.10-v2.15: ReadUnsigned(text_offset_delta) + ReadUnsigned(payload_info).
		//   v2.14+: discarded codes also read compressed_stackmaps(ReadRef) in ReadInstructions.
		// v2.16+: ReadUnsigned(payload_info) only.
		// Deferred codes: ReadInstructions does nothing (early return).
		if i < cm.MainCount {
			if textOffsetDelta {
				tod, err := s.ReadUnsigned()
				if err != nil {
					return codes, fmt.Errorf("code %d/%d text_offset_delta: %w", i, cm.Count, err)
				}
				textOff = tod
			}
			pi, err := s.ReadUnsigned()
			if err != nil {
				return codes, fmt.Errorf("code %d/%d payload_info: %w", i, cm.Count, err)
			}
			payloadInfo = pi
			clusterIndex = instrIdx
			instrIdx++

			// v2.14+: discarded codes read compressed_stackmaps ref inside ReadInstructions,
			// then return without reading any other refs or state_bits.
			if discarded && stateBitsAfterRef == 0 {
				if _, err := readRef(s, fillRefUnsigned); err != nil {
					return codes, fmt.Errorf("code %d/%d discarded compressed_stackmaps: %w", i, cm.Count, err)
				}
			}
		}

		// v2.13 (stateBitsAfterRef > 0): compressed_stackmaps → state_bits → [if discarded: stop] → 6 refs.
		// All codes read compressed_stackmaps and state_bits. DiscardedBit (bit 3) of state_bits
		// determines whether remaining refs are read. This is different from v2.14+ where
		// discarded status comes from the alloc phase.
		var ownerRef int
		var excHandlersRef int = -1
		var pcDescRef int = -1
		var csmRef int = -1
		var inlinedFuncsRef int = -1
		if stateBitsAfterRef > 0 {
			// Read first N refs (before state_bits) — all codes, including discarded.
			for j := 0; j < stateBitsAfterRef; j++ {
				if _, err := readRef(s, fillRefUnsigned); err != nil {
					return codes, fmt.Errorf("code %d/%d ref %d: %w", i, cm.Count, j, err)
				}
			}
			// Read state_bits (Read<int32_t> VLE).
			sbPos := s.Position()
			sb, err := s.ReadTagged32()
			if err != nil {
				// Dump context for diagnosis.
				if debugFill {
					fmt.Fprintf(os.Stderr, "  code[%d] state_bits ERR at pos=0x%x (code start=0x%x)\n", i, sbPos, posStart)
					// Dump raw bytes from code start.
					saved := s.Position()
					s.SetPosition(posStart)
					hexBytes, _ := s.ReadBytes(40)
					s.SetPosition(saved)
					fmt.Fprintf(os.Stderr, "  hex@0x%x=%x\n", posStart, hexBytes)
				}
				return codes, fmt.Errorf("code %d/%d state_bits: %w", i, cm.Count, err)
			}
			if debugFill && (i%1000 == 0 || (i >= 21595 && i <= 21610)) {
				fmt.Fprintf(os.Stderr, "  code[%d] pos=0x%x sb=0x%x discarded=%v cumDisc=%d\n",
					i, posStart, sb, (sb>>3)&1 != 0, discardedCount)
			}
			// DiscardedBit = bit 3 of state_bits.
			discarded = (sb>>3)&1 != 0
			if discarded {
				discardedCount++
				if traceCode {
					fmt.Fprintf(os.Stderr, "  code[%d] pos=0x%x state_bits=0x%x DISCARDED\n", i, posStart, sb)
				}
				goto done
			}
			// Read remaining refs after state_bits.
			for j := stateBitsAfterRef; j < numRefs; j++ {
				r, err := readRef(s, fillRefUnsigned)
				if err != nil {
					return codes, fmt.Errorf("code %d/%d ref %d: %w", i, cm.Count, j, err)
				}
				// Owner is the first ref after state_bits (e.g., ref[1] for v2.13).
				if j == stateBitsAfterRef {
					ownerRef = int(r)
				}
				if j == stateBitsAfterRef+1 {
					excHandlersRef = int(r)
				}
				if j == stateBitsAfterRef+2 {
					pcDescRef = int(r)
				}
			}
		} else if !discarded {
			// v2.10, v2.14+: read all refs in order (no interleaved state_bits).
			for j := 0; j < numRefs; j++ {
				r, err := readRef(s, fillRefUnsigned)
				if err != nil {
					return codes, fmt.Errorf("code %d/%d ref %d: %w", i, cm.Count, j, err)
				}
				if j == 0 {
					ownerRef = int(r)
				}
				if j == 1 {
					excHandlersRef = int(r)
				}
				if j == 2 {
					pcDescRef = int(r)
				}
				// inlined_id_to_function is ref 4: an Array of Functions that
				// CodeSourceMap's PushFunction indices point into.
				if j == 4 {
					inlinedFuncsRef = int(r)
				}
				// code_source_map is ref 5 in AOT: owner(0),
				// exception_handlers(1), pc_descriptors(2), catch_entry(3),
				// inlined_id_to_function(4), code_source_map(5).
				// object_pool and compressed_stackmaps are absent in AOT.
				if j == 5 {
					csmRef = int(r)
				}
			}
		}

		// v2.10: state_bits_ = Read<int32_t>() after ALL refs, unconditionally (no discarded check).
		if stateBitsAtEnd {
			if _, err := s.ReadTagged32(); err != nil {
				return codes, fmt.Errorf("code %d/%d state_bits_at_end: %w", i, cm.Count, err)
			}
		}

	done:
		if traceCode {
			fmt.Fprintf(os.Stderr, "  code[%d] pos=0x%x total=%d discarded=%v\n",
				i, posStart, s.Position()-posStart, discarded)
		}
		if debugFill && (i < 5 || i >= cm.Count-3 || i == cm.MainCount-1 || i == cm.MainCount || i%5000 == 0) {
			fmt.Fprintf(os.Stderr, "  code[%d/%d] main=%d owner=%d discarded=%v endPos=0x%x\n", i, cm.Count, cm.MainCount, ownerRef, discarded, s.Position())
		}
		codes = append(codes, CodeEntry{
			RefID:                ref,
			OwnerRef:             ownerRef,
			ClusterIndex:         clusterIndex,
			PayloadInfo:          payloadInfo,
			TextOffset:           textOff,
			ExceptionHandlersRef: excHandlersRef,
			PcDescriptorsRef:     pcDescRef,
			CodeSourceMapRef:     csmRef,
			InlinedFuncsRef:      inlinedFuncsRef,
		})
		ref++
	}
	if debugFill && discardedCount > 0 {
		fmt.Fprintf(os.Stderr, "  code: %d/%d discarded (from state_bits)\n", discardedCount, cm.Count)
	}
	return codes, nil
}

// readFillObjectPool reads ObjectPool fill data and captures entries.
// Per pool: ReadUnsigned(length) + length × (ReadByte(entry_bits) + type-dependent data).
//
// v2.17.6: TypeBits[0:7] (7 bits), PatchableBit[7].
//
//	0=kTaggedObject→ReadRef, 1=kImmediate→Read<intptr_t>, 2+=nothing.
//
// v3.x: TypeBits[0:4], PatchableBit[4], SnapshotBehaviorBits[5:8].
//
//	behavior 0: 0=kImmediate→Read<intptr_t>, 1=kTaggedObject→ReadRef, 2=kNativeFunction→nothing.
//	behavior 1,2,3: nothing.
func readFillObjectPool(s *dartfmt.Stream, cm *ClusterMeta, oldPoolFormat, poolTypeSwapped, fillRefUnsigned bool) ([]PoolEntry, error) {
	if debugFill {
		saved := s.Position()
		rawBytes, _ := s.ReadBytes(40)
		s.SetPosition(saved)
		fmt.Fprintf(os.Stderr, "  ObjectPool fill start @0x%x raw=%x\n", saved, rawBytes)
	}
	var entries []PoolEntry
	idx := 0
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return nil, fmt.Errorf("pool %d/%d length: %w", i, cm.Count, err)
		}
		for j := int64(0); j < length; j++ {
			entryBits, err := s.ReadByte()
			if err != nil {
				return nil, fmt.Errorf("pool %d entry %d bits: %w", i, j, err)
			}

			pe := PoolEntry{Index: idx}
			idx++

			if oldPoolFormat {
				// ≤3.2: TypeBits = entryBits & 0x7F (7 bits).
				typeBits := entryBits & 0x7F
				// v3.2 swapped kImmediate(0) and kTaggedObject(1). Normalize to pre-3.2 ordering.
				if poolTypeSwapped && typeBits <= 1 {
					typeBits ^= 1
				}
				switch typeBits {
				case 0: // kTaggedObject → ReadRef
					ref, err := readRef(s, fillRefUnsigned)
					if err != nil {
						return nil, fmt.Errorf("pool %d entry %d ref (bits=0x%02x pos=0x%x): %w", i, j, entryBits, s.Position(), err)
					}
					pe.Kind = PoolTagged
					pe.RefID = int(ref)
				case 1: // kImmediate → Read<intptr_t> = Read64
					imm, err := s.ReadTagged64()
					if err != nil {
						return nil, fmt.Errorf("pool %d entry %d imm (bits=0x%02x pos=0x%x): %w", i, j, entryBits, s.Position(), err)
					}
					pe.Kind = PoolImmediate
					pe.Imm = imm
				case 2, 3: // kNativeFunction, kNativeFunctionWrapper → nothing
					pe.Kind = PoolNative
				case 4: // kNativeEntryData → ReadRef (same as kTaggedObject)
					ref, err := readRef(s, fillRefUnsigned)
					if err != nil {
						return nil, fmt.Errorf("pool %d entry %d native_entry_data ref (bits=0x%02x pos=0x%x): %w", i, j, entryBits, s.Position(), err)
					}
					pe.Kind = PoolTagged
					pe.RefID = int(ref)
				default:
					return nil, fmt.Errorf("pool %d entry %d: unknown type %d (bits=0x%02x pos=0x%x)", i, j, typeBits, entryBits, s.Position())
				}
			} else {
				// v3.x: SnapshotBehaviorBits = entryBits >> 5 (3 bits).
				behaviorBits := entryBits >> 5
				typeBits := entryBits & 0x0F
				switch behaviorBits {
				case 0: // kSnapshotable
					switch typeBits {
					case 0: // kImmediate → Read<intptr_t>
						imm, err := s.ReadTagged64()
						if err != nil {
							return nil, fmt.Errorf("pool %d entry %d imm: %w", i, j, err)
						}
						pe.Kind = PoolImmediate
						pe.Imm = imm
					case 1: // kTaggedObject → ReadRef
						ref, err := readRef(s, fillRefUnsigned)
						if err != nil {
							return nil, fmt.Errorf("pool %d entry %d ref: %w", i, j, err)
						}
						pe.Kind = PoolTagged
						pe.RefID = int(ref)
					case 2: // kNativeFunction → nothing
						pe.Kind = PoolNative
					default:
						return nil, fmt.Errorf("pool %d entry %d: unknown type %d", i, j, typeBits)
					}
				case 1, 2, 3, 4: // kResetToBootstrapNative, kResetToSwitchableCallMissEntryPoint, kSetToZero, kResetToMegamorphicCallEntryPoint
					pe.Kind = PoolEmpty
				default:
					return nil, fmt.Errorf("pool %d entry %d: unknown snapshot behavior %d", i, j, behaviorBits)
				}
			}
			entries = append(entries, pe)
		}
	}
	return entries, nil
}

// skipFillInlineBytes skips clusters that store inline byte data.
// Per object: ReadUnsigned(length) + ReadBytes(length).
// Used for PcDescriptors, CodeSourceMap, CompressedStackMaps with compressed pointers.
func skipFillInlineBytes(s *dartfmt.Stream, cm *ClusterMeta) error {
	_, err := readFillInlineBytes(s, cm, false)
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
func readFillInlineBytes(s *dartfmt.Stream, cm *ClusterMeta, capture bool) ([][]byte, error) {
	var payloads [][]byte
	if capture {
		payloads = make([][]byte, 0, cm.Count)
	}
	for i := int64(0); i < cm.Count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return payloads, fmt.Errorf("inline_bytes %d/%d length: %w", i, cm.Count, err)
		}
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

// readFillInstance captures Instance fill data.
// Format: ReadUnsigned64(unboxed_bitmap) ONCE, then per object:
//
//	for each field offset from header to next_field_offset:
//	  if unboxed: ReadWordWith32BitReads (2 × ReadTagged32)
//	  else: ReadRef (ReadRefId)
//
// header_words: 2 for compressed pointers (tags + hash = 2 × 4 bytes = 2 compressed words).
// header_words: 1 for uncompressed (tags = 1 × 8 bytes = 1 word).
func readFillInstance(s *dartfmt.Stream, cm *ClusterMeta, fillRefUnsigned, compressedPointers, preCanonicalSplit bool) ([]InstanceInfo, error) {
	var result []InstanceInfo
	var bitmap int64
	if !preCanonicalSplit {
		var err error
		bitmap, err = s.ReadUnsigned()
		if err != nil {
			return result, fmt.Errorf("instance(%d) bitmap: %w", cm.CID, err)
		}
	}

	nfo := int(cm.NextFieldOffsetInWords)
	if nfo <= 0 {
		return result, nil
	}
	headerWords := 1
	wordSize := 8
	if compressedPointers {
		headerWords = 2
		wordSize = 4
	}
	numFields := nfo - headerWords
	if numFields < 0 {
		numFields = 0
	}

	ref := cm.StartRef
	for i := int64(0); i < cm.Count; i++ {
		if preCanonicalSplit {
			if _, err := s.ReadByte(); err != nil {
				return result, fmt.Errorf("instance(%d) %d/%d is_canonical: %w", cm.CID, i, cm.Count, err)
			}
		}
		inst := InstanceInfo{
			RefID:         ref,
			CID:           cm.CID,
			HeaderWords:   headerWords,
			NumFieldSlots: numFields,
		}
		for j := 0; j < numFields; j++ {
			fieldWordIdx := headerWords + j
			isUnboxed := (bitmap>>uint(fieldWordIdx))&1 != 0
			if isUnboxed { // TODO(BUG-HUNT): unboxed read is always 2x ReadTagged32 (8 bytes) regardless of compressed pointers; bitmap granularity is the machine word (8 bytes), not the compressed word (4 bytes), so two 32-bit tagged reads consume one machine word on disk -- correct for current Dart AOT serialization but would need revisiting if bitmap granularity became compressed-word-sized. Left as-is intentionally; changing it could break verified fill behavior.
				if _, err := s.ReadTagged32(); err != nil {
					return result, fmt.Errorf("instance(%d) %d/%d unboxed field %d lo: %w", cm.CID, i, cm.Count, j, err)
				}
				if _, err := s.ReadTagged32(); err != nil {
					return result, fmt.Errorf("instance(%d) %d/%d unboxed field %d hi: %w", cm.CID, i, cm.Count, j, err)
				}
				continue
			}
			fieldRef, err := readRef(s, fillRefUnsigned)
			if err != nil {
				return result, fmt.Errorf("instance(%d) %d/%d ref %d: %w", cm.CID, i, cm.Count, j, err)
			}
			// Byte offset in the same coordinate system BuildClassLayouts
			// uses for FieldInfo: word index from the object start times the
			// word size (4 under compressed pointers, else 8).
			inst.Fields = append(inst.Fields, InstanceFieldRef{
				ByteOffset: int32(fieldWordIdx) * int32(wordSize),
				Ref:        int(fieldRef),
			})
		}
		result = append(result, inst)
		ref++
	}
	return result, nil
}

// skipFillRecord skips Record fill.
// Per object: ReadRef(shape) + num_fields × ReadRef(field).
// skipFillRecord skips Record fill.
// Per object: ReadUnsigned(shape) + num_fields × ReadRef(field).
// num_fields = RecordShape.NumFieldsBitField (lower 16 bits of shape).
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
// Per scope: num_variables entries, each with multiple refs and scalars.
// ContextScope is non-AOT only (context_scope_ = null in AOT ClosureData).
// In practice this cluster type should not appear in AOT snapshots,
// but we handle it for completeness.
// skipFillContextScope skips ContextScope fill.
// ContextScope is non-AOT only. Should not appear in AOT PRODUCT snapshots.
// Per object: ReadUnsigned(length) + ReadByte(is_implicit) + ReadFromTo(scope, length).
// ReadFromTo reads all pointer fields per variable entry as ReadRef.
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
