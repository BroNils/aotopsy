// Version detection for Dart AOT snapshot format variations.
//
// CID tables and snapshot format constants in this file are derived from
// the Dart SDK source code (dart-lang/sdk), licensed under BSD-3-Clause.
// See the NOTICE file for details.

package snapshot

import (
	"fmt"
	"sort"
	"strings"
)

// TagStyle identifies how cluster tags are encoded in the snapshot.
type TagStyle int

const (
	// TagStyleCidShift1 is the v2.14+ / early v3.x format:
	//   Write<uint64_t>((cid << 1) | canonical)
	// Used in the supported profiles from Dart 2.14.0 through 3.3.0.
	TagStyleCidShift1 TagStyle = iota

	// TagStyleObjectHeader is the v3.4.3+ format:
	//   Write<uint32_t>(ClassIdTag::encode(cid) | CanonicalBit | ImmutableBit)
	// CID at bits 12-31, canonical at bit 1, immutable at bit 6.
	TagStyleObjectHeader

	// TagStyleCidInt32 is the v2.10-2.13 format:
	//   Write<int32_t>(cid)
	// Raw 32-bit CID, no canonical bit (canonical is passed separately or
	// determined by which cluster loop we're in).
	TagStyleCidInt32
)

// BuildMode identifies the Dart VM build configuration, as recorded in the
// snapshot's features string.
//
// Dart::FeaturesString (runtime/vm/dart.cc) writes exactly ONE of three
// tokens, always first in the string:
//
//	#if defined(DEBUG)      -> "debug"
//	#elif defined(PRODUCT)  -> "product"
//	#else                   -> "release"
//
// There is deliberately no "profile" token: a Flutter *profile* build uses a
// release-mode (non-PRODUCT) VM and therefore reports "release". An earlier
// revision here had a BuildProfile constant matched against a "profile"
// feature that Dart never emits, so it was unreachable, and "release" fell
// through to the debug branch.
type BuildMode int

const (
	// BuildUnknown means the snapshot feature string did not prove one of the
	// three SDK-defined build modes. It must never inherit PRODUCT semantics:
	// PRODUCT changes the serialized Code shape as well as VM offset tables.
	BuildUnknown BuildMode = iota

	// BuildProduct is defined(PRODUCT): the mode every shipped release APK
	// uses, and the only mode this tool fully supports. THR offsets come from
	// the defined(PRODUCT) blocks of runtime_offsets_extracted.h.
	BuildProduct

	// BuildRelease is the non-PRODUCT, non-DEBUG mode -- what a Flutter
	// profile build ships. Uses the !defined(PRODUCT) offset blocks.
	BuildRelease

	// BuildDebug is defined(DEBUG). Also uses the !defined(PRODUCT) blocks.
	BuildDebug
)

// String renders the mode using the same token Dart writes.
func (m BuildMode) String() string {
	switch m {
	case BuildProduct:
		return "product"
	case BuildRelease:
		return "release"
	case BuildDebug:
		return "debug"
	}
	return "unknown"
}

// IsProduct reports whether this is a defined(PRODUCT) build. Non-PRODUCT
// snapshots differ from PRODUCT in more than just THR offsets -- see the
// note on VersionProfile.BuildMode -- so callers that only support PRODUCT
// should branch on this rather than on individual offset tables.
func (m BuildMode) IsProduct() bool { return m == BuildProduct }

// SnapshotSymbolLayout identifies the mutually-exclusive AOT export layouts.
// SDK @3.12.2 runtime/include/dart_api.h exports separate VM/isolate data and
// instructions symbols; @3.13.0 exports one data/text pair.
type SnapshotSymbolLayout uint8

const (
	SnapshotSymbolsUnknown SnapshotSymbolLayout = iota
	SnapshotSymbolsLegacy
	SnapshotSymbolsUnified
)

// CompressionFeatureStyle records how Dart::FeaturesString encodes pointer
// compression for this format family. Dart 2.10/2.12 have no compressed-pointer
// build dimension at all; 2.13-2.14 write only the positive token "compressed";
// 2.15+ write exactly one of "compressed-pointers" and
// "no-compressed-pointers". Treating those eras as interchangeable silently
// chooses the wrong object layout.
type CompressionFeatureStyle uint8

const (
	CompressionFeatureUnknown CompressionFeatureStyle = iota
	CompressionFeatureFixedUncompressed
	CompressionFeatureLegacyPositiveOnly
	CompressionFeatureExplicit
)

// TargetFeatureStyle records how Dart::FeaturesString identifies the generated
// machine-code target. Through Dart 2.18 the architecture token also carries
// the ABI (for the supported 64-bit targets, arm64-sysv/x64-sysv). Dart 2.19+
// emits a bare architecture token followed by a separate operating-system
// token. AOTopsy supports only the SysV/Linux-or-Android variants that match
// its ELF64 ARM64/x86_64 analysis paths.
type TargetFeatureStyle uint8

const (
	TargetFeatureUnknown TargetFeatureStyle = iota
	TargetFeatureLegacyABI
	TargetFeatureArchAndOS
)

// InstructionsImageLayout records the versioned instructions-image header.
// Dart 2.10's second Image word is a BSS offset and the InstructionsSection
// starts at Image::kHeaderSize. Dart 2.12+ stores an explicit section offset;
// its section header is 40 bytes through 3.4 and 64 bytes from 3.5 onward.
type InstructionsImageLayout uint8

const (
	InstructionsImageUnknown InstructionsImageLayout = iota
	InstructionsImageLegacy210
	InstructionsImageSection40
	InstructionsImageSection64
)

// VersionProfile holds format parameters that differ across Dart SDK versions.
type VersionProfile struct {
	DartVersion                     string   // e.g. "2.17.6", "3.10.7", "" if unknown
	Supported                       bool     // true if full parsing is available (CID table + format flags)
	HeaderFields                    int      // clustered snapshot header field count (5 or 6)
	Tags                            TagStyle // how cluster tags are encoded
	CIDs                            *CIDTable
	SnapshotSymbols                 SnapshotSymbolLayout
	CompressionFeatures             CompressionFeatureStyle
	TargetFeatures                  TargetFeatureStyle
	InstructionsImage               InstructionsImageLayout
	FullAOTKind                     SnapshotKind // exact enum value written into AOT snapshot headers
	DataImageAlignment              int64        // Snapshot::DataImage RoundUp alignment on 64-bit AOT
	ImageHeaderSize                 uint64       // exact Image::kHeaderSize in bytes
	ClassIdTagPos                   int          // exact bit position of ClassIdTag in object header tags
	ClassIdTagSize                  int          // exact width of ClassIdTag in object header tags
	RootsHasInitialFieldTable       bool         // Program roots serialize initial_field_table
	RootsHasSharedInitialFieldTable bool         // Program roots serialize shared_initial_field_table
	CompressedPointers              bool         // true if snapshot uses compressed pointers (from features string)
	FillRefUnsigned                 bool         // ≤2.17: ReadRef() = ReadUnsigned(); Function has packed_fields
	CodeIndexOneBased               bool         // ≥2.16: Function.code_index is a 1-based InstructionsTable slot (0=LazyCompile stub). ≤2.15: the serialized scalar is an absolute snapshot Code ref ID.
	PreV32Format                    bool         // ≤3.1: PatchClass has 3 refs; ObjectPool uses v2 type bits
	HasTypeParamClassId             bool         // ≤3.0: TypeParameter has parameterized_class_id scalar
	TypeParamByteScalars            bool         // ≤2.19: TypeParameter base_/index_ are Write<uint8_t> not Write<uint16_t>
	OldTypeScalars                  bool         // ≤2.18: Type fill has type_class_id_(unsigned)+combined(uint8) instead of flags(unsigned)
	TopLevelCid16                   bool         // ≤2.18: kTopLevelCidOffset = 1<<16 (vs 1<<20 in ≥2.19)
	OldPoolFormat                   bool         // ≤3.2: ObjectPool uses 7-bit TypeBits (no SnapshotBehavior)
	PoolTypeSwapped                 bool         // ≥3.2: ObjectPool kImmediate=0,kTaggedObject=1 (was swapped in 3.2.0)
	OldStringFormat                 bool         // ≤2.14: separate OneByteString/TwoByteString clusters with plain length (no <<1|flag)
	SplitCanonical                  bool         // 2.12-2.13: header has separate num_canonical_clusters + num_clusters
	NoCanonicalSetData              bool         // ≤2.12: canonical set rebuilt in-memory post-load, not written to alloc stream (2.13 added CanonicalSetDeserializationCluster/BuildCanonicalSetFromLayout)
	StringRODataPerSubclass         bool         // 2.12: OneByteString/TwoByteString clusters each carry their own ROData deltas directly (no abstract kStringCid cluster combining both — that was added in 2.13's NewClusterForClass dispatch)
	PreCanonicalSplit               bool         // ≤2.10: no canonical/non-canonical distinction at all (single cluster loop, no canonical bit)
	ClassNumRefs                    int          // Class pointer field count override. 0 = default (13). v2.10=16, v2.13=15.
	ClassHasTokenPos                bool         // Class fill includes ReadTokenPosition(token_pos) + ReadTokenPosition(end_token_pos)
	FuncNumRefs                     int          // Function pointer field count override. 0 = default (4). v2.10=7, v2.13=5.
	TypeNumRefs                     int          // Type fill ref count override. 0 = default (3). v2.13=4.
	// TypeClassIdIsRef marks the era where UntaggedType.type_class_id is a
	// COMPRESSED_POINTER_FIELD(SmiPtr, ...) inside the visited range rather
	// than a scalar written after it. That is **v2.10 through v2.14**.
	//
	// It used to say v2.15 as well, and 2.15.0's profile set it. raw_object.h
	// disagrees: at 2.15.0 the field is already
	//
	//	ClassIdTagType type_class_id_;
	//
	// and UntaggedType is byte-identical to 2.16.0's, as is
	// TypeSerializationCluster::WriteFill (WriteFromTo, then
	// WriteUnsigned(type_class_id_), then the combined byte). The off-by-one
	// version cost every Type on 2.15 its class id: the captured ref pointed
	// at the wrong field, so 0 of 2228 resolved through MintValues, against
	// 2254 of 2255 on 2.14.0. See docs/findings-repo/012.
	TypeClassIdIsRef   bool
	FuncTypeNumRefs    int  // FunctionType fill ref count override. 0 = default (6); all supported FunctionType layouts currently consume 6 refs.
	FuncTypeOldScalars bool // FunctionType v2.12-v2.13: 2 scalars (uint8+uint32) rather than the later 3-scalar layout.

	// BuildMode records the build configuration detected from the features
	// string. Its zero value is deliberately BuildUnknown; unreadable or malformed
	// feature evidence must never acquire PRODUCT wire semantics by default.
	//
	// A non-PRODUCT snapshot differs in at least two ways, and the second one
	// is fatal, so do not read a non-zero BuildMode as "supported":
	//
	//  1. THR field offsets come from the !defined(PRODUCT) blocks of
	//     runtime_offsets_extracted.h instead of the defined(PRODUCT) ones.
	//  2. Code objects carry TWO EXTRA refs. From
	//     CodeDeserializationCluster::ReadFill @ 3.9.2:
	//         #if !defined(PRODUCT)
	//           code->untag()->return_address_metadata_ = d->ReadRef();
	//           code->untag()->comments_ = FLAG_code_comments ? d->ReadRef()
	//                                                         : Array::null();
	//         #endif
	//     CodeNumRefs does not account for these, so a non-PRODUCT snapshot
	//     would desync the fill stream at the first Code cluster -- long
	//     before any THR table mattered.
	//
	// Extract sets this and emits a diagnostic when it is not BuildProduct.
	BuildMode BuildMode
	// FuncTypeParamTypesIdx is the ref-loop index (0-based) of
	// FunctionType.parameter_types within its ReadFromTo ref sequence.
	// 0 (the zero value) means "not verified for this version -- don't
	// extract" (index 0 is never legitimate: it's always type_test_stub
	// in every version checked). Verified directly against dart-lang/sdk
	// source (runtime/vm/raw_object.h's UntaggedFunctionType/
	// UntaggedAbstractType field declarations) at each version tag listed
	// below, not inferred: the ref order changed exactly once, between
	// the 3.0.5 and 3.1.0 tags, when `hash` moved from being
	// FunctionType's own last field to AbstractType's base-class field
	// (making room for it right after type_test_stub instead of at the
	// end). Before that: type_test_stub(0), type_parameters(1),
	// result_type(2), parameter_types(3), named_parameter_names(4),
	// hash(5) -- so idx=3. After: type_test_stub(0), hash(1) [now in
	// base], type_parameters(2), result_type(3), parameter_types(4),
	// named_parameter_names(5) -- so idx=4. Confirmed at 2.12.0, 2.13.0,
	// 2.14.0, 2.15.0, 2.16.0, 2.17.6, 2.18.0, 2.19.0, 3.0.5 (all idx=3)
	// and 3.1.0, 3.2.5, 3.3.0, 3.4.3, 3.5.0, 3.6.2, 3.7.0, 3.8.1, 3.9.2,
	// 3.10.7, 3.11.0, 3.12.2 (all idx=4). 2.10.0 was NOT checked (its
	// raw_object.h isn't at the same repo path at that tag) -- left at 0
	// (unverified) rather than guessed.
	FuncTypeParamTypesIdx int
	TypeParamNumRefs      int  // TypeParameter fill ref count override. 0 = default (3). v2.10-v2.13=5; v2.14+ consume the default 3 refs.
	TypeParamWideScalars  bool // TypeParameter v2.12-v2.13: base/index use Read<uint16_t> rather than the v2.14-v2.19 uint8 form.
	TypeRefNumRefs        int  // TypeRef fill ref count override. 0 = default (2). All versions use 2 refs (type_test_stub + type).
	CodeNumRefs           int  // Code fill ref count override. 0 = default (6). v2.10-v2.15=7 (includes compressed_stackmaps).
	CodeTextOffsetDelta   bool // Code ReadInstructions reads extra ReadUnsigned (text_offset_delta). v2.10-v2.15.
	CodeStateBitsAfterRef int  // Code interleaved state_bits_ position: N=read after first N refs. v2.13=1 (1 ref → state_bits → 6 refs); 0 means use the non-interleaved path.
	CodeStateBitsAtEnd    bool // Code state_bits_ Read<int32_t> after ALL refs (no discarded check). v2.10 and v2.12.

	// ClassAllocFixedSize marks the Dart 3.13.0+ Class alloc, which is a plain
	// ReadAllocFixedSize: ONE ReadUnsigned(count) and nothing else. Up to
	// 3.12.2 it was predefined_count + per-class ReadCid() + new_count, so a
	// reader using the old shape over-consumes the alloc stream and every
	// later cluster -- and the fill section start -- lands at the wrong offset.
	// SDK-verified: ClassDeserializationCluster::ReadAlloc @3.13.0 vs @3.12.2.
	ClassAllocFixedSize bool

	// CodeFillHasIndexRefs marks the Dart 3.13.0+ Code fill, which begins with
	// two extra ReadRefId values before the per-Code loop:
	// set_lazy_compile_index and set_unknown_dart_code_index.
	// SDK-verified: CodeDeserializationCluster::ReadFill @3.13.0.
	CodeFillHasIndexRefs bool

	// ClosureAllocHasLength marks the Dart 3.13.0+ Closure alloc, which reads
	// a per-object length after the count (Closure::InstanceSize(length))
	// instead of being a plain ReadAllocFixedSize. Same shape as
	// CompressedStackMaps / LocalVarDescriptors.
	// SDK-verified: ClosureDeserializationCluster::ReadAlloc @3.13.0 vs @3.12.2.
	ClosureAllocHasLength bool
	ClosureDataNumRefs    int  // ClosureData ref count override after 2.13. 2.10-2.13 are selected exactly by version in specClosureData.
	TypeHasTokenPos       bool // Type/TypeParameter fill has ReadTokenPosition scalar. v2.10 only.
	ScriptHasLineCol      bool // Script fill has line_offset + col_offset scalars before kernel_script_index. v2.10, v2.13.
	ScriptHasFlags        bool // Script fill has flags (uint8) scalar between col_offset and kernel_script_index. v2.10 only.

	// ObjectStoreAOTFieldCount is the exact number of ObjectStore fields
	// serialized as plain refs in the isolate snapshot's roots section
	// for a kFullAOT snapshot -- i.e. the count of OBJECT_STORE_FIELD_LIST
	// entries from `list_class` through the field to_snapshot(kFullAOT)
	// returns (`slow_tts_stub` in every version checked so far), verified
	// directly against dart-lang/sdk's runtime/vm/object_store.h at the
	// exact release tag (not inferred, not extrapolated from a nearby
	// version -- ARCHITECTURE.md's own prior investigation flagged this
	// count as changing release to release, confirmed true across every
	// 3.x version checked: 229 (3.5.0), 232 (3.2.5/3.4.3), 233 (3.1.0/
	// 3.3.0/3.6.2/3.7.0/3.8.1), 235 (3.9.2), 241 (3.10.7), 242 (3.11.0),
	// 244 (3.12.2). Real-binary end-to-end verified (zero unresolved
	// dispatch-table entries) for 3.7.0, 3.9.2, 3.10.7, 3.11.0, 3.12.2;
	// the rest (3.1.0-3.6.2, 3.8.1) are source-verified only -- no real
	// sample binary was available to also empirically confirm those.
	// 0 (the zero value) means "not counted for this version --
	// ParseDispatchTable refuses to guess." This is the field
	// immediately after ObjectStore's `from()` pointer
	// (`&list_class_`) through `to_snapshot(Snapshot::kFullAOT)`
	// (`&slow_tts_stub_`) inclusive; see cmd/aotopsy's own
	// dispatch-table plumbing for how this is consumed.
	ObjectStoreAOTFieldCount int

	// RootsPrefixRefCount is how many plain refs the roots section carries
	// BEFORE the ObjectStore fields.
	//
	// It was 0 through 3.12.2. Dart 3.13.0 moved the VM's bootstrap objects
	// out of `vm_isolate_snapshot_object_table` and into a `Roots` struct,
	// and ProgramDeserializationRoots::ReadRoots now opens with, under
	// `Snapshot::IncludesCode(kind)` -- true for kFullAOT:
	//
	//	for (ptr = roots->from();   ptr <= roots->to();   ptr++)   *ptr = d->ReadRef();
	//	for (h   = roots->fromh();  h   <= roots->toh();  h++)     h->ptr = d->ReadRef();
	//	for (ptr = roots->fromah(); ptr <= roots->toah(); ptr++)   *ptr = d->ReadRef();
	//	for (cid = kObjectCid;   cid < kInstanceCid;       cid++) { if (IsAbsentCid(cid)) continue; ... ReadRef(); }
	//	for (cid = kInstanceCid; cid < kNumPredefinedCids; cid++) { if (IsAbsentCid(cid)) continue; ... ReadRef(); }
	//
	// (app_snapshot.cc @3.13.0; the serializer writes the same five loops in
	// the same order.) Skipping them desynchronises the stream before the
	// ObjectStore fields are even reached: on the 3.13.0 arm64 sample
	// initial_field_table read back as 6936 entries against 552 on 3.12.2,
	// and the dispatch table came out with 31 entries instead of ~29600 --
	// which left 80 % of BLR sites unresolved, the worst in the corpus.
	//
	// The count is a per-version SDK fact, exactly like
	// ObjectStoreAOTFieldCount, because every term in it can move:
	//
	//	sizeof(Raw)/sizeof(ObjectPtr)       = |RAW_ROOTS_LIST| + 35 + 4 + 256
	//	sizeof(Internal)/sizeof(VMHandle)   = |HANDLE_ROOTS_LIST|
	//	                                      + (kNumPredefinedSymbols + 256)
	//	                                      + kNumStubEntries
	//	sizeof(Api)/sizeof(ObjectPtr)       = |API_HANDLE_ROOTS_LIST|
	//	class table                         = (kNumPredefinedCids - kObjectCid)
	//	                                      - |IsAbsentCid|
	//
	// At 3.13.0 (roots.h, symbol_list.h, stub_code_list.h, class_id.h,
	// app_snapshot.cc for IsAbsentCid):
	// 7+35+4+256 = 302, 63+(557+256)+173 = 1049, 6, and (176-4)-11 = 161,
	// so 1518. Note kNumStubEntries is 173 and not 164: VM_STUB_CODE_LIST
	// pulls in PROBE_POINT_STUBS_LIST (defined on ONE line, which a
	// line-oriented regex misses) and VM_TYPE_TESTING_STUB_CODE_LIST.
	//
	// 1518 was also confirmed independently against the binary: it is the
	// only prefix in [0,3000] for which the whole roots structure replays to
	// exactly IsolateHeader.TotalSize.
	RootsPrefixRefCount int
}

// CIDTable maps predefined type names to class IDs for a specific Dart version.
// Only types with non-trivial alloc behavior need entries.
type CIDTable struct {
	String              int
	OneByteString       int
	TwoByteString       int
	Mint                int
	Double              int
	Float32x4           int
	Int32x4             int
	Float64x2           int
	Array               int
	ImmutableArray      int
	WeakArray           int
	TypeArguments       int
	Type                int
	FunctionType        int
	RecordType          int // 0 if not present (v2.17.6)
	TypeParameter       int
	Class               int
	Function            int
	ClosureData         int
	SignatureData       int // 0 if not present (v2.10 only, removed in v2.13)
	RedirectionData     int // 0 if not present (v2.10 only)
	Field               int
	Script              int
	Library             int
	Namespace           int
	KernelProgramInfo   int
	Code                int
	ObjectPool          int
	PcDescriptors       int
	CodeSourceMap       int
	CompressedStackMaps int
	// LocalVarDescriptors is zero for every version before 3.13.0, and that
	// is not an omission: kLocalVarDescriptorsCid does not appear anywhere in
	// app_snapshot.cc at 3.12.2 (0 occurrences), so no such cluster is ever
	// written. In 3.13.0 it gains both a serialization and a deserialization
	// cluster, sitting next to PcDescriptors / CodeSourceMap /
	// CompressedStackMaps in both switches, and a real snapshot contains one
	// (the empty singleton, count=1) because 3.13.0 shrank the base-object set
	// to 7 Roots entries -- objects that used to arrive as base objects now
	// have to be serialized.
	//
	// Leaving it unmapped made the cluster fall through to the count-only
	// alloc path, consuming one value where the SDK writes two (count, then a
	// length per object). That single missing read shifted every following
	// cluster tag, which is why a 3.13.0 snapshot decoded two clusters with
	// CID 0xFFFFF and then failed in fill.
	LocalVarDescriptors int

	// ApiError / UnwindError gain deserialization clusters in Dart 3.13.0
	// (absent from app_snapshot.cc@3.12.2). Both alloc as ReadAllocFixedSize
	// and fill as ReadFromTo over a single `message` ref; UnwindError reads
	// one extra Read<bool>(is_user_initiated). Zero for older versions.
	ApiError                   int
	UnwindError                int
	ExceptionHandlers          int
	Context                    int
	ContextScope               int
	ParameterTypeCheck         int // 0 if not present (v2.10 only)
	UnlinkedCall               int
	ICData                     int
	MegamorphicCache           int
	SubtypeTestCache           int
	LoadingUnit                int
	Closure                    int
	GrowableObjectArray        int
	Map                        int
	ConstMap                   int
	Set                        int
	ConstSet                   int
	WeakProperty               int
	WeakReference              int
	RegExp                     int
	Record                     int // 0 if not present (v2.17.6)
	TypedData                  int
	TypedDataView              int
	ExternalTypedData          int
	Instance                   int
	Sentinel                   int
	SingleTargetCache          int
	MonomorphicSmiableCall     int
	CallSiteData               int
	WeakSerializationReference int
	LanguageError              int
	UnhandledException         int
	PatchClass                 int
	FfiTrampolineData          int
	TypeParameters             int
	LibraryPrefix              int
	SendPort                   int
	StackTrace                 int
	SuspendState               int // 0 if not present (v2.17.6)
	TypeRef                    int // 0 if not present (removed in v3.x)
	Capability                 int
	ReceivePort                int
	FutureOr                   int
	TransferableTypedData      int
	UserTag                    int

	// TypedData internal CID range. CIDs from TypedDataInt8ArrayCid to
	// ByteDataViewCid-1 are internal typed data classes (stride = TypedDataCidStride).
	// IsTypedDataClassId(cid) = cid >= TypedDataInt8ArrayCid &&
	//   cid < ByteDataViewCid && (cid - TypedDataInt8ArrayCid) % TypedDataCidStride == 0
	TypedDataInt8ArrayCid int // first internal TypedData CID
	ByteDataViewCid       int // end marker (exclusive)
	TypedDataCidStride    int // 3 for v2.17.6, 4 for v3.x
	// FfiMarkerFirstCid..FfiMarkerLastCid is the contiguous
	// CLASS_LIST_FFI_TYPE_MARKER range. NewClusterForClass routes exactly these
	// predefined FFI CIDs through InstanceSerializationCluster; the neighboring
	// FfiNativeFunction/FfiNativeType/FfiStruct (and older Pointer/
	// DynamicLibrary entries) do not take that path.
	//
	// 0/0 before Dart 2.16.0: the serializer has no such case there, so a
	// cluster under these CIDs is malformed and must not be accepted as an
	// Instance. TestCIDTablesMatchSDK derives both the presence of the case and
	// the range from each tag.
	FfiMarkerFirstCid int
	FfiMarkerLastCid  int

	// DeltaEncodedTypedData pseudo-CID (kNativePointer = 1 in all versions).
	NativePointerCid int

	// NumPredefinedCids is the count of VM-internal class IDs. CIDs >= this
	// value are app-defined Instance subclasses. CIDs below it are accepted only
	// when their exact Full-AOT cluster shape is explicitly modeled; there is no
	// generic count-only fallback for unknown predefined CIDs.
	NumPredefinedCids int
}

// Known snapshot compatibility hashes mapped to verified parser profiles.
//
// This is deliberately not an exact SDK-version identity table: Dart derives
// SnapshotString from snapshot-format source files, so multiple patch/dev
// releases can legitimately share one parser shape while carrying distinct
// hashes. Each target value names the exact profile whose CID/root/fill/image
// dimensions have been verified for that compatibility family.
//
// Canonical hashes for every supported exact local tag were independently
// re-derived with that tag's tools/make_version.py VM_SNAPSHOT_FILES algorithm.
// Extra hashes are retained only where a concrete Flutter/Dart build is named;
// speculative "approximate"/"likely" mappings are not parser evidence.
var knownHashes = map[string]string{
	// Dart 2.17.x (Flutter 2.17.0 stable + betas)
	"1441d6b13b8623fa7fbf61433abebd31": "2.17.6", // Flutter 2.17.0.stable
	// Dart 3.0.x (Flutter 3.10.x)
	"aa64af18e7d086041ac127cc4bc50c5e": "3.0.5", // Dart 3.0.0-3.0.2; same VM_SNAPSHOT_FILES family except raw_object.h tags() accessor
	"90b56a561f70cd55e972cb49b79b3d8b": "3.0.5", // Flutter 3.10.4
	// Dart 3.1.x (Flutter 3.13.x)
	"7dbbeeb8ef7b91338640dca3927636de": "3.1.0", // Flutter 3.13.9
	// Dart 3.2.x (Flutter 3.16.x)
	"f71c76320d35b65f1164dbaa6d95fe09": "3.2.5", // Flutter 3.16.0
	// Dart 3.3.x (Flutter 3.19.x)
	"ee1eb666c76a5cb7746faf39d0b97547": "3.3.0", // Flutter 3.19.0
	// Dart 3.4.x (Flutter 3.22.x)
	"d20a1be77c3d3c41b2a5accaee1ce549": "3.4.3", // Flutter 3.22.0
	// Dart 3.5.x (Flutter 3.24.x)
	"80a49c7111088100a233b2ae788e1f48": "3.5.0", // Flutter 3.24.0
	// Dart 3.6.x (Flutter 3.27.x)
	"f956f595844a2f845a55707faaaa51e4": "3.6.2", // Flutter 3.27.1
	// Dart 3.7.x (Flutter 3.29.x)
	"d91c0e6f35f0eb2e44124e8f42aa44a7": "3.7.0", // Flutter 3.29.3
	// Dart 3.8.x (Flutter 3.32.x)
	"830f4f59e7969c70b595182826435c19": "3.8.1", // Flutter 3.32.0
	// Dart 3.9.x (Flutter 3.35.x)
	"97ff04a728735e6b6b098bdf983faaba": "3.9.2", // Flutter 3.35.1
	// Dart 3.10.x (Flutter 3.38.x)
	"1ce86630892e2dca9a8543fdb8ed8e22": "3.10.7", // Flutter 3.38.4
	// Dart 3.11.x (Flutter 3.41.x)
	"78da37fed6bf1489361a312568249f3f": "3.11.0", // Flutter 3.41.1
	// The 3.12 line ships THREE distinct snapshot hashes, all one format.
	//
	// There used to be a separate "3.12.0-dev" profile for the first of them,
	// carrying the note "not verified against a real compiled sample" and a
	// claim that "real, source-verified format changes landed between" it and
	// 3.12.2. Both halves were wrong, and the profile was byte-for-byte
	// identical to 3.12.2 in every field, so it only ever duplicated it.
	//
	// Settled by building Dart 3.12.0 stable (Flutter 3.44.0) here: its
	// snapshot parses end to end under the 3.12.2 profile -- 29576 dispatch
	// entries, 8368 functions, 1925 classes, ground-truth symbols resolving --
	// on both architectures. A pre-release from the same line has no reason to
	// differ from the stable it became, and nothing measurable says it does.
	//
	// All three now map to one profile. The unknown-hash fallback is what made
	// this worth chasing: it hands back a 3.9.2-shaped placeholder, under which
	// 3.12.0 died in the String cluster rather than being reported unsupported.
	"41be3daaabd524b8aa7423bc24584957": "3.12.2", // Flutter 3.44.0 (Dart 3.12.0)
	"ace654289f5abc240509fc941453ebc5": "3.12.2", // Flutter 3.44.7 (Dart 3.12.2)

	// Dart 3.13.0 -- the unified-snapshot format. Taken from a libapp.so built
	// locally with Flutter 3.47.0 stable (whose dart_sdk_version is 3.13.0 per
	// the official releases_linux.json), not from a hash list, so it is a
	// measured value rather than a transcribed one.
	"0451907c2eaa8467e848c0067bfe8ed4": "3.13.0", // Flutter 3.47.0

	// Dart 2.14-2.19 (supported with CID tables)
	"9cf77f4405212c45daf608e1cd646852": "2.14.0", // Flutter 2.5.0
	"d56742caf7b3b3f4bd2df93a9bbb5503": "2.16.0", // Flutter 2.16.0-134.1.beta
	// Flutter 2.8.0 ships Dart 2.15.0, not 2.16.0 -- the comment recorded the
	// Flutter version correctly and the Dart version wrongly. Proven by
	// building this exact hash: flutter_for_dart_2.15.0 is Flutter 2.8.0, its
	// bin/cache/dart-sdk/version reads 2.15.0, and its snapshot hash is this
	// one. The mistake made every Dart 2.15.0 binary parse with the 2.16.0
	// profile, which has a 6-field header where 2.15.0 has 5.
	"adf563436d12ba0d50ea5beb7f3be1bb": "2.15.0", // Flutter 2.8.0
	"b0e899ec5a90e4661501f0b69e9dd70f": "2.18.0", // Flutter 3.3.0-0.1.pre
	"b6d0a1f034d158b0d37b51d559379697": "2.18.0", // Flutter 3.3.10
	"adb4292f3ec25074ca70abcd2d5c7251": "2.19.0", // Flutter 3.7.12
	"501ef5cbd64ca70b6b42672346af6a8a": "2.19.0", // Flutter 3.7.0

	// Dart 2.10-2.13 (supported with CID tables, int32 tag format)
	"8ee4ef7a67df9845fba331734198a953": "2.10.0", // Flutter 1.22.6
	"5b97292b25f0a715613b7a28e0734f77": "2.12.0", // Flutter 2.0.0
	"e4a09dbf2bb120fe4674e0576617a0dc": "2.13.0", // Flutter 2.2.0
	"34f6eec64e9371856eaaa278ccf56538": "2.13.0", // Flutter 2.2.0-10.1.pre
	"7a5b240780941844bae88eca5dbaa7b8": "2.13.0", // Flutter 2.3.0
}

// CID tables generated from dartsdk/v*/runtime/vm/class_id.h.
// Only versions with different CID numbering need separate tables.

// v2.10.0 CIDs: pre-FunctionType split, has Bytecode/SignatureData/RedirectionData/ParameterTypeCheck/WASM.
// No TypeParameters, no Sentinel, no InstructionsTable, no FunctionType, no WeakReference,
// no SuspendState, no Record, no RecordType, no LinkedHashSet, no NativePointer. TypedData stride 3.
// Tag format: raw int32 CID. Single cluster loop (no canonical split).
var cidsV210 = CIDTable{
	Class: 4, PatchClass: 5, Function: 6,
	ClosureData: 7, SignatureData: 8, RedirectionData: 9, FfiTrampolineData: 10, Field: 11, Script: 12,
	Library: 13, Namespace: 14, KernelProgramInfo: 15,
	WeakSerializationReference: 77,
	// No TypeParameters in v2.10
	Code: 16, ObjectPool: 20, PcDescriptors: 21, CodeSourceMap: 22,
	CompressedStackMaps: 23, ExceptionHandlers: 25, Context: 26,
	ContextScope: 27, ParameterTypeCheck: 28, SingleTargetCache: 29, UnlinkedCall: 30,
	MonomorphicSmiableCall: 31, CallSiteData: 32,
	ICData: 33, MegamorphicCache: 34, SubtypeTestCache: 35,
	LoadingUnit: 36, LanguageError: 39, UnhandledException: 40,
	Instance: 42, LibraryPrefix: 43, TypeArguments: 44,
	Type: 46, TypeRef: 47, TypeParameter: 48,
	// No FunctionType in v2.10 (FunctionType was added in 2.13)
	Closure: 49, Mint: 53, Double: 54,
	GrowableObjectArray: 56,
	Float32x4:           57, Int32x4: 58, Float64x2: 59,
	TypedData: 61, ExternalTypedData: 62, TypedDataView: 63,
	Capability: 66, ReceivePort: 67, SendPort: 68,
	StackTrace: 69, RegExp: 70, WeakProperty: 71,
	FutureOr: 74, UserTag: 75, TransferableTypedData: 76,
	// v2.10 has LinkedHashMap only (no Set, no Immutable variants)
	Map:   73,
	Array: 78, ImmutableArray: 79,
	String: 80, OneByteString: 81, TwoByteString: 82,
	// TypedData internals: stride 3 (no UnmodifiableView)
	TypedDataInt8ArrayCid: 108, ByteDataViewCid: 150, TypedDataCidStride: 3,
	NumPredefinedCids: 156,
}

// v2.12.0 CIDs: verified directly against dart-lang/sdk class_id.h at tag 2.12.0
// (commit fbb53ae5f10eda0c36463bf2a0e9c2d74e002f84). Already has FunctionType (like
// 2.13.0) but WeakSerializationReference still sits at the END of the predefined
// class list (right before Array), not right after KernelProgramInfo like 2.13.0 —
// Dart moved it up in the 2.12->2.13 transition. Every CID from Code onward is
// exactly 1 less than the matching 2.13.0 CID (2.13.0 inserted one new predefined
// class between KernelProgramInfo and Code). No TypeParameters, no Sentinel, no
// WeakReference, no SuspendState, no Record, no RecordType, no LinkedHashSet.
// No NativePointer. TypedData stride 3.
// Tag format: raw int32 CID. Split canonical/non-canonical cluster loops (like 2.13.0).
var cidsV212 = CIDTable{
	Class: 4, PatchClass: 5, Function: 6,
	ClosureData: 7, FfiTrampolineData: 8, Field: 9, Script: 10,
	Library: 11, Namespace: 12, KernelProgramInfo: 13,
	// No TypeParameters in v2.12
	Code: 14, ObjectPool: 17, PcDescriptors: 18, CodeSourceMap: 19,
	CompressedStackMaps: 20, ExceptionHandlers: 22, Context: 23,
	ContextScope: 24, SingleTargetCache: 25, UnlinkedCall: 26,
	MonomorphicSmiableCall: 27, CallSiteData: 28,
	ICData: 29, MegamorphicCache: 30, SubtypeTestCache: 31,
	LoadingUnit: 32, LanguageError: 35, UnhandledException: 36,
	Instance: 38, LibraryPrefix: 39, TypeArguments: 40,
	Type: 42, FunctionType: 43, TypeRef: 44, TypeParameter: 45,
	Closure: 46, Mint: 50, Double: 51,
	GrowableObjectArray: 53,
	Float32x4:           54, Int32x4: 55, Float64x2: 56,
	TypedData: 58, ExternalTypedData: 59, TypedDataView: 60,
	Capability: 63, ReceivePort: 64, SendPort: 65,
	StackTrace: 66, RegExp: 67, WeakProperty: 68,
	FutureOr: 71, UserTag: 72, TransferableTypedData: 73,
	// v2.12 has LinkedHashMap only (no Set, no Immutable variants)
	Map: 70,
	// WeakSerializationReference is still at the END of the list here (unlike
	// 2.13.0 where it moved to right after KernelProgramInfo).
	WeakSerializationReference: 74,
	Array:                      75, ImmutableArray: 76,
	String: 77, OneByteString: 78, TwoByteString: 79,
	// TypedData internals: stride 3 (no UnmodifiableView)
	TypedDataInt8ArrayCid: 100, ByteDataViewCid: 142, TypedDataCidStride: 3,
	NumPredefinedCids: 148,
}

// v2.13.0 CIDs: adds FunctionType, removes SignatureData/RedirectionData/Bytecode/ParameterTypeCheck/WASM.
// No TypeParameters, no Sentinel, no WeakReference, no SuspendState, no Record, no RecordType.
// No LinkedHashSet. No NativePointer. TypedData stride 3.
// Tag format: raw int32 CID. Split canonical/non-canonical cluster loops.
var cidsV213 = CIDTable{
	Class: 4, PatchClass: 5, Function: 6,
	ClosureData: 7, FfiTrampolineData: 8, Field: 9, Script: 10,
	Library: 11, Namespace: 12, KernelProgramInfo: 13,
	WeakSerializationReference: 14,
	// No TypeParameters in v2.13
	Code: 15, ObjectPool: 18, PcDescriptors: 19, CodeSourceMap: 20,
	CompressedStackMaps: 21, ExceptionHandlers: 23, Context: 24,
	ContextScope: 25, SingleTargetCache: 26, UnlinkedCall: 27,
	MonomorphicSmiableCall: 28, CallSiteData: 29,
	ICData: 30, MegamorphicCache: 31, SubtypeTestCache: 32,
	LoadingUnit: 33, LanguageError: 36, UnhandledException: 37,
	Instance: 39, LibraryPrefix: 40, TypeArguments: 41,
	Type: 43, FunctionType: 44, TypeRef: 45, TypeParameter: 46,
	Closure: 47, Mint: 51, Double: 52,
	GrowableObjectArray: 54,
	Float32x4:           55, Int32x4: 56, Float64x2: 57,
	TypedData: 59, ExternalTypedData: 60, TypedDataView: 61,
	Capability: 64, ReceivePort: 65, SendPort: 66,
	StackTrace: 67, RegExp: 68, WeakProperty: 69,
	FutureOr: 72, UserTag: 73, TransferableTypedData: 74,
	// v2.13 has LinkedHashMap only (no Set, no Immutable variants)
	Map:   71,
	Array: 75, ImmutableArray: 76,
	String: 77, OneByteString: 78, TwoByteString: 79,
	// TypedData internals: stride 3 (no UnmodifiableView)
	TypedDataInt8ArrayCid: 100, ByteDataViewCid: 142, TypedDataCidStride: 3,
	NumPredefinedCids: 148,
}

// v2.14.0 CIDs: adds TypeParameters, InstructionsTable, Sentinel, LinkedHashSet
// vs 2.13.0. No WeakArray, WeakReference, SuspendState, Record, RecordType.
// No ImmutableLinkedHashMap/Set (ConstMap/ConstSet). No NativePointer. TypedData stride 3.
var cidsV214 = CIDTable{
	Class: 4, PatchClass: 5, Function: 6, TypeParameters: 7,
	ClosureData: 8, FfiTrampolineData: 9, Field: 10, Script: 11,
	Library: 12, Namespace: 13, KernelProgramInfo: 14,
	WeakSerializationReference: 15,
	// No WeakArray in v2.14
	Code: 16, ObjectPool: 20, PcDescriptors: 21, CodeSourceMap: 22,
	CompressedStackMaps: 23, ExceptionHandlers: 25, Context: 26,
	ContextScope: 27, Sentinel: 28, SingleTargetCache: 29,
	UnlinkedCall: 30, MonomorphicSmiableCall: 31, CallSiteData: 32,
	ICData: 33, MegamorphicCache: 34, SubtypeTestCache: 35,
	LoadingUnit: 36, LanguageError: 39, UnhandledException: 40,
	Instance: 42, LibraryPrefix: 43, TypeArguments: 44,
	Type: 46, FunctionType: 47, TypeRef: 48, TypeParameter: 49,
	Closure: 50, Mint: 54, Double: 55,
	Float32x4: 58, Int32x4: 59, Float64x2: 60,
	TypedData: 62, ExternalTypedData: 63, TypedDataView: 64,
	Capability: 67, ReceivePort: 68, SendPort: 69,
	StackTrace: 70, RegExp: 71, WeakProperty: 72,
	FutureOr: 74, UserTag: 75, TransferableTypedData: 76,
	// v2.14 has LinkedHashMap/Set but no Immutable variants
	Map: 77, Set: 78,
	Array: 79, ImmutableArray: 80, GrowableObjectArray: 57,
	String: 81, OneByteString: 82, TwoByteString: 83,
	// TypedData internals: stride 3 (no UnmodifiableView)
	TypedDataInt8ArrayCid: 104, ByteDataViewCid: 146, TypedDataCidStride: 3,
	NumPredefinedCids: 152,
}

// v2.15.0 CIDs: NativePointer(1) inserted at CID 1, and GrowableObjectArray
// moved from CLASS_LIST_INSTANCE_SINGLETONS to CLASS_LIST_ARRAYS (after ImmutableArray).
// Net effect: Class..Bool get +1 shift (NativePointer), Float32x4..TransferableTypedData
// get +0 (NativePointer +1, GOA removal -1), Map/Set/Array/ImmutableArray get +0,
// GOA moves from CID 57 to CID 81, String and beyond get +1.
// No ImmutableLinkedHashMap/Set (those were added in v2.16).
// The exact 2.15.0 SDK and corpus samples use this layout; SDK drift gates
// derive the CID table independently from class_id.h.
var cidsV215 = CIDTable{
	Class: 5, PatchClass: 6, Function: 7, TypeParameters: 8,
	ClosureData: 9, FfiTrampolineData: 10, Field: 11, Script: 12,
	Library: 13, Namespace: 14, KernelProgramInfo: 15,
	WeakSerializationReference: 16,
	// No WeakArray in v2.15
	Code: 17, ObjectPool: 21, PcDescriptors: 22, CodeSourceMap: 23,
	CompressedStackMaps: 24, ExceptionHandlers: 26, Context: 27,
	ContextScope: 28, Sentinel: 29, SingleTargetCache: 30,
	UnlinkedCall: 31, MonomorphicSmiableCall: 32, CallSiteData: 33,
	ICData: 34, MegamorphicCache: 35, SubtypeTestCache: 36,
	LoadingUnit: 37, LanguageError: 40, UnhandledException: 41,
	Instance: 43, LibraryPrefix: 44, TypeArguments: 45,
	Type: 47, FunctionType: 48, TypeRef: 49, TypeParameter: 50,
	Closure: 51, Mint: 55, Double: 56,
	// v2.15 pre-release: NativePointer(CID 1) inserts +1 for Class..Bool,
	// but GrowableObjectArray moved from INSTANCE_SINGLETONS to ARRAYS group
	// (after ImmutableArray), so classes from Float32x4..TransferableTypedData
	// get net +0 shift (+1 NativePointer, -1 GOA removal).
	// Map/Set/Array/ImmutableArray also net +0. GOA moves to CID 81.
	// String and beyond get +1 (NativePointer +1, GOA removal -1, GOA insertion +1).
	Float32x4: 58, Int32x4: 59, Float64x2: 60,
	TypedData: 62, ExternalTypedData: 63, TypedDataView: 64,
	Capability: 67, ReceivePort: 68, SendPort: 69,
	StackTrace: 70, RegExp: 71, WeakProperty: 72,
	FutureOr: 74, UserTag: 75, TransferableTypedData: 76,
	// v2.15 has LinkedHashMap + ImmutableLinkedHashMap, LinkedHashSet + ImmutableLinkedHashSet
	Map: 77, ConstMap: 78, Set: 79, ConstSet: 80,
	Array: 81, ImmutableArray: 82, GrowableObjectArray: 83,
	String: 84, OneByteString: 85, TwoByteString: 86,
	// TypedData internals: stride 3 (no UnmodifiableView)
	TypedDataInt8ArrayCid: 106, ByteDataViewCid: 148, TypedDataCidStride: 3,
	NativePointerCid: 1, NumPredefinedCids: 154,
}

// v2.16.0 CIDs: adds NativePointer(1), ImmutableLinkedHashMap/Set (ConstMap/ConstSet),
// FfiBool, GrowableObjectArray moved to arrays group. TypedData stride 3.
var cidsV216 = CIDTable{
	Class: 5, PatchClass: 6, Function: 7, TypeParameters: 8,
	ClosureData: 9, FfiTrampolineData: 10, Field: 11, Script: 12,
	Library: 13, Namespace: 14, KernelProgramInfo: 15,
	WeakSerializationReference: 16,
	// No WeakArray in v2.16
	Code: 17, ObjectPool: 21, PcDescriptors: 22, CodeSourceMap: 23,
	CompressedStackMaps: 24, ExceptionHandlers: 26, Context: 27,
	ContextScope: 28, Sentinel: 29, SingleTargetCache: 30,
	UnlinkedCall: 31, MonomorphicSmiableCall: 32, CallSiteData: 33,
	ICData: 34, MegamorphicCache: 35, SubtypeTestCache: 36,
	LoadingUnit: 37, LanguageError: 40, UnhandledException: 41,
	Instance: 43, LibraryPrefix: 44, TypeArguments: 45,
	Type: 47, FunctionType: 48, TypeRef: 49, TypeParameter: 50,
	Closure: 51, Mint: 55, Double: 56,
	Float32x4: 58, Int32x4: 59, Float64x2: 60,
	TypedData: 62, ExternalTypedData: 63, TypedDataView: 64,
	Capability: 67, ReceivePort: 68, SendPort: 69,
	StackTrace: 70, RegExp: 71, WeakProperty: 72,
	FutureOr: 74, UserTag: 75, TransferableTypedData: 76,
	// v2.16 has LinkedHashMap + ImmutableLinkedHashMap, LinkedHashSet + ImmutableLinkedHashSet
	Map: 77, ConstMap: 78, Set: 79, ConstSet: 80,
	Array: 81, ImmutableArray: 82, GrowableObjectArray: 83,
	String: 84, OneByteString: 85, TwoByteString: 86,
	// TypedData internals: stride 3 (no UnmodifiableView)
	TypedDataInt8ArrayCid: 106, ByteDataViewCid: 148, TypedDataCidStride: 3,
	FfiMarkerFirstCid: 90, FfiMarkerLastCid: 103,
	NativePointerCid: 1, NumPredefinedCids: 154,
}

var cidsV217 = CIDTable{
	Class: 5, PatchClass: 6, Function: 7, TypeParameters: 8,
	ClosureData: 9, FfiTrampolineData: 10, Field: 11, Script: 12,
	Library: 13, Namespace: 14, KernelProgramInfo: 15,
	WeakSerializationReference: 16,
	// WeakArray not present in v2.17.6 CLASS_LIST_INTERNAL_ONLY
	Code: 17, ObjectPool: 21, PcDescriptors: 22, CodeSourceMap: 23,
	CompressedStackMaps: 24, ExceptionHandlers: 26, Context: 27,
	ContextScope: 28, Sentinel: 29, SingleTargetCache: 30,
	UnlinkedCall: 31, MonomorphicSmiableCall: 32, CallSiteData: 33,
	ICData: 34, MegamorphicCache: 35, SubtypeTestCache: 36,
	LoadingUnit: 37, LanguageError: 40, UnhandledException: 41,
	Instance: 43, LibraryPrefix: 44, TypeArguments: 45,
	Type: 47, FunctionType: 52, TypeParameter: 54,
	TypeRef: 53,
	Closure: 55, Mint: 59, Double: 60,
	Float32x4: 62, Int32x4: 63, Float64x2: 64,
	TypedData: 66, ExternalTypedData: 67, TypedDataView: 68,
	Capability: 71, ReceivePort: 72, SendPort: 73,
	StackTrace: 74, RegExp: 75, WeakProperty: 76, WeakReference: 77,
	FutureOr: 79, UserTag: 80, TransferableTypedData: 81,
	// v2.17.6 uses LinkedHashMap/LinkedHashSet instead of Map/Set
	Map: 82, ConstMap: 83, Set: 84, ConstSet: 85,
	Array: 86, ImmutableArray: 87, GrowableObjectArray: 88,
	String: 89, OneByteString: 90, TwoByteString: 91,
	// TypedData internals: stride 3 (no UnmodifiableView in v2.17.6)
	TypedDataInt8ArrayCid: 110, ByteDataViewCid: 152, TypedDataCidStride: 3,
	FfiMarkerFirstCid: 95, FfiMarkerLastCid: 107,
	NativePointerCid: 1, NumPredefinedCids: 158,
}

// v2.18.0 CIDs: identical to v2.17.6 except SuspendState added after StackTrace,
// shifting RegExp and all subsequent CIDs by +1. No WeakArray. TypedData stride 3.
var cidsV218 = CIDTable{
	Class: 5, PatchClass: 6, Function: 7, TypeParameters: 8,
	ClosureData: 9, FfiTrampolineData: 10, Field: 11, Script: 12,
	Library: 13, Namespace: 14, KernelProgramInfo: 15,
	WeakSerializationReference: 16,
	// No WeakArray in v2.18
	Code: 17, ObjectPool: 21, PcDescriptors: 22, CodeSourceMap: 23,
	CompressedStackMaps: 24, ExceptionHandlers: 26, Context: 27,
	ContextScope: 28, Sentinel: 29, SingleTargetCache: 30,
	UnlinkedCall: 31, MonomorphicSmiableCall: 32, CallSiteData: 33,
	ICData: 34, MegamorphicCache: 35, SubtypeTestCache: 36,
	LoadingUnit: 37, LanguageError: 40, UnhandledException: 41,
	Instance: 43, LibraryPrefix: 44, TypeArguments: 45,
	Type: 47, FunctionType: 52, TypeParameter: 54,
	TypeRef: 53,
	Closure: 55, Mint: 59, Double: 60,
	Float32x4: 62, Int32x4: 63, Float64x2: 64,
	TypedData: 66, ExternalTypedData: 67, TypedDataView: 68,
	Capability: 71, ReceivePort: 72, SendPort: 73,
	StackTrace: 74, SuspendState: 75, RegExp: 76,
	WeakProperty: 77, WeakReference: 78,
	FutureOr: 80, UserTag: 81, TransferableTypedData: 82,
	// v2.18 uses LinkedHashMap/LinkedHashSet
	Map: 83, ConstMap: 84, Set: 85, ConstSet: 86,
	Array: 87, ImmutableArray: 88, GrowableObjectArray: 89,
	String: 90, OneByteString: 91, TwoByteString: 92,
	// TypedData internals: stride 3 (no UnmodifiableView in v2.18)
	TypedDataInt8ArrayCid: 111, ByteDataViewCid: 153, TypedDataCidStride: 3,
	FfiMarkerFirstCid: 96, FfiMarkerLastCid: 108,
	NativePointerCid: 1, NumPredefinedCids: 159,
}

// v2.19.0 CIDs: structurally identical to v3.0.5 but without WeakArray,
// so all CIDs from Code onward are offset by -1 compared to cidsV305.
// Adds RecordType, Record. TypedData stride 4 (with UnmodifiableView).
var cidsV219 = CIDTable{
	Class: 5, PatchClass: 6, Function: 7, TypeParameters: 8,
	ClosureData: 9, FfiTrampolineData: 10, Field: 11, Script: 12,
	Library: 13, Namespace: 14, KernelProgramInfo: 15,
	WeakSerializationReference: 16,
	// No WeakArray in v2.19
	Code: 17, ObjectPool: 21, PcDescriptors: 22, CodeSourceMap: 23,
	CompressedStackMaps: 24, ExceptionHandlers: 26, Context: 27,
	ContextScope: 28, Sentinel: 29, SingleTargetCache: 30,
	UnlinkedCall: 31, MonomorphicSmiableCall: 32, CallSiteData: 33,
	ICData: 34, MegamorphicCache: 35, SubtypeTestCache: 36,
	LoadingUnit: 37, LanguageError: 40, UnhandledException: 41,
	Instance: 43, LibraryPrefix: 44, TypeArguments: 45,
	Type: 47, FunctionType: 48, RecordType: 49, TypeRef: 50, TypeParameter: 51,
	Closure: 56, Mint: 60, Double: 61,
	Float32x4: 63, Int32x4: 64, Float64x2: 65, Record: 66,
	TypedData: 68, ExternalTypedData: 69, TypedDataView: 70,
	Capability: 73, ReceivePort: 74, SendPort: 75,
	StackTrace: 76, SuspendState: 77, RegExp: 78,
	WeakProperty: 79, WeakReference: 80,
	FutureOr: 82, UserTag: 83, TransferableTypedData: 84,
	Map: 85, ConstMap: 86, Set: 87, ConstSet: 88,
	Array: 89, ImmutableArray: 90, GrowableObjectArray: 91,
	String: 92, OneByteString: 93, TwoByteString: 94,
	TypedDataInt8ArrayCid: 113, ByteDataViewCid: 169, TypedDataCidStride: 4,
	FfiMarkerFirstCid: 98, FfiMarkerLastCid: 110,
	NativePointerCid: 1, NumPredefinedCids: 176,
}

// v3.0.5 CIDs: same layout as v3.2.5 except TypeRef still present (between
// RecordType and TypeParameter). This shifts TypeParameter and all subsequent
// CIDs by +1 compared to v3.1.0+.
var cidsV305 = CIDTable{
	Class: 5, PatchClass: 6, Function: 7, TypeParameters: 8,
	ClosureData: 9, FfiTrampolineData: 10, Field: 11, Script: 12,
	Library: 13, Namespace: 14, KernelProgramInfo: 15,
	WeakSerializationReference: 16, WeakArray: 17,
	Code: 18, ObjectPool: 22, PcDescriptors: 23, CodeSourceMap: 24,
	CompressedStackMaps: 25, ExceptionHandlers: 27, Context: 28,
	ContextScope: 29, Sentinel: 30, SingleTargetCache: 31,
	UnlinkedCall: 32, MonomorphicSmiableCall: 33, CallSiteData: 34,
	ICData: 35, MegamorphicCache: 36, SubtypeTestCache: 37,
	LoadingUnit: 38, LanguageError: 41, UnhandledException: 42,
	Instance: 44, LibraryPrefix: 45, TypeArguments: 46,
	Type: 48, FunctionType: 49, RecordType: 50, TypeRef: 51, TypeParameter: 52,
	Closure: 57, Mint: 61, Double: 62,
	Float32x4: 64, Int32x4: 65, Float64x2: 66, Record: 67,
	TypedData: 69, ExternalTypedData: 70, TypedDataView: 71,
	Capability: 74, ReceivePort: 75, SendPort: 76,
	StackTrace: 77, SuspendState: 78, RegExp: 79,
	WeakProperty: 80, WeakReference: 81,
	FutureOr: 83, UserTag: 84, TransferableTypedData: 85,
	Map: 86, ConstMap: 87, Set: 88, ConstSet: 89,
	Array: 90, ImmutableArray: 91, GrowableObjectArray: 92,
	String: 93, OneByteString: 94, TwoByteString: 95,
	TypedDataInt8ArrayCid: 114, ByteDataViewCid: 170, TypedDataCidStride: 4,
	FfiMarkerFirstCid: 99, FfiMarkerLastCid: 111,
	NativePointerCid: 1, NumPredefinedCids: 177,
}

var cidsV325 = CIDTable{
	Class: 5, PatchClass: 6, Function: 7, TypeParameters: 8,
	ClosureData: 9, FfiTrampolineData: 10, Field: 11, Script: 12,
	Library: 13, Namespace: 14, KernelProgramInfo: 15,
	WeakSerializationReference: 16, WeakArray: 17,
	Code: 18, ObjectPool: 22, PcDescriptors: 23, CodeSourceMap: 24,
	CompressedStackMaps: 25, ExceptionHandlers: 27, Context: 28,
	ContextScope: 29, Sentinel: 30, SingleTargetCache: 31,
	UnlinkedCall: 32, MonomorphicSmiableCall: 33, CallSiteData: 34,
	ICData: 35, MegamorphicCache: 36, SubtypeTestCache: 37,
	LoadingUnit: 38, LanguageError: 41, UnhandledException: 42,
	Instance: 44, LibraryPrefix: 45, TypeArguments: 46,
	Type: 48, FunctionType: 49, RecordType: 50, TypeParameter: 51,
	Closure: 56, Mint: 60, Double: 61,
	Float32x4: 63, Int32x4: 64, Float64x2: 65, Record: 66,
	TypedData: 68, ExternalTypedData: 69, TypedDataView: 70,
	Capability: 73, ReceivePort: 74, SendPort: 75,
	StackTrace: 76, SuspendState: 77, RegExp: 78,
	WeakProperty: 79, WeakReference: 80,
	FutureOr: 82, UserTag: 83, TransferableTypedData: 84,
	Map: 85, ConstMap: 86, Set: 87, ConstSet: 88,
	Array: 89, ImmutableArray: 90, GrowableObjectArray: 91,
	String: 92, OneByteString: 93, TwoByteString: 94,
	TypedDataInt8ArrayCid: 113, ByteDataViewCid: 169, TypedDataCidStride: 4,
	FfiMarkerFirstCid: 98, FfiMarkerLastCid: 110,
	NativePointerCid: 1, NumPredefinedCids: 176,
}

// v3.4.3 CIDs: same as v3.2.5 except Bytecode removed (no Bytecode CID 19),
// all CIDs after Code shift by -1 compared to v3.9.2 (which has Bytecode at 19).
var cidsV343 = CIDTable{
	Class: 5, PatchClass: 6, Function: 7, TypeParameters: 8,
	ClosureData: 9, FfiTrampolineData: 10, Field: 11, Script: 12,
	Library: 13, Namespace: 14, KernelProgramInfo: 15,
	WeakSerializationReference: 16, WeakArray: 17,
	Code: 18, ObjectPool: 22, PcDescriptors: 23, CodeSourceMap: 24,
	CompressedStackMaps: 25, ExceptionHandlers: 27, Context: 28,
	ContextScope: 29, Sentinel: 30, SingleTargetCache: 31,
	UnlinkedCall: 32, MonomorphicSmiableCall: 33, CallSiteData: 34,
	ICData: 35, MegamorphicCache: 36, SubtypeTestCache: 37,
	LoadingUnit: 38, LanguageError: 41, UnhandledException: 42,
	Instance: 44, LibraryPrefix: 45, TypeArguments: 46,
	Type: 48, FunctionType: 49, RecordType: 50, TypeParameter: 51,
	Closure: 56, Mint: 60, Double: 61,
	Float32x4: 63, Int32x4: 64, Float64x2: 65, Record: 66,
	TypedData: 68, ExternalTypedData: 69, TypedDataView: 70,
	Capability: 73, ReceivePort: 74, SendPort: 75,
	StackTrace: 76, SuspendState: 77, RegExp: 78,
	WeakProperty: 79, WeakReference: 80,
	FutureOr: 82, UserTag: 83, TransferableTypedData: 84,
	Map: 85, ConstMap: 86, Set: 87, ConstSet: 88,
	Array: 89, ImmutableArray: 90, GrowableObjectArray: 91,
	String: 92, OneByteString: 93, TwoByteString: 94,
	TypedDataInt8ArrayCid: 111, ByteDataViewCid: 167, TypedDataCidStride: 4,
	FfiMarkerFirstCid: 96, FfiMarkerLastCid: 108,
	NativePointerCid: 1, NumPredefinedCids: 174,
}

// v3.6.2 through v3.8.1: nearly identical to v3.9.2 except for
// UnlinkedCall/MonomorphicSmiableCall/CallSiteData ordering.
var cidsV362 = CIDTable{
	Class: 5, PatchClass: 6, Function: 7, TypeParameters: 8,
	ClosureData: 9, FfiTrampolineData: 10, Field: 11, Script: 12,
	Library: 13, Namespace: 14, KernelProgramInfo: 15,
	WeakSerializationReference: 16, WeakArray: 17,
	Code: 18, ObjectPool: 23, PcDescriptors: 24, CodeSourceMap: 25,
	CompressedStackMaps: 26, ExceptionHandlers: 28, Context: 29,
	ContextScope: 30, Sentinel: 31, SingleTargetCache: 32,
	UnlinkedCall: 33, MonomorphicSmiableCall: 34, CallSiteData: 35,
	ICData: 36, MegamorphicCache: 37, SubtypeTestCache: 38,
	LoadingUnit: 39, LanguageError: 42, UnhandledException: 43,
	Instance: 45, LibraryPrefix: 46, TypeArguments: 47,
	Type: 49, FunctionType: 50, RecordType: 51, TypeParameter: 52,
	Closure: 57, Mint: 61, Double: 62,
	Float32x4: 64, Int32x4: 65, Float64x2: 66, Record: 67,
	TypedData: 69, ExternalTypedData: 70, TypedDataView: 71,
	Capability: 74, ReceivePort: 75, SendPort: 76,
	StackTrace: 77, SuspendState: 78, RegExp: 79,
	WeakProperty: 80, WeakReference: 81,
	FutureOr: 83, UserTag: 84, TransferableTypedData: 85,
	Map: 86, ConstMap: 87, Set: 88, ConstSet: 89,
	Array: 90, ImmutableArray: 91, GrowableObjectArray: 92,
	String: 93, OneByteString: 94, TwoByteString: 95,
	TypedDataInt8ArrayCid: 112, ByteDataViewCid: 168, TypedDataCidStride: 4,
	FfiMarkerFirstCid: 97, FfiMarkerLastCid: 109,
	NativePointerCid: 1, NumPredefinedCids: 175,
}

// v3.9.2 through v3.12.0-dev: the CID table currently hardcoded in cid.go.
var cidsV392 = CIDTable{
	Class: 5, PatchClass: 6, Function: 7, TypeParameters: 8,
	ClosureData: 9, FfiTrampolineData: 10, Field: 11, Script: 12,
	Library: 13, Namespace: 14, KernelProgramInfo: 15,
	WeakSerializationReference: 16, WeakArray: 17,
	Code: 18, ObjectPool: 23, PcDescriptors: 24, CodeSourceMap: 25,
	CompressedStackMaps: 26, ExceptionHandlers: 28, Context: 29,
	ContextScope: 30, Sentinel: 31, SingleTargetCache: 32,
	UnlinkedCall: 35, MonomorphicSmiableCall: 33, CallSiteData: 34,
	ICData: 36, MegamorphicCache: 37, SubtypeTestCache: 38,
	LoadingUnit: 39, LanguageError: 42, UnhandledException: 43,
	Instance: 45, LibraryPrefix: 46, TypeArguments: 47,
	Type: 49, FunctionType: 50, RecordType: 51, TypeParameter: 52,
	Closure: 57, Mint: 61, Double: 62,
	Float32x4: 64, Int32x4: 65, Float64x2: 66, Record: 67,
	TypedData: 69, ExternalTypedData: 70, TypedDataView: 71,
	Capability: 74, ReceivePort: 75, SendPort: 76,
	StackTrace: 77, SuspendState: 78, RegExp: 79,
	WeakProperty: 80, WeakReference: 81,
	FutureOr: 83, UserTag: 84, TransferableTypedData: 85,
	Map: 86, ConstMap: 87, Set: 88, ConstSet: 89,
	Array: 90, ImmutableArray: 91, GrowableObjectArray: 92,
	String: 93, OneByteString: 94, TwoByteString: 95,
	TypedDataInt8ArrayCid: 112, ByteDataViewCid: 168, TypedDataCidStride: 4,
	FfiMarkerFirstCid: 97, FfiMarkerLastCid: 109,
	NativePointerCid: 1, NumPredefinedCids: 175,
}

// v3.13.0: CID(LinkedHashBaseCid) added after CLASS_LIST in CLASS_ID_LIST,
// shifting all CIDs after String (FFI, TypedData, ByteDataView, Null, etc) +1
// vs cidsV392. Verified via gh api to dart-lang/sdk class_id.h @3.13.0:
// the only diff from 3.12.2's CLASS_ID_LIST is one added CID(LinkedHashBaseCid)
// line after CLASS_LIST(DEFINE_CLASS_ID). CIDs Object(4) through String(95)
// are unchanged; everything after shifts +1.
var cidsV3130 = CIDTable{
	Class: 5, PatchClass: 6, Function: 7, TypeParameters: 8,
	ClosureData: 9, FfiTrampolineData: 10, Field: 11, Script: 12,
	Library: 13, Namespace: 14, KernelProgramInfo: 15,
	WeakSerializationReference: 16, WeakArray: 17,
	Code: 18, ObjectPool: 23, PcDescriptors: 24, CodeSourceMap: 25,
	CompressedStackMaps: 26, ExceptionHandlers: 28, Context: 29,
	ContextScope: 30, Sentinel: 31, SingleTargetCache: 32,
	UnlinkedCall: 35, MonomorphicSmiableCall: 33, CallSiteData: 34,
	ICData: 36, MegamorphicCache: 37, SubtypeTestCache: 38,
	LoadingUnit: 39, LanguageError: 42, UnhandledException: 43,
	Instance: 45, LibraryPrefix: 46, TypeArguments: 47,
	Type: 49, FunctionType: 50, RecordType: 51, TypeParameter: 52,
	Closure: 57, Mint: 61, Double: 62,
	Float32x4: 64, Int32x4: 65, Float64x2: 66, Record: 67,
	TypedData: 69, ExternalTypedData: 70, TypedDataView: 71,
	Capability: 74, ReceivePort: 75, SendPort: 76,
	StackTrace: 77, SuspendState: 78, RegExp: 79,
	WeakProperty: 80, WeakReference: 81,
	FutureOr: 83, UserTag: 84, TransferableTypedData: 85,
	Map: 86, ConstMap: 87, Set: 88, ConstSet: 89,
	Array: 90, ImmutableArray: 91, GrowableObjectArray: 92,
	String: 93, OneByteString: 94, TwoByteString: 95,
	// LinkedHashBaseCid = 96 (new in 3.13.0, shifts everything below +1)
	TypedDataInt8ArrayCid: 113, ByteDataViewCid: 169, TypedDataCidStride: 4,
	FfiMarkerFirstCid: 98, FfiMarkerLastCid: 110,
	NativePointerCid: 1, NumPredefinedCids: 176,
	// New in 3.13.0: see CIDTable.LocalVarDescriptors / .ApiError.
	LocalVarDescriptors: 27, ApiError: 41, UnwindError: 44,
}

var versionProfiles = map[string]*VersionProfile{
	// StringRODataPerSubclass: at 2.10 ReadOnlyObjectType() already names
	// kOneByteStringCid and kTwoByteStringCid, so NewClusterForClass hands
	// each its own RODataSerializationCluster -- there is no cluster under
	// the abstract String cid (80) to find. Leaving the flag off looked for
	// cid 80, found nothing, and produced a snapshot with ZERO strings: every
	// function came out as sub_<addr> and classes.jsonl was not written at all
	// because no class name would resolve.
	"2.10.0": {DartVersion: "2.10.0", Supported: true, HeaderFields: 4, Tags: TagStyleCidInt32, CIDs: &cidsV210, FillRefUnsigned: true, PreV32Format: true, HasTypeParamClassId: true, TypeParamByteScalars: true, OldTypeScalars: true, TopLevelCid16: true, OldPoolFormat: true, OldStringFormat: true, StringRODataPerSubclass: true, PreCanonicalSplit: true, ClassNumRefs: 16, ClassHasTokenPos: true, FuncNumRefs: 7, TypeNumRefs: 5, TypeClassIdIsRef: true, TypeHasTokenPos: true, TypeParamNumRefs: 5, CodeNumRefs: 7, CodeTextOffsetDelta: true, CodeStateBitsAtEnd: true, ScriptHasLineCol: true, ScriptHasFlags: true, ObjectStoreAOTFieldCount: 176}, // SDK-verified: from()=object_class -> to_snapshot(kFullAOT)=slow_tts_stub = 176 fields (object_store.h @2.10.0)
	// v2.12.0: Code fill differs from v2.13.0's — state_bits_ is read AFTER all 7 refs
	// (owner, exception_handlers, pc_descriptors, catch_entry, compressed_stackmaps,
	// inlined_id_to_function, code_source_map), not interleaved after
	// compressed_stackmaps like v2.13. Verified against dart-lang/sdk
	// runtime/vm/clustered_snapshot.cc CodeDeserializationCluster::ReadFill at the
	// 2.12.0 tag (no Code::IsDiscarded concept either — that's 2.13+/PRECOMPILED_RUNTIME).
	"2.12.0": {DartVersion: "2.12.0", Supported: true, HeaderFields: 5, Tags: TagStyleCidInt32, CIDs: &cidsV212, FillRefUnsigned: true, PreV32Format: true, HasTypeParamClassId: true, TypeParamByteScalars: true, OldTypeScalars: true, TopLevelCid16: true, OldPoolFormat: true, OldStringFormat: true, SplitCanonical: true, NoCanonicalSetData: true, StringRODataPerSubclass: true, ClassNumRefs: 15, ClassHasTokenPos: true, FuncNumRefs: 5, TypeNumRefs: 4, TypeClassIdIsRef: true, FuncTypeOldScalars: true, TypeParamNumRefs: 5, TypeParamWideScalars: true, CodeNumRefs: 7, CodeTextOffsetDelta: true, CodeStateBitsAtEnd: true, ClosureDataNumRefs: 4, ScriptHasLineCol: true, FuncTypeParamTypesIdx: 3, ObjectStoreAOTFieldCount: 191}, // SDK-verified: from()=object_class -> slow_tts_stub = 191 fields (object_store.h @2.12.0)
	"2.13.0": {DartVersion: "2.13.0", Supported: true, HeaderFields: 5, Tags: TagStyleCidInt32, CIDs: &cidsV213, FillRefUnsigned: true, PreV32Format: true, HasTypeParamClassId: true, TypeParamByteScalars: true, OldTypeScalars: true, TopLevelCid16: true, OldPoolFormat: true, OldStringFormat: true, SplitCanonical: true, ClassNumRefs: 15, ClassHasTokenPos: true, FuncNumRefs: 5, TypeNumRefs: 4, TypeClassIdIsRef: true, FuncTypeOldScalars: true, TypeParamNumRefs: 5, TypeParamWideScalars: true, CodeNumRefs: 7, CodeTextOffsetDelta: true, CodeStateBitsAfterRef: 1, ClosureDataNumRefs: 3, ScriptHasLineCol: true, FuncTypeParamTypesIdx: 3, ObjectStoreAOTFieldCount: 191},                                                          // SDK-verified: from()=object_class -> slow_tts_stub = 191 fields (object_store.h @2.13.0)
	"2.14.0": {DartVersion: "2.14.0", Supported: true, HeaderFields: 5, Tags: TagStyleCidShift1, CIDs: &cidsV214, FillRefUnsigned: true, PreV32Format: true, HasTypeParamClassId: true, TypeParamByteScalars: true, OldTypeScalars: true, TopLevelCid16: true, OldPoolFormat: true, OldStringFormat: true, TypeClassIdIsRef: true, TypeNumRefs: 4, CodeNumRefs: 7, CodeTextOffsetDelta: true, FuncTypeNumRefs: 6, TypeParamNumRefs: 3, TypeRefNumRefs: 2, FuncTypeParamTypesIdx: 3, ObjectStoreAOTFieldCount: 202},                                                                                                                                                                                                                                 // SDK-verified: from()=list_class (LAZY_CORE) -> slow_tts_stub = 202 fields (object_store.h @2.14.0)
	// 2.15.0 shares 2.16.0's Type layout exactly -- no TypeClassIdIsRef, no
	// TypeNumRefs override. See the TypeClassIdIsRef doc comment.
	"2.15.0": {DartVersion: "2.15.0", Supported: true, HeaderFields: 5, Tags: TagStyleCidShift1, CIDs: &cidsV215, FillRefUnsigned: true, PreV32Format: true, HasTypeParamClassId: true, TypeParamByteScalars: true, OldTypeScalars: true, TopLevelCid16: true, OldPoolFormat: true, CodeNumRefs: 7, CodeTextOffsetDelta: true, FuncTypeNumRefs: 6, TypeParamNumRefs: 3, TypeRefNumRefs: 2, FuncTypeParamTypesIdx: 3, ObjectStoreAOTFieldCount: 182}, // SDK-verified: from()=list_class (LAZY_CORE) -> slow_tts_stub = 182 fields (object_store.h @2.15.0)
	"2.16.0": {DartVersion: "2.16.0", Supported: true, HeaderFields: 6, Tags: TagStyleCidShift1, CIDs: &cidsV216, FillRefUnsigned: true, CodeIndexOneBased: true, PreV32Format: true, HasTypeParamClassId: true, TypeParamByteScalars: true, OldTypeScalars: true, TopLevelCid16: true, OldPoolFormat: true, FuncTypeParamTypesIdx: 3, ObjectStoreAOTFieldCount: 184},
	"2.17.6": {DartVersion: "2.17.6", Supported: true, HeaderFields: 6, Tags: TagStyleCidShift1, CIDs: &cidsV217, FillRefUnsigned: true, CodeIndexOneBased: true, PreV32Format: true, HasTypeParamClassId: true, TypeParamByteScalars: true, OldTypeScalars: true, TopLevelCid16: true, OldPoolFormat: true, FuncTypeParamTypesIdx: 3, ObjectStoreAOTFieldCount: 194},
	"2.18.0": {DartVersion: "2.18.0", Supported: true, HeaderFields: 5, Tags: TagStyleCidShift1, CIDs: &cidsV218, PreV32Format: true, HasTypeParamClassId: true, TypeParamByteScalars: true, OldTypeScalars: true, TopLevelCid16: true, OldPoolFormat: true, FuncTypeParamTypesIdx: 3, CodeIndexOneBased: true, ObjectStoreAOTFieldCount: 212},
	"2.19.0": {DartVersion: "2.19.0", Supported: true, HeaderFields: 5, Tags: TagStyleCidShift1, CIDs: &cidsV219, PreV32Format: true, HasTypeParamClassId: true, TypeParamByteScalars: true, OldPoolFormat: true, FuncTypeParamTypesIdx: 3, CodeIndexOneBased: true, ObjectStoreAOTFieldCount: 224},
	"3.0.5":  {DartVersion: "3.0.5", Supported: true, HeaderFields: 5, Tags: TagStyleCidShift1, CIDs: &cidsV305, PreV32Format: true, HasTypeParamClassId: true, OldPoolFormat: true, FuncTypeParamTypesIdx: 3, CodeIndexOneBased: true, ObjectStoreAOTFieldCount: 232},
	"3.1.0":  {DartVersion: "3.1.0", Supported: true, HeaderFields: 5, Tags: TagStyleCidShift1, CIDs: &cidsV325, PreV32Format: true, OldPoolFormat: true, FuncTypeParamTypesIdx: 4, ObjectStoreAOTFieldCount: 233, CodeIndexOneBased: true},    // ObjectStoreAOTFieldCount: source-verified only (no real-binary test)
	"3.2.5":  {DartVersion: "3.2.5", Supported: true, HeaderFields: 5, Tags: TagStyleCidShift1, CIDs: &cidsV325, OldPoolFormat: true, PoolTypeSwapped: true, FuncTypeParamTypesIdx: 4, ObjectStoreAOTFieldCount: 232, CodeIndexOneBased: true}, // ObjectStoreAOTFieldCount: source-verified only
	"3.3.0":  {DartVersion: "3.3.0", Supported: true, HeaderFields: 5, Tags: TagStyleCidShift1, CIDs: &cidsV325, FuncTypeParamTypesIdx: 4, ObjectStoreAOTFieldCount: 233, CodeIndexOneBased: true},                                             // ObjectStoreAOTFieldCount: source-verified only
	"3.4.3":  {DartVersion: "3.4.3", Supported: true, HeaderFields: 5, Tags: TagStyleObjectHeader, CIDs: &cidsV343, FuncTypeParamTypesIdx: 4, ObjectStoreAOTFieldCount: 232, CodeIndexOneBased: true},                                          // ObjectStoreAOTFieldCount: source-verified only
	"3.5.0":  {DartVersion: "3.5.0", Supported: true, HeaderFields: 5, Tags: TagStyleObjectHeader, CIDs: &cidsV343, FuncTypeParamTypesIdx: 4, ObjectStoreAOTFieldCount: 229, CodeIndexOneBased: true},                                          // ObjectStoreAOTFieldCount: source-verified only
	"3.6.2":  {DartVersion: "3.6.2", Supported: true, HeaderFields: 5, Tags: TagStyleObjectHeader, CIDs: &cidsV362, FuncTypeParamTypesIdx: 4, ObjectStoreAOTFieldCount: 233, CodeIndexOneBased: true},                                          // ObjectStoreAOTFieldCount: source-verified only
	"3.7.0":  {DartVersion: "3.7.0", Supported: true, HeaderFields: 5, Tags: TagStyleObjectHeader, CIDs: &cidsV362, FuncTypeParamTypesIdx: 4, ObjectStoreAOTFieldCount: 233, CodeIndexOneBased: true},                                          // ObjectStoreAOTFieldCount: real-binary verified
	"3.8.1":  {DartVersion: "3.8.1", Supported: true, HeaderFields: 5, Tags: TagStyleObjectHeader, CIDs: &cidsV362, FuncTypeParamTypesIdx: 4, ObjectStoreAOTFieldCount: 233, CodeIndexOneBased: true},                                          // ObjectStoreAOTFieldCount: source-verified only
	"3.9.2":  {DartVersion: "3.9.2", Supported: true, HeaderFields: 5, Tags: TagStyleObjectHeader, CIDs: &cidsV392, FuncTypeParamTypesIdx: 4, ObjectStoreAOTFieldCount: 235, CodeIndexOneBased: true},                                          // ObjectStoreAOTFieldCount: real-binary verified
	"3.10.7": {DartVersion: "3.10.7", Supported: true, HeaderFields: 5, Tags: TagStyleObjectHeader, CIDs: &cidsV392, FuncTypeParamTypesIdx: 4, ObjectStoreAOTFieldCount: 241, CodeIndexOneBased: true},                                         // ObjectStoreAOTFieldCount: real-binary verified (3.10.7 arm64+x64, zero unresolved)
	"3.11.0": {DartVersion: "3.11.0", Supported: true, HeaderFields: 5, Tags: TagStyleObjectHeader, CIDs: &cidsV392, FuncTypeParamTypesIdx: 4, ObjectStoreAOTFieldCount: 242, CodeIndexOneBased: true},                                         // ObjectStoreAOTFieldCount: real-binary verified (3.11.0 arm64+x64, zero unresolved)
	// 3.12.2: verified end-to-end against a real compiled sample (Flutter
	// 3.44.7) -- same CID table as 3.9.2 despite class_id.h's macro-based
	// refactor at this version (CLASS_LIST/CLASS_LIST_FFI/
	// CLASS_LIST_TYPED_DATA generation order unchanged, confirmed by real
	// function-name resolution succeeding on the sample, not just by
	// reading the refactored source).
	"3.12.2": {DartVersion: "3.12.2", Supported: true, HeaderFields: 5, Tags: TagStyleObjectHeader, CIDs: &cidsV392, FuncTypeParamTypesIdx: 4, ObjectStoreAOTFieldCount: 244, CodeIndexOneBased: true},
	// 3.13.0: class_id.h adds CID(LinkedHashBaseCid) after CLASS_LIST but
	// before CLASS_LIST_FFI, shifting all FFI/TypedData/ByteDataView/
	// Null/Dynamic/Void/Never CIDs +1 vs 3.12.2. ObjectStore: resume_stub
	// and slow_tts_stub removed, to_snapshot(kFullAOT) still points at
	// ffi_callback_functions_. Function kinds expanded to 30 (vs 17) but
	// the first 8 (RegularFunction..ImplicitSetter) are unchanged, so
	// layout219's mask 0x1F still works. Stub list changed: AllocateClosure
	// split into AllocateClosure1-4, RunExceptionHandlerUnbox added,
	// TypeIsTopTypeForSubtyping* renamed. CID table, stub names, THR
	// offsets, and function kind layout all verified via gh api to
	// dart-lang/sdk at tag 3.13.0.
	"3.13.0": {DartVersion: "3.13.0", Supported: true, HeaderFields: 5, Tags: TagStyleObjectHeader, CIDs: &cidsV3130, FuncTypeParamTypesIdx: 4, ObjectStoreAOTFieldCount: 171, RootsPrefixRefCount: 1518, CodeIndexOneBased: true, ClassAllocFixedSize: true, CodeFillHasIndexRefs: true, ClosureAllocHasLength: true},
}

// verifiedWireDimensions holds format facts that used to be inferred from
// version comparisons at their consumers. Every supported release has an exact
// row. This is intentionally a second table instead of broad ranges: the SDK
// source at each supported tag is the contract, and adding a release without
// verifying these dimensions must be visible in review.
//
// Sources verified locally under ~/dev/dartsdk-research/<tag>/:
//   - runtime/include/dart_api.h: legacy vs unified exported snapshot symbols.
//   - runtime/vm/snapshot.h: Snapshot::Kind and DataImage() alignment.
//   - runtime/vm/dart.cc: pointer-compression feature spelling.
//   - runtime/vm/image_snapshot.h/object.h/compiler/runtime_api.cc: image layout
//     and InstructionsSection header size.
//   - runtime/vm/app_snapshot.cc / clustered_snapshot.cc: roots field tables.
type wireDimensions struct {
	symbols                 SnapshotSymbolLayout
	compression             CompressionFeatureStyle
	targetFeatures          TargetFeatureStyle
	instructionsImage       InstructionsImageLayout
	fullAOTKind             SnapshotKind
	dataImageAlignment      int64
	imageHeaderSize         uint64
	classIDTagPos           int
	classIDTagSize          int
	initialFieldTable       bool
	sharedInitialFieldTable bool
}

var verifiedWireDimensions = map[string]wireDimensions{
	"2.10.0": {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureFixedUncompressed, instructionsImage: InstructionsImageLegacy210, fullAOTKind: KindFullAOTV210, dataImageAlignment: 16, imageHeaderSize: 16, classIDTagPos: 16, classIDTagSize: 16},
	"2.12.0": {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureFixedUncompressed, instructionsImage: InstructionsImageSection40, fullAOTKind: KindFullAOT, dataImageAlignment: 16, imageHeaderSize: 16, classIDTagPos: 16, classIDTagSize: 16},
	"2.13.0": {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureLegacyPositiveOnly, instructionsImage: InstructionsImageSection40, fullAOTKind: KindFullAOT, dataImageAlignment: 16, imageHeaderSize: 16, classIDTagPos: 16, classIDTagSize: 16},
	"2.14.0": {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureLegacyPositiveOnly, instructionsImage: InstructionsImageSection40, fullAOTKind: KindFullAOT, dataImageAlignment: 16, imageHeaderSize: 16, classIDTagPos: 16, classIDTagSize: 16},
	"2.15.0": {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection40, fullAOTKind: KindFullAOT, dataImageAlignment: 16, imageHeaderSize: 16, classIDTagPos: 16, classIDTagSize: 16},
	"2.16.0": {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection40, fullAOTKind: KindFullAOT, dataImageAlignment: 16, imageHeaderSize: 16, classIDTagPos: 16, classIDTagSize: 16},
	"2.17.6": {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection40, fullAOTKind: KindFullAOT, dataImageAlignment: 16, imageHeaderSize: 16, classIDTagPos: 16, classIDTagSize: 16},
	"2.18.0": {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection40, fullAOTKind: KindFullAOT, dataImageAlignment: 16, imageHeaderSize: 16, classIDTagPos: 16, classIDTagSize: 16, initialFieldTable: true},
	"2.19.0": {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection40, fullAOTKind: KindFullAOT, dataImageAlignment: 64, imageHeaderSize: 64, classIDTagPos: 12, classIDTagSize: 20, initialFieldTable: true},
	"3.0.5":  {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection40, fullAOTKind: KindFullAOT, dataImageAlignment: 64, imageHeaderSize: 64, classIDTagPos: 12, classIDTagSize: 20, initialFieldTable: true},
	"3.1.0":  {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection40, fullAOTKind: KindFullAOT, dataImageAlignment: 64, imageHeaderSize: 64, classIDTagPos: 12, classIDTagSize: 20, initialFieldTable: true},
	"3.2.5":  {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection40, fullAOTKind: KindFullAOT, dataImageAlignment: 64, imageHeaderSize: 64, classIDTagPos: 12, classIDTagSize: 20, initialFieldTable: true},
	"3.3.0":  {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection40, fullAOTKind: KindFullAOT, dataImageAlignment: 64, imageHeaderSize: 64, classIDTagPos: 12, classIDTagSize: 20, initialFieldTable: true},
	"3.4.3":  {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection40, fullAOTKind: KindFullAOT, dataImageAlignment: 64, imageHeaderSize: 64, classIDTagPos: 12, classIDTagSize: 20, initialFieldTable: true},
	"3.5.0":  {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection64, fullAOTKind: KindFullAOT, dataImageAlignment: 64, imageHeaderSize: 64, classIDTagPos: 12, classIDTagSize: 20, initialFieldTable: true, sharedInitialFieldTable: true},
	"3.6.2":  {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection64, fullAOTKind: KindFullAOT, dataImageAlignment: 64, imageHeaderSize: 64, classIDTagPos: 12, classIDTagSize: 20, initialFieldTable: true, sharedInitialFieldTable: true},
	"3.7.0":  {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection64, fullAOTKind: KindFullAOT, dataImageAlignment: 64, imageHeaderSize: 64, classIDTagPos: 12, classIDTagSize: 20, initialFieldTable: true, sharedInitialFieldTable: true},
	"3.8.1":  {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection64, fullAOTKind: KindFullAOT, dataImageAlignment: 64, imageHeaderSize: 64, classIDTagPos: 12, classIDTagSize: 20, initialFieldTable: true, sharedInitialFieldTable: true},
	"3.9.2":  {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection64, fullAOTKind: KindFullAOT, dataImageAlignment: 64, imageHeaderSize: 64, classIDTagPos: 12, classIDTagSize: 20, initialFieldTable: true, sharedInitialFieldTable: true},
	"3.10.7": {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection64, fullAOTKind: KindFullAOT, dataImageAlignment: 64, imageHeaderSize: 64, classIDTagPos: 12, classIDTagSize: 20, initialFieldTable: true, sharedInitialFieldTable: true},
	"3.11.0": {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection64, fullAOTKind: KindFullAOT, dataImageAlignment: 64, imageHeaderSize: 64, classIDTagPos: 12, classIDTagSize: 20, initialFieldTable: true, sharedInitialFieldTable: true},
	"3.12.2": {symbols: SnapshotSymbolsLegacy, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection64, fullAOTKind: KindFullAOT, dataImageAlignment: 64, imageHeaderSize: 64, classIDTagPos: 12, classIDTagSize: 20, initialFieldTable: true, sharedInitialFieldTable: true},
	"3.13.0": {symbols: SnapshotSymbolsUnified, compression: CompressionFeatureExplicit, instructionsImage: InstructionsImageSection64, fullAOTKind: KindFullAOTV313, dataImageAlignment: 64, imageHeaderSize: 64, classIDTagPos: 12, classIDTagSize: 20, initialFieldTable: true, sharedInitialFieldTable: true},
}

func init() {
	if len(verifiedWireDimensions) != len(versionProfiles) {
		panic(fmt.Sprintf("snapshot: wire-dimension rows=%d profiles=%d", len(verifiedWireDimensions), len(versionProfiles)))
	}
	for version, p := range versionProfiles {
		d, ok := verifiedWireDimensions[version]
		if !ok {
			panic(fmt.Sprintf("snapshot: supported profile %s has no verified wire dimensions", version))
		}
		if p == nil || !p.Supported || p.CIDs == nil {
			panic(fmt.Sprintf("snapshot: profile %s is incomplete", version))
		}
		// SDK @2.10.0..2.18.0 runtime/vm/dart.cc emits the ABI-qualified
		// arm64-sysv/x64-sysv vocabulary; @2.19.0+ emits arm64/x64 followed by
		// a separate OS token. TestWireDimensionsMatchSDK re-derives this boundary
		// from each exact supported SDK tag.
		if VersionAtLeast(version, "2.19.0") {
			d.targetFeatures = TargetFeatureArchAndOS
		} else {
			d.targetFeatures = TargetFeatureLegacyABI
		}
		if d.symbols == SnapshotSymbolsUnknown || d.compression == CompressionFeatureUnknown ||
			d.targetFeatures == TargetFeatureUnknown ||
			d.instructionsImage == InstructionsImageUnknown || d.dataImageAlignment <= 0 || d.imageHeaderSize == 0 ||
			d.classIDTagPos <= 0 || d.classIDTagSize <= 0 ||
			(d.fullAOTKind != KindFullAOT && d.fullAOTKind != KindFullAOTV210) ||
			(d.sharedInitialFieldTable && !d.initialFieldTable) {
			panic(fmt.Sprintf("snapshot: profile %s has invalid wire dimensions: %+v", version, d))
		}
		p.SnapshotSymbols = d.symbols
		p.CompressionFeatures = d.compression
		p.TargetFeatures = d.targetFeatures
		p.InstructionsImage = d.instructionsImage
		p.FullAOTKind = d.fullAOTKind
		p.DataImageAlignment = d.dataImageAlignment
		p.ImageHeaderSize = d.imageHeaderSize
		p.ClassIdTagPos = d.classIDTagPos
		p.ClassIdTagSize = d.classIDTagSize
		p.RootsHasInitialFieldTable = d.initialFieldTable
		p.RootsHasSharedInitialFieldTable = d.sharedInitialFieldTable
	}
	for version := range verifiedWireDimensions {
		if _, ok := versionProfiles[version]; !ok {
			panic(fmt.Sprintf("snapshot: wire dimensions exist for unknown profile %s", version))
		}
	}
}

// DetectVersion returns the parser profile associated with a known snapshot
// compatibility hash. Unknown hashes return nil. A compatibility-family probe
// may still be useful for diagnostics, but it is never sufficient evidence to
// select CIDs, roots, image layout, or other wire-format dimensions.
func DetectVersion(hash string) *VersionProfile {
	version, ok := knownHashes[hash]
	if !ok {
		return nil
	}
	return ProfileForVersion(version)
}

// FormatProbe is diagnostic-only evidence from the first clustered tag. It
// intentionally contains no CID table or other parser dimensions: multiple SDK
// releases share the same header/tag family while differing in roots, CIDs and
// fill layouts.
type FormatProbe struct {
	HeaderFields int      `json:"header_fields"`
	Tags         TagStyle `json:"tags"`
	Family       string   `json:"family"`
}

// ProbeTagStyle identifies a coarse header/tag family for an unknown hash. A
// successful result must never be promoted to VersionProfile.
func ProbeTagStyle(data []byte, clusterStart int) *FormatProbe {
	type candidate struct {
		family string
		prof   *VersionProfile
	}
	candidates := []candidate{
		{"object-header/hf5", versionProfiles["3.9.2"]},
		{"cid-shift1/hf5", versionProfiles["3.2.5"]},
		{"cid-shift1/hf6", versionProfiles["2.17.6"]},
		{"cid-int32/hf5", versionProfiles["2.13.0"]},
		{"cid-int32/hf4", versionProfiles["2.10.0"]},
	}

	for _, c := range candidates {
		cid := probeFirstCID(data, clusterStart, c.prof)
		if c.prof.CIDs != nil && cid > 0 && cid < c.prof.CIDs.NumPredefinedCids {
			return &FormatProbe{HeaderFields: c.prof.HeaderFields, Tags: c.prof.Tags, Family: c.family}
		}
	}
	return nil
}

// probeFirstCID reads the header and first cluster tag, returning the CID.
// Returns -1 on any error.
func probeFirstCID(data []byte, clusterStart int, prof *VersionProfile) int {
	if prof == nil || clusterStart < 0 || clusterStart >= len(data) {
		return -1
	}

	// Use a minimal stream reader to skip header fields and read the tag.
	pos := clusterStart

	// Skip header fields using inline VLE decoding.
	// Both ReadUnsigned (endMarker=128) and ReadTagged64 (endMarker=192)
	// use the same terminal condition: byte > 127. They differ only in
	// value decoding, which we don't need here.
	for i := 0; i < prof.HeaderFields; i++ {
		var ok bool
		pos, ok = skipProbeVLE(data, pos)
		if !ok {
			return -1
		}
	}

	// Cluster tags are VLEs, not fixed 4-byte words. A valid ObjectHeader CID
	// such as 5 encodes as three bytes (00 20 c1), so requiring four remaining
	// bytes rejects a complete minimal tag. The bounded decoders below perform
	// their own exact EOF/width checks.
	if pos >= len(data) {
		return -1
	}

	// Decode tag based on tag style.
	switch prof.Tags {
	case TagStyleCidShift1:
		// ReadTagged64: read until byte > 127, subtract 192.
		var val int64
		var shift uint
		terminated := false
		for n := 0; n < 10 && pos < len(data) && shift < 64; n++ {
			b := data[pos]
			pos++
			if b > 127 {
				val |= int64(int(b)-192) << shift
				terminated = true
				break
			}
			val |= int64(b) << shift
			shift += 7
		}
		if !terminated {
			return -1
		}
		cid := int(val >> 1)
		return cid

	case TagStyleObjectHeader:
		// ReadTagged32: read until byte > 127, subtract 192.
		var val int32
		var shift uint
		terminated := false
		for n := 0; n < 5 && pos < len(data) && shift < 32; n++ {
			b := data[pos]
			pos++
			if b > 127 {
				val |= int32(int(b)-192) << shift
				terminated = true
				break
			}
			val |= int32(b) << shift
			shift += 7
		}
		if !terminated {
			return -1
		}
		cid := int((uint32(val) >> 12) & 0xFFFFF)
		return cid

	case TagStyleCidInt32:
		// Read<int32_t>(cid): signed VLE (endMarker=192), value = CID directly.
		var val int64
		var shift uint
		terminated := false
		for n := 0; n < 5 && pos < len(data) && shift < 32; n++ {
			b := data[pos]
			pos++
			if b > 127 {
				val |= int64(int(b)-192) << shift
				terminated = true
				break
			}
			val |= int64(b) << shift
			shift += 7
		}
		if !terminated {
			return -1
		}
		return int(val)
	}
	return -1
}

func skipProbeVLE(data []byte, pos int) (int, bool) {
	for n := 0; n < 10 && pos < len(data); n++ {
		b := data[pos]
		pos++
		if b > 127 {
			return pos, true
		}
	}
	return pos, false
}

// SupportedVersions returns every Dart version this package can analyse
// natively, sorted ascending.
//
// "Supported" means the same thing here as everywhere else in this package:
// there is a VersionProfile whose Supported flag is set, i.e. a verified CID
// table, header shape and cluster format for that release. A version with a
// known hash but no profile is not included.
func SupportedVersions() []string {
	out := make([]string, 0, len(versionProfiles))
	for v, p := range versionProfiles {
		if p != nil && p.Supported {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return compareDartVersions(out[i], out[j]) < 0 })
	return out
}

// compareDartVersions orders two "A.B.C" Dart versions numerically.
//
// Numerically, because these must not be compared as strings: "2.9.0" sorts
// AFTER "2.10.0" lexicographically, which is how a version check elsewhere in
// this project came to report 2 of 10 versions and say nothing about it.
func compareDartVersions(a, b string) int {
	pa, pb := parseVersionTriple(a), parseVersionTriple(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseVersionTriple(s string) [3]int {
	var v [3]int
	for i, part := range strings.SplitN(s, ".", 3) {
		if i >= 3 {
			break
		}
		n := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		v[i] = n
	}
	return v
}

// String names the tag encoding, for coverage reports and error messages.
func (t TagStyle) String() string {
	switch t {
	case TagStyleCidShift1:
		return "TagStyleCidShift1"
	case TagStyleObjectHeader:
		return "TagStyleObjectHeader"
	case TagStyleCidInt32:
		return "TagStyleCidInt32"
	}
	return fmt.Sprintf("TagStyle(%d)", int(t))
}

// ProfileForVersion returns the profile for an exact Dart version string, or
// nil when there is none. Unlike DetectVersion it takes a version rather than
// a snapshot hash, and it never invents a placeholder: callers asking "is this
// version supported" need a straight no.
func ProfileForVersion(version string) *VersionProfile {
	p := versionProfiles[version]
	if p == nil {
		return nil
	}
	// Profiles are templates. Extraction attaches per-binary feature state
	// (CompressedPointers and BuildMode), so callers must never receive the
	// mutable global row itself.
	pCopy := *p
	return &pCopy
}

// IsExactSupportedProfile reports whether profile is an unmodified static
// parser profile for one of the repository's exact supported Dart versions.
// Extraction is allowed to attach only the two per-binary feature dimensions
// below; every other field is a version-specific wire/layout fact and must still
// match the verified template exactly. This keeps internal semantic entry points
// from accepting a caller-fabricated "Supported" profile for a future/unknown
// Dart version, or a known version with guessed layout dimensions.
func IsExactSupportedProfile(profile *VersionProfile) bool {
	if profile == nil || !profile.Supported || profile.DartVersion == "" {
		return false
	}
	template := versionProfiles[profile.DartVersion]
	if template == nil || !template.Supported {
		return false
	}

	got := *profile
	want := *template
	// These are the only VersionProfile fields populated from the binary rather
	// than fixed by the exact SDK version.
	got.CompressedPointers = false
	want.CompressedPointers = false
	got.BuildMode = BuildUnknown
	want.BuildMode = BuildUnknown
	return got == want
}

// VersionAtLeast reports whether a Dart version string is >= minimum,
// comparing numerically rather than as text.
//
// It exists because the same question keeps arising in more than one package
// and it must never be answered with a string comparison: "2.9.0" sorts AFTER
// "2.10.0" lexicographically, which is how a version check in this project
// once reported 2 of 10 versions and said nothing about the other 8.
func VersionAtLeast(version, minimum string) bool {
	return compareDartVersions(version, minimum) >= 0
}

// ClassIdTagLayout returns the bit position and width of the ClassIdTag
// bitfield inside an object header's tags word, for a Dart version:
//
//	cid = (tags >> pos) & ((1 << size) - 1)
//
// Verified by reading runtime/vm/raw_object.h at each tag:
//
//	<= 2.18.0   kClassIdTagPos = 16, kClassIdTagSize = 16
//	>= 2.19.0   kClassIdTagPos = 12, kClassIdTagSize = 20
//
// (From 3.12.2 the same numbers also appear in the generated
// runtime_offsets_extracted.h as UntaggedObject_kClassIdTagPos/Size, which is
// what TestClassIdTagLayoutMatchesSDK cross-checks.)
//
// This exists because the same fact was being decided three different ways.
// internal/sdk carried the numbers, typetrack carried a boolean
// (ClassIDIsHalfWord) that threw the numbers away, and fill_strings.go chose
// between them on VersionProfile.PreV32Format -- a flag that means "PatchClass
// has 3 refs; ObjectPool uses v2 type bits" and is set for 2.19.0, 3.0.5 and
// 3.1.0, three versions whose tag layout is already the 20-bit one. One
// predicate, in one place, so a fourth cannot appear.
func ClassIdTagLayout(dartVersion string) (pos, size int, ok bool) {
	p := ProfileForVersion(dartVersion)
	if p == nil || !p.Supported || p.ClassIdTagPos <= 0 || p.ClassIdTagSize <= 0 {
		return 0, 0, false
	}
	return p.ClassIdTagPos, p.ClassIdTagSize, true
}
