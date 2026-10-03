package cluster

import (
	"fmt"
	"io"
	"math"
	"os"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

var debugFill = os.Getenv("DEFLUTTER_DEBUG_FILL") != ""

// NamedObject holds an object that participates in name/owner resolution.
// Most entries have a source name, while structural carriers such as
// PatchClass and TypeParameter intentionally use NameRefID=-1.
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

	// ResultTypeRefID/ParamTypesRefID are Function.result_type and
	// Function.parameter_types, which exist on the Function itself only before
	// FunctionType did (2.10). From 2.12 they are -1 and the same information
	// is reached through SignatureRefID instead. See FunctionRefLayout.
	ResultTypeRefID int
	ParamTypesRefID int

	// NumFixedParams/NumOptionalParams come from UntaggedFunction.packed_fields_
	// on Dart 2.x, where a regular function's arity lives on the Function
	// object itself rather than on a FunctionType signature. Both are -1 when
	// not captured (3.x, or a non-Function).
	//
	// NumFixedParams INCLUDES the implicit receiver for instance methods,
	// matching the SDK's num_fixed_parameters.
	NumFixedParams    int
	NumOptionalParams int

	// IsStatic comes from UntaggedFunction.kind_tag_. A static
	// method has no receiver, so its argument 0 is an ordinary parameter --
	// seeding it with the owning class would be a fabricated type.
	IsStatic bool
	// IsNative/IsExternal are the corresponding kind_tag_ flags. The VM's
	// Function::is_ffi_native() is exactly is_native() && is_external().
	IsNative   bool
	IsExternal bool
	// FuncKind is UntaggedFunction::Kind, NORMALISED: the raw ordinal is
	// version-dependent (2.10 numbers Constructor 6, later versions 5) and
	// so is the field width, so decodeFunctionKind maps both onto a
	// canonical value at parse time. FunctionKindUnknown when the version
	// is outside the verified range or the tag was not captured.
	FuncKind FunctionKind
	// HasKindTag is false when kind_tag was not captured, so IsStatic=false
	// cannot be mistaken for "known to be an instance method".
	HasKindTag bool

	// IsSuspendable is UntaggedFunction::modifier() != kNoModifier -- the
	// function is async, sync* or async*.
	//
	// It decides where the receiver lives before Dart 3.4.3, via
	// Function::MakesCopyOfParameters() = HasOptionalParameters() ||
	// IsSuspendableFunction(). See ReceiverFrameSlot.
	//
	// ModifierBits sits at bit 14 with width 2 in kind_tag_, immediately
	// below the single-bit flags (is_static is the first, at bit 16, which
	// is what IsStatic reads). Verified constant across every supported
	// version -- object.h KindTagBits gives kKindTagSize=5,
	// kRecognizedTagSize=9, kModifierPos=14, kModifierSize=2 identically at
	// 2.10.0, 2.12.0, 2.17.6, 2.19.0, 3.0.5, 3.1.0, 3.2.5, 3.3.0 and 3.4.3.
	IsSuspendable bool
	// FuncModifier is the exact UntaggedFunction::AsyncModifier decoded from
	// kind_tag_: none/async/sync*/async*. HasKindTag distinguishes a captured
	// kNoModifier from unavailable metadata.
	FuncModifier FunctionModifier

	// TypeParameter metadata is carried here because TypeParameter is an
	// AbstractType with no source name of its own. The VM names it from
	// (class-vs-function, base, index), e.g. X0/Y0/C1X0/F1Y0. Keeping the
	// scalar metadata next to the object's RefID lets exact type rendering
	// resolve TypeArguments entries that point at a TypeParameter instead of a
	// concrete Type. HasTypeParamMetadata distinguishes zero-valued fields from
	// an object whose version/layout was not captured.
	HasTypeParamMetadata bool
	TypeParamIsFunction  bool
	TypeParamBase        int
	TypeParamIndex       int
	TypeParamNullability TypeNullability
}

// FuncTypeInfo holds parameter count data extracted from a FunctionType object.
type FuncTypeInfo struct {
	RefID       int
	NumFixed    int  // fixed parameters (excludes implicit 'this')
	NumOptional int  // optional parameters
	HasImplicit bool // true if instance method (has implicit 'this' parameter)

	// HasNamedOptional is packed_parameter_counts bit 1
	// (UntaggedFunctionType::PackedHasNamedOptionalParameters, raw_object.h
	// @3.12.2 -- it sits between PackedNumImplicitParameters at bit 0 and
	// PackedNumFixedParameters at bit 2).
	//
	// It decides what NumOptional MEANS: the optional parameters are named
	// when this is set and positional when it is not. Without it,
	// named_parameter_names cannot be interpreted at all -- a function with
	// optional POSITIONAL parameters has an empty names array, and reading
	// one anyway invents names for parameters that never had any.
	HasNamedOptional bool

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

	// ResultTypeRefID is the ref ID of this FunctionType's result_type
	// (an AbstractType object): the declared return type of the function.
	// -1 when not captured/not applicable.
	//
	// Its ref-loop index is FuncTypeParamTypesIdx-1, because
	// UntaggedFunctionType lays out type_parameters, result_type,
	// parameter_types consecutively (verified in raw_object.h @3.9.2).
	ResultTypeRefID int

	// NamedParamNamesArrayRefID is the ref ID of this FunctionType's
	// named_parameter_names Array object: the names of named optional
	// parameters (e.g. ["name", "age"] for foo({String? name, int? age})).
	// -1 when absent or not captured for this Dart version.
	//
	// Its ref-loop index is FuncTypeParamTypesIdx+1, because
	// UntaggedFunctionType lays out type_parameters, result_type,
	// parameter_types, named_parameter_names consecutively
	// (VISIT_TO(named_parameter_names), verified in raw_object.h @3.12.2).
	// The Array's elements are String refs, resolved via
	// ArrayInfo.ElementRefIDs → Strings (same chain as TypeParamNames).
	NamedParamNamesArrayRefID int
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
	RefID     int
	NameRefID int
	ClassID   int32

	// InstanceSize, NextFieldOff and TypeArgsOff are all in WORDS, not bytes.
	// The serializer writes them straight from the *_in_words fields:
	//
	//	s->Write<int32_t>(Class::target_instance_size_in_words(cls));
	//	s->Write<int32_t>(Class::target_next_field_offset_in_words(cls));
	//	s->Write<int32_t>(Class::target_type_arguments_field_offset_in_words(cls));
	//	                        -- app_snapshot.cc:1050-1053 @3.13.0
	//
	// Two of these carried "in bytes" comments while the code that used them
	// multiplied by wordSize, which is right. The comments were the wrong
	// half, and TypeArgsOff had no reader at all to contradict them -- so the
	// first consumer would have been wrong by a factor of 8.
	InstanceSize int32
	NextFieldOff int32
	// TypeArgsOff is the word offset of the instance's TypeArguments pointer,
	// or NoTypeArguments (-1) for a class that has none. object.h:1369 defines
	// that sentinel; treating it as an offset yields word -1.
	TypeArgsOff    int32
	SuperTypeRefID int // ref ID of the super_type Type object (-1 if not captured for this spec.NumRefs)
	LibraryRefID   int // ref ID of the owning Library object (-1 if not captured for this spec.NumRefs)
	// TypeParamsRefID is the class's TypeParameters object. RefNull means the
	// class declares no type parameters; -1 means the field was not captured.
	// For Dart <=3.0 the TTS namer uses this class-local arity to select only
	// the trailing own arguments from Type.arguments(). Dart >=3.1 names the
	// full vector instead.
	TypeParamsRefID int

	// UnboxedFieldBitmap marks which of this class's instance field slots hold
	// a raw machine word rather than a ref, indexed by word offset from the
	// object start -- the same indexing readFillInstance uses.
	//
	// In AOT the Class cluster's fill carries this per class:
	//
	//	if (FLAG_precompiled_mode && !ClassTable::IsTopLevelCid(class_id)) {
	//	  const UnboxedFieldBitmap unboxed_fields_map(d->ReadUnsigned64());
	//	  shared_class_table->SetUnboxedFieldsMapAt(class_id, unboxed_fields_map);
	//	}
	//
	// (clustered_snapshot.cc, ClassDeserializationCluster::ReadFill.) It is
	// the ONLY copy at 2.10; from 2.12 the Instance cluster writes its own
	// copy in its fill and reads it back there. See InstanceUnboxedBitmaps.
	UnboxedFieldBitmap uint64
}

// NoTypeArguments is the sentinel ClassInfo.TypeArgsOff carries for a class
// with no type-arguments field. Source: object.h:1369,
// `static constexpr intptr_t kNoTypeArguments = -1`.
const NoTypeArguments int32 = -1

// HasTypeArguments reports whether instances of this class carry a
// TypeArguments pointer, i.e. whether TypeArgsOff is a real offset rather
// than the sentinel.
func (c ClassInfo) HasTypeArguments() bool { return c.TypeArgsOff != NoTypeArguments }

// TypeArgsByteOffset returns the byte offset of the TypeArguments pointer
// within an instance, and false when the class has none.
func (c ClassInfo) TypeArgsByteOffset(wordSize int32) (int32, bool) {
	if !c.HasTypeArguments() {
		return 0, false
	}
	return c.TypeArgsOff * wordSize, true
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

	// ArgumentsRef is the TypeArguments this type was instantiated with,
	// or -1. UntaggedType's visited range is type_test_stub, hash,
	// arguments (raw_object.h: VISIT_FROM(type_test_stub) in
	// UntaggedAbstractType, VISIT_TO(arguments) in UntaggedType), so it is
	// the LAST ref of the fill.
	//
	// Without it a type is only ever as specific as its class. The type
	// testing stub for List<double> and the one for List<String> both
	// named themselves TypeTestingStub_List, which is why they are the
	// single largest category of symbol-table disagreement: the ELF says
	// "assert type is List<double>".
	ArgumentsRef int
	// Nullability is decoded from the same scalar that carries Type state:
	// v2.15-v2.18 use the low bits of the trailing combined byte, while
	// v2.19+ packs them into flags. Unknown means the layout was not captured
	// and exact type naming must refuse rather than silently drop a suffix.
	Nullability TypeNullability
}

// RecordTypeInfo holds the serialized identity needed to reproduce the VM's
// TypeTestingStubNamer spelling for a RecordType. Dart 3.x stores the packed
// RecordShape as a Smi ref and the record's AbstractType field vector as an
// Array ref; named-field strings are reached separately through ObjectStore's
// record_field_names table using the shape's field-names index.
type RecordTypeInfo struct {
	RefID              int
	ShapeRef           int
	FieldTypesArrayRef int
	Nullability        TypeNullability
}

// TypeNullability mirrors the VM's semantic nullability states without
// exposing their version-dependent packed bit width. Dart 2.x/early 3.x use
// two bits (nullable=0, non-nullable=1, legacy=2); Dart 3.5+ uses one bit and
// therefore has only nullable/non-nullable. Unknown is deliberately separate
// from nullable even though the VM encodes nullable as zero.
type TypeNullability uint8

const (
	TypeNullabilityUnknown TypeNullability = iota
	TypeNullabilityNullable
	TypeNullabilityNonNullable
	TypeNullabilityLegacy
)

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
	UnitID    int64 // loading unit ID; serialized as intptr_t from Dart 3.5+
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

// ClosureInfo holds a Closure object's function ref, enabling closure
// dispatch BLR resolution. UntaggedClosure ReadFromTo (raw_object.h):
// instantiator_type_arguments(0), function_type_arguments(1),
// delayed_type_arguments(2), function(3), context(4), hash(5).
// The function ref (index 3) points to the Function the closure wraps.
type ClosureInfo struct {
	RefID       int
	FunctionRef int // ref ID of the wrapped Function (-1 if not captured)
}

// CompressedStackMapsInfo holds one CompressedStackMaps object's canonical
// decoder input: the little-endian uint32 flags_and_size header followed by
// the encoded map bytes. The analysis pipeline consumes these maps for GC
// pointer-slot annotations in both decompilation and stack_maps.jsonl.
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
	HostOffset       int32 // ref ID of instance-field word offset Smi/Mint; -1 for static fields
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

// initialCaptureCap bounds speculative slice capacity derived from snapshot
// counts. Counts are attacker-controlled and can be large while the remaining
// fill stream is tiny; preallocating the declared count before reading a single
// object turns a few bytes of malformed input into a large memory allocation.
//
// This affects capacity only, never the number of objects parsed. Slices grow
// normally as valid input is consumed.
func initialCaptureCap(count int64, remaining int) int {
	if count <= 0 || remaining <= 0 {
		return 0
	}
	n := count
	if n > int64(remaining) {
		n = int64(remaining)
	}
	const maxInitialCapture = 4096
	if n > maxInitialCapture {
		n = maxInitialCapture
	}
	return int(n)
}

// validateFillLength cross-checks the size scalar serialized twice by Dart's
// variable-size clusters: once during ReadAlloc (to allocate the object) and
// again during ReadFill (to initialize/populate it). The alloc pass records the
// first copy in ClusterMeta.Lengths. Accepting a different fill copy lets a
// corrupt snapshot drive large loops/allocations even though the object that
// was supposedly allocated had a different shape.
func validateFillLength(cm *ClusterMeta, index int64, got int64, label string) error {
	if cm == nil || index < 0 || index >= cm.Count {
		return fmt.Errorf("%s: invalid object index %d", label, index)
	}
	if int64(len(cm.Lengths)) != cm.Count {
		return fmt.Errorf("%s %d/%d: alloc lengths missing or incomplete (%d recorded)", label, index, cm.Count, len(cm.Lengths))
	}
	want := cm.Lengths[index]
	if got != want {
		return fmt.Errorf("%s %d/%d: fill length %d differs from alloc length %d", label, index, cm.Count, got, want)
	}
	return nil
}

// advanceRODataOffset applies the VM's `delta << kObjectAlignmentLog2` using
// checked arithmetic. Both delta and the cumulative offset are snapshot data;
// unchecked signed shifts/additions can wrap to a negative slice index.
func advanceRODataOffset(current, delta int64, shift uint) (int64, bool) {
	if current < 0 || delta < 0 || shift >= 63 {
		return 0, false
	}
	maxInt64 := int64(^uint64(0) >> 1)
	if delta > maxInt64>>shift {
		return 0, false
	}
	inc := delta << shift
	if current > maxInt64-inc {
		return 0, false
	}
	return current + inc, true
}

func checkedAddNonnegativeInt64(a, b int64) (int64, bool) {
	if a < 0 || b < 0 {
		return 0, false
	}
	maxInt64 := int64(^uint64(0) >> 1)
	if a > maxInt64-b {
		return 0, false
	}
	return a + b, true
}

// classUnboxedBitmaps indexes the per-class unboxed-field bitmaps captured
// from the Class cluster by class id, for the Instance clusters that need them
// (see readFillInstance). The Class cluster is serialized before every
// Instance cluster, so by the time this is first asked for it is complete;
// the result is memoized because there are hundreds of Instance clusters and
// thousands of classes.
func classUnboxedBitmaps(result *Result) map[int32]uint64 {
	if result.unboxedByClassID != nil {
		return result.unboxedByClassID
	}
	m := make(map[int32]uint64, len(result.Classes))
	for i := range result.Classes {
		if b := result.Classes[i].UnboxedFieldBitmap; b != 0 {
			m[result.Classes[i].ClassID] = b
		}
	}
	result.unboxedByClassID = m
	return m
}

// DebugFillPositions iterates the fill section and prints the stream position
// before/after each cluster's fill to w. Used to diagnose fill drift.
func DebugFillPositions(data []byte, result *Result, profile *snapshot.VersionProfile, isVM bool, w io.Writer) error {
	if result.FillStart <= 0 || result.FillStart >= len(data) {
		return fmt.Errorf("fill: invalid start offset %d", result.FillStart)
	}
	s, err := dartfmt.NewStreamAt(data, result.FillStart)
	if err != nil {
		return fmt.Errorf("fill: debug stream start: %w", err)
	}
	fillRefUnsigned := profile.FillRefUnsigned
	instrIdx := 0
	// Keep the minimal fill state needed by later clusters. In particular,
	// Dart 2.10 stores Instance unboxed-field bitmaps only in the preceding
	// Class cluster, so a stateless debug walk cannot size Instance fill
	// correctly. Using a scratch Result also avoids mutating the scan result.
	scratch := &Result{}
	for i := range result.Clusters {
		cm := &result.Clusters[i]
		spec := GetFillSpec(cm.CID, cm, profile)
		startPos := s.Position()
		name := CidNameV(cm.CID, profile.CIDs)
		if name == "" {
			name = fmt.Sprintf("CID_%d", cm.CID)
		}
		err := fillOneCluster(s, cm, &spec, fillRefUnsigned, profile, &instrIdx, scratch)
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
func ReadFill(data []byte, result *Result, profile *snapshot.VersionProfile, isVM bool, snapshotSize int64, opts dartfmt.Options) error {
	if result == nil {
		return fmt.Errorf("fill: nil cluster result")
	}
	if !result.AllocComplete {
		return fmt.Errorf("fill: alloc phase incomplete; refusing to treat offset %d as fill start", result.FillStart)
	}
	if result.FillStart <= 0 || result.FillStart >= len(data) {
		return fmt.Errorf("fill: invalid start offset %d", result.FillStart)
	}

	s, err := dartfmt.NewStreamAt(data, result.FillStart)
	if err != nil {
		return fmt.Errorf("fill: stream start: %w", err)
	}
	if opts.MaxBytes > 0 {
		est, err := estimateFillCaptureBytes(result, profile)
		if err != nil {
			return fmt.Errorf("fill: capture budget estimate: %w", err)
		}
		if est > int64(opts.MaxBytes) {
			return fmt.Errorf("fill: decoded capture estimate %d bytes exceeds max_bytes %d", est, opts.MaxBytes)
		}
	}
	ct := profile.CIDs
	fillRefUnsigned := profile.FillRefUnsigned
	maxSteps := opts.EffectiveMaxSteps()
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

		case FillNone:
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
			var payloads [][]byte
			var err error
			if captureCSM2 {
				payloads, err = readFillCompressedStackMaps(s, cm, spec.InlineBytesLengthShift)
			} else {
				payloads, err = readFillInlineBytes(s, cm, capturePcDesc || captureCSM, spec.InlineBytesLengthShift)
			}
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
			named, funcTypes, fieldInfos, typeInfos, recordTypeInfos, icDataInfos, scriptInfos, loadingUnitInfos, closureDataInfos, typeParamInfos, closureInfos, ffiInfos, err := readFillRefs(s, cm, &spec, fillRefUnsigned, profile)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (CID %d): %w", i, cm.CID, err)
			}
			result.Named = append(result.Named, named...)
			result.FuncTypes = append(result.FuncTypes, funcTypes...)
			result.Fields = append(result.Fields, fieldInfos...)
			result.Types = append(result.Types, typeInfos...)
			result.RecordTypes = append(result.RecordTypes, recordTypeInfos...)
			result.ICData = append(result.ICData, icDataInfos...)
			result.Scripts = append(result.Scripts, scriptInfos...)
			result.LoadingUnits = append(result.LoadingUnits, loadingUnitInfos...)
			result.ClosureData = append(result.ClosureData, closureDataInfos...)
			result.TypeParameters = append(result.TypeParameters, typeParamInfos...)
			result.Closures = append(result.Closures, closureInfos...)
			result.FfiTrampolines = append(result.FfiTrampolines, ffiInfos...)

		case FillDouble:
			if err := skipFillDouble(s, cm, profile.PreCanonicalSplit); err != nil {
				return fmt.Errorf("fill: cluster %d (Double): %w", i, err)
			}

		case FillCode:
			codes, err := readFillCode(s, cm, profile.CIDs, fillRefUnsigned, instrIdx, profile.CodeNumRefs, profile.CodeTextOffsetDelta, profile.CodeStateBitsAfterRef, profile.CodeStateBitsAtEnd, profile.CodeFillHasIndexRefs)
			if err != nil {
				return fmt.Errorf("fill: cluster %d (Code): %w", i, err)
			}
			result.Codes = append(result.Codes, codes...)
			// Advance instrIdx by the number of main (non-deferred) codes.
			instrIdx += int(cm.MainCount)

		case FillObjectPool:
			pool, err := readFillObjectPool(s, cm, profile, fillRefUnsigned)
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
			if result.Int32Arrays == nil {
				result.Int32Arrays = make(map[int][]byte)
			}
			if err := readFillTypedData(s, cm, profile.CIDs, profile.PreCanonicalSplit, result.Int32Arrays); err != nil {
				return fmt.Errorf("fill: cluster %d (TypedData CID %d): %w", i, cm.CID, err)
			}

		case FillExternalTypedData:
			if err := skipFillExternalTypedData(s, cm, profile.CIDs); err != nil {
				return fmt.Errorf("fill: cluster %d (ExternalTypedData CID %d): %w", i, cm.CID, err)
			}

		case FillSimd128:
			if err := skipFillSimd128(s, cm); err != nil {
				return fmt.Errorf("fill: cluster %d (SIMD CID %d): %w", i, cm.CID, err)
			}

		case FillDeltaEncodedTypedData:
			if err := skipFillDeltaEncodedTypedData(s, cm, maxSteps); err != nil {
				return fmt.Errorf("fill: cluster %d (DeltaEncodedTypedData CID %d): %w", i, cm.CID, err)
			}

		case FillLocalVarDescriptors:
			if err := skipFillLocalVarDescriptors(s, cm, fillRefUnsigned, maxSteps); err != nil {
				return fmt.Errorf("fill: cluster %d (LocalVarDescriptors CID %d): %w", i, cm.CID, err)
			}

		case FillLegacyMap:
			if err := skipFillLegacyMap(s, cm, fillRefUnsigned, spec.LeadingBool, maxSteps); err != nil {
				return fmt.Errorf("fill: cluster %d (legacy Map CID %d): %w", i, cm.CID, err)
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
			instInfos, err := readFillInstance(s, cm, profile, classUnboxedBitmaps(result))
			if err != nil {
				return fmt.Errorf("fill: cluster %d (Instance CID %d): %w", i, cm.CID, err)
			}
			result.Instances = append(result.Instances, instInfos...)

		case FillRecord:
			if err := skipFillRecord(s, cm, fillRefUnsigned, profile); err != nil {
				return fmt.Errorf("fill: cluster %d (Record): %w", i, err)
			}

		case FillContextScope:
			if err := skipFillContextScope(s, cm, fillRefUnsigned, profile); err != nil {
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
			// CompressedStackMaps has a different ROData object header from
			// PcDescriptors/CodeSourceMap: flags_and_size replaces their uword
			// length_. Use its dedicated extractor so the flags survive.
			for _, cm := range rodataCSM2Clusters {
				result.CompressedStackMaps = append(result.CompressedStackMaps,
					extractRODataCompressedStackMaps(data, cm, objStart, profile)...)
			}
		}
	}

	resolveTypeClassIDs(result)

	return nil
}

// estimateFillCaptureBytes computes a conservative logical retained-output
// budget from alloc-phase metadata before the fill parser allocates any of the
// variable-sized capture slices. It intentionally overestimates fixed records;
// MaxBytes is a safety ceiling, not a serialization-size promise.
func estimateFillCaptureBytes(result *Result, profile *snapshot.VersionProfile) (int64, error) {
	var total int64
	add := func(n int64) error {
		if n < 0 || total > math.MaxInt64-n {
			return fmt.Errorf("capture-size overflow")
		}
		total += n
		return nil
	}
	mul := func(a, b int64) (int64, error) {
		if a < 0 || b < 0 || (a != 0 && b > math.MaxInt64/a) {
			return 0, fmt.Errorf("capture-size multiplication overflow (%d*%d)", a, b)
		}
		return a * b, nil
	}
	sumLengths := func(cm *ClusterMeta, shift uint) (int64, error) {
		var sum int64
		for _, raw := range cm.Lengths {
			if raw < 0 {
				return 0, fmt.Errorf("CID %d has negative alloc length %d", cm.CID, raw)
			}
			v := raw >> shift
			if sum > math.MaxInt64-v {
				return 0, fmt.Errorf("CID %d length sum overflow", cm.CID)
			}
			sum += v
		}
		return sum, nil
	}
	ct := profile.CIDs
	for i := range result.Clusters {
		cm := &result.Clusters[i]
		spec := GetFillSpec(cm.CID, cm, profile)
		count := cm.Count
		if count < 0 {
			return 0, fmt.Errorf("CID %d negative count %d", cm.CID, count)
		}
		// Fixed per-object bookkeeping retained by the capture layer. 192 bytes
		// comfortably covers current structs/maps/slice headers without relying
		// on Go's architecture-specific unsafe.Sizeof values.
		fixed := int64(0)
		switch spec.Kind {
		case FillRefs, FillCode, FillObjectPool, FillArray, FillExceptionHandlers,
			FillContext, FillTypeArguments, FillClass, FillField, FillInstance:
			fixed = 192
		case FillString, FillInlineBytes:
			fixed = 48
		}
		if fixed != 0 {
			n, err := mul(count, fixed)
			if err != nil {
				return 0, err
			}
			if err := add(n); err != nil {
				return 0, err
			}
		}

		switch spec.Kind {
		case FillString:
			sum, err := sumLengths(cm, func() uint {
				if profile.OldStringFormat {
					return 0
				}
				return 1
			}())
			if err != nil {
				return 0, err
			}
			// UTF-16 decoding transiently uses []rune and the resulting UTF-8
			// string; 8 bytes/code-unit is a conservative combined budget.
			n, err := mul(sum, 8)
			if err != nil {
				return 0, err
			}
			if err := add(n); err != nil {
				return 0, err
			}
		case FillInlineBytes:
			capture := ct != nil && ((ct.PcDescriptors != 0 && cm.CID == ct.PcDescriptors) ||
				(ct.CodeSourceMap != 0 && cm.CID == ct.CodeSourceMap) ||
				(ct.CompressedStackMaps != 0 && cm.CID == ct.CompressedStackMaps))
			if capture {
				sum, err := sumLengths(cm, spec.InlineBytesLengthShift)
				if err != nil {
					return 0, err
				}
				if err := add(sum); err != nil {
					return 0, err
				}
			}
		case FillArray, FillContext, FillTypeArguments:
			sum, err := sumLengths(cm, 0)
			if err != nil {
				return 0, err
			}
			n, err := mul(sum, 8)
			if err != nil {
				return 0, err
			}
			if err := add(n); err != nil {
				return 0, err
			}
		case FillObjectPool:
			sum, err := sumLengths(cm, 0)
			if err != nil {
				return 0, err
			}
			n, err := mul(sum, 48)
			if err != nil {
				return 0, err
			}
			if err := add(n); err != nil {
				return 0, err
			}
		case FillExceptionHandlers:
			sum, err := sumLengths(cm, 0)
			if err != nil {
				return 0, err
			}
			n, err := mul(sum, 24)
			if err != nil {
				return 0, err
			}
			if err := add(n); err != nil {
				return 0, err
			}
		case FillTypedData:
			if ct != nil && cm.CID == typedDataInt32ArrayCid(ct) {
				sum, err := sumLengths(cm, 0)
				if err != nil {
					return 0, err
				}
				n, err := mul(sum, 4)
				if err != nil {
					return 0, err
				}
				if err := add(n); err != nil {
					return 0, err
				}
			}
		case FillRefs:
			if spec.VarLenRefs {
				sum, err := sumLengths(cm, 0)
				if err != nil {
					return 0, err
				}
				n, err := mul(sum, 8)
				if err != nil {
					return 0, err
				}
				if err := add(n); err != nil {
					return 0, err
				}
			}
		}
	}
	return total, nil
}

// resolveTypeClassIDs turns the captured Type.type_class_id Smi ref into a
// class id, for the Dart versions (2.10-2.14) that serialise it as a pointer
// inside the visited range rather than as a scalar after it.
//
// This runs HERE, at the end of the fill phase, rather than in whichever
// consumer happens to need it first. It used to live in
// typetrack.BuildTypeContext and mutate the shared Result in place, which made
// TypeInfo.ClassID mean different things depending on which package had run:
//
//   - Its own doc comment records the first casualty -- it once ran after
//     BuildClassHierarchy, so "the hierarchy saw 0 for every Type and came out
//     empty on 2.x, taking LCA, CHA and any leaf-class test with it."
//   - The second was analysis.BuildFieldTypeByClassOffset, which reads
//     result.Types[i].ClassID directly from a path that never calls
//     BuildTypeContext. Measured on byte-identical Dart source: 0 classes and
//     0 resolved field-type slots at 2.13.0 and 2.14.0, against 84 and 178 at
//     2.16.0.
//
// Moving the call a second time would only relocate the hazard. Resolving at
// parse time removes it: ClassID is meaningful the moment a Result exists, and
// no consumer needs to know TypeClassIdRef is there.
//
// MintValues is filled during the alloc phase, which precedes fill, so the
// values are already available. No-op from 2.15 on, where the class id is a
// scalar and TypeClassIdRef is never set.
func resolveTypeClassIDs(result *Result) {
	if len(result.MintValues) == 0 {
		return
	}
	for i := range result.Types {
		ti := &result.Types[i]
		if ti.ClassID == 0 && ti.TypeClassIdRef > 0 {
			if v, ok := result.MintValues[ti.TypeClassIdRef]; ok {
				ti.ClassID = int32(v)
			}
		}
	}
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
	case FillNone, FillROData:
		// No fill data.
	case FillInlineBytes:
		return skipFillInlineBytes(s, cm, spec.InlineBytesLengthShift)
	case FillRefs:
		_, _, _, _, _, _, _, _, _, _, _, _, err := readFillRefs(s, cm, spec, fillRefUnsigned, profile)
		return err
	case FillDouble:
		return skipFillDouble(s, cm, profile.PreCanonicalSplit)
	case FillCode:
		_, err := readFillCode(s, cm, profile.CIDs, fillRefUnsigned, *instrIdx, profile.CodeNumRefs, profile.CodeTextOffsetDelta, profile.CodeStateBitsAfterRef, profile.CodeStateBitsAtEnd, profile.CodeFillHasIndexRefs)
		*instrIdx += int(cm.MainCount)
		return err
	case FillObjectPool:
		_, err := readFillObjectPool(s, cm, profile, fillRefUnsigned)
		return err
	case FillArray:
		return skipFillArray(s, cm, fillRefUnsigned, profile)
	case FillWeakArray:
		return skipFillWeakArray(s, cm, fillRefUnsigned)
	case FillTypedData:
		// Skip-only path (used to step over a cluster whose contents are not
		// wanted): pass no sink, so nothing is captured.
		return readFillTypedData(s, cm, profile.CIDs, profile.PreCanonicalSplit, nil)
	case FillExternalTypedData:
		return skipFillExternalTypedData(s, cm, profile.CIDs)
	case FillSimd128:
		return skipFillSimd128(s, cm)
	case FillDeltaEncodedTypedData:
		return skipFillDeltaEncodedTypedData(s, cm, dartfmt.DefaultMaxSteps)
	case FillLocalVarDescriptors:
		return skipFillLocalVarDescriptors(s, cm, fillRefUnsigned, dartfmt.DefaultMaxSteps)
	case FillLegacyMap:
		return skipFillLegacyMap(s, cm, fillRefUnsigned, spec.LeadingBool, dartfmt.DefaultMaxSteps)
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
		_, classes, err := readFillClass(s, cm, spec, fillRefUnsigned, profile.TopLevelCid16, profile.ClassHasTokenPos)
		if err == nil && result != nil {
			result.Classes = append(result.Classes, classes...)
		}
		return err
	case FillField:
		_, _, err := readFillField(s, cm, spec, fillRefUnsigned)
		return err
	case FillInstance:
		_, err := readFillInstance(s, cm, profile, classUnboxedBitmaps(result))
		return err
	case FillRecord:
		return skipFillRecord(s, cm, fillRefUnsigned, profile)
	case FillContextScope:
		return skipFillContextScope(s, cm, fillRefUnsigned, profile)
	default:
		return fmt.Errorf("unknown fill kind %d", spec.Kind)
	}
	return nil
}
