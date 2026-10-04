package typetrack

import (
	"slices"

	"aotopsy/internal/cluster"
	"aotopsy/internal/sdk"
	"aotopsy/internal/snapshot"
)

// TypeContext holds all precomputed lookup tables needed for type inference.
// It is built once from cluster.Result + PoolLookups and reused across
// all functions during intra-procedural and inter-procedural analysis.
type TypeContext struct {
	// DartVersion is required for calling-convention decisions. Register
	// parameters do not exist before 3.4.3; leaving version outside the type
	// context made inter-procedural propagation silently assume a modern ABI for
	// every supported snapshot.
	DartVersion string
	// funcParamTypes[funcRefID] = list of parameter ClassIDs (or -1 if unknown).
	// Index 0 = 'this' receiver for instance methods.
	FuncParamTypes map[int][]int

	// fieldTypes[fieldRefID] = ClassID of the field's declared type (or -1).
	// Used when a field load (LDUR Xn, [Xm, #offset]) is encountered:
	// the loaded value has the field's declared type.
	FieldTypes map[int]int

	// fieldByOwnerOffset[ownerClassID][byteOffset] = fieldRefID.
	// Maps a class + host offset to the field stored there, so we can
	// look up fieldTypes when we see LDUR Xn, [Xm, #offset] and know
	// Xm's type (the receiver).
	FieldByOwnerOffset map[int]map[int32]int

	// poolClassByIndex[poolIndex] = runtime ClassID of the OBJECT stored at
	// PP[poolIndex]. A Type object remains kTypeCid; the class described by the
	// Type is metadata, not the runtime class of the loaded heap object.
	PoolClassByIndex map[int]int

	// dispatchBySlot[slot] = DispatchTableEntry for that slot.
	// Maps a dispatch table slot index to its target (Code/Stub/Null).
	DispatchBySlot map[int]cluster.DispatchTableEntry

	// superClass[classID] = superclassID (or -1). Besides object-bound joins,
	// its keys form the structural runtime-CID universe for selector scans.
	SuperClass map[int]int

	// dispatchCodeIndexToName[clusterIndex] = function name.
	// Direct lookup from dispatch table ClusterIndex to resolved name.
	DispatchCodeIndexToName map[int]string

	// classIDToName[classID] = class name (for debugging/reporting).
	ClassIDToName map[int]string

	// funcIsInstance[funcRefID] = true if instance method (has 'this').
	FuncIsInstance map[int]bool

	// FuncOwnerClass maps function name → owner class ID.
	// It contains INSTANCE methods only; class-owned static methods are excluded.
	// Used to initialize the receiver when its location is independently proven.
	FuncOwnerClass map[string]int
	// FuncMayUseRegisterCC is a conservative per-function eligibility gate from
	// snapshot metadata. True does not prove register arguments (precompiler
	// unboxing metadata can still force the stack); RunInterprocedural further
	// requires independent multi-call-site register-setup evidence.
	FuncMayUseRegisterCC map[string]bool
	// FuncReceiverInRegister is callee-side machine-code evidence that the SDK
	// convention's receiver register is live on function entry. This is separate
	// from call-site masks because virtual methods can have zero direct callers --
	// exactly the methods whose receiver type matters for BLR resolution.
	FuncReceiverInRegister map[string]bool

	// FuncReceiverStackSlot maps a function name to the FP-relative byte offset
	// its receiver arrives at, for the Dart versions that pass arguments on the
	// stack rather than in registers.
	//
	// Before Dart 3.4.3 there is no DartCallingConvention: arguments, receiver
	// included, come in on the caller's stack. From 3.4.3 onward the register
	// table exists, but Function::MaxNumberOfParametersInRegisters still forces
	// generics, closures/tear-offs, FFI trampolines and several generated kinds
	// to the stack; precompiler unboxing metadata can force further functions.
	// This map therefore remains meaningful on modern binaries too, but is only
	// populated where stack calling is proved or recovered from actual code.
	FuncReceiverStackSlot map[string]int

	// ReceiverLoadAtPC types the destination of an
	// ArgumentsDescriptor-relative parameter-0 load, keyed by the load's PC.
	//
	// It is keyed by PC rather than by function because that is where the
	// value comes into existence: a function with optional parameters has no
	// static receiver slot to seed and no receiver register at entry, so an
	// entry seed would be overwritten by the load itself. See
	// RecoverArgsDescReceiverARM64.
	//
	// It can be populated on modern stack-called functions as well.
	ReceiverLoadAtPC map[uint64]ReceiverLoad

	// ClassIDTagPos and ClassIDTagSize are the ClassIdTag bitfield's position
	// and width in the object header's tags word, from
	// snapshot.ClassIdTagLayout:
	//
	//	<= 2.18.0  pos 16, size 16 -- movzxw(result, FieldAddress(obj, tags + 16/8))
	//	>= 2.19.0  pos 12, size 20 -- movl(result, FieldAddress(obj, tags)); shrl(12)
	//
	// These replace a ClassIDIsHalfWord boolean. The boolean answered
	// "is it the 16-bit form?" and threw away the two numbers that answer it,
	// so the x86 handler then hardcoded `mem.Disp == 1` to rediscover what
	// position 16 implies -- FieldAddress subtracts the heap tag, so the
	// half-word sits at (pos/8) - kHeapObjectTag = 1. Carrying the numbers
	// lets the handler compute that displacement, and makes a future third
	// layout a changed constant rather than a silent misread.
	ClassIDTagPos  int
	ClassIDTagSize int

	// HalfWordClassIDDisp is computed from the two above by
	// SetClassIDTagLayout; see its doc comment.
	halfWordClassIDDisp int64
	halfWordClassID     bool

	// FuncReturnType maps function NamedObject refID → return type ClassID.
	// Built from FunctionType.result_type (AbstractType → Type → ClassID).
	// Used to seed CalleeExitTypes as ClassBound. A declaration constrains the
	// returned object to that class/subclasses; it is not an exact runtime class.
	FuncReturnType map[int]int

	// RefToType maps Type ref ID → TypeInfo, including both isolate
	// and VM snapshot Types. Built once in BuildTypeContext and shared across
	// buildFieldTypes and buildFuncParamTypes.
	RefToType map[int]*cluster.TypeInfo

	// KOriginElement is the dispatch table origin element offset.
	// The Dart runtime allocates the dispatch table with KOriginElement
	// padding entries at the beginning, so entries[0] corresponds to
	// runtime slot -KOriginElement. ARM64=4096, x86_64=16.
	// DispatchBySlot is keyed by (entry.Index - KOriginElement) so that
	// computed slots (cid + selector_offset - KOriginElement) map directly.
	KOriginElement int

	// THRFields maps THR byte offset → field name (e.g. "allocate_object_ep").
	// Used to identify THR loads (LDR Xt, [X26, #imm]) as KnownStub.
	THRFields map[int]string

	// AllocStubOffsets maps THR byte offset → allocation stub name.
	// Used to identify allocation stub calls (from ThreadStubOffsets).
	AllocStubOffsets map[int64]string

	// Fase 7 PART A: CalleeExitTypes maps BL target address → callee's
	// ExitTypes[0] (return value type). Populated by inter-procedural
	// iteration. Used by transferInstruction to propagate return type
	// to X0 after a BL call, enabling type chain across function calls.
	CalleeExitTypes map[uint64]TypeLattice

	// CalleeAllExitTypes maps BL target address → the callee analysis's full exit
	// array for fixed-point comparison/debugging. Call transfer functions consume
	// ONLY the ABI return register; callee-local register facts never cross a
	// Dart call boundary.
	CalleeAllExitTypes map[uint64][31]TypeLattice

	// MethodNameToRefIDs maps method name (e.g., "adoptChild") → list of
	// Function NamedObject refIDs. Used by interproc to look up
	// FuncParamTypes for each function by stripping owner/hex from the
	// pipeline function name.
	MethodNameToRefIDs map[string][]int

	// SUPER FEATURE 3: PoolUnlinkedCallNames maps PP index → UnlinkedCall
	// target_name (method name). Used to resolve IC-based BLR calls where
	// IC_DATA_REG (R5) is loaded from PP with an UnlinkedCall object.
	// UnlinkedCall.target_name gives the method name being called.
	PoolUnlinkedCallNames map[int]string

	// MethodNameToSelectorImms maps method name → selector immediates
	// (`selector_offset - kOriginElement`) where that method appears in the dispatch table. Built from
	// DispatchBySlot + DispatchCodeIndexToName in buildDispatchTables.
	// Used by resolveBLR to resolve UnlinkedCall BLR sites: when the BLR
	// register carries an UnlinkedCall with target_name "foo", we look up
	// "foo" here to find the selector immediate(s), then call selectorCandidates
	// to enumerate all class implementations of that selector.
	MethodNameToSelectorImms map[string][]int

	// PoolClosureFunctionNames maps PP index → function name for Closure
	// objects in the pool. Built from Closure.SignatureRefID (which captures
	// the Function ref at index 3). Used to resolve closure dispatch BLR:
	// when a BLR's register was loaded from a pool Closure, the target
	// function name is looked up here.
	PoolClosureFunctionNames map[int]string

	// PoolCodeNames maps PP index to function name for Code objects.
	PoolCodeNames map[int]string

	// AllocationStubCID maps the entry VA of a per-class allocation stub to
	// the class id it allocates.
	//
	// This is a structural fact, not an inference. raw_object.h says of
	// UntaggedCode::owner_: "If owner_ is a Class the owner is the allocation
	// stub for that class." naming/pool.go already computes it (and names
	// those Codes "new X"), it simply had no reader.
	//
	// What it replaces: a rule that took the allocated class from RDI on
	// x86_64, described in the code as "SysV arg 0 (receiver for instance
	// methods)". AllocateObjectABI is not the SysV convention -- it is
	// {RAX, RDX, R8} on x64 and {R0, R1, R2} on ARM64, and RDI appears inside
	// GenerateAllocateObjectHelper only as a scratch register (kNextFieldReg,
	// kTypeOffsetReg). The class actually reaches the stub in the tags word,
	// which the per-class stub materialises internally
	// (stub_code_compiler_x64.cc:2355-2362), so the caller carries it in no
	// register at all. The old guess produced an exact object-class fact that
	// downstream code could use to select a dispatch target.
	//
	// Measured on 3.12.2: 918 allocation stubs, reached by 3202 of 35060
	// direct calls on ARM64 and 3202 of 28828 on x64. ARM64 had no allocation
	// handling at all before this.
	AllocationStubCID map[uint64]int

	// TypeTestingStubNames maps PP index to the type testing stub name
	// for the Type in that pool slot. Used to resolve BLR calls through
	// AbstractType::type_test_stub_entry_point_ (offset 7 from tagged
	// pointer on non-compressed builds).
	TypeTestingStubNames map[int]string

	// InstantiatedClasses is the set of classes observed in serialized instances
	// or pool objects. It is a population metric only, not an exhaustive
	// candidate filter.
	InstantiatedClasses map[int]bool

	// SelectorOffsets maps BLR instruction address → selector offset
	// (in dispatch table slot units). Pre-scanned from the instruction
	// stream: ADD/SUB X30, X0, #imm before LDR X30, [X21, X30, LSL #3]
	// gives the selector offset. Used to resolve dispatch table calls
	// even when the receiver class ID is unknown (Top).
	SelectorOffsets map[uint64]int

	// SelectorCache caches selectorCandidates results per selector immediate.
	// Keyed by selector imm, value is the sorted unique function name list.
	// Built lazily on first call to selectorCandidates for each imm, then
	// reused across all BLR sites with the same selector and across all
	// inter-procedural iterations. This avoids re-scanning the entire
	// DispatchBySlot map (potentially hundreds of thousands of entries)
	// for every BLR site.
	//
	SelectorCache map[int][]string

	// SelectorMonomorphic maps selector imm → single function name when every
	// structural runtime CID represented by SuperClass maps that selector either
	// to that implementation or to no code entry.
	SelectorMonomorphic map[int]string

	// Debug counters.
	// PPHits counts object-pool loads that RESOLVED to something: an exact runtime
	// object class, or a KnownStub for Code/type-testing/unlinked-call/closure
	// entries. PPLoads counts every pool load the transfer function
	// saw, resolved or not, so PPHits/PPLoads is a rate rather than a bare
	// count.
	//
	// These two were briefly one number. handlePPLoad incremented PPHits on
	// every pool load on ARM64 while x86_64 kept incrementing it only on a
	// successful resolution, so typetrack_report.json's "pool_hits" meant
	// attempts on one architecture and resolutions on the other, under the
	// same key.
	PPHits       int
	PPLoads      int
	HeaderHits   int
	UBFXHits     int
	ADDClassHits int
	DispatchHits int
	// AllocStubHits counts calls resolved to a per-class allocation stub,
	// where the result register's class comes from Code.owner rather than
	// from any register the caller set up. Both architectures.
	AllocStubHits int
	// NarrowHits counts flow-sensitive narrowings actually applied: a
	// `CMP class_id, #N` whose equality edge turned the compared CID scalar
	// into ExactClassID(N). Both ARM64 and x86_64 implement narrowing.
	NarrowHits int
	// NarrowShape / NarrowNoType diagnose why narrowing does or does not
	// fire: how many block edges had the right shape (a CMP against an
	// immediate, terminated by an equality branch), and how many of those
	// had an untyped register so nothing could be narrowed.
	NarrowShape  int
	NarrowNoType int

	// x86_64 dispatch-call diagnosis. The SDK folds the dispatch slot into
	// the CALL's addressing mode there --
	// flow_graph_compiler_x64.cc: `call(Address(table_reg, cid_reg, TIMES_8,
	// (selector_offset - kOriginElement) * kWordSize))` -- so resolving one
	// needs BOTH the table register and the class-id register to be typed.
	// These say which of the two is missing when it fails, instead of
	// leaving the 39x dispatch_hits gap against ARM64 unexplained.
	X86DispatchShape    int // CALL [base + cid_reg*8 + disp] matched
	X86DispatchNoTable  int // ...but the base register is not a known dispatch table
	X86DispatchNoClass  int // ...but cid_reg does not hold an exact class-ID scalar
	X86DispatchResolved int // ...and both were known
	// Splitting NoClass by WHY distinguishes no CID producer (Top) from a proven
	// class-ID scalar whose numeric value is unknown.
	X86DispatchClassTop        int
	X86DispatchClassUnknownCID int
	X86DispatchClassOther      int
	// Debug: BL return value propagation stats.
	BLTotal       int
	BLHasExitType int
	BLExitKnown   int
	// BLR lattice state distribution at the BLR point. Counts which
	// lattice kind the BLR register has when resolveBLR is called,
	// diagnosing why monomorphic rate is what it is.
	BLRAtKnownDispatch    int // direct slot lookup possible
	BLRAtKnownDispatchSel int // SelectorOnly — selector scan
	BLRAtObject           int // object value reached a control-target register
	BLRAtStub             int // KnownStub
	BLRAtTop              int // no info at all
	BLRAtUnreachable      int // invariant violation: Bottom reached executable BLR
	BLRAtOther            int // anything else
	// Field type source count. Only declared types are authoritative bounds.
	FieldTypeDeclaredHits int // FieldByOwnerOffset + FieldTypes
	// ArgsDescReceiverHits counts parameter-0 loads typed from the
	// ArgumentsDescriptor pattern on either architecture.
	ArgsDescReceiverHits int
	// Fixed-point telemetry. If InterConverged is false, the configured
	// propagation budget was exhausted and the engine discarded propagated
	// exact facts in favor of a conservative declared-types-only fallback pass.
	InterIterations int
	InterConverged  bool
	// Private per-PC telemetry state. These maps make counters describe code-site
	// populations/final categories instead of CFG worklist or interproc revisit
	// counts.
	metricSites           map[string]map[uint64]struct{}
	x86DispatchMetricByPC map[uint64]x86DispatchMetricState
	blrMetricByPC         map[uint64]blrMetricState
	narrowMetricByPC      map[uint64]narrowMetricState
	blReturnMetricByPC    map[uint64]blReturnMetricState
	FuncReturnTypeSeeds   int `json:"func_return_type_seeds,omitempty"`

	// MintValues maps ref IDs to Smi/Mint integer values, used to
	// convert Field.HostOffset (a ref ID) to the actual word offset.
	// Set from clResult.MintValues in BuildTypeContext.
	MintValues map[int]int64 `json:"-"`

	// WordSize is the pointer size in bytes (4 for compressed pointers,
	// 8 for non-compressed). Used to convert word offsets to byte offsets
	// for FieldByOwnerOffset keys.
	WordSize int32 `json:"-"`
}

// buildMethodNameToRefIDs builds a map from method name → list of Function
// NamedObject refIDs. Used by interproc to look up FuncParamTypes.
// Q10 fix: maps BOTH the bare method name AND the qualified "Owner.method" name.
// The qualified name is more precise and avoids false matches from overloaded
// methods in different classes. Callers should try qualified name first,
// then fall back to bare method name.
func buildMethodNameToRefIDs(pl *PoolLookupData) map[string][]int {
	m := make(map[string][]int)
	if pl.RefToNamed == nil || pl.CT == nil {
		return m
	}
	// Iterate ref IDs in order. RefToNamed is a map, so appending while
	// ranging it left each name's ref-ID list in a random order -- and
	// setEntryFromParamTypes takes "the FIRST refID that has param types",
	// so an overloaded method name seeded different parameter types on
	// different runs. Downstream that surfaced as a field access whose
	// receiver class was resolved in some runs and not others.
	refIDs := make([]int, 0, len(pl.RefToNamed))
	for refID := range pl.RefToNamed {
		refIDs = append(refIDs, refID)
	}
	slices.Sort(refIDs)
	for _, refID := range refIDs {
		no := pl.RefToNamed[refID]
		if no == nil || no.CID != pl.CT.Function {
			continue
		}
		// The naming package already resolved VM-base strings, PatchClass hops,
		// closure parents, constructor spelling and top-level owners. Rebuilding a
		// name here from RefToStr silently discarded those semantics. Index each
		// Function under its exact semantic identity and its selector/leaf spelling
		// (when distinct) so interproc can use the precise key first and retain the
		// existing bare-name fallback for ambiguous call sites.
		semantic := pl.FunctionRefToName[refID]
		leaf := pl.FunctionRefToLeafName[refID]
		if semantic != "" {
			m[semantic] = append(m[semantic], refID)
		}
		if leaf != "" && leaf != semantic {
			m[leaf] = append(m[leaf], refID)
		}
	}
	return m
}

// PoolLookupData is the subset of pipeline.PoolLookups needed by typetrack.
// Passed as a struct to avoid importing the pipeline package (import cycle).
type PoolLookupData struct {
	RefToNamed            map[int]*cluster.NamedObject // ref ID → NamedObject
	RefCID                map[int]int                  // ref ID → CID (class ID of the object)
	CT                    *snapshot.CIDTable           // CID table (for Class/Function CID checks)
	BaseObjLimit          int                          // first isolate-only ref; VM fallback is legal only below this
	CodeRefToName         map[int]string               // code ref ID → function name
	VmRefCID              map[int]int                  // VM snapshot CID by ref ID
	PoolCodeNames         map[int]string               // PP index → function name for Code objects
	TypeTestingStubNames  map[int]string               // Type ref ID → type testing stub name
	FunctionRefToName     map[int]string               // Function ref ID → semantic display name from naming.PoolLookups
	FunctionRefToLeafName map[int]string               // Function ref ID → raw selector/leaf name, with guarded VM-string fallback
	ObjectRefToName       map[int]string               // named object ref ID → guarded semantic leaf name
	ClassIDToName         map[int]string               // runtime ClassID → class name resolved by naming layer
	// VmFields and VmTypes give access to the VM snapshot's Field and
	// Type objects, enabling declared field type resolution for framework
	// classes (String, List, Map, etc.) whose Fields live in the VM
	// snapshot, not the isolate snapshot.
	VmFields  []cluster.FieldInfo
	VmTypes   []cluster.TypeInfo
	VmClasses []cluster.ClassInfo
}

// BuildTypeContext constructs a TypeContext from the cluster fill result,
// pool lookup data, dispatch table entries, and version profile.
//
// clResult must have Fields, Classes, Types, FuncTypes, Named, Pool populated.
// pl provides centralized semantic/leaf names plus ref/CID metadata. Typetrack
// intentionally does not rebuild callable identities from raw string tables.
// dispatchEntries come from cluster.ParseDispatchTable.
// byCodeIndex comes from pipeline.CodeIndexToFunc.
// kOriginElement is the dispatch table origin offset (ARM64=4096, x86_64=16).
// thrFields maps THR byte offsets to field names (for allocation stub detection).
// allocStubOffsets maps THR byte offsets to allocation stub names.
func BuildTypeContext(
	clResult *cluster.Result,
	pl *PoolLookupData,
	dispatchEntries []cluster.DispatchTableEntry,
	byCodeIndex map[int]*cluster.NamedObject,
	profile *snapshot.VersionProfile,
	kOriginElement int,
	thrFields map[int]string,
	allocStubOffsets map[int64]string,
	allocationStubCID map[uint64]int,
) *TypeContext {
	ctx := &TypeContext{
		DartVersion:             "",
		FuncParamTypes:          make(map[int][]int),
		FieldTypes:              make(map[int]int),
		FieldByOwnerOffset:      make(map[int]map[int32]int),
		PoolClassByIndex:        make(map[int]int),
		DispatchBySlot:          make(map[int]cluster.DispatchTableEntry, len(dispatchEntries)),
		DispatchCodeIndexToName: make(map[int]string),
		ClassIDToName:           make(map[int]string),
		MintValues:              clResult.MintValues,
		WordSize:                8,
		FuncIsInstance:          make(map[int]bool),
		FuncOwnerClass:          make(map[string]int),
		FuncMayUseRegisterCC:    make(map[string]bool),
		FuncReceiverInRegister:  make(map[string]bool),
		FuncReceiverStackSlot:   make(map[string]int),
		ReceiverLoadAtPC:        make(map[uint64]ReceiverLoad),
		FuncReturnType:          make(map[int]int),
		RefToType:               make(map[int]*cluster.TypeInfo, len(clResult.Types)),
		KOriginElement:          kOriginElement,
		THRFields:               thrFields,
		AllocStubOffsets:        allocStubOffsets,
		AllocationStubCID:       allocationStubCID,
		CalleeExitTypes:         make(map[uint64]TypeLattice),
		CalleeAllExitTypes:      make(map[uint64][31]TypeLattice),
		MethodNameToRefIDs:      buildMethodNameToRefIDs(pl),
		InstantiatedClasses:     make(map[int]bool),
		PoolCodeNames:           make(map[int]string),
		TypeTestingStubNames:    pl.TypeTestingStubNames,
		SelectorOffsets:         make(map[uint64]int),
		SelectorCache:           make(map[int][]string),
		SelectorMonomorphic:     make(map[int]string),
	}
	if profile != nil {
		ctx.DartVersion = profile.DartVersion
	}

	// Adjust word size for compressed pointers.
	if profile != nil && profile.CompressedPointers {
		ctx.WordSize = 4
	}

	// Type class IDs are resolved at parse time now (cluster.ReadFill), so
	// TypeInfo.ClassID is already meaningful here and on every other path.
	// See cluster.resolveTypeClassIDs for why it does not live in this
	// package any more.

	// 0b. Build RefToType once: isolate Types + VM Types.
	// Shared across buildFieldTypes, buildPoolClassByIndex, buildFuncParamTypes.
	for i := range clResult.Types {
		ctx.RefToType[clResult.Types[i].RefID] = &clResult.Types[i]
	}
	for i := range pl.VmTypes {
		ctx.RefToType[pl.VmTypes[i].RefID] = &pl.VmTypes[i]
	}

	// 1. Class hierarchy + subclasses + instantiated classes.
	buildClassHierarchy(ctx, clResult, pl)

	// 2. classID → name.
	buildClassIDToName(ctx, pl)

	// 3+4. Field types + fieldByOwnerOffset.
	buildFieldTypes(ctx, clResult, pl)

	// 5. Pool class by index.
	buildPoolClassByIndex(ctx, clResult, pl)

	// 6+7. Dispatch tables + code index to name.
	buildDispatchTables(ctx, dispatchEntries, byCodeIndex, clResult, pl, kOriginElement)

	// SUPER FEATURE 3: Pool UnlinkedCall names.
	ctx.PoolUnlinkedCallNames = buildPoolUnlinkedCallNames(clResult, pl)
	ctx.PoolClosureFunctionNames = buildPoolClosureFunctionNames(clResult, pl)
	if pl.PoolCodeNames != nil {
		ctx.PoolCodeNames = pl.PoolCodeNames
	}

	// 8. FuncParamTypes + FuncIsInstance + declared return bounds.
	buildFuncParamTypes(ctx, clResult, pl)

	// Population telemetry only: observed instances/value classes are not a
	// candidate-elimination or field-type source.
	buildObservedInstantiationPopulation(ctx, clResult, pl)

	return ctx
}

// FieldValueType resolves the declared static bound of a field load. A declared
// field type is not an exact runtime class, so the result is ClassBound.
//
// Snapshot const-instance observations and scanned stores deliberately do NOT
// produce a type here. They are samples of values, not an exhaustive proof of
// all values the mutable field can hold; treating unanimity in those samples as
// exact previously let a partial observation choose a concrete dispatch callee.
//
// IMPORTANT: byteOff from the caller is the raw instruction's displacement,
// which is field_offset - kHeapObjectTag (kHeapObjectTag = 1 for both ARM64
// and x86_64 compressed-pointer builds). FieldByOwnerOffset is keyed by
// field_offset (from object
// start, without kHeapObjectTag subtraction). So we add kHeapObjectTag back
// before lookup.
// SetClassIDTagLayout records the ClassIdTag bitfield layout and derives the
// displacement at which Assembler::LoadClassId emits its half-word read.
//
// The derivation, rather than the hardcoded +1 it replaces: the class id is a
// 16-bit field starting at bit `pos`, so it is readable whole by a MOVZX at
// byte offset pos/8 from the tags word; FieldAddress subtracts kHeapObjectTag,
// so the emitted displacement is pos/8 - 1. For pos 16 that is 1, which is the
// number the handler used to assert. A layout whose class id is not 16 bits
// or not byte-aligned has no half-word form at all, and the compiler emits
// movl+shrl instead.
func (ctx *TypeContext) SetClassIDTagLayout(pos, size int) {
	ctx.ClassIDTagPos, ctx.ClassIDTagSize = pos, size
	ctx.halfWordClassID = size == 16 && pos%8 == 0
	if ctx.halfWordClassID {
		ctx.halfWordClassIDDisp = int64(pos/8) - sdk.HeapObjectTag
	}
}

// HalfWordClassIDDisp returns the displacement of the half-word class-id load
// for this build, and false when the build uses the 32-bit shift form.
func (ctx *TypeContext) HalfWordClassIDDisp() (int64, bool) {
	return ctx.halfWordClassIDDisp, ctx.halfWordClassID
}

func (ctx *TypeContext) FieldValueType(receiverCID int, byteOff int32, pc uint64) (TypeLattice, bool) {
	_, fieldRefID, ok := ctx.DeclaredFieldOwner(receiverCID, byteOff)
	if !ok {
		return Top(), false
	}
	if classID, ok := ctx.FieldTypes[fieldRefID]; ok && classID >= 0 {
		ctx.hitMetric(metricFieldDeclared, pc, &ctx.FieldTypeDeclaredHits)
		return ClassBound(classID), true
	}
	return Top(), false
}

// DeclaredFieldOwner returns the class that actually declares the field at the
// tagged-pointer-relative machine offset. receiverCID can be an exact runtime
// class or a static receiver bound; inherited fields are found by walking the
// superclass chain. No observed-instance layout is accepted here: field xrefs
// must not manufacture a declaring class from a partial runtime sample.
func (ctx *TypeContext) DeclaredFieldOwner(receiverCID int, rawOff int32) (ownerCID, fieldRefID int, ok bool) {
	lookupOff := rawOff + sdk.HeapObjectTag
	cid := receiverCID
	seen := make(map[int]bool)
	for cid >= 0 && !seen[cid] {
		seen[cid] = true
		if fields := ctx.FieldByOwnerOffset[cid]; fields != nil {
			if refID, found := fields[lookupOff]; found {
				return cid, refID, true
			}
		}
		if ctx.SuperClass == nil {
			break
		}
		next, found := ctx.SuperClass[cid]
		if !found || next < 0 || next == cid {
			break
		}
		cid = next
	}
	return 0, 0, false
}

// OwnerHasFieldAt reports whether class receiverCID (or any superclass) declares
// an instance field at the raw instruction offset rawOff (i.e. field_offset - 1,
// the form that appears in `ldr Wt, [base, #rawOff]`). Unlike FieldValueType it
// does not require the field's TYPE to be known -- it only confirms a field
// exists there. This is the validator for CODE-based receiver recovery: a
// register loaded from the candidate receiver slot is the receiver only if it is
// used as a base for a field that genuinely belongs to the owner class, which
// rules out static methods (whose parameter 0 is not an owner instance) and so
// prevents fabricating owner field names for a non-receiver value.
func (ctx *TypeContext) OwnerHasFieldAt(ownerCID int, rawOff int32) bool {
	_, _, ok := ctx.DeclaredFieldOwner(ownerCID, rawOff)
	return ok
}

// ResolveDispatchTarget resolves a dispatch table slot to a function name.
// Returns ("", false) if the slot is null, a stub, or unresolvable.
func (ctx *TypeContext) ResolveDispatchTarget(slot int) (string, bool) {
	entry, ok := ctx.DispatchBySlot[slot]
	if !ok {
		return "", false
	}
	switch entry.Kind {
	case cluster.DispatchCode:
		// Direct lookup from ClusterIndex → name.
		if name, ok2 := ctx.DispatchCodeIndexToName[entry.ClusterIndex]; ok2 && name != "" {
			return name, true
		}
		return "", false
	case cluster.DispatchStub:
		// Stubs are not Dart functions — skip for reachability.
		return "", false
	default:
		return "", false
	}
}
