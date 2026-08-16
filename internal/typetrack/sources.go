package typetrack

import (
	"slices"

	"aotopsy/internal/cluster"
	"aotopsy/internal/snapshot"
)

// TypeContext holds all precomputed lookup tables needed for type inference.
// It is built once from cluster.Result + PoolLookups and reused across
// all functions during intra-procedural and inter-procedural analysis.
type TypeContext struct {
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

	// poolClassByIndex[poolIndex] = ClassID loaded from PP[poolIndex].
	// PP loads (LDR Xt, [X27, #imm]) where the pool entry is a Type
	// or Class give us a KnownClass directly.
	PoolClassByIndex map[int]int

	// dispatchBySlot[slot] = DispatchTableEntry for that slot.
	// Maps a dispatch table slot index to its target (Code/Stub/Null).
	DispatchBySlot map[int]cluster.DispatchTableEntry

	// superClass[classID] = superclassID (or -1).
	// Used by LCA for meetType on conflicting KnownClass values.
	SuperClass map[int]int

	// codeIndexToFunc[clusterIndex] = function NamedObject.
	// Used to resolve DispatchCode entries to function names.
	CodeIndexToFunc map[int]*cluster.NamedObject

	// codeRefToName[codeRefID] = qualified function name.
	CodeRefToName map[int]string

	// dispatchCodeIndexToName[clusterIndex] = function name.
	// Direct lookup from dispatch table ClusterIndex to resolved name.
	DispatchCodeIndexToName map[int]string

	// classIDToName[classID] = class name (for debugging/reporting).
	ClassIDToName map[int]string

	// funcParamCount[funcRefID] = number of parameters (from FuncTypeInfo).
	FuncParamCount map[int]int

	// funcIsInstance[funcRefID] = true if instance method (has 'this').
	FuncIsInstance map[int]bool

	// FuncOwnerClass maps function name → owner class ID.
	// Used to initialize X0 = KnownClass(ownerClassID) for instance methods.
	FuncOwnerClass map[string]int

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

	// CalleeAllExitTypes maps BL target address → callee's full ExitTypes
	// array (all 31 registers). This enables propagating not just the
	// return value (X0) but also any other registers the callee preserves
	// or produces (e.g., allocation results in X0, class ID in R0 for
	// dispatch table calls, etc.).
	CalleeAllExitTypes map[uint64][31]TypeLattice

	// MinAppClassID is the first app-defined class ID (NumPredefinedCids).
	// Used to filter parameter types: only app-defined classes have dispatch
	// methods worth tracking. Set from version profile's CID table.
	MinAppClassID int

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

	// PoolCodeNames maps PP index to function name for Code objects.
	PoolCodeNames map[int]string

	// TypeTestingStubNames maps PP index to the type testing stub name
	// for the Type in that pool slot. Used to resolve BLR calls through
	// AbstractType::type_test_stub_entry_point_ (offset 7 from tagged
	// pointer on non-compressed builds).
	TypeTestingStubNames map[int]string

	// InstanceFieldTypes is the observed (class, byte offset) -> value class
	// map recovered from const Instance objects serialized in the snapshot:
	// classID -> byteOffset -> classID of the stored value.
	//
	// This is the consumer for the Instance capture and the seed of the
	// gap-analysis §3.1 "(class, offset) -> type map". It is *observed* type
	// information, complementary to FieldByOwnerOffset/FieldTypes which give
	// the *declared* type: it can type a field declared `dynamic`/`Object?`
	// whose canonicalized const instances all hold one concrete class.
	//
	// Only unanimous offsets are recorded. If two instances of the same class
	// store different concrete classes at the same offset, the entry is
	// dropped rather than picking one -- a wrong concrete type is worse than
	// no type, because callers treat KnownClass as authoritative. Null values
	// (RefNull) are ignored: null constrains nothing.
	//
	// Note two earlier maps here (ICDataByOwner/ICDataByPPIndex and
	// ContextVariables) were removed rather than fixed, because ICData and
	// Context are absent from AOT snapshots so both were always empty.
	InstanceFieldTypes map[int]map[int32]int

	// FieldStoreTypes is the whole-program (class, byte offset) → value class
	// map recovered from field STORE instructions in function bodies:
	// classID → byteOffset → classID of the stored value.
	// This is the interprocedural field-store → field-load tracking (gap-analysis §3.1).
	// When a STR Xt, [Xn, #offset] is encountered and both Xn (receiver) and
	// Xt (value) have KnownClass, we record (Xn.ClassID, offset) → Xt.ClassID.
	// This information is used by FieldValueClass as a third source (after
	// declared type and observed instance type) to type field loads.
	FieldStoreTypes map[int]map[int32]int

	// AllocationSites maps allocation site PC → classID.
	// Distinguishes same class allocated at different sites (gap-analysis §3.1).
	// When an allocation stub call is detected, the site (call PC) and class
	// (from the stub or from RDI/X0 before the call) are recorded.
	AllocationSites map[uint64]int

	// InstantiatedClasses is the set of class IDs that are instantiated
	// (allocated) anywhere in the program. Used by RTA (gap-analysis §3.1).
	InstantiatedClasses map[int]bool

	// ClosureDataByClosure maps closure ref ID → parent function ref ID.
	// In AOT, Context objects are not serialized, but ClosureData IS.
	// Each ClosureData has parent_function and closure refs, enabling
	// closure → parent function resolution without Context data.
	ClosureDataByClosure map[int]int

	// ClosureDataByParent maps parent function ref ID → list of closure ref IDs.
	// Reverse mapping of ClosureDataByClosure for lookup by parent function.
	ClosureDataByParent map[int][]int

	// PoolClosureClass maps PP pool index → owner class ID for Closure objects.
	// When a PP load fetches a Closure, the Closure's ClosureData.parent_function
	// gives us the declaring function, whose owner class determines the dispatch
	// table slot for any BLR through that closure. This enables BLR resolution
	// for closure calls that would otherwise be Top (no type info).
	PoolClosureClass map[int]int

	// SelectorOffsets maps BLR instruction address → selector offset
	// (in dispatch table slot units). Pre-scanned from the instruction
	// stream: ADD/SUB X30, X0, #imm before LDR X30, [X21, X30, LSL #3]
	// gives the selector offset. Used to resolve dispatch table calls
	// even when the receiver class ID is unknown (Top).
	SelectorOffsets map[uint64]int

	// Subclasses maps class ID → list of direct subclass IDs.
	// Built as the inverse of SuperClass, this is the Class Hierarchy Analysis
	// (CHA) structure: for a given receiver class, enumerate all subclasses
	// that might override a method, then collect their dispatch targets.
	Subclasses map[int][]int

	// Debug counters.
	// InstanceFieldHits counts field loads typed from observed const-instance
	// data that the declared field type could not resolve.
	InstanceFieldHits int
	PPHits            int
	HeaderHits        int
	UBFXHits          int
	ADDClassHits      int
	DispatchHits      int
	// NarrowHits counts flow-sensitive narrowings actually applied: a
	// `CMP class_id, #N` whose equality edge turned the compared register
	// into KnownClass(N). ARM64 only; x86 has no narrowing.
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
	X86DispatchNoClass  int // ...but cid_reg does not hold a KnownClass
	X86DispatchResolved int // ...and both were known
	// Splitting NoClass by WHY tells apart two different problems that a
	// single counter conflates: Top means the receiver was never typed
	// anywhere on the path (missing producer), Bottom means it was typed
	// and then contradicted (a merge killed it). Chasing the wrong one
	// wastes the effort -- the same mistake as reading one ratio without
	// checking both sides measure the same population.
	X86DispatchClassTop    int
	X86DispatchClassBottom int
	X86DispatchClassOther  int
	// Debug: BL return value propagation stats.
	BLTotal        int
	BLHasExitType  int
	BLExitKnown    int
	BLExitBottom   int
	// BLR lattice state distribution at the BLR point. Counts which
	// lattice kind the BLR register has when resolveBLR is called,
	// diagnosing why monomorphic rate is what it is.
	BLRAtKnownDispatch    int // direct slot lookup possible
	BLRAtKnownDispatchSel int // SelectorOnly — selector scan
	BLRAtKnownClass       int // scan 128 slots for this class
	BLRAtStub             int // KnownStub
	BLRAtTop              int // no info at all
	BLRAtBottom           int // conflicting info
	BLRAtOther            int // anything else
	// Field type source breakdown: which of the 3 sources in
	// FieldValueClass actually produced a hit. Diagnoses whether
	// the bottleneck is declared types, instance types, or store types.
	FieldTypeDeclaredHits int // FieldByOwnerOffset + FieldTypes
	FieldTypeInstanceHits int // InstanceFieldTypes (already counted in InstanceFieldHits)
	FieldTypeStoreHits    int // FieldStoreTypes
	// Field type map sizes: how many classes have entries in each map.
	FieldTypeDeclaredClasses int // len(FieldByOwnerOffset)
	FieldTypeStoreClasses    int // len(FieldStoreTypes)
	// Diagnostic: how many fields had their declared type resolved
	// to a ClassID in buildFieldTypes. If this is 0, the declared
	// field type source is completely dead.
	FieldTypesResolvedCount int `json:"-"`
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
		if no.NameRefID >= 0 {
			if name, ok := pl.RefToStr[no.NameRefID]; ok && name != "" {
				// Add bare method name
				m[name] = append(m[name], refID)
				// Q10: Also add qualified "Owner.method" name if owner is resolvable
				if no.OwnerRefID >= 0 {
					if ownerNo, ok2 := pl.RefToNamed[no.OwnerRefID]; ok2 && ownerNo != nil {
						if ownerName, ok3 := pl.RefToStr[ownerNo.NameRefID]; ok3 && ownerName != "" {
							qualified := ownerName + "." + name
							m[qualified] = append(m[qualified], refID)
						}
					}
				}
			}
		}
	}
	return m
}

// PoolLookupData is the subset of pipeline.PoolLookups needed by typetrack.
// Passed as a struct to avoid importing the pipeline package (import cycle).
type PoolLookupData struct {
	RefToStr            map[int]string               // ref ID → string value
	RefToNamed          map[int]*cluster.NamedObject // ref ID → NamedObject
	RefCID              map[int]int                  // ref ID → CID (class ID of the object)
	CT                  *snapshot.CIDTable           // CID table (for Class/Function CID checks)
	CodeRefToName       map[int]string               // code ref ID → function name
	VmRefToStr          map[int]string               // VM snapshot strings by ref ID
	VmRefToNamed        map[int]*cluster.NamedObject // VM snapshot NamedObjects by ref ID
	VmRefCID            map[int]int                  // VM snapshot CID by ref ID
	PoolCodeNames       map[int]string               // PP index → function name for Code objects
	TypeTestingStubNames map[int]string              // Type ref ID → type testing stub name
}

// BuildTypeContext constructs a TypeContext from the cluster fill result,
// pool lookup data, dispatch table entries, and version profile.
//
// clResult must have Fields, Classes, Types, FuncTypes, Named, Pool populated.
// pl provides RefToStr, RefToNamed, and CT for name/CID resolution.
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
) *TypeContext {
	ctx := &TypeContext{
		FuncParamTypes:          make(map[int][]int),
		FieldTypes:              make(map[int]int),
		FieldByOwnerOffset:      make(map[int]map[int32]int),
		PoolClassByIndex:        make(map[int]int),
		DispatchBySlot:          make(map[int]cluster.DispatchTableEntry, len(dispatchEntries)),
		CodeIndexToFunc:         byCodeIndex,
		CodeRefToName:           make(map[int]string),
		DispatchCodeIndexToName: make(map[int]string),
		ClassIDToName:           make(map[int]string),
		FuncParamCount:          make(map[int]int),
		FuncIsInstance:          make(map[int]bool),
		FuncOwnerClass:          make(map[string]int),
		KOriginElement:          kOriginElement,
		THRFields:               thrFields,
		AllocStubOffsets:        allocStubOffsets,
		CalleeExitTypes:         make(map[uint64]TypeLattice),
		CalleeAllExitTypes:      make(map[uint64][31]TypeLattice),
		MinAppClassID:           minAppClassIDSafe(pl.CT),
		MethodNameToRefIDs:      buildMethodNameToRefIDs(pl),
		InstanceFieldTypes:      make(map[int]map[int32]int),
		FieldStoreTypes:         make(map[int]map[int32]int),
		AllocationSites:         make(map[uint64]int),
		InstantiatedClasses:     make(map[int]bool),
		ClosureDataByClosure:    make(map[int]int),
		ClosureDataByParent:     make(map[int][]int),
		PoolClosureClass:        make(map[int]int),
		PoolCodeNames:           make(map[int]string),
		TypeTestingStubNames:    pl.TypeTestingStubNames,
		SelectorOffsets:         make(map[uint64]int),
		Subclasses:              make(map[int][]int),
	}

	// 0. Resolve Dart 2.x Type class IDs before anything reads them.
	resolveTypeClassIDs(clResult)

	// 1. Class hierarchy + subclasses + instantiated classes.
	buildClassHierarchy(ctx, clResult, pl, dispatchEntries)

	// 2. classID → name.
	buildClassIDToName(ctx, clResult, pl)

	// 3+4. Field types + fieldByOwnerOffset.
	buildFieldTypes(ctx, clResult, pl)

	// 5. Pool class by index.
	buildPoolClassByIndex(ctx, clResult, pl)

	// 6+7. Dispatch tables + code index to name.
	buildDispatchTables(ctx, dispatchEntries, byCodeIndex, clResult, pl, kOriginElement)

	// SUPER FEATURE 3: Pool UnlinkedCall names.
	ctx.PoolUnlinkedCallNames = buildPoolUnlinkedCallNames(clResult, pl)
	if pl.PoolCodeNames != nil {
		ctx.PoolCodeNames = pl.PoolCodeNames
	}

	// 8. FuncParamTypes + FuncParamCount + FuncIsInstance.
	buildFuncParamTypes(ctx, clResult, pl)

	// Phase 3: observed instance field types.
	buildInstanceFieldTypes(ctx, clResult, pl)

	// ClosureData + PoolClosureClass.
	buildClosureData(ctx, clResult)
	buildPoolClosureClass(ctx, clResult, pl)

	return ctx
}


// FieldValueClass resolves a field load `base.<byteOff>` on a receiver of class
// receiverCID to the class of the loaded value.
//
// Three sources, in precedence order:
//
//  1. The DECLARED field type -- FieldByOwnerOffset gives the Field object at
//     that offset and FieldTypes its resolved type class. Authoritative when
//     present.
//  2. The OBSERVED type from const Instance objects in the snapshot
//     (InstanceFieldTypes), used only when every observed instance of the
//     class agrees.
//  3. The STORED type from field-store instructions in function bodies
//     (FieldStoreTypes), recovered from interprocedural analysis. This types
//     fields that neither declared nor observed types can (e.g., fields set
//     at runtime to objects of a known class).
//
// Both ARM64 and x86_64 field-load handlers call this, so the precedence rule
// lives in exactly one place.
//
// IMPORTANT: byteOff from the caller is the raw instruction's displacement,
// which is field_offset - kHeapObjectTag (kHeapObjectTag = 1 for both ARM64
// and x86_64 compressed-pointer builds). The maps (FieldByOwnerOffset,
// InstanceFieldTypes, FieldStoreTypes) are keyed by field_offset (from object
// start, without kHeapObjectTag subtraction). So we add kHeapObjectTag back
// before lookup.
func (ctx *TypeContext) FieldValueClass(receiverCID int, byteOff int32) (int, bool) {
	// kHeapObjectTag = 1: raw instruction offset = field_offset - 1,
	// map key = field_offset. Add 1 to align.
	lookupOff := byteOff + 1
	// Walk the superclass chain: FieldByOwnerOffset is keyed by the
	// DECLARING class's CID, but receiverCID is the receiver's actual
	// (possibly subclass) CID. A field declared in class A is inherited
	// by subclass B, so when accessing it on a B instance, we must look
	// up A's entry. Without this walk, declared field types never hit
	// for any subclass — measured: 369 fields resolved, 89 declaring
	// classes, but 0 hits because every receiver was a subclass.
	cid := receiverCID
	for cid >= 0 {
		if fields, ok := ctx.FieldByOwnerOffset[cid]; ok {
			if fieldRefID, ok := fields[lookupOff]; ok {
				if classID, ok := ctx.FieldTypes[fieldRefID]; ok && classID >= 0 {
					ctx.FieldTypeDeclaredHits++
					return classID, true
				}
			}
		}
		// Walk up to superclass: FieldByOwnerOffset is keyed by the
		// declaring class, but the receiver may be a subclass.
		if ctx.SuperClass == nil {
			break
		}
		next, ok := ctx.SuperClass[cid]
		if !ok || next < 0 || next == cid {
			break
		}
		cid = next
	}
	if byOff, ok := ctx.InstanceFieldTypes[receiverCID]; ok {
		if classID, ok := byOff[lookupOff]; ok && classID > 0 {
			ctx.InstanceFieldHits++
			ctx.FieldTypeInstanceHits++
			return classID, true
		}
	}
	// P1.3: Field-store → field-load tracking.
	if byOff, ok := ctx.FieldStoreTypes[receiverCID]; ok {
		if classID, ok := byOff[lookupOff]; ok && classID > 0 {
			ctx.FieldTypeStoreHits++
			return classID, true
		}
	}
	return 0, false
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

// AllSubclasses returns all transitive subclass IDs of the given class,
// including the class itself. Used by CHA to enumerate all possible
// dispatch targets for a virtual call on a known receiver class.
func (ctx *TypeContext) AllSubclasses(classID int) []int {
	seen := map[int]bool{classID: true}
	var out []int
	var walk func(int)
	walk = func(cid int) {
		out = append(out, cid)
		for _, sub := range ctx.Subclasses[cid] {
			if !seen[sub] {
				seen[sub] = true
				walk(sub)
			}
		}
	}
	walk(classID)
	return out
}

// ResolveDispatchCHA enumerates all dispatch targets for a virtual call
// on a receiver of classID at the given selector offset. Returns all
// distinct target function names found across the class and its subclasses.
//
// This is the CHA consumer: when resolveBLR knows the receiver class
// (LatticeKnownClass) and the selector offset is known (from a preceding
// ADD/SUB), it can enumerate all possible targets instead of giving up.
func (ctx *TypeContext) ResolveDispatchCHA(classID, selectorOffset int) []string {
	slot := classID + selectorOffset - ctx.KOriginElement
	var targets []string
	seen := map[string]bool{}
	for _, cid := range ctx.AllSubclasses(classID) {
		s := cid + selectorOffset - ctx.KOriginElement
		if name, ok := ctx.ResolveDispatchTarget(s); ok && !seen[name] {
			seen[name] = true
			targets = append(targets, name)
		}
	}
	// Also check the original slot directly.
	if name, ok := ctx.ResolveDispatchTarget(slot); ok && !seen[name] {
		seen[name] = true
		targets = append(targets, name)
	}
	return targets
}

// minAppClassIDSafe returns NumPredefinedCids from ct, or 0 if ct is nil.
func minAppClassIDSafe(ct *snapshot.CIDTable) int {
	if ct == nil {
		return 0
	}
	return int(ct.NumPredefinedCids)
}
