package typetrack

import (
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
	UBFXHits     int
	ADDClassHits int
	DispatchHits int
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
	for refID, no := range pl.RefToNamed {
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
	RefToStr       map[int]string               // ref ID → string value
	RefToNamed     map[int]*cluster.NamedObject // ref ID → NamedObject
	RefCID         map[int]int                  // ref ID → CID (class ID of the object)
	CT             *snapshot.CIDTable           // CID table (for Class/Function CID checks)
	CodeRefToName  map[int]string               // code ref ID → function name
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
		CalleeExitTypes:         make(map[uint64]TypeLattice), // Fase 7 PART A
		CalleeAllExitTypes:      make(map[uint64][31]TypeLattice), // Full exit types
		// M-14 fix: nil check for pl.CT
	MinAppClassID:           minAppClassIDSafe(pl.CT),
		MethodNameToRefIDs:      buildMethodNameToRefIDs(pl),
		InstanceFieldTypes:      make(map[int]map[int32]int),
		ClosureDataByClosure:    make(map[int]int),
		ClosureDataByParent:     make(map[int][]int),
		PoolClosureClass:        make(map[int]int),
		SelectorOffsets:         make(map[uint64]int),
		Subclasses:              make(map[int][]int),
	}

	// 1. Build class hierarchy for LCA.
	ctx.SuperClass = BuildClassHierarchy(clResult.Classes, clResult.Types, pl.RefToNamed)

	// 1b. Build inverse hierarchy (subclasses) for CHA.
	for cid, parent := range ctx.SuperClass {
		if parent >= 0 {
			ctx.Subclasses[parent] = append(ctx.Subclasses[parent], cid)
		}
	}

	// 2. Build classID → name map.
	for i := range clResult.Classes {
		c := &clResult.Classes[i]
		name := ""
		if c.NameRefID >= 0 {
			if s, ok := pl.RefToStr[c.NameRefID]; ok {
				name = s
			}
		}
		ctx.ClassIDToName[int(c.ClassID)] = name
	}

	// 3. Build field type lookup: fieldRefID → ClassID.
	// FieldInfo.TypeRefID points to a Type object; Type.ClassID gives the CID.
	// For v2.x TypeClassIdIsRef, Type.ClassID is 0 and TypeClassIdRef holds
	// the Smi ref — resolve it via MintValues (Smi encoding: classID = value >> 1).
	refToType := make(map[int]*cluster.TypeInfo, len(clResult.Types))
	for i := range clResult.Types {
		ti := &clResult.Types[i]
		// Resolve TypeClassIdRef via MintValues for v2.x TypeClassIdIsRef.
		if ti.ClassID == 0 && ti.TypeClassIdRef > 0 {
			if smiValue, ok := clResult.MintValues[ti.TypeClassIdRef]; ok {
				ti.ClassID = int32(smiValue >> 1) // Smi: value << 1 | 0
			}
		}
		refToType[ti.RefID] = ti
	}
	for i := range clResult.Fields {
		f := &clResult.Fields[i]
		classID := -1
		if f.TypeRefID >= 0 {
			if ti, ok := refToType[f.TypeRefID]; ok && ti.ClassID >= 0 {
				classID = int(ti.ClassID)
			}
		}
		ctx.FieldTypes[f.RefID] = classID
	}

	// 4. Build fieldByOwnerOffset: ownerClassID → byteOffset → fieldRefID.
	// FieldInfo.OwnerRefID points to a Class NamedObject; we need the
	// Class's ClassID. Build ref→ClassID map from Classes.
	refToClassID := make(map[int]int32, len(clResult.Classes))
	for i := range clResult.Classes {
		refToClassID[clResult.Classes[i].RefID] = clResult.Classes[i].ClassID
	}
	// Also check Named objects with Class CID.
	if pl.CT != nil {
		for ref, no := range pl.RefToNamed {
			if no.CID == pl.CT.Class {
				// This NamedObject is a Class; find its ClassInfo by RefID.
				if cid, ok := refToClassID[ref]; ok {
					refToClassID[ref] = cid
				}
			}
		}
	}
	for i := range clResult.Fields {
		f := &clResult.Fields[i]
		if f.HostOffset < 0 {
			continue // static field
		}
		ownerClassID := -1
		if f.OwnerRefID >= 0 {
			if cid, ok := refToClassID[f.OwnerRefID]; ok {
				ownerClassID = int(cid)
			}
		}
		if ownerClassID < 0 {
			continue
		}
		m, ok := ctx.FieldByOwnerOffset[ownerClassID]
		if !ok {
			m = make(map[int32]int)
			ctx.FieldByOwnerOffset[ownerClassID] = m
		}
		m[f.HostOffset] = f.RefID
	}

	// 5. Build poolClassByIndex: PP index → ClassID.
	// For Instance objects, RefCID gives the instance's class ID.
	// For Type objects, RefCID gives the Type class's CID (wrong for
	// dispatch — need the class the Type represents, from TypeInfo.ClassID).
	// For other objects (Class, Function, etc.), skip.
	//
	// IMPORTANT: We populate ALL CIDs, including predefined/framework classes
	// (Widget, State, RenderObject, etc.). Framework classes DO have dispatch
	// methods (Widget.build, State.initState, etc.) and are the majority of
	// dispatch table calls. The previous restriction (cid >= NumPredefinedCids)
	// excluded 90%+ of dispatch calls from resolution.
	for _, pe := range clResult.Pool {
		if pe.Kind != cluster.PoolTagged {
			continue
		}
		classID := -1
		if pl.RefCID != nil {
			if cid, ok := pl.RefCID[pe.RefID]; ok && cid >= 0 {
				if pl.CT != nil && cid == pl.CT.Type {
					// Type object: resolve to the class it represents.
					if ti, ok := refToType[pe.RefID]; ok && ti.ClassID >= 0 {
						classID = int(ti.ClassID)
					}
				} else {
					// Instance or other tagged object: RefCID IS the class ID.
					// Include ALL classes — both app-defined and framework.
					classID = cid
				}
			}
		}
		if classID >= 0 {
			ctx.PoolClassByIndex[pe.Index] = classID
		}
	}

	// 6. Build dispatchBySlot.
	// Key by (entry.Index - KOriginElement) so that computed slots
	// (cid + selector_offset - KOriginElement) map directly.
	// The Dart runtime allocates the dispatch table with KOriginElement
	// padding entries at the beginning; the snapshot stores only the real
	// entries, so entries[0] corresponds to runtime slot -KOriginElement.
	for _, e := range dispatchEntries {
		ctx.DispatchBySlot[e.Index-kOriginElement] = e
	}

	// 7. Build codeRefToName from PoolLookupData.CodeRefToName.
	for ref, name := range pl.CodeRefToName {
		ctx.CodeRefToName[ref] = name
	}

	// 7b. Build DispatchCodeIndexToName: ClusterIndex → function name.
	// This is the direct path from dispatch table slot → target function name.
	if byCodeIndex != nil {
		for clusterIdx, no := range byCodeIndex {
			if no == nil || no.NameRefID < 0 {
				continue
			}
			name := ""
			if s, ok := pl.RefToStr[no.NameRefID]; ok {
				name = s
			}
			if name != "" {
				ctx.DispatchCodeIndexToName[clusterIdx] = name
			}
		}
	}

	// SUPER FEATURE 1: ClusterIndex → CodeRange → function name fallback.
	// For dispatch table entries where byCodeIndex doesn't have a Function
	// NamedObject (stubs, synthesized code, NoSuchMethod dispatchers), try
	// to resolve via CodeRange → binary address → symbol table lookup.
	// This recovers names for Code objects whose owner is Null or Class
	// instead of Function.
	// Build ClusterIndex → OwnerRef map from clResult.Codes.
	codeClusterToOwner := make(map[int]int, len(clResult.Codes))
	for i := range clResult.Codes {
		c := &clResult.Codes[i]
		if c.ClusterIndex >= 0 {
			codeClusterToOwner[c.ClusterIndex] = c.OwnerRef
		}
	}
	// For each ClusterIndex not in DispatchCodeIndexToName, try owner-based resolution.
	for clusterIdx, ownerRef := range codeClusterToOwner {
		if _, hasName := ctx.DispatchCodeIndexToName[clusterIdx]; hasName {
			continue // already resolved
		}
		// Try to resolve ownerRef → NamedObject → name
		if ownerRef >= 0 {
			if ownerNo, ok := pl.RefToNamed[ownerRef]; ok && ownerNo != nil && ownerNo.NameRefID >= 0 {
				if name, ok2 := pl.RefToStr[ownerNo.NameRefID]; ok2 && name != "" {
					ctx.DispatchCodeIndexToName[clusterIdx] = name
				}
			}
		}
	}

	// SUPER FEATURE 3: Build PoolIndex → UnlinkedCall target_name map.
	// UnlinkedCall objects are serialized in AOT snapshots with target_name
	// (StringPtr) and args_descriptor (ArrayPtr). When IC_DATA_REG (R5) is
	// loaded from PP with an UnlinkedCall object, we can resolve the BLR
	// target to the method name from target_name.
	// Verified via gh api: raw_object.h UntaggedCallSiteData has target_name
	// field, and app_snapshot.cc UnlinkedCallSerializationCluster serializes it.
	poolUnlinkedCallNames := make(map[int]string)
	if pl.CT != nil && pl.RefToNamed != nil && pl.RefToStr != nil {
		for _, pe := range clResult.Pool {
			if pe.Kind != cluster.PoolTagged {
				continue
			}
			if pl.RefCID != nil {
				if cid, ok := pl.RefCID[pe.RefID]; ok && cid == pl.CT.UnlinkedCall {
					if no, ok2 := pl.RefToNamed[pe.RefID]; ok2 && no != nil && no.NameRefID >= 0 {
						if name, ok3 := pl.RefToStr[no.NameRefID]; ok3 && name != "" {
							poolUnlinkedCallNames[pe.Index] = name
						}
					}
				}
			}
		}
	}
	ctx.PoolUnlinkedCallNames = poolUnlinkedCallNames

	// 8. Build FuncParamTypes and FuncParamCount from FuncTypeInfo.
	// TARGET 1: Also resolve parameter type ClassIDs from parameter_types Array.
	funcTypeByRef := make(map[int]*cluster.FuncTypeInfo, len(clResult.FuncTypes))
	for i := range clResult.FuncTypes {
		funcTypeByRef[clResult.FuncTypes[i].RefID] = &clResult.FuncTypes[i]
	}
	// Build Array ref → element Type refs lookup.
	arrayByRef := make(map[int]*cluster.ArrayInfo, len(clResult.Arrays))
	for i := range clResult.Arrays {
		arrayByRef[clResult.Arrays[i].RefID] = &clResult.Arrays[i]
	}
	// refToType already built above (line 160).
	for i := range clResult.Named {
		no := &clResult.Named[i]
		if pl.CT != nil && no.CID == pl.CT.Function {
			if no.SignatureRefID >= 0 {
				if ft, ok := funcTypeByRef[no.SignatureRefID]; ok {
					ctx.FuncParamCount[no.RefID] = ft.NumFixed + ft.NumOptional
					ctx.FuncIsInstance[no.RefID] = ft.HasImplicit

					// TARGET 1: Resolve parameter type ClassIDs.
					if ft.ParamTypesArrayRefID >= 0 {
						if arr, ok2 := arrayByRef[ft.ParamTypesArrayRefID]; ok2 {
							paramTypes := make([]int, len(arr.ElementRefIDs))
							for j, elemRef := range arr.ElementRefIDs {
								cid := -1
								if ti, ok3 := refToType[elemRef]; ok3 && ti.ClassID >= 0 {
									cid = int(ti.ClassID)
								}
								paramTypes[j] = cid
							}
							ctx.FuncParamTypes[no.RefID] = paramTypes
						}
					}
				}
			}
		}
	}

	// --- Phase 3: observed instance field types + ClosureData index ---

	// Instance -> (class, offset) -> value class. Offsets come straight from
	// the capture (cluster.InstanceFieldRef.ByteOffset), which records the
	// field's word index at read time; do NOT try to reconstruct them from the
	// order of a ref list -- unboxed slots and inherited fields both break
	// that. Unanimity is required, see InstanceFieldTypes' doc comment.
	type offsetVotes struct {
		classID  int
		conflict bool
	}
	votes := map[int]map[int32]*offsetVotes{}
	for i := range clResult.Instances {
		inst := &clResult.Instances[i]
		for _, f := range inst.Fields {
			if f.Ref <= cluster.RefNull {
				continue // null (or an invalid ref) tells us nothing
			}
			valCID, ok := pl.RefCID[f.Ref]
			if !ok || valCID <= 0 {
				continue
			}
			byCls, ok := votes[inst.CID]
			if !ok {
				byCls = map[int32]*offsetVotes{}
				votes[inst.CID] = byCls
			}
			v, ok := byCls[f.ByteOffset]
			if !ok {
				byCls[f.ByteOffset] = &offsetVotes{classID: valCID}
				continue
			}
			if v.classID != valCID {
				v.conflict = true
			}
		}
	}
	for cid, byOff := range votes {
		for off, v := range byOff {
			if v.conflict {
				continue
			}
			m, ok := ctx.InstanceFieldTypes[cid]
			if !ok {
				m = map[int32]int{}
				ctx.InstanceFieldTypes[cid] = m
			}
			m[off] = v.classID
		}
	}

	// ClosureData: map closure ref → parent function ref (AOT alternative to Context).
	// ClosureData IS serialized in AOT, unlike Context -- verified against
	// ClosureDataDeserializationCluster::ReadFill in the Dart SDK, which skips
	// context_scope_ for kFullAOT and then reads parent_function then closure,
	// and empirically (925-33712 ClosureData objects per sample in the corpus).
	for i := range clResult.ClosureData {
		cd := &clResult.ClosureData[i]
		if cd.ClosureRef >= 0 && cd.ParentFunctionRef >= 0 {
			ctx.ClosureDataByClosure[cd.ClosureRef] = cd.ParentFunctionRef
			ctx.ClosureDataByParent[cd.ParentFunctionRef] = append(ctx.ClosureDataByParent[cd.ParentFunctionRef], cd.ClosureRef)
		}
	}

	// Build PoolClosureClass: for each PP entry that is a Closure object,
	// resolve closure → ClosureData.parent_function → Function.owner → Class → ClassID.
	// This lets a PP load of a Closure set KnownClass(parentOwnerClassID) instead
	// of Top(), enabling BLR resolution for closure call sites.
	if pl.CT != nil && pl.CT.Closure != 0 {
		// Build Function ref → owner class ref map.
		funcOwnerRef := make(map[int]int)
		for i := range clResult.Named {
			no := &clResult.Named[i]
			if no.CID == pl.CT.Function && no.OwnerRefID > 0 {
				funcOwnerRef[no.RefID] = no.OwnerRefID
			}
		}
		// Build class ref → class ID map.
		classRefToID := make(map[int]int32)
		for _, ci := range clResult.Classes {
			classRefToID[ci.RefID] = ci.ClassID
		}
		// For each pool entry that is a Closure, resolve the chain.
		for _, pe := range clResult.Pool {
			if pe.Kind != cluster.PoolTagged || pe.RefID <= 0 {
				continue
			}
			cid, ok := pl.RefCID[pe.RefID]
			if !ok || cid != pl.CT.Closure {
				continue
			}
			// Closure ref → parent function ref via ClosureDataByClosure.
			parentFuncRef, ok2 := ctx.ClosureDataByClosure[pe.RefID]
			if !ok2 || parentFuncRef <= 0 {
				continue
			}
			// Parent function → owner class ref.
			ownerRef, ok3 := funcOwnerRef[parentFuncRef]
			if !ok3 || ownerRef <= 0 {
				continue
			}
			// PatchClass hop: owner may be a PatchClass, hop to real class.
			if ownerNo, ok4 := pl.RefToNamed[ownerRef]; ok4 && pl.CT.PatchClass != 0 && ownerNo.CID == pl.CT.PatchClass {
				ownerRef = ownerNo.OwnerRefID
			}
			// Class ref → class ID.
			classID, ok5 := classRefToID[ownerRef]
			if !ok5 || classID < 0 {
				continue
			}
			ctx.PoolClosureClass[pe.Index] = int(classID)
		}
	}

	return ctx
}

// FieldValueClass resolves a field load `base.<byteOff>` on a receiver of class
// receiverCID to the class of the loaded value.
//
// Two sources, in precedence order:
//
//  1. The DECLARED field type -- FieldByOwnerOffset gives the Field object at
//     that offset and FieldTypes its resolved type class. Authoritative when
//     present.
//  2. The OBSERVED type from const Instance objects in the snapshot
//     (InstanceFieldTypes), used only when every observed instance of the
//     class agrees. This is what the Instance capture buys: it types fields
//     the declared type cannot (dynamic/Object?, or a version where Type ->
//     ClassID resolution is unavailable, e.g. Dart 2.13-2.15 where
//     TypeClassIdIsRef makes FieldTypes empty).
//
// Both ARM64 and x86_64 field-load handlers call this, so the precedence rule
// lives in exactly one place.
//
// IMPORTANT: byteOff from the caller is the raw instruction's displacement,
// which is field_offset - kHeapObjectTag (kHeapObjectTag = 1 for both ARM64
// and x86_64 compressed-pointer builds). The maps (FieldByOwnerOffset,
// InstanceFieldTypes) are keyed by field_offset (from object start, without
// kHeapObjectTag subtraction). So we add kHeapObjectTag back before lookup.
func (ctx *TypeContext) FieldValueClass(receiverCID int, byteOff int32) (int, bool) {
	// kHeapObjectTag = 1: raw instruction offset = field_offset - 1,
	// map key = field_offset. Add 1 to align.
	lookupOff := byteOff + 1
	if fields, ok := ctx.FieldByOwnerOffset[receiverCID]; ok {
		if fieldRefID, ok := fields[lookupOff]; ok {
			if classID, ok := ctx.FieldTypes[fieldRefID]; ok && classID >= 0 {
				return classID, true
			}
		}
	}
	if byOff, ok := ctx.InstanceFieldTypes[receiverCID]; ok {
		if classID, ok := byOff[lookupOff]; ok && classID > 0 {
			ctx.InstanceFieldHits++
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
