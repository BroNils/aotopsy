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

	// Debug counters.
	PPHits       int
	HeaderHits   int
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
	}

	// 1. Build class hierarchy for LCA.
	ctx.SuperClass = BuildClassHierarchy(clResult.Classes, clResult.Types, pl.RefToNamed)

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
	refToType := make(map[int]*cluster.TypeInfo, len(clResult.Types))
	for i := range clResult.Types {
		refToType[clResult.Types[i].RefID] = &clResult.Types[i]
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
	// Fase 7 PART A fix: for Instance objects (CID >= ct.Instance), RefCID
	// gives the instance's class ID (correct for dispatch). For Type objects,
	// RefCID gives the Type class's CID (wrong for dispatch — need the class
	// the Type represents, from TypeInfo.ClassID). For other objects (Class,
	// Function, etc.), skip — they don't participate in dispatch.
	// refToType is already built above (line 160) as map[int]*cluster.TypeInfo.
	for _, pe := range clResult.Pool {
		if pe.Kind != cluster.PoolTagged {
			continue
		}
		classID := -1
		if pl.RefCID != nil {
			if cid, ok := pl.RefCID[pe.RefID]; ok && cid >= 0 {
				if pl.CT != nil && cid >= pl.CT.NumPredefinedCids {
					// App-defined Instance subclass: RefCID IS the dispatch class ID.
					// Only app-defined classes (>= NumPredefinedCids) have dispatch
					// methods — predefined CIDs like TypeArguments (47), Array (90),
					// etc. don't have user-defined methods to dispatch.
					classID = cid
				} else if pl.CT != nil && cid == pl.CT.Type {
					// Type object: resolve to the class it represents.
					if ti, ok := refToType[pe.RefID]; ok && ti.ClassID >= 0 {
						classID = int(ti.ClassID)
					}
				}
				// Other objects (Class, Function, etc.): skip, classID stays -1.
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

	return ctx
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

// minAppClassIDSafe returns NumPredefinedCids from ct, or 0 if ct is nil.
func minAppClassIDSafe(ct *snapshot.CIDTable) int {
	if ct == nil {
		return 0
	}
	return int(ct.NumPredefinedCids)
}
