package typetrack

import (
	"aotopsy/internal/cluster"
)

// This file holds the sub-builder functions that BuildTypeContext
// (sources.go) dispatches to. Each function builds one piece of the
// TypeContext from the cluster result and pool lookups.

// buildClassHierarchy builds the exact superclass relation used for safe
// object-bound joins and inherited-field lookup.
func buildClassHierarchy(ctx *TypeContext, clResult *cluster.Result, pl *PoolLookupData) {
	// 1. Build one hierarchy across isolate + VM snapshot objects. SuperTypeRefID
	// can point into the VM snapshot; isolate-only input silently loses those
	// edges even though BuildTypeContext already exposes VmClasses/VmTypes.
	classes := make([]cluster.ClassInfo, 0, len(clResult.Classes)+len(pl.VmClasses))
	classes = append(classes, clResult.Classes...)
	classes = append(classes, pl.VmClasses...)
	types := make([]cluster.TypeInfo, 0, len(clResult.Types)+len(pl.VmTypes))
	types = append(types, clResult.Types...)
	types = append(types, pl.VmTypes...)
	ctx.SuperClass = BuildClassHierarchy(classes, types)

	// Do not prefill InstantiatedClasses from serialized Class metadata. That set
	// is telemetry for classes observed as objects, not the class universe used by
	// dispatch resolution.
}

// buildClassIDToName builds the classID → name map.
func buildClassIDToName(ctx *TypeContext, pl *PoolLookupData) {
	for cid, name := range pl.ClassIDToName {
		ctx.ClassIDToName[cid] = name
	}
}

// buildFieldTypes builds FieldTypes (fieldRefID → ClassID) and
// FieldByOwnerOffset (ownerClassID → byteOffset → fieldRefID).
func buildFieldTypes(ctx *TypeContext, clResult *cluster.Result, pl *PoolLookupData) {
	// 3. Build field type lookup: fieldRefID → ClassID.
	// RefToType is built once in BuildTypeContext (includes VM Types).
	refToType := ctx.RefToType
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
	ctx.FieldTypeDeclaredHits = 0 // will be counted during analysis

	// 4. Build fieldByOwnerOffset.
	// Include VM snapshot Classes and Fields so framework class field
	// types (String, List, Map, etc.) are available for resolution.
	refToClassID := make(map[int]int32, len(clResult.Classes)+len(pl.VmClasses))
	for i := range clResult.Classes {
		refToClassID[clResult.Classes[i].RefID] = clResult.Classes[i].ClassID
	}
	// VM Classes: add their ref → ClassID mapping so VM Fields can
	// resolve their owner class. This is the missing piece that
	// prevented framework class field types from resolving.
	for i := range pl.VmClasses {
		refToClassID[pl.VmClasses[i].RefID] = pl.VmClasses[i].ClassID
	}
	// Process isolate Fields.
	// P-2 fix: Field.HostOffset is a REF ID into MintValues, not the
	// actual offset. BuildClassLayouts converts it via
	// MintValues[HostOffset] * wordSize; buildFieldTypes was using the
	// raw ref ID as the map key, so FieldByOwnerOffset was keyed by
	// ref IDs (10000+) instead of byte offsets (7, 75, 95, ...).
	// FieldValueType never found anything, making the declared field
	// type source completely dead (0 hits on BOTH ARM64 and x86_64).
	for i := range clResult.Fields {
		f := &clResult.Fields[i]
		if f.HostOffset < 0 {
			continue // static field
		}
		// Convert ref ID → word offset → byte offset, matching
		// BuildClassLayouts' conversion.
		wordOff, ok := ctx.MintValues[int(f.HostOffset)]
		if !ok {
			continue
		}
		byteOff := int32(wordOff) * ctx.WordSize
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
		m[byteOff] = f.RefID
	}
	// Process VM Fields: resolve TypeRefID → ClassID AND build
	// FieldByOwnerOffset using VmClasses for owner ClassID resolution.
	// This enables declared field type lookup for framework classes
	// (String, List, Map, etc.) whose Fields live in the VM snapshot.
	// P-2 fix: same ref ID → byte offset conversion as isolate Fields.
	for i := range pl.VmFields {
		f := &pl.VmFields[i]
		if f.TypeRefID >= 0 {
			if ti, ok := refToType[f.TypeRefID]; ok && ti.ClassID >= 0 {
				ctx.FieldTypes[f.RefID] = int(ti.ClassID)
			}
		}
		// Build FieldByOwnerOffset for VM fields.
		if f.HostOffset >= 0 && f.OwnerRefID >= 0 {
			wordOff, ok := ctx.MintValues[int(f.HostOffset)]
			if !ok {
				continue
			}
			byteOff := int32(wordOff) * ctx.WordSize
			if cid, ok := refToClassID[f.OwnerRefID]; ok {
				ownerClassID := int(cid)
				m, ok2 := ctx.FieldByOwnerOffset[ownerClassID]
				if !ok2 {
					m = make(map[int32]int)
					ctx.FieldByOwnerOffset[ownerClassID] = m
				}
				m[byteOff] = f.RefID
			}
		}
	}
}

// buildPoolClassByIndex builds PP index → ClassID map.
func buildPoolClassByIndex(ctx *TypeContext, clResult *cluster.Result, pl *PoolLookupData) {
	for _, pe := range clResult.Pool {
		if pe.Kind != cluster.PoolTagged {
			continue
		}
		// Check isolate RefCID first, then VM VmRefCID.
		// Pool entries can reference objects from either snapshot;
		// VM objects (e.g. Type, Class) are common in the pool but
		// only have VmRefCID, not RefCID. Without this fallback,
		// PoolClassByIndex was empty for every VM-referenced pool
		// entry, which on 2.12 meant pp_hits=0 across the entire
		// binary (every PP load of a Type/Class came from the VM
		// snapshot).
		//
		// Both maps carry the runtime CID of the object in the pool. Metadata
		// reachable through a Type object is deliberately not runtime identity.
		classID := -1
		if pl.RefCID != nil {
			classID = poolEntryClassID(pl.RefCID, pe.RefID)
		}
		if classID < 0 && pe.RefID > cluster.RefNull && pe.RefID < pl.BaseObjLimit && pl.VmRefCID != nil {
			classID = poolEntryClassID(pl.VmRefCID, pe.RefID)
		}
		if classID >= 0 {
			ctx.PoolClassByIndex[pe.Index] = classID
		}
	}
}

// poolEntryClassID resolves one pool entry's ref to a class ID through a
// CID map, returning -1 when it cannot.
//
// This function returns the runtime CID of the OBJECT stored in the pool. A
// Type object is therefore kTypeCid, not the class the Type describes. The old
// extra hop through TypeInfo.ClassID confused metadata (`Type(Foo)`) with a Foo
// instance, then fed that false runtime class into field and dispatch inference.
func poolEntryClassID(cidByRef map[int]int, refID int) int {
	cid, ok := cidByRef[refID]
	if !ok || cid < 0 {
		return -1
	}
	return cid
}

// buildDispatchTables builds DispatchBySlot and DispatchCodeIndexToName.
func buildDispatchTables(ctx *TypeContext, dispatchEntries []cluster.DispatchTableEntry, byCodeIndex map[int]*cluster.NamedObject, clResult *cluster.Result, pl *PoolLookupData, kOriginElement int) {
	// 6. Build dispatchBySlot.
	for _, e := range dispatchEntries {
		ctx.DispatchBySlot[e.Index-kOriginElement] = e
	}

	// 7b. Build DispatchCodeIndexToName from the naming layer's semantic
	// Function identity. Dispatch results are user-visible call targets, so a
	// bare leaf such as "build" is not enough when several owners implement it.
	for clusterIdx, no := range byCodeIndex {
		if no == nil {
			continue
		}
		if name := pl.FunctionRefToName[no.RefID]; name != "" {
			ctx.DispatchCodeIndexToName[clusterIdx] = name
		}
	}

	// ClusterIndex → Code fallback. A Code without a Function cross-reference can
	// still have an exact semantic identity from CodeNames (allocation/TTS/stub).
	codeClusterToEntry := make(map[int]*cluster.CodeEntry, len(clResult.Codes))
	for i := range clResult.Codes {
		c := &clResult.Codes[i]
		if c.ClusterIndex >= 0 {
			codeClusterToEntry[c.ClusterIndex] = c
		}
	}
	for clusterIdx, code := range codeClusterToEntry {
		if _, hasName := ctx.DispatchCodeIndexToName[clusterIdx]; hasName {
			continue
		}
		if name := pl.CodeRefToName[code.RefID]; name != "" {
			ctx.DispatchCodeIndexToName[clusterIdx] = name
		}
	}

	// Build MethodNameToSelectorImms. DispatchBySlot is keyed by
	// `entry.Index-kOriginElement`, the register-relative slot index used by the
	// generated call. For a receiver class cid, the generated selector immediate
	// is therefore simply `key-cid`.
	ctx.MethodNameToSelectorImms = make(map[string][]int)

	classCIDByRef := make(map[int]int, len(clResult.Classes))
	for i := range clResult.Classes {
		classCIDByRef[clResult.Classes[i].RefID] = int(clResult.Classes[i].ClassID)
	}
	ownerClassCID := func(owner *cluster.NamedObject) (int, bool) {
		if owner == nil || pl.CT == nil {
			return 0, false
		}
		cur := owner
		if cur.CID == pl.CT.Function {
			if cur.OwnerRefID < 0 {
				return 0, false
			}
			cur = pl.RefToNamed[cur.OwnerRefID]
			if cur == nil {
				return 0, false
			}
		}
		if pl.CT.PatchClass != 0 && cur.CID == pl.CT.PatchClass {
			if cur.OwnerRefID < 0 {
				return 0, false
			}
			cur = pl.RefToNamed[cur.OwnerRefID]
			if cur == nil {
				return 0, false
			}
		}
		if cur.CID != pl.CT.Class {
			return 0, false
		}
		cid, ok := classCIDByRef[cur.RefID]
		return cid, ok
	}

	// Build ClusterIndex → owner class CID. Prefer the Function→CodeIndex
	// cross-reference: Code.OwnerRef is known to be unreliable on some real
	// snapshots and can point at an unrelated non-owner object.
	codeClusterToCID := make(map[int]int, len(clResult.Codes))
	for i := range clResult.Codes {
		c := &clResult.Codes[i]
		if c.ClusterIndex < 0 {
			continue
		}
		owner := byCodeIndex[c.ClusterIndex]
		if owner == nil && c.OwnerRef >= 0 {
			owner = pl.RefToNamed[c.OwnerRef]
		}
		if cid, ok := ownerClassCID(owner); ok {
			codeClusterToCID[c.ClusterIndex] = cid
		}
	}
	if ctx.DispatchSlotMeta == nil {
		ctx.DispatchSlotMeta = make(map[int]DispatchSlotMeta, len(ctx.DispatchBySlot))
	}
	for key, entry := range ctx.DispatchBySlot {
		if entry.Kind != cluster.DispatchCode {
			continue
		}
		// Row identity for selectorCandidates: owner class + selector leaf of the
		// Function this Code implements (UnlinkedCall.target_name is a selector
		// leaf too, not a semantic target identity: "foo" locates all
		// implementations while the candidates stay qualified A.foo / B.foo). A
		// Code without a resolvable Function keeps Owner=-1 / empty Leaf.
		fn := byCodeIndex[entry.ClusterIndex]
		if fn == nil {
			if code := codeClusterToEntry[entry.ClusterIndex]; code != nil && code.OwnerRef > cluster.RefNull {
				fn = pl.RefToNamed[code.OwnerRef]
			}
		}
		meta := DispatchSlotMeta{Owner: -1}
		if fn != nil {
			meta.Leaf = pl.FunctionRefToLeafName[fn.RefID]
		}
		if cid, ok := codeClusterToCID[entry.ClusterIndex]; ok {
			meta.Owner = cid
		}
		ctx.DispatchSlotMeta[key] = meta
	}
	// Selector immediates per leaf come from the reconstructed rows, not from
	// `slot - ownerCID`: that only equals the row offset for the slot of the
	// implementing class itself, and was wrong for every inherited slot.
	ctx.MethodNameToSelectorImms = ctx.inferSelectorRowImms()
}

// buildPoolUnlinkedCallNames builds PP index → UnlinkedCall target_name.
func buildPoolUnlinkedCallNames(clResult *cluster.Result, pl *PoolLookupData) map[int]string {
	poolUnlinkedCallNames := make(map[int]string)
	if pl.CT != nil && pl.RefToNamed != nil {
		for _, pe := range clResult.Pool {
			if pe.Kind != cluster.PoolTagged {
				continue
			}
			if pl.RefCID != nil {
				if cid, ok := pl.RefCID[pe.RefID]; ok && cid == pl.CT.UnlinkedCall {
					if name := pl.ObjectRefToName[pe.RefID]; name != "" {
						poolUnlinkedCallNames[pe.Index] = name
					}
				}
			}
		}
	}
	return poolUnlinkedCallNames
}

// buildPoolClosureFunctionNames builds PP index → function name for Closure
// objects in the pool. Uses clResult.Closures (captured via ClosureInfo in
// readFillRefs) to find each Closure's function ref, then resolves the
// function's name via the pool lookups.
func buildPoolClosureFunctionNames(clResult *cluster.Result, pl *PoolLookupData) map[int]string {
	poolClosureFuncNames := make(map[int]string)
	if pl.CT == nil || pl.RefToNamed == nil {
		return poolClosureFuncNames
	}
	// Build ref → ClosureInfo lookup.
	closureByRef := make(map[int]cluster.ClosureInfo, len(clResult.Closures))
	for i := range clResult.Closures {
		closureByRef[clResult.Closures[i].RefID] = clResult.Closures[i]
	}
	for _, pe := range clResult.Pool {
		if pe.Kind != cluster.PoolTagged {
			continue
		}
		if pl.RefCID != nil {
			if cid, ok := pl.RefCID[pe.RefID]; ok && cid == pl.CT.Closure {
				if ci, ok2 := closureByRef[pe.RefID]; ok2 && ci.FunctionRef >= 0 {
					if name := pl.FunctionRefToName[ci.FunctionRef]; name != "" {
						poolClosureFuncNames[pe.Index] = name
					}
				}
			}
		}
	}
	return poolClosureFuncNames
}

// buildFuncParamTypes builds parameter/return declaration bounds and the
// instance-method bit used to interpret parameter 0.
func buildFuncParamTypes(ctx *TypeContext, clResult *cluster.Result, pl *PoolLookupData) {
	// 8. Build declaration metadata from FuncTypeInfo.
	funcTypeByRef := make(map[int]*cluster.FuncTypeInfo, len(clResult.FuncTypes))
	for i := range clResult.FuncTypes {
		funcTypeByRef[clResult.FuncTypes[i].RefID] = &clResult.FuncTypes[i]
	}
	arrayByRef := make(map[int]*cluster.ArrayInfo, len(clResult.Arrays))
	for i := range clResult.Arrays {
		arrayByRef[clResult.Arrays[i].RefID] = &clResult.Arrays[i]
	}
	// RefToType is built once in BuildTypeContext.
	refToType := ctx.RefToType
	// paramTypesFromArray resolves an Array of AbstractType refs to class ids,
	// -1 where the element is not a Type we resolved.
	paramTypesFromArray := func(arrayRef int) ([]int, bool) {
		arr, ok := arrayByRef[arrayRef]
		if !ok {
			return nil, false
		}
		out := make([]int, len(arr.ElementRefIDs))
		for j, elemRef := range arr.ElementRefIDs {
			out[j] = -1
			if ti, ok2 := refToType[elemRef]; ok2 && ti.ClassID >= 0 {
				out[j] = int(ti.ClassID)
			}
		}
		return out, true
	}

	for i := range clResult.Named {
		no := &clResult.Named[i]
		if pl.CT != nil && no.CID == pl.CT.Function {
			// Before FunctionType existed, result_type and parameter_types sit
			// on the Function itself and there is no signature to follow. The
			// signature-only path left every 2.10 function with no declared
			// return type at all -- func_return_type_count 0 against 994 on
			// 2.12 from the same source. See cluster.FunctionRefLayout.
			if no.ResultTypeRefID >= 0 {
				if ti, ok := refToType[no.ResultTypeRefID]; ok && ti.ClassID >= 0 {
					ctx.FuncReturnType[no.RefID] = int(ti.ClassID)
				}
			}
			if no.ParamTypesRefID >= 0 {
				if paramTypes, ok := paramTypesFromArray(no.ParamTypesRefID); ok {
					ctx.FuncParamTypes[no.RefID] = paramTypes
				}
			}
			if no.SignatureRefID >= 0 {
				if ft, ok := funcTypeByRef[no.SignatureRefID]; ok {
					ctx.FuncIsInstance[no.RefID] = ft.HasImplicit

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
					// Capture declared return type from FunctionType.result_type.
					// result_type is an AbstractType ref; resolve to ClassID via
					// refToType (same map used for parameter types).
					if ft.ResultTypeRefID >= 0 {
						if ti, ok2 := refToType[ft.ResultTypeRefID]; ok2 && ti.ClassID >= 0 {
							ctx.FuncReturnType[no.RefID] = int(ti.ClassID)
						}
					}
				}
			}
		}
	}
}

// buildObservedInstantiationPopulation records only population telemetry from
// serialized objects. It is never used to remove dispatch candidates or type a
// mutable field because the snapshot is not an exhaustive runtime population.
func buildObservedInstantiationPopulation(ctx *TypeContext, clResult *cluster.Result, pl *PoolLookupData) {
	for i := range clResult.Instances {
		inst := &clResult.Instances[i]
		ctx.InstantiatedClasses[inst.CID] = true
		for _, f := range inst.Fields {
			if f.Ref > cluster.RefNull {
				if valCID, ok := pl.RefCID[f.Ref]; ok && valCID > 0 {
					ctx.InstantiatedClasses[valCID] = true
				}
			}
		}
	}
}
