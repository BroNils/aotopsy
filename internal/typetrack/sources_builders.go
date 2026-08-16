package typetrack

import (
	"sort"

	"aotopsy/internal/cluster"
)

// This file holds the sub-builder functions that BuildTypeContext
// (sources.go) dispatches to. Each function builds one piece of the
// TypeContext from the cluster result and pool lookups.

// buildClassHierarchy builds SuperClass + Subclasses + InstantiatedClasses.
func buildClassHierarchy(ctx *TypeContext, clResult *cluster.Result, pl *PoolLookupData, dispatchEntries []cluster.DispatchTableEntry) {
	// 1. Build class hierarchy for LCA.
	ctx.SuperClass = BuildClassHierarchy(clResult.Classes, clResult.Types, pl.RefToNamed)

	// 1b. Build inverse hierarchy (subclasses) for CHA.
	for cid, parent := range ctx.SuperClass {
		if parent >= 0 {
			ctx.Subclasses[parent] = append(ctx.Subclasses[parent], cid)
		}
	}
	// Sort for determinism (CHA takes first match).
	for parent := range ctx.Subclasses {
		sort.Ints(ctx.Subclasses[parent])
	}

	// 1c. Populate InstantiatedClasses from class table.
	for _, ci := range clResult.Classes {
		ctx.InstantiatedClasses[int(ci.ClassID)] = true
	}
}

// buildClassIDToName builds the classID → name map.
func buildClassIDToName(ctx *TypeContext, clResult *cluster.Result, pl *PoolLookupData) {
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
}

// buildFieldTypes builds FieldTypes (fieldRefID → ClassID) and
// FieldByOwnerOffset (ownerClassID → byteOffset → fieldRefID).
func buildFieldTypes(ctx *TypeContext, clResult *cluster.Result, pl *PoolLookupData) {
	// 3. Build field type lookup: fieldRefID → ClassID.
	refToType := make(map[int]*cluster.TypeInfo, len(clResult.Types))
	for i := range clResult.Types {
		refToType[clResult.Types[i].RefID] = &clResult.Types[i]
	}
	fieldTypeResolved := 0
	fieldTypeTotal := 0
	for i := range clResult.Fields {
		f := &clResult.Fields[i]
		classID := -1
		fieldTypeTotal++
		if f.TypeRefID >= 0 {
			if ti, ok := refToType[f.TypeRefID]; ok && ti.ClassID >= 0 {
				classID = int(ti.ClassID)
				fieldTypeResolved++
			}
		}
		ctx.FieldTypes[f.RefID] = classID
	}
	ctx.FieldTypeDeclaredHits = 0 // will be counted during analysis
	ctx.FieldTypesResolvedCount = fieldTypeResolved

	// 4. Build fieldByOwnerOffset.
	refToClassID := make(map[int]int32, len(clResult.Classes))
	for i := range clResult.Classes {
		refToClassID[clResult.Classes[i].RefID] = clResult.Classes[i].ClassID
	}
	if pl.CT != nil {
		for ref, no := range pl.RefToNamed {
			if no.CID == pl.CT.Class {
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
}

// buildPoolClassByIndex builds PP index → ClassID map.
func buildPoolClassByIndex(ctx *TypeContext, clResult *cluster.Result, pl *PoolLookupData) {
	// refToType is needed; rebuild it here to keep this function independent.
	refToType := make(map[int]*cluster.TypeInfo, len(clResult.Types))
	for i := range clResult.Types {
		refToType[clResult.Types[i].RefID] = &clResult.Types[i]
	}
	for _, pe := range clResult.Pool {
		if pe.Kind != cluster.PoolTagged {
			continue
		}
		classID := -1
		// Check isolate RefCID first, then VM VmRefCID.
		// Pool entries can reference objects from either snapshot;
		// VM objects (e.g. Type, Class) are common in the pool but
		// only have VmRefCID, not RefCID. Without this fallback,
		// PoolClassByIndex was empty for every VM-referenced pool
		// entry, which on 2.12 meant pp_hits=0 across the entire
		// binary (every PP load of a Type/Class came from the VM
		// snapshot).
		if pl.RefCID != nil {
			if cid, ok := pl.RefCID[pe.RefID]; ok && cid >= 0 {
				if pl.CT != nil && cid == pl.CT.Type {
					if ti, ok := refToType[pe.RefID]; ok && ti.ClassID >= 0 {
						classID = int(ti.ClassID)
					}
				} else {
					classID = cid
				}
			}
		}
		if classID < 0 && pl.VmRefCID != nil {
			if cid, ok := pl.VmRefCID[pe.RefID]; ok && cid >= 0 {
				if pl.CT != nil && cid == pl.CT.Type {
					// VM Type object: resolve to the class it represents.
					// refToType only covers isolate Types; VM Types are
					// in vmResult.Types which we don't have here. Skip —
					// the isolate Type path above handles the common case.
				} else {
					classID = cid
				}
			}
		}
		if classID >= 0 {
			ctx.PoolClassByIndex[pe.Index] = classID
		}
	}
}

// buildDispatchTables builds DispatchBySlot and DispatchCodeIndexToName.
func buildDispatchTables(ctx *TypeContext, dispatchEntries []cluster.DispatchTableEntry, byCodeIndex map[int]*cluster.NamedObject, clResult *cluster.Result, pl *PoolLookupData, kOriginElement int) {
	// 6. Build dispatchBySlot.
	for _, e := range dispatchEntries {
		ctx.DispatchBySlot[e.Index-kOriginElement] = e
	}

	// 7. Build codeRefToName.
	for ref, name := range pl.CodeRefToName {
		ctx.CodeRefToName[ref] = name
	}

	// 7b. Build DispatchCodeIndexToName.
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

	// SUPER FEATURE 1: ClusterIndex → OwnerRef fallback.
	codeClusterToOwner := make(map[int]int, len(clResult.Codes))
	for i := range clResult.Codes {
		c := &clResult.Codes[i]
		if c.ClusterIndex >= 0 {
			codeClusterToOwner[c.ClusterIndex] = c.OwnerRef
		}
	}
	for clusterIdx, ownerRef := range codeClusterToOwner {
		if _, hasName := ctx.DispatchCodeIndexToName[clusterIdx]; hasName {
			continue
		}
		if ownerRef >= 0 {
			if ownerNo, ok := pl.RefToNamed[ownerRef]; ok && ownerNo != nil && ownerNo.NameRefID >= 0 {
				if name, ok2 := pl.RefToStr[ownerNo.NameRefID]; ok2 && name != "" {
					ctx.DispatchCodeIndexToName[clusterIdx] = name
				}
			}
		}
	}
}

// buildPoolUnlinkedCallNames builds PP index → UnlinkedCall target_name.
func buildPoolUnlinkedCallNames(clResult *cluster.Result, pl *PoolLookupData) map[int]string {
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
	return poolUnlinkedCallNames
}

// buildFuncParamTypes builds FuncParamTypes, FuncParamCount, FuncIsInstance.
func buildFuncParamTypes(ctx *TypeContext, clResult *cluster.Result, pl *PoolLookupData) {
	// 8. Build FuncParamTypes and FuncParamCount from FuncTypeInfo.
	funcTypeByRef := make(map[int]*cluster.FuncTypeInfo, len(clResult.FuncTypes))
	for i := range clResult.FuncTypes {
		funcTypeByRef[clResult.FuncTypes[i].RefID] = &clResult.FuncTypes[i]
	}
	arrayByRef := make(map[int]*cluster.ArrayInfo, len(clResult.Arrays))
	for i := range clResult.Arrays {
		arrayByRef[clResult.Arrays[i].RefID] = &clResult.Arrays[i]
	}
	refToType := make(map[int]*cluster.TypeInfo, len(clResult.Types))
	for i := range clResult.Types {
		refToType[clResult.Types[i].RefID] = &clResult.Types[i]
	}
	for i := range clResult.Named {
		no := &clResult.Named[i]
		if pl.CT != nil && no.CID == pl.CT.Function {
			if no.SignatureRefID >= 0 {
				if ft, ok := funcTypeByRef[no.SignatureRefID]; ok {
					ctx.FuncParamCount[no.RefID] = ft.NumFixed + ft.NumOptional
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
				}
			}
		}
	}
}

// buildInstanceFieldTypes builds InstanceFieldTypes from const Instance objects.
// Unanimity is required: if two instances of the same class store different
// concrete classes at the same offset, the entry is dropped.
func buildInstanceFieldTypes(ctx *TypeContext, clResult *cluster.Result, pl *PoolLookupData) {
	type offsetVotes struct {
		classID  int
		conflict bool
	}
	votes := map[int]map[int32]*offsetVotes{}
	for i := range clResult.Instances {
		inst := &clResult.Instances[i]
		ctx.InstantiatedClasses[inst.CID] = true
		for _, f := range inst.Fields {
			if f.Ref <= cluster.RefNull {
				continue
			}
			valCID, ok := pl.RefCID[f.Ref]
			if !ok || valCID <= 0 {
				continue
			}
			ctx.InstantiatedClasses[valCID] = true
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
}

// buildClosureData builds ClosureDataByClosure and ClosureDataByParent.
func buildClosureData(ctx *TypeContext, clResult *cluster.Result) {
	for i := range clResult.ClosureData {
		cd := &clResult.ClosureData[i]
		if cd.ClosureRef >= 0 && cd.ParentFunctionRef >= 0 {
			ctx.ClosureDataByClosure[cd.ClosureRef] = cd.ParentFunctionRef
			ctx.ClosureDataByParent[cd.ParentFunctionRef] = append(ctx.ClosureDataByParent[cd.ParentFunctionRef], cd.ClosureRef)
		}
	}
}

// buildPoolClosureClass builds PoolClosureClass: PP index → owner class ID
// for Closure objects, via ClosureData.parent_function → Function.owner → Class.
func buildPoolClosureClass(ctx *TypeContext, clResult *cluster.Result, pl *PoolLookupData) {
	if pl.CT == nil || pl.CT.Closure == 0 {
		return
	}
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
		parentFuncRef, ok2 := ctx.ClosureDataByClosure[pe.RefID]
		if !ok2 || parentFuncRef <= 0 {
			continue
		}
		ownerRef, ok3 := funcOwnerRef[parentFuncRef]
		if !ok3 || ownerRef <= 0 {
			continue
		}
		// PatchClass hop.
		if ownerNo, ok4 := pl.RefToNamed[ownerRef]; ok4 && pl.CT.PatchClass != 0 && ownerNo.CID == pl.CT.PatchClass {
			ownerRef = ownerNo.OwnerRefID
		}
		classID, ok5 := classRefToID[ownerRef]
		if !ok5 || classID < 0 {
			continue
		}
		ctx.PoolClosureClass[pe.Index] = int(classID)
		// Also resolve parent function name.
		if parentFuncNo, ok6 := pl.RefToNamed[parentFuncRef]; ok6 && parentFuncNo.NameRefID >= 0 {
			if name, ok7 := pl.RefToStr[parentFuncNo.NameRefID]; ok7 && name != "" {
				if ctx.PoolCodeNames == nil {
					ctx.PoolCodeNames = make(map[int]string)
				}
				if _, exists := ctx.PoolCodeNames[pe.Index]; !exists {
					ctx.PoolCodeNames[pe.Index] = name
				}
			}
		}
	}
}

