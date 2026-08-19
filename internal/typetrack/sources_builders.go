package typetrack

import (
	"sort"

	"aotopsy/internal/cluster"
	"aotopsy/internal/snapshot"
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
	// RefToType is built once in BuildTypeContext (includes VM Types).
	refToType := ctx.RefToType
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
	// FieldValueClass never found anything, making the declared field
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
				fieldTypeResolved++
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
	ctx.FieldTypesResolvedCount = fieldTypeResolved
}

// buildPoolClassByIndex builds PP index → ClassID map.
func buildPoolClassByIndex(ctx *TypeContext, clResult *cluster.Result, pl *PoolLookupData) {
	// RefToType is built once in BuildTypeContext.
	refToType := ctx.RefToType
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
		// Both maps are resolved the same way, including the Type
		// indirection. The VM branch used to skip Types on the grounds
		// that "refToType only covers isolate Types" -- which stopped
		// being true when RefToType was unified in BuildTypeContext,
		// where it is now filled from clResult.Types AND pl.VmTypes.
		// The comment outlived the limitation, and a VM Type in the pool
		// stayed unresolved for no reason.
		classID := -1
		if pl.RefCID != nil {
			classID = poolEntryClassID(pl.RefCID, refToType, pl.CT, pe.RefID)
		}
		if classID < 0 && pl.VmRefCID != nil {
			classID = poolEntryClassID(pl.VmRefCID, refToType, pl.CT, pe.RefID)
		}
		if classID >= 0 {
			ctx.PoolClassByIndex[pe.Index] = classID
		}
	}
}

// poolEntryClassID resolves one pool entry's ref to a class ID through a
// CID map, returning -1 when it cannot.
//
// A Type object needs one more hop: the entry's own CID is kTypeCid, which
// says only "this is a type", so the class it DESCRIBES comes from
// TypeInfo.ClassID. Reporting kTypeCid instead would type every PP load of a
// Type as an instance of Type. A Type whose ClassID is unresolved stays -1 --
// unresolved is the safe answer, since the caller turns a non-negative result
// into a KnownClass the BLR resolver then trusts.
func poolEntryClassID(cidByRef map[int]int, refToType map[int]*cluster.TypeInfo, ct *snapshot.CIDTable, refID int) int {
	cid, ok := cidByRef[refID]
	if !ok || cid < 0 {
		return -1
	}
	if ct != nil && cid == ct.Type {
		if ti, ok := refToType[refID]; ok && ti.ClassID >= 0 {
			return int(ti.ClassID)
		}
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
