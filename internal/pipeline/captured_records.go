package pipeline

import (
	"aotopsy/internal/cluster"
	"aotopsy/internal/naming"
)

type ScriptRecord struct {
	RefID             int    `json:"ref_id"`
	URL               string `json:"url"`
	LineOffset        int32  `json:"line_offset,omitempty"`
	ColOffset         int32  `json:"col_offset,omitempty"`
	KernelScriptIndex int32  `json:"kernel_script_index,omitempty"`
}

// BuildScripts joins cluster.ScriptInfo + PoolLookups string table → script records.
func BuildScripts(result *cluster.Result, pl *naming.PoolLookups) []ScriptRecord {
	var records []ScriptRecord
	for _, si := range result.Scripts {
		url := pl.RefToStr[si.URLRef]
		rec := ScriptRecord{
			RefID:             si.RefID,
			URL:               url,
			LineOffset:        si.LineOffset,
			ColOffset:         si.ColOffset,
			KernelScriptIndex: si.KernelScriptIndex,
		}
		records = append(records, rec)
	}
	return records
}

// RefNull re-exports cluster.RefNull for readability at call sites here.
const RefNull = cluster.RefNull

// LoadingUnitRecord is one LoadingUnit entry in loading_units.jsonl.
type LoadingUnitRecord struct {
	RefID     int   `json:"ref_id"`
	ParentRef int   `json:"parent_ref,omitempty"`
	UnitID    int32 `json:"unit_id,omitempty"`
	// IsRoot is true when parent_ is null, i.e. this is the base unit whose
	// Code objects live in the snapshot we just parsed.
	IsRoot bool `json:"is_root,omitempty"`
	// MainCodeCount / DeferredCodeCount describe the Code partition. Only set
	// on the root unit -- see PartitionCodesByLoadingUnit for why a non-root
	// unit's codes are not in this snapshot at all.
	MainCodeCount     int `json:"main_code_count,omitempty"`
	DeferredCodeCount int `json:"deferred_code_count,omitempty"`
}

// LoadingUnitPartition is the Code-to-loading-unit attribution for one snapshot.
//
// This implements the "partition Codes by loading unit" half of the LoadingUnit
// gap. What it can and cannot say is a property of split AOT, not a shortcut:
//
// Dart's deferred loading splits an app into a root unit plus one unit per
// deferred import, and each unit gets its OWN snapshot blob (app.so,
// app-2.part.so, ...). The Code cluster inside a single blob is written in two
// sections -- see CodeDeserializationCluster::ReadAlloc, which reads `count`
// main codes and then `deferred_count` deferred ones. The main section is the
// code this blob defines; the deferred section is a set of Code objects that
// this blob references but whose instructions live in another unit's blob
// (ReadInstructions early-returns for them, which is why our reader leaves
// ClusterIndex == -1).
//
// So per-blob the honest partition is exactly two buckets: "defined here"
// (root unit) and "defined in some other unit" (deferred). Attributing a
// deferred Code to a SPECIFIC unit id requires loading that unit's blob too,
// which is a multi-file input this tool does not take yet.
type LoadingUnitPartition struct {
	// RootUnitID is the id of the unit this snapshot defines, or 0 if no
	// LoadingUnit cluster was present.
	RootUnitID int32
	// UnitCount is the number of LoadingUnit objects described in this
	// snapshot (including non-root ones, which are metadata-only here).
	UnitCount int
	// MainCodeRefs are Code ref IDs defined by the root unit.
	MainCodeRefs []int
	// DeferredCodeRefs are Code ref IDs referenced here but defined in
	// another loading unit's blob.
	DeferredCodeRefs []int
	// Degenerate is true when there is at most one unit and no deferred
	// codes, i.e. the app uses no deferred imports and the partition carries
	// no information. Callers should say so rather than presenting a
	// single-bucket split as a result.
	Degenerate bool
}

// PartitionCodesByLoadingUnit splits result.Codes into root-unit and deferred
// buckets and pairs that with the LoadingUnit metadata.
func PartitionCodesByLoadingUnit(result *cluster.Result) *LoadingUnitPartition {
	p := &LoadingUnitPartition{UnitCount: len(result.LoadingUnits)}
	for _, lui := range result.LoadingUnits {
		if lui.ParentRef == RefNull {
			p.RootUnitID = lui.UnitID
			break
		}
	}
	for _, ce := range result.Codes {
		if ce.ClusterIndex >= 0 {
			p.MainCodeRefs = append(p.MainCodeRefs, ce.RefID)
		} else {
			p.DeferredCodeRefs = append(p.DeferredCodeRefs, ce.RefID)
		}
	}
	p.Degenerate = p.UnitCount <= 1 && len(p.DeferredCodeRefs) == 0
	return p
}

// UnitOf reports which bucket a Code ref belongs to: the root unit id when the
// Code is defined in this snapshot, or 0 with deferred=true when it is defined
// in another unit. found is false for a ref that is not a Code at all.
func (p *LoadingUnitPartition) UnitOf(codeRef int) (unitID int32, deferred, found bool) {
	for _, r := range p.MainCodeRefs {
		if r == codeRef {
			return p.RootUnitID, false, true
		}
	}
	for _, r := range p.DeferredCodeRefs {
		if r == codeRef {
			return 0, true, true
		}
	}
	return 0, false, false
}

// BuildLoadingUnits converts cluster.LoadingUnitInfo → output records, with the
// Code partition folded onto the root unit.
func BuildLoadingUnits(result *cluster.Result) []LoadingUnitRecord {
	part := PartitionCodesByLoadingUnit(result)
	var records []LoadingUnitRecord
	for _, lui := range result.LoadingUnits {
		rec := LoadingUnitRecord{
			RefID:     lui.RefID,
			ParentRef: lui.ParentRef,
			UnitID:    lui.UnitID,
			IsRoot:    lui.ParentRef == RefNull,
		}
		if rec.IsRoot {
			rec.MainCodeCount = len(part.MainCodeRefs)
			rec.DeferredCodeCount = len(part.DeferredCodeRefs)
		}
		records = append(records, rec)
	}
	return records
}

// KPIRecord is one KernelProgramInfo entry in kpi.jsonl.
type KPIRecord struct {
	RefID              int `json:"ref_id"`
	KernelComponentRef int `json:"kernel_component_ref,omitempty"`
	StringOffsetsRef   int `json:"string_offsets_ref,omitempty"`
	StringDataRef      int `json:"string_data_ref,omitempty"`
	CanonicalNamesRef  int `json:"canonical_names_ref,omitempty"`
	ConstantsRef       int `json:"constants_ref,omitempty"`
	ConstantsTableRef  int `json:"constants_table_ref,omitempty"`
}

// BuildKPI converts cluster.KernelProgramInfoRef → output records.
func BuildKPI(result *cluster.Result) []KPIRecord {
	var records []KPIRecord
	for _, kpi := range result.KernelProgramInfo {
		rec := KPIRecord{
			RefID:              kpi.RefID,
			KernelComponentRef: kpi.KernelComponentRef,
			StringOffsetsRef:   kpi.StringOffsetsRef,
			StringDataRef:      kpi.StringDataRef,
			CanonicalNamesRef:  kpi.CanonicalNamesRef,
			ConstantsRef:       kpi.ConstantsRef,
			ConstantsTableRef:  kpi.ConstantsTableRef,
		}
		records = append(records, rec)
	}
	return records
}

// InstanceFieldRecord is one captured pointer field of an instance.
type InstanceFieldRecord struct {
	Offset int    `json:"offset"`
	Ref    int    `json:"ref"`
	Name   string `json:"name,omitempty"` // field name when the offset maps to a known layout slot
}

// InstanceRecord is one Instance entry in instances.jsonl.
type InstanceRecord struct {
	RefID int `json:"ref_id"`
	CID   int `json:"cid"`
	// SlotCount is the number of field slots the object has, including unboxed
	// ones that produce no entry in Fields.
	SlotCount int                   `json:"slot_count,omitempty"`
	Fields    []InstanceFieldRecord `json:"fields,omitempty"`
}

// BuildInstances converts cluster.InstanceInfo → output records, naming each
// field offset via the class layout where possible.
//
// The old shape was a bare "field_refs":[...] list with no offsets, which was
// not usable: the position of a ref in that list is not its field index once
// any unboxed field is present. Offsets now come from the capture itself.
func BuildInstances(result *cluster.Result, layouts []DartClassLayout) []InstanceRecord {
	// classID -> byteOffset -> field name.
	nameByCIDOffset := make(map[int32]map[int32]string, len(layouts))
	for _, l := range layouts {
		m := make(map[int32]string, len(l.Fields))
		for _, f := range l.Fields {
			m[f.ByteOffset] = f.Name
		}
		nameByCIDOffset[l.ClassID] = m
	}

	records := make([]InstanceRecord, 0, len(result.Instances))
	for _, ii := range result.Instances {
		rec := InstanceRecord{
			RefID:     ii.RefID,
			CID:       ii.CID,
			SlotCount: ii.NumFieldSlots,
		}
		names := nameByCIDOffset[int32(ii.CID)]
		for _, f := range ii.Fields {
			fr := InstanceFieldRecord{Offset: int(f.ByteOffset), Ref: f.Ref}
			if names != nil {
				fr.Name = names[f.ByteOffset]
			}
			rec.Fields = append(rec.Fields, fr)
		}
		records = append(records, rec)
	}
	return records
}

// ContextRecord is one Context entry in contexts.jsonl.
type ContextRecord struct {
	RefID     int   `json:"ref_id"`
	ParentRef int   `json:"parent_ref,omitempty"`
	VarRefs   []int `json:"var_refs,omitempty"`
}

// BuildContexts converts cluster.ContextInfo → output records.
func BuildContexts(result *cluster.Result) []ContextRecord {
	var records []ContextRecord
	for _, ci := range result.Contexts {
		rec := ContextRecord{
			RefID:     ci.RefID,
			ParentRef: ci.ParentRef,
			VarRefs:   ci.VarRefs,
		}
		records = append(records, rec)
	}
	return records
}

// TypeArgumentsRecord is one TypeArguments entry in type_arguments.jsonl.
type TypeArgumentsRecord struct {
	RefID          int   `json:"ref_id"`
	Length         int   `json:"length"`
	TypeRefs       []int `json:"type_refs,omitempty"`
	Instantiations int   `json:"instantiations_ref,omitempty"`
	Hash           int32 `json:"hash,omitempty"`
	Nullability    int   `json:"nullability,omitempty"`
}

// BuildTypeArguments converts cluster.TypeArgumentsInfo → output records.
func BuildTypeArguments(result *cluster.Result) []TypeArgumentsRecord {
	var records []TypeArgumentsRecord
	for _, ta := range result.TypeArguments {
		rec := TypeArgumentsRecord{
			RefID:          ta.RefID,
			Length:         ta.Length,
			TypeRefs:       ta.TypeRefs,
			Instantiations: ta.Instantiations,
			Hash:           ta.Hash,
			Nullability:    ta.Nullability,
		}
		records = append(records, rec)
	}
	return records
}

// ExceptionHandlerRecord is one ExceptionHandlers entry in exception_handlers.jsonl.
type ExceptionHandlerRecord struct {
	RefID           int                     `json:"ref_id"`
	HandledTypesRef int                     `json:"handled_types_ref,omitempty"`
	Handlers        []ExceptionHandlerEntry `json:"handlers,omitempty"`
}

// ExceptionHandlerEntry is one handler in an ExceptionHandlerRecord.
type ExceptionHandlerEntry struct {
	PCOffset        int32 `json:"pc_offset"`
	OuterTryIndex   int16 `json:"outer_try_index,omitempty"`
	NeedsStacktrace bool  `json:"needs_stacktrace,omitempty"`
	HasCatchAll     bool  `json:"has_catch_all,omitempty"`
	IsGenerated     bool  `json:"is_generated,omitempty"`
}

// BuildExceptionHandlers converts cluster.ExceptionHandlerInfo → output records.
func BuildExceptionHandlers(result *cluster.Result) []ExceptionHandlerRecord {
	var records []ExceptionHandlerRecord
	for _, eh := range result.ExceptionHandlers {
		rec := ExceptionHandlerRecord{
			RefID:           eh.RefID,
			HandledTypesRef: eh.HandledTypesRef,
		}
		for _, h := range eh.Handlers {
			rec.Handlers = append(rec.Handlers, ExceptionHandlerEntry{
				PCOffset:        h.PCOffset,
				OuterTryIndex:   h.OuterTryIndex,
				NeedsStacktrace: h.NeedsStacktrace,
				HasCatchAll:     h.HasCatchAll,
				IsGenerated:     h.IsGenerated,
			})
		}
		records = append(records, rec)
	}
	return records
}

// ICDataRecord is one ICData entry in icdata.jsonl.
//
// Emitted only if an ICData cluster is ever present; AOT snapshots have none
// (see cluster.ICDataInfo). The fields track ICData's ReadFromTo order --
// the old single "owner_ref" field did not correspond to any ICData ref slot.
type ICDataRecord struct {
	RefID         int `json:"ref_id"`
	TargetNameRef int `json:"target_name_ref,omitempty"`
	ArgsDescRef   int `json:"args_desc_ref,omitempty"`
	EntriesRef    int `json:"entries_ref,omitempty"`
}

// BuildICData converts cluster.ICDataInfo → output records.
func BuildICData(result *cluster.Result) []ICDataRecord {
	var records []ICDataRecord
	for _, icd := range result.ICData {
		rec := ICDataRecord{
			RefID:         icd.RefID,
			TargetNameRef: icd.TargetNameRef,
			ArgsDescRef:   icd.ArgsDescRef,
			EntriesRef:    icd.EntriesRef,
		}
		records = append(records, rec)
	}
	return records
}

// ClosureDataRecord is one ClosureData entry in closure_data.jsonl.
type ClosureDataRecord struct {
	RefID             int `json:"ref_id"`
	ParentFunctionRef int `json:"parent_function_ref,omitempty"`
	ClosureRef        int `json:"closure_ref,omitempty"`
}

// BuildClosureData converts cluster.ClosureDataInfo → output records.
func BuildClosureData(result *cluster.Result) []ClosureDataRecord {
	var records []ClosureDataRecord
	for _, cd := range result.ClosureData {
		rec := ClosureDataRecord{
			RefID:             cd.RefID,
			ParentFunctionRef: cd.ParentFunctionRef,
			ClosureRef:        cd.ClosureRef,
		}
		records = append(records, rec)
	}
	return records
}
