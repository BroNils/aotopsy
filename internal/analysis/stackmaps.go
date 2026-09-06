package analysis

import (
	"sort"

	"aotopsy/internal/cluster"
)

// DecodeAllStackMaps returns the decoded GC stack maps for every Code object
// that has them, keyed by Code.RefID.
//
// There are two sources and they are version-disjoint:
//
//   - The CompressedStackMaps cluster, which carries one payload per Code.
//     Written in AOT only up to Dart 2.15: from 2.16.0 app_snapshot.cc guards
//     `WriteField(code, compressed_stackmaps_)` with `kind() == kFullJIT`.
//   - The InstructionsTable rodata, where each entry carries the offset of its
//     own payload and the header carries the canonicalized global table. This
//     is where the maps live on every 3.x build.
//
// The cluster wins where both exist, because it is the Code object's own
// payload rather than one located by table index.
//
// This lives in one function on purpose. It has two callers -- the decompiler
// enrichment path and the stack_maps.jsonl writer -- and a decoder that two
// callers reimplement is a decoder that two callers disagree about.
func DecodeAllStackMaps(result *cluster.Result, table *cluster.InstructionsTable) map[int][]cluster.StackMapEntry {
	out := make(map[int][]cluster.StackMapEntry)

	csmByRef := make(map[int]*cluster.CompressedStackMapsInfo, len(result.CompressedStackMaps))
	var globalTablePayload []byte
	for i := range result.CompressedStackMaps {
		csmByRef[result.CompressedStackMaps[i].RefID] = &result.CompressedStackMaps[i]
		p := result.CompressedStackMaps[i].Payload
		if len(p) >= 4 && globalTablePayload == nil {
			flagsAndSize := uint32(p[0]) | uint32(p[1])<<8 | uint32(p[2])<<16 | uint32(p[3])<<24
			if flagsAndSize&1 != 0 { // GlobalTableBit
				globalTablePayload = p
			}
		}
	}
	for _, ce := range result.Codes {
		if ce.CompressedStackMapsRef < 0 {
			continue
		}
		csm, ok := csmByRef[ce.CompressedStackMapsRef]
		if !ok || len(csm.Payload) == 0 {
			continue
		}
		entries, err := cluster.DecodeCompressedStackMaps(csm.Payload, globalTablePayload)
		if err != nil || len(entries) == 0 {
			continue
		}
		out[ce.RefID] = entries
	}

	if table != nil && table.HasStackMaps() {
		first := int(table.FirstEntryWithCode)
		for _, ce := range result.Codes {
			if ce.ClusterIndex < 0 {
				continue
			}
			if _, done := out[ce.RefID]; done {
				continue
			}
			entries, err := table.StackMapsAt(first + ce.ClusterIndex)
			if err != nil || len(entries) == 0 {
				continue
			}
			out[ce.RefID] = entries
		}
	}
	return out
}

// StackMapRecord is one Code object's GC stack maps in stack_maps.jsonl.
type StackMapRecord struct {
	CodeRef int             `json:"code_ref"`
	Entries []StackMapPoint `json:"entries"`
}

// StackMapPoint is one safepoint within a Code object.
//
// ObjectSpillSlots holds the frame-pointer-relative BYTE offsets of the spill
// slots the VM would trace as tagged object pointers at this PC. Absence of an
// offset means "not a tagged pointer" -- an unboxed double is live and absent
// -- so this field must not be read as a liveness set.
type StackMapPoint struct {
	PCOffset         uint32  `json:"pc_offset"`
	SpillSlotCount   int     `json:"spill_slot_count"`
	SavedSlotCount   int     `json:"saved_slot_count"`
	ObjectSpillSlots []int64 `json:"object_spill_slots,omitempty"`
}

// BuildStackMaps converts decoded stack maps into output records.
//
// Only Code objects with at least one safepoint carrying a set spill bit are
// emitted: an entry with no tagged slot states nothing a reader can act on,
// and including them would bury the real ones under empty rows.
func BuildStackMaps(decoded map[int][]cluster.StackMapEntry) []StackMapRecord {
	records := make([]StackMapRecord, 0, len(decoded))
	for codeRef, entries := range decoded {
		rec := StackMapRecord{CodeRef: codeRef}
		for _, e := range entries {
			slots := e.ObjectSpillSlotOffsets(8)
			if len(slots) == 0 {
				continue
			}
			rec.Entries = append(rec.Entries, StackMapPoint{
				PCOffset:         e.PCOffset,
				SpillSlotCount:   e.SpillSlotCount,
				SavedSlotCount:   e.SavedSlotCount,
				ObjectSpillSlots: slots,
			})
		}
		if len(rec.Entries) == 0 {
			continue
		}
		sort.Slice(rec.Entries, func(a, b int) bool {
			return rec.Entries[a].PCOffset < rec.Entries[b].PCOffset
		})
		records = append(records, rec)
	}
	// Map iteration order is randomised; the pipeline is required to be
	// byte-deterministic, so sort before returning.
	sort.Slice(records, func(a, b int) bool { return records[a].CodeRef < records[b].CodeRef })
	return records
}
