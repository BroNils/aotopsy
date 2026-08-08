package typetrack

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aotopsy/internal/cluster"
)

// WriteTypeInferenceReport writes a summary report of the type inference
// results to typetrack_report.json in the output directory.
//
// ctx may be nil. When present, its hit counters are included so each type
// source's contribution is measurable rather than assumed -- specifically
// instance_field_hits, which is the only visible evidence that the Instance
// capture (gap §1.2) actually feeds type inference (gap §3.1). A consumer whose
// contribution is never measured is how this project previously ended up
// shipping an ICData resolver that resolved zero call sites.
func WriteTypeInferenceReport(outDir string, resolved, total int, ctx *TypeContext) error {
	report := struct {
		ResolvedBLR int `json:"resolved_blr"`
		TotalBLR    int `json:"total_blr"`
		// Per-source hit counters (omitted when no context was supplied).
		PoolHits          int `json:"pool_hits,omitempty"`
		HeaderHits        int `json:"header_hits,omitempty"`
		DispatchHits      int `json:"dispatch_hits,omitempty"`
		InstanceFieldHits int `json:"instance_field_hits,omitempty"`
		// InstanceFieldClasses is how many classes have at least one
		// unanimously-typed field offset recovered from const instances.
		InstanceFieldClasses int `json:"instance_field_classes,omitempty"`
	}{
		ResolvedBLR: resolved,
		TotalBLR:    total,
	}
	if ctx != nil {
		report.PoolHits = ctx.PPHits
		report.HeaderHits = ctx.HeaderHits
		report.DispatchHits = ctx.DispatchHits
		report.InstanceFieldHits = ctx.InstanceFieldHits
		report.InstanceFieldClasses = len(ctx.InstanceFieldTypes)
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(outDir, "typetrack_report.json")
	return os.WriteFile(path, data, 0644)
}

// WriteDispatchTable writes the parsed dispatch table to dispatch_table.jsonl
// in the output directory, for debugging and verification.
func WriteDispatchTable(outDir string, entries []cluster.DispatchTableEntry, ctx *TypeContext) error {
	path := filepath.Join(outDir, "dispatch_table.jsonl")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, e := range entries {
		record := struct {
			Index    int    `json:"index"`
			Kind     string `json:"kind"`
			Target   string `json:"target,omitempty"`
			SlotInfo string `json:"slot_info,omitempty"`
		}{
			Index: e.Index,
			Kind:  dispatchKindString(e.Kind),
		}

		switch e.Kind {
		case cluster.DispatchCode:
			if name, ok := ctx.DispatchCodeIndexToName[e.ClusterIndex]; ok {
				record.Target = name
			}
			record.SlotInfo = fmt.Sprintf("code cluster_index=%d", e.ClusterIndex)
		case cluster.DispatchStub:
			record.SlotInfo = fmt.Sprintf("stub index=%d", e.StubIndex)
		}

		if err := enc.Encode(record); err != nil {
			return err
		}
	}

	return nil
}

func dispatchKindString(k cluster.DispatchTableEntryKind) string {
	switch k {
	case cluster.DispatchNull:
		return "null"
	case cluster.DispatchCode:
		return "code"
	case cluster.DispatchStub:
		return "stub"
	default:
		return "unknown"
	}
}

// FormatLattice returns a human-readable string for a TypeLattice value.
func FormatLattice(t TypeLattice, ctx *TypeContext) string {
	switch t.Kind {
	case LatticeTop:
		return "Top"
	case LatticeBottom:
		return "Bottom"
	case LatticeKnownClass:
		name := ""
		if ctx != nil {
			name = ctx.ClassIDToName[t.ClassID]
		}
		if name != "" {
			return fmt.Sprintf("Class(%s/%d)", name, t.ClassID)
		}
		return fmt.Sprintf("Class(%d)", t.ClassID)
	case LatticeKnownDispatchIndex:
		return fmt.Sprintf("Dispatch(%d)", t.DispatchIndex)
	case LatticeKnownStub:
		return fmt.Sprintf("Stub(%s@0x%x)", t.StubName, t.StubOff)
	default:
		return strings.ToLower(fmt.Sprintf("Unknown(%d)", t.Kind))
	}
}
