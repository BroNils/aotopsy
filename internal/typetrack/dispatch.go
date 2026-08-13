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
// BLRBreakdown separates the three different claims an indirect-call
// "resolution" can make. Reporting a single "resolved N/M" conflated them: a
// site with one known callee and a site with 43 possible ones counted the
// same, so the headline figure could rise while precision fell.
type BLRBreakdown struct {
	Total int `json:"total"`
	// Monomorphic: exactly one callee is known.
	Monomorphic int `json:"monomorphic"`
	// Polymorphic: the callee is one of N implementations of a selector.
	Polymorphic int `json:"polymorphic"`
	// PolymorphicCandidates is the sum of candidate counts over all
	// polymorphic sites -- average fan-out is Candidates/Polymorphic.
	PolymorphicCandidates int `json:"polymorphic_candidates"`
	// Stub: resolved to a VM stub through its THR slot. A real callee, but
	// not a Dart function, so it is counted apart from Monomorphic.
	Stub int `json:"stub"`
	// Unresolved: nothing was recovered.
	Unresolved int `json:"unresolved"`
}

// Resolved counts sites with exactly one known callee. It is deliberately NOT
// the total of everything the analysis said something about.
func (b BLRBreakdown) Resolved() int { return b.Monomorphic + b.Stub }

func WriteTypeInferenceReport(outDir string, bd BLRBreakdown, ctx *TypeContext) error {
	report := struct {
		// ResolvedBLR/TotalBLR are kept for compatibility with existing
		// readers; ResolvedBLR counts single-callee sites only.
		ResolvedBLR int          `json:"resolved_blr"`
		TotalBLR    int          `json:"total_blr"`
		BLR         BLRBreakdown `json:"blr"`
		// Per-source hit counters (omitted when no context was supplied).
		PoolHits          int `json:"pool_hits,omitempty"`
		HeaderHits        int `json:"header_hits,omitempty"`
		DispatchHits      int `json:"dispatch_hits,omitempty"`
		UBFXHits          int `json:"ubfx_hits,omitempty"`
		ADDClassHits      int `json:"add_class_hits,omitempty"`
		InstanceFieldHits int `json:"instance_field_hits,omitempty"`
		// x86_64 dispatch-call diagnosis; see TypeContext for what each
		// counter separates. Absent on ARM64, which computes the slot with
		// an ADD before the call rather than in the addressing mode.
		X86DispatchShape    int `json:"x86_dispatch_shape,omitempty"`
		X86DispatchNoTable  int `json:"x86_dispatch_no_table,omitempty"`
		X86DispatchNoClass  int `json:"x86_dispatch_no_class,omitempty"`
		X86DispatchResolved int `json:"x86_dispatch_resolved,omitempty"`
		NarrowHits          int `json:"narrow_hits,omitempty"`
		NarrowShape         int `json:"narrow_shape,omitempty"`
		NarrowNoType        int `json:"narrow_no_type,omitempty"`
		// InstantiatedClasses is the RTA universe: classes observed to be
		// allocated anywhere in the program. RTAApplied says whether the
		// selector-offset scan actually filtered candidates by it -- below
		// rtaMinInstantiatedClasses the universe is too small to trust and
		// the filter is skipped, which is easy to have on by accident.
		InstantiatedClasses int  `json:"instantiated_classes,omitempty"`
		RTAApplied          bool `json:"rta_applied"`
		// InstanceFieldClasses is how many classes have at least one
		// unanimously-typed field offset recovered from const instances.
		InstanceFieldClasses int `json:"instance_field_classes,omitempty"`
	}{
		ResolvedBLR: bd.Resolved(),
		TotalBLR:    bd.Total,
		BLR:         bd,
	}
	if ctx != nil {
		report.PoolHits = ctx.PPHits
		report.HeaderHits = ctx.HeaderHits
		report.DispatchHits = ctx.DispatchHits
		report.UBFXHits = ctx.UBFXHits
		report.X86DispatchShape = ctx.X86DispatchShape
		report.X86DispatchNoTable = ctx.X86DispatchNoTable
		report.X86DispatchNoClass = ctx.X86DispatchNoClass
		report.X86DispatchResolved = ctx.X86DispatchResolved
		report.NarrowHits = ctx.NarrowHits
		report.NarrowShape = ctx.NarrowShape
		report.NarrowNoType = ctx.NarrowNoType
		report.ADDClassHits = ctx.ADDClassHits
		report.InstanceFieldHits = ctx.InstanceFieldHits
		report.InstanceFieldClasses = len(ctx.InstanceFieldTypes)
		report.InstantiatedClasses = len(ctx.InstantiatedClasses)
		report.RTAApplied = ctx.RTAApplied()
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
