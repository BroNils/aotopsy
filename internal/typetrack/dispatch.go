package typetrack

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/output"
)

// WriteTypeInferenceReport writes a summary report of the type inference
// results to typetrack_report.json in the output directory.
//
// ctx may be nil. When present, its hit counters are included so each inference
// rule's actual firing population is measurable rather than assumed.
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
		PoolHits      int `json:"pool_hits,omitempty"`
		PoolLoads     int `json:"pool_loads,omitempty"`
		HeaderHits    int `json:"header_hits,omitempty"`
		NarrowSrcHits int `json:"narrow_src_hits,omitempty"`
		SelRecvBound  int `json:"sel_recv_bound,omitempty"`
		SelRecvTop    int `json:"sel_recv_top,omitempty"`
		SelRecvNoLink int `json:"sel_recv_nolink,omitempty"`
		DispatchHits  int `json:"dispatch_hits,omitempty"`
		UBFXHits      int `json:"ubfx_hits,omitempty"`
		ADDClassHits  int `json:"add_class_hits,omitempty"`
		// AllocStubHits counts calls whose result class came from a
		// per-class allocation stub's Code.owner -- a structural fact, not
		// an inference from registers. Both architectures.
		AllocStubHits int `json:"alloc_stub_hits,omitempty"`
		// x86_64 dispatch-call diagnosis; see TypeContext for what each
		// counter separates. Absent on ARM64, which computes the slot with
		// an ADD before the call rather than in the addressing mode.
		X86DispatchShape    int `json:"x86_dispatch_shape,omitempty"`
		X86DispatchNoTable  int `json:"x86_dispatch_no_table,omitempty"`
		X86DispatchNoClass  int `json:"x86_dispatch_no_class,omitempty"`
		X86DispatchResolved int `json:"x86_dispatch_resolved,omitempty"`
		// NoClass split by cause: no CID producer (Top) versus a proven CID
		// scalar whose numeric value is unknown.
		X86DispatchClassTop        int `json:"x86_dispatch_class_top,omitempty"`
		X86DispatchClassUnknownCID int `json:"x86_dispatch_class_unknown_cid,omitempty"`
		X86DispatchClassOther      int `json:"x86_dispatch_class_other,omitempty"`
		// BL return value propagation stats: how many BL calls found usable
		// callee exit types, and how many of those were object class facts.
		BLTotal       int `json:"bl_total,omitempty"`
		BLHasExitType int `json:"bl_has_exit_type,omitempty"`
		BLExitKnown   int `json:"bl_exit_known,omitempty"`
		NarrowHits    int `json:"narrow_hits,omitempty"`
		NarrowShape   int `json:"narrow_shape,omitempty"`
		NarrowNoType  int `json:"narrow_no_type,omitempty"`
		// Observed populations only; these are not candidate-elimination rules.
		InstantiatedClasses int `json:"instantiated_classes,omitempty"`
		// BLR lattice state distribution at the BLR point.
		BLRAtKnownDispatch    int `json:"blr_at_known_dispatch,omitempty"`
		BLRAtKnownDispatchSel int `json:"blr_at_known_dispatch_sel,omitempty"`
		BLRAtObject           int `json:"blr_at_object,omitempty"`
		BLRAtStub             int `json:"blr_at_stub,omitempty"`
		BLRAtTop              int `json:"blr_at_top,omitempty"`
		BLRAtUnreachable      int `json:"blr_at_unreachable_invariant,omitempty"`
		BLRAtOther            int `json:"blr_at_other,omitempty"`
		// Declared static field bounds are the only authoritative field type source.
		FieldTypeDeclaredHits    int `json:"field_type_declared_hits,omitempty"`
		FieldTypeDeclaredClasses int `json:"field_type_declared_classes,omitempty"`
		SelectorMonomorphicCount int `json:"selector_monomorphic_count,omitempty"`
		// Row identity coverage of the dispatch table's Code slots (selector_rows.go):
		// slots whose declaring class / selector leaf were recovered. Low values mean
		// selectorCandidates falls back to leaf-less matching and over-approximates.
		DispatchCodeSlots     int  `json:"dispatch_code_slots,omitempty"`
		DispatchSlotsOwned    int  `json:"dispatch_slots_with_owner,omitempty"`
		DispatchSlotsLeafed   int  `json:"dispatch_slots_with_leaf,omitempty"`
		FuncReturnTypeCount   int  `json:"func_return_type_count,omitempty"`
		FuncReturnTypeSeeds   int  `json:"func_return_type_seeds,omitempty"`
		ArgsDescReceiverHits  int  `json:"args_desc_receiver_hits,omitempty"`
		ArgsDescReceiverFuncs int  `json:"args_desc_receiver_funcs,omitempty"`
		InterIterations       int  `json:"inter_iterations,omitempty"`
		InterConverged        bool `json:"inter_converged"`
	}{
		ResolvedBLR: bd.Resolved(),
		TotalBLR:    bd.Total,
		BLR:         bd,
	}
	if ctx != nil {
		report.PoolHits = ctx.PPHits
		report.PoolLoads = ctx.PPLoads
		report.HeaderHits = ctx.HeaderHits
		report.NarrowSrcHits = ctx.NarrowSrcHits
		report.SelRecvBound = ctx.SelRecvBound
		report.SelRecvTop = ctx.SelRecvTop
		report.SelRecvNoLink = ctx.SelRecvNoLink
		report.DispatchHits = ctx.DispatchHits
		report.UBFXHits = ctx.UBFXHits
		report.AllocStubHits = ctx.AllocStubHits
		report.X86DispatchShape = ctx.X86DispatchShape
		report.X86DispatchNoTable = ctx.X86DispatchNoTable
		report.X86DispatchNoClass = ctx.X86DispatchNoClass
		report.X86DispatchResolved = ctx.X86DispatchResolved
		report.X86DispatchClassTop = ctx.X86DispatchClassTop
		report.X86DispatchClassUnknownCID = ctx.X86DispatchClassUnknownCID
		report.X86DispatchClassOther = ctx.X86DispatchClassOther
		report.BLTotal = ctx.BLTotal
		report.BLHasExitType = ctx.BLHasExitType
		report.BLExitKnown = ctx.BLExitKnown
		report.NarrowHits = ctx.NarrowHits
		report.NarrowShape = ctx.NarrowShape
		report.NarrowNoType = ctx.NarrowNoType
		report.ADDClassHits = ctx.ADDClassHits
		report.InstantiatedClasses = len(ctx.InstantiatedClasses)
		report.BLRAtKnownDispatch = ctx.BLRAtKnownDispatch
		report.BLRAtKnownDispatchSel = ctx.BLRAtKnownDispatchSel
		report.BLRAtObject = ctx.BLRAtObject
		report.BLRAtStub = ctx.BLRAtStub
		report.BLRAtTop = ctx.BLRAtTop
		report.BLRAtUnreachable = ctx.BLRAtUnreachable
		report.BLRAtOther = ctx.BLRAtOther
		report.FieldTypeDeclaredHits = ctx.FieldTypeDeclaredHits
		report.FieldTypeDeclaredClasses = len(ctx.FieldByOwnerOffset)
		report.SelectorMonomorphicCount = len(ctx.SelectorMonomorphic)
		report.DispatchCodeSlots = len(ctx.DispatchSlotMeta)
		for _, m := range ctx.DispatchSlotMeta {
			if m.Owner >= 0 {
				report.DispatchSlotsOwned++
			}
			if m.Leaf != "" {
				report.DispatchSlotsLeafed++
			}
		}
		report.FuncReturnTypeCount = len(ctx.FuncReturnType)
		report.FuncReturnTypeSeeds = ctx.FuncReturnTypeSeeds
		report.ArgsDescReceiverHits = ctx.ArgsDescReceiverHits
		report.ArgsDescReceiverFuncs = len(ctx.ReceiverLoadAtPC)
		report.InterIterations = ctx.InterIterations
		report.InterConverged = ctx.InterConverged
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(outDir, "typetrack_report.json")
	return output.WriteFileAtomic(path, data, 0o644)
}

type dispatchRecord struct {
	Index    int    `json:"index"`
	Kind     string `json:"kind"`
	Target   string `json:"target,omitempty"`
	SlotInfo string `json:"slot_info,omitempty"`
}

// WriteDispatchTable writes the parsed dispatch table to dispatch_table.jsonl
// in the output directory, for debugging and verification.
func WriteDispatchTable(outDir string, entries []cluster.DispatchTableEntry, ctx *TypeContext) error {
	path := filepath.Join(outDir, "dispatch_table.jsonl")
	records := make([]dispatchRecord, 0, len(entries))
	for _, e := range entries {
		record := dispatchRecord{
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

		records = append(records, record)
	}
	_, err := jsonutil.WriteJSONLFile(path, records)
	return err
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
	case LatticeBottom:
		return "Bottom"
	case LatticeTop:
		return "Top"
	case LatticeExactClass, LatticeClassBound, LatticeExactClassID:
		name := ""
		if ctx != nil {
			name = ctx.ClassIDToName[t.ClassID]
		}
		prefix := "ExactClass"
		if t.Kind == LatticeClassBound {
			prefix = "ClassBound"
		} else if t.Kind == LatticeExactClassID {
			prefix = "ClassID"
		}
		if name != "" {
			return fmt.Sprintf("%s(%s/%d)", prefix, name, t.ClassID)
		}
		return fmt.Sprintf("%s(%d)", prefix, t.ClassID)
	case LatticeUnknownClassID:
		return "ClassID(?)"
	case LatticeKnownDispatchIndex:
		return fmt.Sprintf("Dispatch(%d)", t.DispatchIndex)
	case LatticeKnownStub:
		return fmt.Sprintf("Stub(%s@0x%x)", t.StubName, t.StubOff)
	default:
		return strings.ToLower(fmt.Sprintf("Unknown(%d)", t.Kind))
	}
}
