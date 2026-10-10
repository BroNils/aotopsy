package disasm

import "aotopsy/internal/thraudit"

// FuncRecord is one line in functions.jsonl.
type FuncRecord struct {
	PC         string `json:"pc"`
	PCOffset   uint32 `json:"pc_offset"`
	RefID      int    `json:"ref_id"`
	Size       int    `json:"size"`
	Name       string `json:"name"`
	Owner      string `json:"owner,omitempty"`
	ParamCount int    `json:"param_count,omitempty"`

	// Reflutter* fields are populated only by reflutter-import in a merged
	// artifact directory. Static analysis never sets them, so the ordinary
	// functions.jsonl schema stays byte-for-byte unchanged, while the strict
	// jsonutil readers can still load the merged file.
	ReflutterName    string `json:"reflutter_name,omitempty"`
	ReflutterClass   string `json:"reflutter_class,omitempty"`
	ReflutterLibrary string `json:"reflutter_library,omitempty"`
}

// RuntimeAgreement describes the relationship between a bounded runtime
// observation and the static prediction at the same call site. It does not
// change the certainty of the static claim.
type RuntimeAgreement string

const (
	RuntimeObservedOnly  RuntimeAgreement = "observed_only"
	RuntimeAgrees        RuntimeAgreement = "agreement"
	RuntimeConflicts     RuntimeAgreement = "conflict"
	RuntimeIndeterminate RuntimeAgreement = "indeterminate"
)

func (a RuntimeAgreement) Valid() bool {
	switch a {
	case RuntimeObservedOnly, RuntimeAgrees, RuntimeConflicts, RuntimeIndeterminate:
		return true
	}
	return false
}

// RuntimeTargetObservation is one target seen at a call site and the number of
// observations for that target. Counts are kept instead of collapsing runtime
// behavior into a set.
type RuntimeTargetObservation struct {
	Target string `json:"target"`
	Count  int    `json:"count"`
}

// RuntimeEvidence is runtime-only enrichment attached to a static call edge.
// Binary and generation identity make the observation reproducible and prevent
// a consumer from treating data from another build as support for this edge.
type RuntimeEvidence struct {
	Source       string                     `json:"source"`
	GenerationID string                     `json:"generation_id"`
	SourceSHA256 string                     `json:"source_sha256"`
	SourceSize   int64                      `json:"source_size"`
	ModuleName   string                     `json:"module_name"`
	DartVersion  string                     `json:"dart_version"`
	Architecture string                     `json:"architecture"`
	Agreement    RuntimeAgreement           `json:"agreement"`
	Targets      []RuntimeTargetObservation `json:"targets"`
	ClassIDs     []int                      `json:"class_ids,omitempty"`
	Observations int                        `json:"observations"`
}

// CallEdgeRecord is one line in call_edges.jsonl.
type CallEdgeRecord struct {
	FromFunc      string `json:"from_func"`
	FromPC        string `json:"from_pc"`
	Kind          string `json:"kind"`                     // "bl"/"call" (direct), "blr"/"call_indirect" (indirect)
	Target        string `json:"target,omitempty"`         // resolved callee identity used by graph consumers
	TargetAddress string `json:"target_address,omitempty"` // exact encoded destination for direct BL/CALL only
	Reg           string `json:"reg,omitempty"`            // "X16" etc for blr/call_indirect
	Via           string `json:"via,omitempty"`            // provenance for blr/call_indirect

	// Targets lists possible callees for a POLYMORPHIC indirect call: the
	// receiver class was unknown but the selector was, so the callee is one
	// of the implementations of that selector. Target is empty in that case
	// -- there is no single callee to name, and consumers that follow Target
	// (render.ReachableSet, the call graph, signal's flow analysis) must not
	// be handed a guess as if it were a fact.
	//
	// Candidates is how many distinct callees the scan found; Targets is
	// capped, so Candidates can be larger than len(Targets).
	Targets    []string `json:"targets,omitempty"`
	Candidates int      `json:"candidates,omitempty"`

	// Runtime is populated only by frida-import. Target/Targets above remain
	// strictly static analyzer output even when runtime observed a callee.
	Runtime *RuntimeEvidence `json:"runtime,omitempty"`
}

// UnresolvedTHRRecord is one line in unresolved_thr.jsonl.
type UnresolvedTHRRecord struct {
	FuncName       string                      `json:"func_name"`
	PC             string                      `json:"pc"`
	THROffset      int64                       `json:"thr_offset"`
	Width          int                         `json:"width"`
	Access         thraudit.AccessMode         `json:"access"`
	HeuristicClass thraudit.THRClass           `json:"heuristic_class"`
	Confidence     thraudit.EvidenceConfidence `json:"confidence"`
}

// StringRefRecord is one line in string_refs.jsonl.
type StringRefRecord struct {
	Func    string `json:"func"`
	PC      string `json:"pc"`
	Kind    string `json:"kind"` // "PP" or "PP_peep"
	PoolIdx int    `json:"pool_idx"`
	Value   string `json:"value"` // raw string value (unquoted)
}

// ResolvedTargets returns the resolved callee identity stored on a call edge,
// in priority order:
// 1. Target (single callee)
// 2. Targets (polymorphic indirect call — multiple candidates)
// 3. nil (no callee identity recorded)
//
// Via is deliberately excluded: it records provenance such as THR fields,
// object-pool slots, dispatch-table loads, or object fields. Provenance is
// evidence about where a call target came from, not itself a callee identity.
// Runtime evidence is deliberately excluded: one observed execution does not
// make a runtime target a static callee identity for graph/render consumers.
func (e CallEdgeRecord) ResolvedTargets() []string {
	if e.Target != "" {
		return []string{e.Target}
	}
	if len(e.Targets) > 0 {
		return e.Targets
	}
	return nil
}
