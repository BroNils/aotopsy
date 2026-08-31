package disasm

// FuncRecord is one line in functions.jsonl.
type FuncRecord struct {
	PC         string `json:"pc"`
	Size       int    `json:"size"`
	Name       string `json:"name"`
	Owner      string `json:"owner,omitempty"`
	ParamCount int    `json:"param_count,omitempty"`
}

// CallEdgeRecord is one line in call_edges.jsonl.
type CallEdgeRecord struct {
	FromFunc string `json:"from_func"`
	FromPC   string `json:"from_pc"`
	Kind     string `json:"kind"`             // "bl"/"call" (direct), "blr"/"call_indirect" (indirect)
	Target   string `json:"target,omitempty"` // THE callee: resolved name, or "0x..." for bl/call
	Reg      string `json:"reg,omitempty"`    // "X16" etc for blr/call_indirect
	Via      string `json:"via,omitempty"`    // provenance for blr/call_indirect

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
}

// UnresolvedTHRRecord is one line in unresolved_thr.jsonl.
type UnresolvedTHRRecord struct {
	FuncName  string `json:"func_name"`
	PC        string `json:"pc"`
	THROffset string `json:"thr_offset"`
	Width     int    `json:"width"`
	IsStore   bool   `json:"is_store,omitempty"`
	Class     string `json:"class"` // RUNTIME_ENTRY, OBJSTORE, ISO_GROUP, UNKNOWN
}

// StringRefRecord is one line in string_refs.jsonl.
type StringRefRecord struct {
	Func    string `json:"func"`
	PC      string `json:"pc"`
	Kind    string `json:"kind"` // "PP" or "PP_peep"
	PoolIdx int    `json:"pool_idx"`
	Value   string `json:"value"` // raw string value (unquoted)
}

// ResolvedTargets returns the callee name(s) for a call edge, in priority order:
// 1. Target (direct call — single callee)
// 2. Targets (polymorphic indirect call — multiple candidates)
// 3. Via (indirect call with provenance but no resolved target — last resort)
// 4. nil (truly unresolved)
//
// All consumers that need "what does this edge call?" should use this helper
// instead of checking Target/Via/Candidates individually, so the resolution
// policy is consistent across render, signal, callgraph, and xref.
func (e CallEdgeRecord) ResolvedTargets() []string {
	if e.Target != "" {
		return []string{e.Target}
	}
	if len(e.Targets) > 0 {
		return e.Targets
	}
	if e.Via != "" {
		return []string{e.Via}
	}
	return nil
}
