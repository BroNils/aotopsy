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
	Target   string `json:"target,omitempty"` // resolved name or "0x..." for bl/call
	Reg      string `json:"reg,omitempty"`    // "X16" etc for blr/call_indirect
	Via      string `json:"via,omitempty"`    // provenance for blr/call_indirect
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
