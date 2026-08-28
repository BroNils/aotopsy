package frida

// FridaMetadata is the JSON structure exported for Frida scripts.
type FridaMetadata struct {
	DartVersion        string                 `json:"dart_version"`
	Architecture       string                 `json:"architecture"`
	CompressedPointers bool                   `json:"compressed_pointers"`
	PointerSize        int                    `json:"pointer_size"`
	ModuleBase         string                 `json:"module_base"`
	THRFields          map[int]string         `json:"thr_fields"`
	THRReg             string                 `json:"thr_reg"`
	PPReg              string                 `json:"pp_reg"`
	DTReg              string                 `json:"dt_reg"`
	HeapBaseReg        string                 `json:"heap_base_reg"`
	HeaderBitOffset    int                    `json:"header_bit_offset"`
	HeaderBitWidth     int                    `json:"header_bit_width"`
	Functions          []FridaFunction        `json:"functions"`
	UnresolvedBLRs     []FridaUnresolvedBLR   `json:"unresolved_blrs"`
	DispatchTable      []FridaDispatchEntry   `json:"dispatch_table"`
	StringRefs         []FridaStringRef       `json:"string_refs"`
	FFICallSites       []FridaFFICallSite     `json:"ffi_call_sites"`
}

type FridaFunction struct {
	VA    string `json:"va"`
	Name  string `json:"name"`
	Owner string `json:"owner,omitempty"`
	Size  int    `json:"size"`
}

type FridaUnresolvedBLR struct {
	VA       string `json:"va"`
	FromFunc string `json:"from_func"`
	Reg      string `json:"reg,omitempty"`
	Via      string `json:"via,omitempty"`
}

type FridaDispatchEntry struct {
	Index  int    `json:"index"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
}

type FridaStringRef struct {
	FromFunc string `json:"from_func"`
	Value    string `json:"value"`
	Kind     string `json:"kind,omitempty"`
}

type FridaFFICallSite struct {
	FromFunc string `json:"from_func"`
	VA       string `json:"va"`
	Kind     string `json:"kind"`
}
