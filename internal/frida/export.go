package frida

import (
	"regexp"
	"strconv"
	"strings"

	"aotopsy/internal/disasm"
)

const MetadataSchemaVersion = 2

// FridaMetadata is the JSON structure exported for Frida scripts.
type FridaMetadata struct {
	SchemaVersion      int                   `json:"schema_version"`
	AnalyzerVersion    string                `json:"analyzer_version"`
	AnalyzerCommit     string                `json:"analyzer_commit"`
	GenerationID       string                `json:"generation_id"`
	SourceSHA256       string                `json:"source_sha256"`
	SourceSize         int64                 `json:"source_size"`
	ModuleName         string                `json:"module_name"`
	RuntimeIdentity    []RuntimeRegionDigest `json:"runtime_identity"`
	DartVersion        string                `json:"dart_version"`
	Architecture       string                `json:"architecture"`
	CompressedPointers bool                  `json:"compressed_pointers"`
	PointerSize        int                   `json:"pointer_size"`
	THRFields          map[int]string        `json:"thr_fields"`
	THRReg             string                `json:"thr_reg"`
	PPReg              string                `json:"pp_reg"`
	DTReg              string                `json:"dt_reg"`
	HeapBaseMode       string                `json:"heap_base_mode,omitempty"` // none, register, heap_bits, thread_field
	HeapBaseReg        string                `json:"heap_base_reg,omitempty"`
	HeapBaseTHRField   string                `json:"heap_base_thr_field,omitempty"`
	HeaderBitOffset    int                   `json:"header_bit_offset"`
	HeaderBitWidth     int                   `json:"header_bit_width"`
	Functions          []FridaFunction       `json:"functions"`
	UnresolvedBLRs     []FridaUnresolvedBLR  `json:"unresolved_blrs"`
	InstalledFunctions []FridaFunction       `json:"installed_functions"`
	InstalledBLRs      []FridaUnresolvedBLR  `json:"installed_blrs"`
	Artifacts          []ArtifactDigest      `json:"artifacts"`
	DispatchTable      []FridaDispatchEntry  `json:"dispatch_table"`
	StringRefs         []FridaStringRef      `json:"string_refs"`
}

type RuntimeRegionDigest struct {
	Kind   string `json:"kind"`
	Offset string `json:"offset"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type FridaFunction struct {
	VA    string `json:"va"`
	Name  string `json:"name"`
	Owner string `json:"owner,omitempty"`
	Size  int    `json:"size"`
}

type FridaUnresolvedBLR struct {
	VA         string `json:"va"`
	FromFunc   string `json:"from_func"`
	Via        string `json:"via,omitempty"`
	TargetKind string `json:"target_kind"` // "register" or "x86_mem"
	Reg        string `json:"reg,omitempty"`
	BaseReg    string `json:"base_reg,omitempty"`
	IndexReg   string `json:"index_reg,omitempty"`
	Scale      int    `json:"scale,omitempty"`
	Disp       int64  `json:"disp,omitempty"`
	ClassIDReg string `json:"class_id_reg,omitempty"`
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

var x86MemTargetRE = regexp.MustCompile(`^\[([A-Za-z0-9]+)(?:\+([A-Za-z0-9]+)\*([1248]))?(?:([+-])0x([0-9A-Fa-f]+))?\]$`)

const (
	minX86MemoryDisp int64 = -(1 << 31)
	maxX86MemoryDisp int64 = 1<<31 - 1
)

// NewUnresolvedProbe converts the call-edge target spelling emitted by
// internal/disasm into an explicit runtime target recipe. Frida's CPU context
// is keyed by register name; a CALL [base+index*scale+disp] is NOT a register
// name and has to be evaluated then dereferenced at runtime.
//
// Returning false is intentional fail-closed behavior: if a future disassembler
// spelling is not understood, the exporter must not emit a probe that can never
// resolve or, worse, reads the wrong context slot.
func NewUnresolvedProbe(va, fromFunc, target, via string) (FridaUnresolvedBLR, bool) {
	p := FridaUnresolvedBLR{VA: va, FromFunc: fromFunc, Via: via}
	target = strings.TrimSpace(target)
	if target == "" {
		return p, false
	}
	if !strings.HasPrefix(target, "[") {
		if !isContextRegister(target) {
			return p, false
		}
		p.TargetKind = "register"
		p.Reg = strings.ToLower(target)
		return p, true
	}
	m := x86MemTargetRE.FindStringSubmatch(target)
	if m == nil || !isContextRegister(m[1]) {
		return p, false
	}
	p.TargetKind = "x86_mem"
	p.BaseReg = strings.ToLower(m[1])
	if m[2] != "" {
		if !isContextRegister(m[2]) {
			return p, false
		}
		p.IndexReg = strings.ToLower(m[2])
		p.Scale, _ = strconv.Atoi(m[3])
	}
	if m[5] != "" {
		v, err := strconv.ParseUint(m[5], 16, 64)
		if err != nil {
			return p, false
		}
		if m[4] == "-" {
			if v > uint64(-minX86MemoryDisp) {
				return p, false
			}
			p.Disp = -int64(v)
		} else {
			if v > uint64(maxX86MemoryDisp) {
				return p, false
			}
			p.Disp = int64(v)
		}
	}
	return p, true
}

// RuntimeProbeForEdge is the single eligibility contract shared by Frida
// export and import. If this returns false, a generated aotopsy script will not
// instrument the static call edge and frida-import must therefore reject any
// runtime event claiming to originate from it.
func RuntimeProbeForEdge(e disasm.CallEdgeRecord) (FridaUnresolvedBLR, bool) {
	if e.Kind != "blr" && e.Kind != "call_indirect" {
		return FridaUnresolvedBLR{}, false
	}
	if e.Target != "" {
		return FridaUnresolvedBLR{}, false
	}
	if e.Via != "" && e.Via != "dispatch_table" && !strings.HasPrefix(e.Via, disasm.ObjectFieldVia) {
		return FridaUnresolvedBLR{}, false
	}
	return NewUnresolvedProbe(e.FromPC, e.FromFunc, e.Reg, e.Via)
}

func isContextRegister(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) >= 2 && s[0] == 'x' {
		n, err := strconv.Atoi(s[1:])
		return err == nil && n >= 0 && n <= 30
	}
	switch s {
	case "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15":
		return true
	}
	return false
}

func isContextRegisterForArch(architecture, s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	switch architecture {
	case "arm64":
		if len(s) < 2 || s[0] != 'x' {
			return false
		}
		n, err := strconv.Atoi(s[1:])
		return err == nil && n >= 0 && n <= 30
	case "x64":
		switch s {
		case "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
			"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15":
			return true
		}
	}
	return false
}
