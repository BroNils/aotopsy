package frida

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"aotopsy/internal/disasm"
)

// ValidateStaticCallEdges enforces the call-edge invariants required by a
// Frida static generation. Runtime-enriched edges are deliberately rejected:
// otherwise exporting a previously merged directory would bind stale runtime
// observations into a new generation, and an unobserved site on the next run
// could retain evidence from the old execution.
func ValidateStaticCallEdges(edges []disasm.CallEdgeRecord) error {
	for i, e := range edges {
		if strings.TrimSpace(e.FromFunc) == "" || strings.TrimSpace(e.FromPC) == "" || strings.TrimSpace(e.Kind) == "" {
			return fmt.Errorf("call edge %d missing required field", i)
		}
		canonicalPC, err := canonicalRuntimeHex(e.FromPC)
		if err != nil {
			return fmt.Errorf("call edge %d has invalid from_pc %q: %w", i, e.FromPC, err)
		}
		if canonicalPC != e.FromPC {
			return fmt.Errorf("call edge %d has non-canonical from_pc %q", i, e.FromPC)
		}
		if e.Runtime != nil {
			return fmt.Errorf("call edge %d contains runtime enrichment in a static generation", i)
		}

		switch e.Kind {
		case "bl", "call":
			if e.TargetAddress != "" {
				canonicalTarget, err := canonicalRuntimeHex(e.TargetAddress)
				if err != nil {
					return fmt.Errorf("direct call edge %d has invalid target_address %q: %w", i, e.TargetAddress, err)
				}
				if canonicalTarget != e.TargetAddress {
					return fmt.Errorf("direct call edge %d has non-canonical target_address %q", i, e.TargetAddress)
				}
			} else if e.Target != "" {
				return fmt.Errorf("direct call edge %d has symbolic target without encoded target_address", i)
			}
			if len(e.Targets) != 0 || e.Candidates != 0 {
				return fmt.Errorf("direct call edge %d carries polymorphic candidates", i)
			}
		case "blr", "call_indirect":
			if e.TargetAddress != "" {
				return fmt.Errorf("indirect call edge %d carries a direct target_address", i)
			}
			if e.Target != "" && len(e.Targets) != 0 {
				return fmt.Errorf("indirect call edge %d claims both one target and a candidate set", i)
			}
			if len(e.Targets) == 0 {
				if e.Target == "" && e.Candidates != 0 {
					return fmt.Errorf("indirect call edge %d has candidate_count without any static target", i)
				}
				if e.Target != "" && e.Candidates != 0 && e.Candidates != 1 {
					return fmt.Errorf("monomorphic indirect call edge %d has candidate_count %d", i, e.Candidates)
				}
				continue
			}
			if len(e.Targets) < 2 || e.Candidates < len(e.Targets) {
				return fmt.Errorf("indirect call edge %d has malformed polymorphic candidates", i)
			}
			last := ""
			for j, target := range e.Targets {
				if strings.TrimSpace(target) == "" || (j > 0 && target <= last) {
					return fmt.Errorf("indirect call edge %d targets are not strictly sorted and unique", i)
				}
				last = target
			}
		default:
			return fmt.Errorf("call edge %d has unsupported kind %q", i, e.Kind)
		}
	}
	return nil
}

const MetadataSchemaVersion = 3

// FridaMetadata is the JSON structure exported for Frida scripts.
type FridaMetadata struct {
	SchemaVersion       int                   `json:"schema_version"`
	AnalyzerVersion     string                `json:"analyzer_version"`
	AnalyzerCommit      string                `json:"analyzer_commit"`
	GenerationID        string                `json:"generation_id"`
	SourceSHA256        string                `json:"source_sha256"`
	SourceSize          int64                 `json:"source_size"`
	ModuleName          string                `json:"module_name"`
	RuntimeIdentity     []RuntimeRegionDigest `json:"runtime_identity"`
	DartVersion         string                `json:"dart_version"`
	Architecture        string                `json:"architecture"`
	CompressedPointers  bool                  `json:"compressed_pointers"`
	PointerSize         int                   `json:"pointer_size"`
	THRFields           map[int]string        `json:"thr_fields"`
	THRReg              string                `json:"thr_reg"`
	PPReg               string                `json:"pp_reg"`
	DTReg               string                `json:"dt_reg"`
	HeapBaseMode        string                `json:"heap_base_mode,omitempty"` // none, register, heap_bits, thread_field
	HeapBaseReg         string                `json:"heap_base_reg,omitempty"`
	HeapBaseTHRField    string                `json:"heap_base_thr_field,omitempty"`
	HeaderBitOffset     int                   `json:"header_bit_offset"`
	HeaderBitWidth      int                   `json:"header_bit_width"`
	Functions           []FridaFunction       `json:"functions"`
	CallProbes          []FridaCallProbe      `json:"call_probes"`
	InstalledFunctions  []FridaFunction       `json:"installed_functions"`
	InstalledCallProbes []FridaCallProbe      `json:"installed_call_probes"`
	Artifacts           []ArtifactDigest      `json:"artifacts"`
	DispatchTable       []FridaDispatchEntry  `json:"dispatch_table"`
	StringRefs          []FridaStringRef      `json:"string_refs"`
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

// FridaCallProbe describes how the runtime script evaluates one indirect call
// target. The static analyzer may already have a prediction for the site; the
// probe exists to observe runtime behavior independently of that prediction.
type FridaCallProbe struct {
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

// NewCallProbe converts the call-edge target spelling emitted by
// internal/disasm into an explicit runtime target recipe. Frida's CPU context
// is keyed by register name; a CALL [base+index*scale+disp] is NOT a register
// name and has to be evaluated then dereferenced at runtime.
//
// Returning false is intentional fail-closed behavior: if a future disassembler
// spelling is not understood, the exporter must not emit a probe that can never
// resolve or, worse, reads the wrong context slot.
func NewCallProbe(va, fromFunc, target, via string) (FridaCallProbe, bool) {
	p := FridaCallProbe{VA: va, FromFunc: fromFunc, Via: via}
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
func RuntimeProbeForEdge(e disasm.CallEdgeRecord) (FridaCallProbe, bool) {
	if e.Kind != "blr" && e.Kind != "call_indirect" {
		return FridaCallProbe{}, false
	}
	if e.Via != "" && e.Via != "dispatch_table" && !strings.HasPrefix(e.Via, disasm.ObjectFieldVia) {
		return FridaCallProbe{}, false
	}
	return NewCallProbe(e.FromPC, e.FromFunc, e.Reg, e.Via)
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
