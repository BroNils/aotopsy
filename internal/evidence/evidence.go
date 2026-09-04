// Package evidence provides a unified evidence model that collects analysis
// results from call_edges, dispatch_table, typetrack, and signal into a single
// queryable structure. Each evidence record carries provenance (which rule
// produced it), confidence (exact/inferred/polymorphic/unknown), and SDK
// source references where applicable.
package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"aotopsy/internal/disasm"
	"aotopsy/internal/output"
	"aotopsy/internal/typetrack"
)

// Evidence is one analysis finding with full provenance.
type Evidence struct {
	PC          string         `json:"pc"`
	Function    string         `json:"function"`
	Kind        string         `json:"kind"` // "call", "dispatch", "field_access", "signal"
	Instruction string         `json:"instruction,omitempty"`
	Inputs      map[string]any `json:"inputs,omitempty"`
	Result      map[string]any `json:"result,omitempty"`
	Confidence  Confidence     `json:"confidence"`
	Rule        string         `json:"rule,omitempty"`
	SDKRef      *SDKReference  `json:"sdk_ref,omitempty"`
}

// Confidence is how much the analysis is claiming.
//
// It was a bare string, set from three packages with no shared vocabulary
// and no check. A typo would have serialised straight into the artifact
// and read as a new confidence tier by anything consuming it.
type Confidence string

const (
	// ConfExact: the target is known from the instruction itself (a
	// direct BL/CALL to a resolved address).
	ConfExact Confidence = "exact"
	// ConfStaticInferred: derived by the type analysis, not read off the
	// instruction.
	ConfStaticInferred Confidence = "static_inferred"
	// ConfPolymorphic: a set of candidates, not one target.
	ConfPolymorphic Confidence = "polymorphic"
	// ConfStub: resolved to a VM stub through the Thread table.
	ConfStub Confidence = "stub"
	// ConfUnknown: the site was seen and not resolved. Distinct from
	// absent -- an unresolved call is a finding.
	ConfUnknown Confidence = "unknown"
	// ConfRuntimeConfirmed: a runtime observation agreed with the static
	// prediction, or supplied one where static analysis had none.
	ConfRuntimeConfirmed Confidence = "runtime_confirmed"
)

// Valid reports whether c is one of the defined tiers.
func (c Confidence) Valid() bool {
	switch c {
	case ConfExact, ConfStaticInferred, ConfPolymorphic, ConfStub,
		ConfUnknown, ConfRuntimeConfirmed:
		return true
	}
	return false
}

// normalizeConfidence maps an externally-supplied string onto a defined
// tier, falling back to unknown. An unrecognised value is a bug in the
// producer, but silently emitting it is worse than recording that we do
// not know.
func normalizeConfidence(s string) Confidence {
	if c := Confidence(s); c.Valid() {
		return c
	}
	return ConfUnknown
}

// SDKReference points to the SDK source that justifies a rule or constant.
type SDKReference struct {
	Tag    string `json:"tag,omitempty"`
	File   string `json:"file"`
	Symbol string `json:"symbol,omitempty"`
}

// Collector gathers evidence from multiple analysis stages.
type Collector struct {
	records []Evidence
}

// NewCollector creates an empty evidence collector.
func NewCollector() *Collector {
	return &Collector{}
}

// FromCallEdges collects evidence from call_edges.jsonl records.
// Each edge becomes an evidence record with its resolution confidence.
func (c *Collector) FromCallEdges(edges []disasm.CallEdgeRecord) {
	for _, e := range edges {
		ev := Evidence{
			PC:         e.FromPC,
			Function:   e.FromFunc,
			Kind:       "call",
			Confidence: classifyEdgeConfidence(e),
			Rule:       edgeRule(e),
		}
		if e.Target != "" {
			ev.Result = map[string]any{"target": e.Target}
			if e.Kind == "bl" || e.Kind == "call" {
				// GenerateStaticDartCall, not EmitDirectCall: there is no
				// EmitDirectCall anywhere in runtime/vm/compiler/backend
				// (the name exists only in pkg/dart2wasm and
				// pkg/dart2bytecode), so the reference pointed at nothing
				// a reader could look up.
				sdkFile := "runtime/vm/compiler/backend/flow_graph_compiler_arm64.cc"
				if e.Kind == "call" {
					sdkFile = "runtime/vm/compiler/backend/flow_graph_compiler_x64.cc"
				}
				ev.SDKRef = &SDKReference{
					File:   sdkFile,
					Symbol: "GenerateStaticDartCall",
				}
			}
		} else if len(e.Targets) > 0 {
			ev.Result = map[string]any{"targets": e.Targets, "candidate_count": e.Candidates}
			sdkFile := "runtime/vm/compiler/backend/flow_graph_compiler_arm64.cc"
			if e.Kind == "call" || e.Kind == "call_indirect" {
				sdkFile = "runtime/vm/compiler/backend/flow_graph_compiler_x64.cc"
			}
			ev.SDKRef = &SDKReference{
				File:   sdkFile,
				Symbol: "EmitDispatchTableCall",
			}
		} else if e.Via != "" {
			ev.Result = map[string]any{"via": e.Via}
			if strings.HasPrefix(e.Via, "THR.") {
				ev.SDKRef = &SDKReference{
					File:   "runtime/vm/compiler/runtime_offsets_extracted.h",
					Symbol: "Thread::" + strings.TrimPrefix(e.Via, "THR."),
				}
			}
		} else {
			ev.Result = map[string]any{"resolved": false}
			ev.Confidence = ConfUnknown
		}
		if e.Reg != "" {
			if ev.Inputs == nil {
				ev.Inputs = map[string]any{}
			}
			ev.Inputs["reg"] = e.Reg
		}
		c.records = append(c.records, ev)
	}
}

// FromBLRResolutions collects evidence from typetrack BLR resolution records.
func (c *Collector) FromBLRResolutions(funcName string, resols []typetrack.BlrResolution) {
	for _, r := range resols {
		ev := Evidence{
			PC:       fmt.Sprintf("0x%x", r.PC),
			Function: funcName,
			Kind:     "dispatch",
			// typetrack supplies a bare string; anything it does not
			// recognise becomes unknown rather than passing through.
			Confidence: normalizeConfidence(r.Confidence),
			Rule:       "typetrack.BLRResolution",
			SDKRef: &SDKReference{
				File:   "runtime/vm/compiler/backend/flow_graph_compiler_arm64.cc",
				Symbol: "EmitDispatchTableCall",
			},
		}
		if r.Confidence == "" {
			ev.Confidence = ConfUnknown
		}
		if r.TargetName != "" {
			ev.Result = map[string]any{"target": r.TargetName}
		} else if len(r.TargetNames) > 0 {
			ev.Result = map[string]any{"targets": r.TargetNames, "candidate_count": r.Candidates}
		}
		if r.SlotIndex >= 0 {
			if ev.Inputs == nil {
				ev.Inputs = map[string]any{}
			}
			ev.Inputs["slot_index"] = r.SlotIndex
		}
		c.records = append(c.records, ev)
	}
}

// FromSignalFindings collects evidence from security signal findings.
func (c *Collector) FromSignalFindings(findings []output.SignalFinding) {
	for _, f := range findings {
		c.records = append(c.records, Evidence{
			PC:         f.PC,
			Function:   f.Function,
			Kind:       "signal",
			Confidence: ConfStaticInferred,
			Rule:       "signal." + f.Category,
			Result:     map[string]any{"signal": f.StringValue, "category": f.Category},
		})
	}
}

// FromFieldAccesses collects evidence from typetrack field access records.
func (c *Collector) FromFieldAccesses(funcName string, accesses []typetrack.FieldAccess, className func(int) string) {
	for _, a := range accesses {
		res := map[string]any{}
		if className != nil {
			if name := className(a.ClassID); name != "" {
				res["class_name"] = name
			}
		}
		c.records = append(c.records, Evidence{
			PC:         fmt.Sprintf("0x%x", a.PC),
			Function:   funcName,
			Kind:       "field_access",
			Confidence: ConfStaticInferred,
			Rule:       "typetrack.FieldAccess",
			Inputs:     map[string]any{"class_id": a.ClassID, "byte_offset": a.ByteOffset, "is_store": a.IsStore},
			Result:     res,
		})
	}
}

// parsePCUint parses an address string to a number, for sorting and for
// matching records against runtime observations.
//
// Matching on the raw string was a silent failure: our own records are
// written as "0x%x" by some collectors and copied verbatim from
// call_edges.jsonl by others, while a runtime resolution arrives from
// whatever the Frida script emitted. "0x1000", "0X1000" and "4096" are
// the same address and compared unequal, so a mismatch looked exactly
// like "runtime never observed this PC".
func parsePCUint(pc string) uint64 {
	pc = strings.TrimSpace(pc)
	neg := false
	if strings.HasPrefix(pc, "-") {
		neg, pc = true, pc[1:]
	}
	base := 10
	switch {
	case strings.HasPrefix(pc, "0x"), strings.HasPrefix(pc, "0X"):
		pc, base = pc[2:], 16
	default:
		// A bare string is ambiguous. The tie goes to hex, because every
		// producer here writes addresses as hex with or without the 0x --
		// so "4096" means 0x4096. Reading it as decimal would make a
		// handful of addresses quietly match the wrong record.
		if _, err := strconv.ParseUint(pc, 16, 64); err == nil {
			base = 16
		}
	}
	v, err := strconv.ParseUint(pc, base, 64)
	if err != nil || neg {
		return 0
	}
	return v
}

// candidateTargets reads Result["targets"], which survives a JSON round
// trip as []any and arrives in-process as []string.
func candidateTargets(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// runtimeByPC indexes runtime resolutions by numeric PC.
func runtimeByPC(resolutions []RuntimeResolution) map[uint64]string {
	out := make(map[uint64]string, len(resolutions))
	for _, r := range resolutions {
		out[parsePCUint(r.PC)] = r.TargetName
	}
	return out
}

// Records returns all collected evidence, sorted numerically by PC.
func (c *Collector) Records() []Evidence {
	out := make([]Evidence, len(c.records))
	copy(out, c.records)
	// Fully ordered, not just by PC. Records now arrive from several
	// collectors, and two of them iterate a map of function names, so
	// ties broken by insertion order would make the file differ between
	// runs of the same binary.
	sort.Slice(out, func(i, j int) bool {
		pi, pj := parsePCUint(out[i].PC), parsePCUint(out[j].PC)
		if pi != pj {
			return pi < pj
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Function != out[j].Function {
			return out[i].Function < out[j].Function
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}

// WriteJSONL writes all evidence records to a JSONL file.
func (c *Collector) WriteJSONL(path string) error {
	records := c.Records()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

// RuntimeResolution is one runtime-observed dispatch resolution from Frida.
type RuntimeResolution struct {
	PC         string `json:"pc"`
	Function   string `json:"function"`
	TargetName string `json:"target_name"`
}

// MergeRuntime marks static evidence records that are confirmed by runtime
// observation. A static evidence record is "confirmed" when its PC matches
// a runtime resolution's PC and (if the static record has a target) the
// targets match.
//
// Records that have no runtime match keep their original confidence.
// Records that DO match get their confidence upgraded to "runtime_confirmed"
// and a "runtime_target" field added to their Result.
func (c *Collector) MergeRuntime(resolutions []RuntimeResolution) {
	rtByPC := runtimeByPC(resolutions)

	for i := range c.records {
		rec := &c.records[i]
		if rtTarget, ok := rtByPC[parsePCUint(rec.PC)]; ok {
			if rec.Result == nil {
				rec.Result = map[string]any{}
			}
			rec.Result["runtime_target"] = rtTarget
			// Upgrade confidence: exact/stub/static_inferred → runtime_confirmed.
			// polymorphic stays polymorphic (runtime confirmed ONE of many).
			// unknown → runtime_confirmed (runtime observed what static couldn't).
			switch rec.Confidence {
			case ConfExact, ConfStub, ConfStaticInferred, ConfUnknown:
				rec.Confidence = ConfRuntimeConfirmed
			case ConfPolymorphic:
				// Keep polymorphic but note runtime confirmed one candidate.
				rec.Result["runtime_confirmed_candidate"] = rtTarget
			}
		}
	}
}

// CoverageReport summarizes how many static predictions were confirmed,
// contradicted, or left unobserved by runtime evidence.
type CoverageReport struct {
	StaticOnly       int `json:"static_only"`
	RuntimeOnly      int `json:"runtime_only"`
	BothMatch        int `json:"both_match"`
	BothConflict     int `json:"both_conflict"`
	RuntimeConfirmed int `json:"runtime_confirmed"`
	TotalStatic      int `json:"total_static"`
	TotalRuntime     int `json:"total_runtime"`
}

// Coverage computes a summary of static vs runtime evidence overlap.
func (c *Collector) Coverage(resolutions []RuntimeResolution) CoverageReport {
	rep := CoverageReport{TotalStatic: len(c.records), TotalRuntime: len(resolutions)}
	rtByPC := runtimeByPC(resolutions)
	seenPCs := make(map[uint64]bool)
	for _, rec := range c.records {
		pc := parsePCUint(rec.PC)
		rtTarget, ok := rtByPC[pc]
		if !ok {
			rep.StaticOnly++
			continue
		}
		seenPCs[pc] = true

		// A polymorphic record predicts a SET of targets, in
		// Result["targets"]. Reading only Result["target"] left that set
		// invisible, so the record fell through to "runtime confirmed" --
		// counted as agreement even when the runtime target was not among
		// the candidates the analysis proposed. That is precisely the
		// case the report exists to surface.
		if staticTarget, _ := rec.Result["target"].(string); staticTarget != "" {
			if staticTarget == rtTarget {
				rep.BothMatch++
			} else {
				rep.BothConflict++
			}
			continue
		}
		if cands := candidateTargets(rec.Result["targets"]); len(cands) > 0 {
			matched := false
			for _, cand := range cands {
				if cand == rtTarget {
					matched = true
					break
				}
			}
			if matched {
				rep.BothMatch++
			} else {
				rep.BothConflict++
			}
			continue
		}
		// No static prediction at all: runtime saw something we did not.
		rep.RuntimeConfirmed++
	}
	rep.RuntimeOnly = len(resolutions) - len(seenPCs)
	return rep
}

// classifyEdgeConfidence maps a CallEdgeRecord's fields to a confidence.
func classifyEdgeConfidence(e disasm.CallEdgeRecord) Confidence {
	if e.Target != "" {
		return ConfExact
	}
	if len(e.Targets) > 0 {
		return ConfPolymorphic
	}
	if e.Via != "" {
		return ConfStub
	}
	return ConfUnknown
}

// edgeRule returns the rule name that produced this edge.
func edgeRule(e disasm.CallEdgeRecord) string {
	switch e.Kind {
	case "bl", "call":
		return "direct_call"
	case "blr", "call_indirect":
		if e.Via != "" {
			return "indirect_call_via_" + e.Via
		}
		return "indirect_call_unresolved"
	}
	return "unknown"
}
