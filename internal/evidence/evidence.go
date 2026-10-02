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
	"aotopsy/internal/jsonutil"
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
	// ConfStub: resolved through callable stub provenance (for example a
	// Thread entry-point field or a named pool Code/TTS target), rather than
	// inferred from receiver/dispatch-table types.
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

// NewCollectorFromRecords creates a collector from previously written static
// evidence so runtime import can enrich the same records rather than copying a
// stale evidence.jsonl beside enriched call edges.
func NewCollectorFromRecords(records []Evidence) *Collector {
	out := make([]Evidence, len(records))
	copy(out, records)
	for i := range out {
		out[i].Confidence = normalizeConfidence(string(out[i].Confidence))
	}
	return &Collector{records: out}
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
func (c *Collector) FromBLRResolutions(funcName string, resols []typetrack.BlrResolution, isARM64 bool) {
	for _, r := range resols {
		confidence := normalizeConfidence(r.Confidence)
		// typetrack's "exact" means an indirect dispatch-table slot was
		// resolved with a known receiver class. That is strong static evidence,
		// but the target is not encoded in the BLR/CALL instruction itself, which
		// is the contract of ConfExact in this package.
		if confidence == ConfExact {
			confidence = ConfStaticInferred
		}
		ev := Evidence{
			PC:       fmt.Sprintf("0x%x", r.PC),
			Function: funcName,
			Kind:     "dispatch",
			// typetrack supplies a bare string; anything it does not
			// recognise becomes unknown rather than passing through.
			Confidence: confidence,
			Rule:       "typetrack.BLRResolution",
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
		// Only dispatch-derived resolutions cite EmitDispatchTableCall. Stub
		// resolutions can come from THR runtime entries, pool Code objects,
		// UnlinkedCall or TTS and must not cite an unrelated ARM64 dispatch rule.
		if ev.Confidence == ConfExact || ev.Confidence == ConfStaticInferred || ev.Confidence == ConfPolymorphic {
			sdkFile := "runtime/vm/compiler/backend/flow_graph_compiler_x64.cc"
			if isARM64 {
				sdkFile = "runtime/vm/compiler/backend/flow_graph_compiler_arm64.cc"
			}
			ev.SDKRef = &SDKReference{File: sdkFile, Symbol: "EmitDispatchTableCall"}
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
// whatever the Frida script emitted. Equivalent spellings such as "0x1000",
// "0X1000" and "1000" are the same address and compared unequal, so a
// mismatch looked exactly like "runtime never observed this PC". Bare address
// strings are interpreted as hexadecimal below, matching every producer in
// this repository.
func parsePCUint(pc string) (uint64, bool) {
	pc = strings.TrimSpace(pc)
	if pc == "" {
		return 0, false
	}
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
		return 0, false
	}
	return v, true
}

// candidateTargets reads Result["targets"], which survives a JSON round trip
// as []any and arrives in-process as []string. The bool reports whether the
// serialized candidate list is well-formed. Keeping that bit matters for
// runtime comparison: silently dropping a malformed element and then treating
// the shortened list as complete would turn bad input into a false conflict.
func candidateTargets(v any) ([]string, bool) {
	switch t := v.(type) {
	case []string:
		if len(t) == 0 {
			return nil, false
		}
		seen := make(map[string]struct{}, len(t))
		for _, s := range t {
			if strings.TrimSpace(s) == "" {
				return t, false
			}
			if _, duplicate := seen[s]; duplicate {
				return t, false
			}
			seen[s] = struct{}{}
		}
		return t, true
	case []any:
		if len(t) == 0 {
			return nil, false
		}
		out := make([]string, 0, len(t))
		wellFormed := true
		seen := make(map[string]struct{}, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok || strings.TrimSpace(s) == "" {
				wellFormed = false
				continue
			}
			if _, duplicate := seen[s]; duplicate {
				wellFormed = false
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
		return out, wellFormed
	}
	return nil, false
}

func candidateCount(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, n >= 0
	case int8:
		return int(n), n >= 0
	case int16:
		return int(n), n >= 0
	case int32:
		return int(n), n >= 0
	case int64:
		return int(n), n >= 0 && int64(int(n)) == n
	case uint:
		return int(n), uint(int(n)) == n
	case uint8:
		return int(n), true
	case uint16:
		return int(n), true
	case uint32:
		return int(n), uint32(int(n)) == n
	case uint64:
		return int(n), uint64(int(n)) == n
	case float64:
		i := int(n)
		return i, n >= 0 && float64(i) == n
	case json.Number:
		i, err := strconv.ParseInt(string(n), 10, 64)
		if err != nil || i < 0 || int64(int(i)) != i {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}

// candidateListComplete reports whether a serialized polymorphic list is known
// to enumerate every candidate. TargetNames is deliberately capped by
// typetrack; absence from a truncated list is not evidence of contradiction.
func candidateListComplete(result map[string]any, listed int, wellFormed bool) bool {
	if result == nil || !wellFormed {
		return false
	}
	n, ok := candidateCount(result["candidate_count"])
	// typetrack's candidate_count is the number of distinct candidates before
	// its serialized TargetNames list is capped. Equality is therefore the only
	// state that proves the list complete. n > listed is truncation; n < listed
	// is malformed input and must be conservative too.
	return ok && n == listed
}

// runtimeByPC indexes runtime resolutions by numeric PC.
func runtimeByPC(resolutions []RuntimeResolution) map[uint64][]RuntimeResolution {
	out := make(map[uint64][]RuntimeResolution, len(resolutions))
	seen := make(map[string]bool, len(resolutions))
	for _, r := range resolutions {
		pc, ok := parsePCUint(r.PC)
		if !ok || r.TargetName == "" {
			continue
		}
		key := fmt.Sprintf("%x\x00%s\x00%s", pc, r.Function, r.TargetName)
		if seen[key] {
			continue
		}
		seen[key] = true
		out[pc] = append(out[pc], r)
	}
	return out
}

func runtimeTargetsForRecord(rec Evidence, byPC map[uint64][]RuntimeResolution) []string {
	pc, ok := parsePCUint(rec.PC)
	if !ok {
		return nil
	}
	set := map[string]struct{}{}
	for _, r := range byPC[pc] {
		if r.Function != "" && rec.Function != "" && r.Function != rec.Function {
			continue
		}
		set[r.TargetName] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func runtimeComparableRecord(rec Evidence) bool {
	// RuntimeResolution is produced by Frida's indirect-call probes. Signal
	// findings and field accesses are static evidence with no corresponding
	// runtime resolution event, even when they happen to share a PC with a call.
	return rec.Kind == "call" || rec.Kind == "dispatch"
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
		pi, iok := parsePCUint(out[i].PC)
		pj, jok := parsePCUint(out[j].PC)
		if iok != jok {
			return iok // valid addresses sort before malformed ones
		}
		if !iok && out[i].PC != out[j].PC {
			return out[i].PC < out[j].PC
		}
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
	_, err := jsonutil.WriteJSONLFile(path, records)
	return err
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
		if !runtimeComparableRecord(*rec) {
			continue
		}
		rtTargets := runtimeTargetsForRecord(*rec, rtByPC)
		if len(rtTargets) == 0 {
			continue
		}
		if rec.Result == nil {
			rec.Result = map[string]any{}
		}
		if len(rtTargets) == 1 {
			rec.Result["runtime_target"] = rtTargets[0]
		} else {
			rec.Result["runtime_targets"] = rtTargets
		}

		if staticTarget, _ := rec.Result["target"].(string); staticTarget != "" {
			allMatch := true
			for _, rt := range rtTargets {
				if rt != staticTarget {
					allMatch = false
					break
				}
			}
			if allMatch && (rec.Confidence == ConfExact || rec.Confidence == ConfStaticInferred) {
				rec.Confidence = ConfRuntimeConfirmed
			} else if !allMatch {
				rec.Result["runtime_conflict"] = true
			}
			continue
		}

		if rawCandidates, present := rec.Result["targets"]; present {
			cands, wellFormed := candidateTargets(rawCandidates)
			allowed := make(map[string]bool, len(cands))
			for _, cand := range cands {
				allowed[cand] = true
			}
			var confirmed []string
			conflict := false
			for _, rt := range rtTargets {
				if allowed[rt] {
					confirmed = append(confirmed, rt)
				} else {
					conflict = true
				}
			}
			if len(confirmed) > 0 {
				rec.Result["runtime_confirmed_candidates"] = confirmed
			}
			if conflict {
				if candidateListComplete(rec.Result, len(cands), wellFormed) {
					rec.Result["runtime_conflict"] = true
				} else {
					rec.Result["runtime_indeterminate"] = true
				}
			}
			continue
		}

		// No static target/candidate set exists. Runtime supplied information
		// that static analysis genuinely did not have.
		if rec.Confidence == ConfUnknown {
			rec.Confidence = ConfRuntimeConfirmed
		}
	}
}

// CoverageReport summarizes how many static predictions were confirmed,
// contradicted, or left unobserved by runtime evidence.
type CoverageReport struct {
	StaticOnly        int `json:"static_only"`
	RuntimeOnly       int `json:"runtime_only"`
	BothMatch         int `json:"both_match"`
	BothConflict      int `json:"both_conflict"`
	BothIndeterminate int `json:"both_indeterminate"`
	RuntimeConfirmed  int `json:"runtime_confirmed"`
	TotalStatic       int `json:"total_static"`
	TotalRuntime      int `json:"total_runtime"`
	InvalidRuntime    int `json:"invalid_runtime"`
}

// Coverage computes a summary of static vs runtime evidence overlap.
func (c *Collector) Coverage(resolutions []RuntimeResolution) CoverageReport {
	type siteKey struct {
		pc       uint64
		function string
	}
	rep := CoverageReport{}
	rtByPC := runtimeByPC(resolutions)
	runtimeSites := make(map[siteKey]bool)
	for _, r := range resolutions {
		pc, ok := parsePCUint(r.PC)
		if !ok || r.TargetName == "" {
			rep.InvalidRuntime++
			continue
		}
		runtimeSites[siteKey{pc: pc, function: r.Function}] = true
	}
	rep.TotalRuntime = len(runtimeSites)

	staticSites := make(map[siteKey][]Evidence)
	for _, rec := range c.records {
		if !runtimeComparableRecord(rec) {
			continue
		}
		pc, validPC := parsePCUint(rec.PC)
		if !validPC {
			rep.StaticOnly++
			rep.TotalStatic++
			continue
		}
		key := siteKey{pc: pc, function: rec.Function}
		staticSites[key] = append(staticSites[key], rec)
	}
	rep.TotalStatic += len(staticSites)

	seenRuntimeSites := make(map[siteKey]bool)
	for key, records := range staticSites {
		representative := Evidence{PC: fmt.Sprintf("0x%x", key.pc), Function: key.function}
		rtTargets := runtimeTargetsForRecord(representative, rtByPC)
		if len(rtTargets) == 0 {
			rep.StaticOnly++
			continue
		}
		for rtKey := range runtimeSites {
			if rtKey.pc != key.pc {
				continue
			}
			if key.function == "" || rtKey.function == "" || rtKey.function == key.function {
				seenRuntimeSites[rtKey] = true
			}
		}

		predicted := make(map[string]bool)
		hasPrediction := false
		complete := true
		for _, rec := range records {
			if staticTarget, _ := rec.Result["target"].(string); staticTarget != "" {
				predicted[staticTarget] = true
				hasPrediction = true
			}
			if rawCandidates, present := rec.Result["targets"]; present {
				cands, wellFormed := candidateTargets(rawCandidates)
				hasPrediction = true
				for _, cand := range cands {
					predicted[cand] = true
				}
				if !candidateListComplete(rec.Result, len(cands), wellFormed) {
					complete = false
				}
			}
		}
		if !hasPrediction {
			rep.RuntimeConfirmed++
			continue
		}
		allMatch := true
		for _, rtTarget := range rtTargets {
			if !predicted[rtTarget] {
				allMatch = false
				break
			}
		}
		switch {
		case allMatch:
			rep.BothMatch++
		case !complete:
			rep.BothIndeterminate++
		default:
			rep.BothConflict++
		}
	}
	for key := range runtimeSites {
		if !seenRuntimeSites[key] {
			rep.RuntimeOnly++
		}
	}
	return rep
}

// classifyEdgeConfidence maps a CallEdgeRecord's fields to a confidence.
func classifyEdgeConfidence(e disasm.CallEdgeRecord) Confidence {
	if edgeViaIsStub(e) {
		return ConfStub
	}
	if e.Target != "" {
		if e.Kind == "bl" || e.Kind == "call" {
			return ConfExact
		}
		return ConfStaticInferred
	}
	if len(e.Targets) > 0 {
		return ConfPolymorphic
	}
	return ConfUnknown
}

// edgeRule returns the rule name that produced this edge.
func edgeRule(e disasm.CallEdgeRecord) string {
	switch e.Kind {
	case "bl", "call":
		return "direct_call"
	case "blr", "call_indirect":
		if edgeViaIsStub(e) {
			return "indirect_call_via_" + e.Via
		}
		if e.Target != "" {
			return "indirect_call_static_inferred"
		}
		if e.Via != "" {
			return "indirect_call_via_" + e.Via
		}
		return "indirect_call_unresolved"
	}
	return "unknown"
}

func edgeViaIsStub(e disasm.CallEdgeRecord) bool {
	if e.Kind != "blr" && e.Kind != "call_indirect" {
		return false
	}
	if strings.HasPrefix(e.Target, "TypeTestingStub_") {
		return true
	}
	via := strings.TrimSpace(e.Via)
	if via == "" || via == "dispatch_table" || via == disasm.ObjectFieldVia || strings.HasPrefix(via, disasm.ObjectFieldVia+"+") || strings.HasPrefix(via, disasm.ObjectFieldVia+"-") {
		return false
	}
	lower := strings.ToLower(via)
	if strings.HasPrefix(lower, "pp[") {
		// A pool display is provenance only. Exact TTS/Code resolution is stored
		// in Target by analysis after the pool slot's object kind is proven.
		return false
	}
	if strings.HasPrefix(via, "THR.") {
		field := strings.ToLower(strings.TrimPrefix(via, "THR."))
		// THR is a provenance namespace for every Thread field, including
		// ordinary data such as dispatch_table_array and stack_limit. Only
		// entry-point fields establish a callable stub by themselves.
		return field == "stub" || strings.HasSuffix(field, "_entry_point") || strings.HasSuffix(field, "_ep")
	}
	return false
}
