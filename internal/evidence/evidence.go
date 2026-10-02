// Package evidence provides a unified evidence model that collects analysis
// results from call_edges, typetrack, signal, and bounded runtime observations
// into a single queryable structure. Each evidence record carries provenance,
// a closed confidence tier, and exact-version SDK references where applicable.
package evidence

import (
	"encoding/hex"
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
	PC          string                  `json:"pc"`
	Function    string                  `json:"function"`
	Kind        string                  `json:"kind"` // "call", "dispatch", "field_access", "signal", "runtime_call"
	Source      Source                  `json:"source"`
	Instruction string                  `json:"instruction,omitempty"`
	Inputs      map[string]any          `json:"inputs,omitempty"`
	Result      map[string]any          `json:"result,omitempty"`
	Confidence  Confidence              `json:"confidence"`
	Rule        RuleID                  `json:"rule_id"`
	SDKRef      *SDKReference           `json:"sdk_ref,omitempty"`
	Runtime     *disasm.RuntimeEvidence `json:"runtime,omitempty"`
}

// Source names the producer whose claim this row represents. It is not a
// confidence signal: two rows derived from the same underlying fact do not
// become independent support merely because they passed through two stages.
type Source string

const (
	SourceCallEdges Source = "call_edges"
	SourceTypeTrack Source = "typetrack"
	SourceSignal    Source = "signal"
	SourceFrida     Source = "frida"
)

func (s Source) Valid() bool {
	switch s {
	case SourceCallEdges, SourceTypeTrack, SourceSignal, SourceFrida:
		return true
	}
	return false
}

// RuleID is a stable machine identifier for the rule that made the claim.
// Observed provenance belongs in Inputs/Result, never inside the identifier.
type RuleID string

const (
	RuleDirectCallAddress        RuleID = "call.direct.address"
	RuleDirectCallTarget         RuleID = "call.direct.target"
	RuleDirectCallUnresolved     RuleID = "call.direct.unresolved"
	RuleIndirectStaticInferred   RuleID = "call.indirect.static_inferred"
	RuleIndirectPolymorphic      RuleID = "call.indirect.polymorphic"
	RuleIndirectStub             RuleID = "call.indirect.stub"
	RuleIndirectUnresolved       RuleID = "call.indirect.unresolved"
	RuleTypeTrackDispatch        RuleID = "typetrack.dispatch"
	RuleTypeTrackFieldAccess     RuleID = "typetrack.field_access"
	RuleFridaDispatchObservation RuleID = "frida.dispatch_observation"
)

func (r RuleID) Valid() bool {
	if r == "" || len(r) > 256 {
		return false
	}
	for _, ch := range r {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return true
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
	// ConfHeuristic: a detector/classifier emitted a semantic finding from
	// static facts. This intentionally does not inherit the stronger-sounding
	// static_inferred tier: detector-specific strength (low/medium/etc.) remains
	// explicit in result.producer_confidence when the producer has one.
	ConfHeuristic Confidence = "heuristic"
	// ConfUnknown: the site was seen and not resolved. Distinct from
	// absent -- an unresolved call is a finding.
	ConfUnknown Confidence = "unknown"
	// ConfRuntimeObserved is a bounded observation from a runtime execution.
	// It says that the target occurred in the identity-bound run; it makes no
	// universal claim about other executions and never upgrades static evidence.
	ConfRuntimeObserved Confidence = "runtime_observed"
)

// Valid reports whether c is one of the defined tiers.
func (c Confidence) Valid() bool {
	switch c {
	case ConfExact, ConfStaticInferred, ConfPolymorphic, ConfStub, ConfHeuristic,
		ConfUnknown, ConfRuntimeObserved:
		return true
	}
	return false
}

// SDKReference points to the SDK source that justifies a rule or constant.
type SDKReference struct {
	Tag    string `json:"tag"`
	File   string `json:"file"`
	Symbol string `json:"symbol"`
}

// Collector gathers evidence from multiple analysis stages.
type Collector struct {
	dartVersion string
	records     []Evidence
}

// NewCollector creates an empty evidence collector.
func NewCollector(dartVersion string) *Collector {
	return &Collector{dartVersion: dartVersion}
}

// NewCollectorFromRecords creates a collector from previously written static
// evidence so runtime import can enrich the same records rather than copying a
// stale evidence.jsonl beside enriched call edges.
func NewCollectorFromRecords(dartVersion string, records []Evidence) *Collector {
	out := make([]Evidence, len(records))
	copy(out, records)
	return &Collector{dartVersion: dartVersion, records: out}
}

func (c *Collector) sdkReference(file, symbol string) *SDKReference {
	if strings.TrimSpace(c.dartVersion) == "" {
		return nil
	}
	return &SDKReference{Tag: c.dartVersion, File: file, Symbol: symbol}
}

// FromCallEdges collects evidence from call_edges.jsonl records.
// Each edge becomes an evidence record with its resolution confidence.
func (c *Collector) FromCallEdges(edges []disasm.CallEdgeRecord) {
	for _, e := range edges {
		if e.Kind == "bl" || e.Kind == "call" {
			c.fromDirectCallEdge(e)
			continue
		}
		ev := Evidence{
			PC:         e.FromPC,
			Function:   e.FromFunc,
			Kind:       "call",
			Source:     SourceCallEdges,
			Confidence: classifyEdgeConfidence(e),
			Rule:       edgeRule(e),
		}
		if e.Via != "" {
			ev.Inputs = map[string]any{"via": e.Via}
		}
		if e.Target != "" {
			ev.Result = map[string]any{"target": e.Target}
		} else if len(e.Targets) > 0 {
			ev.Result = map[string]any{"targets": e.Targets, "candidate_count": e.Candidates}
		} else {
			ev.Result = map[string]any{"resolved": false}
			ev.Confidence = ConfUnknown
		}
		// Do not manufacture an SDK symbol from THR provenance. THRFields is a
		// union of literal Thread fields and runtime-entry names reconstructed
		// from runtime_entry_list.h plus exact SDK anchors. Most reconstructed
		// names intentionally have no Thread_<name>_offset constant in
		// runtime_offsets_extracted.h, so a mechanical string transform would
		// publish a source reference that does not exist.
		if e.Reg != "" {
			if ev.Inputs == nil {
				ev.Inputs = map[string]any{}
			}
			ev.Inputs["reg"] = e.Reg
		}
		c.records = append(c.records, ev)
	}
}

func (c *Collector) fromDirectCallEdge(e disasm.CallEdgeRecord) {
	base := Evidence{
		PC:       e.FromPC,
		Function: e.FromFunc,
		Kind:     "call",
		Source:   SourceCallEdges,
	}
	if e.TargetAddress != "" {
		exact := base
		exact.Confidence = ConfExact
		exact.Rule = RuleDirectCallAddress
		exact.Result = map[string]any{"target_address": e.TargetAddress}
		c.records = append(c.records, exact)
	}

	// A symbolic identity is resolved by AOTopsy's symbol/name tables. The call
	// instruction proves the destination address, not the recovered name, so the
	// name is a separate static-inference claim rather than part of exact evidence.
	if e.Target != "" && e.Target != e.TargetAddress {
		identity := base
		identity.Confidence = ConfStaticInferred
		identity.Rule = RuleDirectCallTarget
		identity.Result = map[string]any{"target": e.Target}
		if e.TargetAddress != "" {
			identity.Inputs = map[string]any{"target_address": e.TargetAddress}
		}
		c.records = append(c.records, identity)
	}

	if e.TargetAddress == "" && e.Target == "" {
		unresolved := base
		unresolved.Confidence = ConfUnknown
		unresolved.Rule = RuleDirectCallUnresolved
		unresolved.Result = map[string]any{"resolved": false}
		c.records = append(c.records, unresolved)
	}
}

// FromBLRResolutions collects evidence from typetrack BLR resolution records.
func (c *Collector) FromBLRResolutions(funcName string, resols []typetrack.BlrResolution, isARM64 bool) {
	for _, r := range resols {
		confidence := ConfUnknown
		switch r.Confidence {
		case typetrack.ResolutionStaticInferred:
			confidence = ConfStaticInferred
		case typetrack.ResolutionPolymorphic:
			confidence = ConfPolymorphic
		case typetrack.ResolutionStub:
			confidence = ConfStub
		case typetrack.ResolutionUnknown:
			confidence = ConfUnknown
		}
		ev := Evidence{
			PC:         fmt.Sprintf("0x%x", r.PC),
			Function:   funcName,
			Kind:       "dispatch",
			Source:     SourceTypeTrack,
			Confidence: confidence,
			Rule:       RuleTypeTrackDispatch,
		}
		if r.TargetName != "" {
			ev.Result = map[string]any{"target": r.TargetName}
		} else if len(r.TargetNames) > 0 {
			ev.Result = map[string]any{"targets": r.TargetNames, "candidate_count": r.Candidates}
		} else {
			ev.Result = map[string]any{"resolved": false}
		}
		if r.SlotIndex >= 0 {
			if ev.Inputs == nil {
				ev.Inputs = map[string]any{}
			}
			ev.Inputs["slot_index"] = r.SlotIndex
		}
		if r.Derivation.Valid() {
			if ev.Inputs == nil {
				ev.Inputs = map[string]any{}
			}
			ev.Inputs["derivation"] = string(r.Derivation)
		}
		// Only dispatch-derived resolutions cite EmitDispatchTableCall. Stub
		// resolutions can come from THR runtime entries, pool Code objects,
		// UnlinkedCall or TTS and must not cite an unrelated ARM64 dispatch rule.
		if r.Derivation == typetrack.DerivationDispatchTable && (ev.Confidence == ConfStaticInferred || ev.Confidence == ConfPolymorphic) {
			sdkFile := "runtime/vm/compiler/backend/flow_graph_compiler_x64.cc"
			if isARM64 {
				sdkFile = "runtime/vm/compiler/backend/flow_graph_compiler_arm64.cc"
			}
			ev.SDKRef = c.sdkReference(sdkFile, "EmitDispatchTableCall")
		}
		c.records = append(c.records, ev)
	}
}

// FromSignalFindings collects evidence from security signal findings.
func (c *Collector) FromSignalFindings(findings []output.SignalFinding) {
	for _, f := range findings {
		result := map[string]any{"signal": f.StringValue, "category": f.Category}
		if f.ProducerConfidence != "" {
			result["producer_confidence"] = f.ProducerConfidence
		}
		c.records = append(c.records, Evidence{
			PC:         f.PC,
			Function:   f.Function,
			Kind:       "signal",
			Source:     SourceSignal,
			Confidence: ConfHeuristic,
			Rule:       RuleID(f.RuleID),
			Result:     result,
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
			Source:     SourceTypeTrack,
			Confidence: ConfStaticInferred,
			Rule:       RuleTypeTrackFieldAccess,
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
		last := ""
		for i, s := range t {
			if strings.TrimSpace(s) == "" {
				return t, false
			}
			if i > 0 && s <= last {
				return t, false
			}
			last = s
		}
		return t, true
	case []any:
		if len(t) == 0 {
			return nil, false
		}
		out := make([]string, 0, len(t))
		wellFormed := true
		last := ""
		for _, e := range t {
			s, ok := e.(string)
			if !ok || strings.TrimSpace(s) == "" {
				wellFormed = false
				continue
			}
			if len(out) > 0 && s <= last {
				wellFormed = false
				continue
			}
			out = append(out, s)
			last = s
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

func runtimeComparableRecord(rec Evidence) bool {
	// RuntimeObservation is produced by Frida's indirect-call probes. Signal
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
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return evidenceCanonicalKey(out[i]) < evidenceCanonicalKey(out[j])
	})
	if len(out) < 2 {
		return out
	}
	deduped := out[:0]
	lastKey := ""
	for i := range out {
		key := evidenceCanonicalKey(out[i])
		if len(deduped) > 0 && key == lastKey {
			continue
		}
		deduped = append(deduped, out[i])
		lastKey = key
	}
	return deduped
}

func evidenceCanonicalKey(rec Evidence) string {
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Sprintf("%#v", rec)
	}
	return string(b)
}

// WriteJSONL writes all evidence records to a JSONL file.
func (c *Collector) WriteJSONL(path string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	records := c.Records()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	_, err := jsonutil.WriteJSONLFile(path, records)
	return err
}

// Validate enforces the evidence schema before it crosses an artifact trust
// boundary. In-memory producers may build records incrementally; serialized or
// imported records must have a closed source/rule/confidence vocabulary and
// self-consistent certainty semantics.
func (c *Collector) Validate() error {
	runtimeIdentity := ""
	for i := range c.records {
		if err := c.validateRecord(&c.records[i]); err != nil {
			return fmt.Errorf("evidence record %d: %w", i, err)
		}
		if c.records[i].Runtime != nil {
			key := runtimeIdentityKey(*c.records[i].Runtime)
			if runtimeIdentity == "" {
				runtimeIdentity = key
			} else if key != runtimeIdentity {
				return fmt.Errorf("evidence record %d: runtime provenance does not match the other runtime observations", i)
			}
		}
	}
	return nil
}

// ValidateStatic enforces the stricter contract of a generation that has not
// been runtime-enriched yet. Frida export/import binds exactly such a static
// generation; accepting Runtime fields or frida-only rows here would allow an
// observation from an older run to survive a later run where the site was not
// observed at all.
func (c *Collector) ValidateStatic() error {
	if err := c.Validate(); err != nil {
		return err
	}
	for i, rec := range c.records {
		if rec.Runtime != nil || rec.Source == SourceFrida || rec.Confidence == ConfRuntimeObserved {
			return fmt.Errorf("evidence record %d contains runtime enrichment in a static generation", i)
		}
	}
	return nil
}

func (c *Collector) validateRecord(rec *Evidence) error {
	if strings.TrimSpace(rec.Kind) == "" {
		return fmt.Errorf("empty kind")
	}
	if rec.PC == "" {
		if rec.Kind != "signal" {
			return fmt.Errorf("kind %s requires a pc", rec.Kind)
		}
	} else {
		pc, ok := parsePCUint(rec.PC)
		if !ok || rec.PC != fmt.Sprintf("0x%x", pc) {
			return fmt.Errorf("non-canonical pc %q", rec.PC)
		}
	}
	if !rec.Source.Valid() {
		return fmt.Errorf("invalid source %q", rec.Source)
	}
	if !rec.Rule.Valid() {
		return fmt.Errorf("invalid rule_id %q", rec.Rule)
	}
	if !rec.Confidence.Valid() {
		return fmt.Errorf("invalid confidence %q", rec.Confidence)
	}
	switch rec.Source {
	case SourceCallEdges:
		if rec.Kind != "call" || !callEdgeRule(rec.Rule) {
			return fmt.Errorf("call_edges source requires call kind and a defined call rule")
		}
		if !callEdgeRuleConfidence(rec.Rule, rec.Confidence) {
			return fmt.Errorf("call_edges rule %s is incompatible with confidence %s", rec.Rule, rec.Confidence)
		}
	case SourceTypeTrack:
		switch rec.Kind {
		case "dispatch":
			if rec.Rule != RuleTypeTrackDispatch {
				return fmt.Errorf("typetrack dispatch requires rule %s", RuleTypeTrackDispatch)
			}
		case "field_access":
			if rec.Rule != RuleTypeTrackFieldAccess || rec.Confidence != ConfStaticInferred {
				return fmt.Errorf("typetrack field_access requires rule %s and static_inferred confidence", RuleTypeTrackFieldAccess)
			}
		default:
			return fmt.Errorf("typetrack source requires dispatch or field_access kind")
		}
	case SourceSignal:
		if rec.Kind != "signal" || !strings.HasPrefix(string(rec.Rule), "signal.") || rec.Confidence != ConfHeuristic {
			return fmt.Errorf("signal source requires signal kind, signal.* rule, and heuristic confidence")
		}
	case SourceFrida:
		if rec.Kind != "runtime_call" || rec.Rule != RuleFridaDispatchObservation {
			return fmt.Errorf("frida source requires runtime_call kind and %s rule", RuleFridaDispatchObservation)
		}
	}
	if rec.SDKRef != nil {
		if rec.SDKRef.Tag == "" || rec.SDKRef.File == "" || rec.SDKRef.Symbol == "" {
			return fmt.Errorf("incomplete sdk_ref %+v", *rec.SDKRef)
		}
		if c.dartVersion != "" && rec.SDKRef.Tag != c.dartVersion {
			return fmt.Errorf("sdk_ref tag %q does not match artifact Dart version %q", rec.SDKRef.Tag, c.dartVersion)
		}
		if rec.SDKRef.Symbol != "EmitDispatchTableCall" ||
			(rec.SDKRef.File != "runtime/vm/compiler/backend/flow_graph_compiler_arm64.cc" &&
				rec.SDKRef.File != "runtime/vm/compiler/backend/flow_graph_compiler_x64.cc") {
			return fmt.Errorf("unsupported sdk_ref %s:%s", rec.SDKRef.File, rec.SDKRef.Symbol)
		}
		derivation, _ := rec.Inputs["derivation"].(string)
		if !(rec.Source == SourceTypeTrack && rec.Rule == RuleTypeTrackDispatch &&
			(rec.Confidence == ConfStaticInferred || rec.Confidence == ConfPolymorphic) &&
			derivation == string(typetrack.DerivationDispatchTable)) {
			return fmt.Errorf("sdk_ref %s is not valid for source=%s rule=%s confidence=%s", rec.SDKRef.Symbol, rec.Source, rec.Rule, rec.Confidence)
		}
	}
	if rec.Runtime != nil {
		if err := validateRuntimeEvidence(rec.Runtime); err != nil {
			return fmt.Errorf("runtime: %w", err)
		}
		if c.dartVersion != "" && rec.Runtime.DartVersion != c.dartVersion {
			return fmt.Errorf("runtime Dart version %q does not match artifact Dart version %q", rec.Runtime.DartVersion, c.dartVersion)
		}
	}
	if rec.Source == SourceFrida {
		if rec.Confidence != ConfRuntimeObserved || rec.Runtime == nil {
			return fmt.Errorf("frida-only row must be runtime_observed with runtime provenance")
		}
		if rec.Runtime.Agreement != disasm.RuntimeObservedOnly {
			return fmt.Errorf("frida-only row cannot claim static/runtime relationship %q", rec.Runtime.Agreement)
		}
	} else if rec.Confidence == ConfRuntimeObserved {
		return fmt.Errorf("runtime_observed confidence requires frida source")
	}

	if rec.Kind != "call" && rec.Kind != "dispatch" {
		return nil
	}
	staticTarget, _ := rec.Result["target"].(string)
	staticAddress, _ := rec.Result["target_address"].(string)
	rawTargets, hasTargets := rec.Result["targets"]
	targets, targetsWellFormed := candidateTargets(rawTargets)
	switch rec.Confidence {
	case ConfExact:
		if rec.Kind != "call" || rec.Rule != RuleDirectCallAddress || staticAddress == "" || staticTarget != "" || hasTargets {
			return fmt.Errorf("exact confidence requires only an encoded direct-call target_address")
		}
		addr, ok := parsePCUint(staticAddress)
		if !ok || staticAddress != fmt.Sprintf("0x%x", addr) {
			return fmt.Errorf("exact direct-call target_address %q is not hexadecimal", staticAddress)
		}
	case ConfStaticInferred, ConfStub:
		if staticTarget == "" || staticAddress != "" || hasTargets {
			return fmt.Errorf("%s confidence requires one resolved target", rec.Confidence)
		}
	case ConfPolymorphic:
		if staticTarget != "" || staticAddress != "" || !hasTargets || !targetsWellFormed || len(targets) < 2 {
			return fmt.Errorf("polymorphic confidence requires a well-formed candidate set")
		}
		count, ok := candidateCount(rec.Result["candidate_count"])
		if !ok || count < len(targets) {
			return fmt.Errorf("polymorphic candidate_count is missing or smaller than serialized targets")
		}
	case ConfUnknown:
		resolved, ok := rec.Result["resolved"].(bool)
		if staticTarget != "" || staticAddress != "" || hasTargets || !ok || resolved {
			return fmt.Errorf("unknown confidence cannot carry a static target")
		}
	}
	if rec.Runtime != nil {
		if want := runtimeAgreementForRecord(*rec, *rec.Runtime); rec.Runtime.Agreement != want {
			return fmt.Errorf("runtime agreement %q does not match static evidence; want %q", rec.Runtime.Agreement, want)
		}
	}
	return nil
}

func callEdgeRule(rule RuleID) bool {
	switch rule {
	case RuleDirectCallAddress, RuleDirectCallTarget, RuleDirectCallUnresolved,
		RuleIndirectStaticInferred, RuleIndirectPolymorphic, RuleIndirectStub,
		RuleIndirectUnresolved:
		return true
	}
	return false
}

func callEdgeRuleConfidence(rule RuleID, confidence Confidence) bool {
	switch rule {
	case RuleDirectCallAddress:
		return confidence == ConfExact
	case RuleDirectCallTarget, RuleIndirectStaticInferred:
		return confidence == ConfStaticInferred
	case RuleIndirectPolymorphic:
		return confidence == ConfPolymorphic
	case RuleIndirectStub:
		return confidence == ConfStub
	case RuleDirectCallUnresolved, RuleIndirectUnresolved:
		return confidence == ConfUnknown
	}
	return false
}

func validateRuntimeEvidence(rt *disasm.RuntimeEvidence) error {
	if rt.Source != "frida" {
		return fmt.Errorf("unsupported source %q", rt.Source)
	}
	if len(rt.GenerationID) != 64 {
		return fmt.Errorf("invalid generation_id length")
	}
	if _, err := hex.DecodeString(rt.GenerationID); err != nil {
		return fmt.Errorf("invalid generation_id: %w", err)
	}
	if len(rt.SourceSHA256) != 64 {
		return fmt.Errorf("invalid source_sha256 length")
	}
	if _, err := hex.DecodeString(rt.SourceSHA256); err != nil {
		return fmt.Errorf("invalid source_sha256: %w", err)
	}
	if rt.SourceSize <= 0 || rt.ModuleName == "" || rt.DartVersion == "" {
		return fmt.Errorf("incomplete binary identity")
	}
	if rt.Architecture != "arm64" && rt.Architecture != "x64" {
		return fmt.Errorf("unsupported architecture %q", rt.Architecture)
	}
	if !rt.Agreement.Valid() {
		return fmt.Errorf("invalid agreement %q", rt.Agreement)
	}
	if rt.Observations <= 0 || len(rt.Targets) == 0 {
		return fmt.Errorf("runtime observation has no targets")
	}
	total := 0
	last := ""
	for i, target := range rt.Targets {
		if strings.TrimSpace(target.Target) == "" || target.Count <= 0 {
			return fmt.Errorf("invalid target observation at index %d", i)
		}
		if i > 0 && target.Target <= last {
			return fmt.Errorf("targets are not strictly sorted and unique")
		}
		last = target.Target
		if target.Count > rt.Observations-total {
			return fmt.Errorf("target counts exceed observations")
		}
		total += target.Count
	}
	if total != rt.Observations {
		return fmt.Errorf("target counts total %d, observations %d", total, rt.Observations)
	}
	for i, classID := range rt.ClassIDs {
		if classID <= 0 || int64(classID) > 1<<31-1 {
			return fmt.Errorf("invalid class_id %d", classID)
		}
		if i > 0 && classID <= rt.ClassIDs[i-1] {
			return fmt.Errorf("class_ids are not strictly sorted and unique")
		}
	}
	return nil
}

func runtimeIdentityKey(rt disasm.RuntimeEvidence) string {
	return strings.Join([]string{
		rt.Source,
		strings.ToLower(rt.GenerationID),
		strings.ToLower(rt.SourceSHA256),
		strconv.FormatInt(rt.SourceSize, 10),
		rt.ModuleName,
		rt.DartVersion,
		rt.Architecture,
	}, "\x00")
}

// RuntimeObservation is one identity-bound runtime call-site observation. The
// embedded RuntimeEvidence keeps target counts and binary/generation provenance
// together instead of flattening them into target-name-only rows.
type RuntimeObservation struct {
	PC       string                 `json:"pc"`
	Function string                 `json:"function"`
	Runtime  disasm.RuntimeEvidence `json:"runtime"`
}

func runtimeObservationKey(obs RuntimeObservation) (uint64, string, bool) {
	pc, ok := parsePCUint(obs.PC)
	if !ok {
		return 0, "", false
	}
	return pc, obs.Function, true
}

func runtimeTargets(rt disasm.RuntimeEvidence) []string {
	out := make([]string, 0, len(rt.Targets))
	for _, target := range rt.Targets {
		out = append(out, target.Target)
	}
	return out
}

func cloneRuntimeEvidence(rt disasm.RuntimeEvidence) disasm.RuntimeEvidence {
	rt.Targets = append([]disasm.RuntimeTargetObservation(nil), rt.Targets...)
	rt.ClassIDs = append([]int(nil), rt.ClassIDs...)
	return rt
}

func runtimeAgreementForRecord(rec Evidence, rt disasm.RuntimeEvidence) disasm.RuntimeAgreement {
	targets := runtimeTargets(rt)
	if staticTarget, _ := rec.Result["target"].(string); staticTarget != "" {
		for _, target := range targets {
			if target != staticTarget {
				return disasm.RuntimeConflicts
			}
		}
		return disasm.RuntimeAgrees
	}
	if rawCandidates, present := rec.Result["targets"]; present {
		cands, wellFormed := candidateTargets(rawCandidates)
		allowed := make(map[string]struct{}, len(cands))
		for _, cand := range cands {
			allowed[cand] = struct{}{}
		}
		allListed := true
		for _, target := range targets {
			if _, ok := allowed[target]; !ok {
				allListed = false
				break
			}
		}
		if allListed && wellFormed {
			return disasm.RuntimeAgrees
		}
		if candidateListComplete(rec.Result, len(cands), wellFormed) {
			return disasm.RuntimeConflicts
		}
		return disasm.RuntimeIndeterminate
	}
	return disasm.RuntimeObservedOnly
}

func runtimeObservationForRecord(rec Evidence, observations []RuntimeObservation) (int, *RuntimeObservation) {
	pc, ok := parsePCUint(rec.PC)
	if !ok {
		return -1, nil
	}
	for i := range observations {
		opc, ofn, valid := runtimeObservationKey(observations[i])
		if !valid || opc != pc {
			continue
		}
		if ofn != "" && rec.Function != "" && ofn != rec.Function {
			continue
		}
		return i, &observations[i]
	}
	return -1, nil
}

// MergeRuntime attaches runtime evidence without changing the static confidence
// or Target/Targets fields. Runtime-only sites become their own evidence rows so
// an observation is never confused with absence of static evidence.
func (c *Collector) MergeRuntime(observations []RuntimeObservation) error {
	seenSites := make(map[string]struct{}, len(observations))
	identity := ""
	for i := range observations {
		if err := validateRuntimeEvidence(&observations[i].Runtime); err != nil {
			return fmt.Errorf("runtime observation %d: %w", i, err)
		}
		if c.dartVersion != "" && observations[i].Runtime.DartVersion != c.dartVersion {
			return fmt.Errorf("runtime observation %d: Dart version %q does not match artifact Dart version %q", i, observations[i].Runtime.DartVersion, c.dartVersion)
		}
		keyIdentity := runtimeIdentityKey(observations[i].Runtime)
		if identity == "" {
			identity = keyIdentity
		} else if keyIdentity != identity {
			return fmt.Errorf("runtime observation %d: binary/generation identity differs from the observation batch", i)
		}
		pc, fn, ok := runtimeObservationKey(observations[i])
		if !ok {
			return fmt.Errorf("runtime observation %d: invalid pc %q", i, observations[i].PC)
		}
		if observations[i].PC != fmt.Sprintf("0x%x", pc) {
			return fmt.Errorf("runtime observation %d: non-canonical pc %q", i, observations[i].PC)
		}
		if strings.TrimSpace(fn) == "" {
			return fmt.Errorf("runtime observation %d: empty function identity", i)
		}
		key := fmt.Sprintf("%x\x00%s", pc, fn)
		if _, duplicate := seenSites[key]; duplicate {
			return fmt.Errorf("runtime observation %d: duplicate site %s/%s", i, observations[i].PC, fn)
		}
		seenSites[key] = struct{}{}
	}

	matched := make([]bool, len(observations))
	for i := range c.records {
		rec := &c.records[i]
		if !runtimeComparableRecord(*rec) {
			continue
		}
		idx, obs := runtimeObservationForRecord(*rec, observations)
		if obs == nil {
			continue
		}
		matched[idx] = true
		rt := cloneRuntimeEvidence(obs.Runtime)
		rt.Agreement = runtimeAgreementForRecord(*rec, rt)
		rec.Runtime = &rt
	}

	for i := range observations {
		if matched[i] {
			continue
		}
		rt := cloneRuntimeEvidence(observations[i].Runtime)
		rt.Agreement = disasm.RuntimeObservedOnly
		c.records = append(c.records, Evidence{
			PC:         observations[i].PC,
			Function:   observations[i].Function,
			Kind:       "runtime_call",
			Source:     SourceFrida,
			Confidence: ConfRuntimeObserved,
			Rule:       RuleFridaDispatchObservation,
			Runtime:    &rt,
		})
	}
	return nil
}

// CoverageReport summarizes how observed runtime behavior related to static
// predictions without treating bounded observation as a certainty upgrade.
type CoverageReport struct {
	StaticOnly               int `json:"static_only"`
	RuntimeOnly              int `json:"runtime_only"`
	BothMatch                int `json:"both_match"`
	BothConflict             int `json:"both_conflict"`
	BothIndeterminate        int `json:"both_indeterminate"`
	StaticUnresolvedObserved int `json:"static_unresolved_observed"`
	TotalStatic              int `json:"total_static"`
	TotalRuntime             int `json:"total_runtime"`
	InvalidRuntime           int `json:"invalid_runtime"`
}

// Coverage computes a summary of static vs runtime evidence overlap.
func (c *Collector) Coverage(observations []RuntimeObservation) CoverageReport {
	type siteKey struct {
		pc       uint64
		function string
	}
	rep := CoverageReport{}
	runtimeSites := make(map[siteKey]RuntimeObservation)
	identity := ""
	for _, obs := range observations {
		pc, ok := parsePCUint(obs.PC)
		if !ok || strings.TrimSpace(obs.Function) == "" || validateRuntimeEvidence(&obs.Runtime) != nil ||
			obs.PC != fmt.Sprintf("0x%x", pc) ||
			(c.dartVersion != "" && obs.Runtime.DartVersion != c.dartVersion) {
			rep.InvalidRuntime++
			continue
		}
		keyIdentity := runtimeIdentityKey(obs.Runtime)
		if identity == "" {
			identity = keyIdentity
		} else if keyIdentity != identity {
			rep.InvalidRuntime++
			continue
		}
		key := siteKey{pc: pc, function: obs.Function}
		if _, duplicate := runtimeSites[key]; duplicate {
			rep.InvalidRuntime++
			continue
		}
		runtimeSites[key] = obs
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
		var obs RuntimeObservation
		var rtKey siteKey
		found := false
		for candidateKey, candidate := range runtimeSites {
			if candidateKey.pc != key.pc {
				continue
			}
			if key.function != "" && candidateKey.function != "" && candidateKey.function != key.function {
				continue
			}
			obs, rtKey, found = candidate, candidateKey, true
			break
		}
		if !found {
			rep.StaticOnly++
			continue
		}
		seenRuntimeSites[rtKey] = true
		relation := disasm.RuntimeObservedOnly
		for _, rec := range records {
			candidateRelation := runtimeAgreementForRecord(rec, obs.Runtime)
			if candidateRelation == disasm.RuntimeConflicts {
				relation = candidateRelation
				break
			}
			if candidateRelation == disasm.RuntimeIndeterminate {
				relation = candidateRelation
				continue
			}
			if candidateRelation == disasm.RuntimeAgrees && relation == disasm.RuntimeObservedOnly {
				relation = candidateRelation
			}
		}
		switch relation {
		case disasm.RuntimeAgrees:
			rep.BothMatch++
		case disasm.RuntimeConflicts:
			rep.BothConflict++
		case disasm.RuntimeIndeterminate:
			rep.BothIndeterminate++
		case disasm.RuntimeObservedOnly:
			rep.StaticUnresolvedObserved++
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
	if e.Kind == "bl" || e.Kind == "call" {
		if e.TargetAddress != "" {
			return ConfExact
		}
		if e.Target != "" {
			return ConfStaticInferred
		}
		return ConfUnknown
	}
	if e.Target != "" {
		return ConfStaticInferred
	}
	if len(e.Targets) > 0 {
		return ConfPolymorphic
	}
	return ConfUnknown
}

// edgeRule returns the stable rule ID that produced this edge. Provenance such
// as THR or pool display text is data, not part of the identifier.
func edgeRule(e disasm.CallEdgeRecord) RuleID {
	switch e.Kind {
	case "bl", "call":
		if e.TargetAddress != "" {
			return RuleDirectCallAddress
		}
		if e.Target != "" {
			return RuleDirectCallTarget
		}
		return RuleDirectCallUnresolved
	case "blr", "call_indirect":
		if edgeViaIsStub(e) {
			return RuleIndirectStub
		}
		if e.Target != "" {
			return RuleIndirectStaticInferred
		}
		if len(e.Targets) > 0 {
			return RuleIndirectPolymorphic
		}
		return RuleIndirectUnresolved
	}
	return ""
}

func edgeViaIsStub(e disasm.CallEdgeRecord) bool {
	if e.Kind != "blr" && e.Kind != "call_indirect" {
		return false
	}
	// Provenance text alone cannot resolve a call. A stub confidence requires a
	// separately recovered target identity.
	if e.Target == "" {
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
