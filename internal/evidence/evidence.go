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

	"aotopsy/internal/disasm"
	"aotopsy/internal/typetrack"
)

// Evidence is one analysis finding with full provenance.
type Evidence struct {
	PC         string         `json:"pc"`
	Function   string         `json:"function"`
	Kind       string         `json:"kind"`       // "call", "dispatch", "field_access", "signal"
	Instruction string        `json:"instruction,omitempty"`
	Inputs     map[string]any `json:"inputs,omitempty"`
	Result     map[string]any `json:"result,omitempty"`
	Confidence string         `json:"confidence"` // exact, static_inferred, polymorphic, stub, unknown
	Rule       string         `json:"rule,omitempty"`
	SDKRef     *SDKReference  `json:"sdk_ref,omitempty"`
}

// SDKReference points to the SDK source that justifies a rule or constant.
type SDKReference struct {
	Tag    string `json:"tag"`
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
			PC:       e.FromPC,
			Function: e.FromFunc,
			Kind:     "call",
			Confidence: classifyEdgeConfidence(e),
			Rule:     edgeRule(e),
		}
		if e.Target != "" {
			ev.Result = map[string]any{"target": e.Target}
		} else if len(e.Targets) > 0 {
			ev.Result = map[string]any{"targets": e.Targets, "candidate_count": e.Candidates}
		} else if e.Via != "" {
			ev.Result = map[string]any{"via": e.Via}
		} else {
			ev.Result = map[string]any{"resolved": false}
			ev.Confidence = "unknown"
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
			PC:         fmt.Sprintf("0x%x", r.PC),
			Function:   funcName,
			Kind:       "dispatch",
			Confidence: r.Confidence,
			Rule:       "typetrack.BLRResolution",
		}
		if r.Confidence == "" {
			ev.Confidence = "unknown"
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

// Records returns all collected evidence, sorted by PC.
func (c *Collector) Records() []Evidence {
	out := make([]Evidence, len(c.records))
	copy(out, c.records)
	sort.Slice(out, func(i, j int) bool {
		return out[i].PC < out[j].PC
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
	// Build PC → runtime target map.
	rtByPC := make(map[string]string, len(resolutions))
	for _, r := range resolutions {
		rtByPC[r.PC] = r.TargetName
	}

	for i := range c.records {
		rec := &c.records[i]
		if rtTarget, ok := rtByPC[rec.PC]; ok {
			if rec.Result == nil {
				rec.Result = map[string]any{}
			}
			rec.Result["runtime_target"] = rtTarget
			// Upgrade confidence: exact/stub/static_inferred → runtime_confirmed.
			// polymorphic stays polymorphic (runtime confirmed ONE of many).
			// unknown → runtime_confirmed (runtime observed what static couldn't).
			switch rec.Confidence {
			case "exact", "stub", "static_inferred", "unknown":
				rec.Confidence = "runtime_confirmed"
			case "polymorphic":
				// Keep polymorphic but note runtime confirmed one candidate.
				rec.Result["runtime_confirmed_candidate"] = rtTarget
			}
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
	RuntimeConfirmed  int `json:"runtime_confirmed"`
	TotalStatic       int `json:"total_static"`
	TotalRuntime      int `json:"total_runtime"`
}

// Coverage computes a summary of static vs runtime evidence overlap.
func (c *Collector) Coverage(resolutions []RuntimeResolution) CoverageReport {
	rep := CoverageReport{TotalStatic: len(c.records), TotalRuntime: len(resolutions)}
	rtByPC := make(map[string]string, len(resolutions))
	for _, r := range resolutions {
		rtByPC[r.PC] = r.TargetName
	}
	seenPCs := make(map[string]bool)
	for _, rec := range c.records {
		if rtTarget, ok := rtByPC[rec.PC]; ok {
			seenPCs[rec.PC] = true
			staticTarget, _ := rec.Result["target"].(string)
			if staticTarget != "" && staticTarget == rtTarget {
				rep.BothMatch++
			} else if staticTarget != "" && staticTarget != rtTarget {
				rep.BothConflict++
			} else {
				rep.RuntimeConfirmed++
			}
		} else {
			rep.StaticOnly++
		}
	}
	rep.RuntimeOnly = len(resolutions) - len(seenPCs)
	return rep
}

// classifyEdgeConfidence maps a CallEdgeRecord's fields to a confidence string.
func classifyEdgeConfidence(e disasm.CallEdgeRecord) string {
	if e.Target != "" {
		return "exact"
	}
	if len(e.Targets) > 0 {
		return "polymorphic"
	}
	if e.Via != "" {
		return "stub"
	}
	return "unknown"
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
