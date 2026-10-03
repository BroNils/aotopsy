package analysis

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"

	"aotopsy/internal/cluster"
	"aotopsy/internal/disasm"
	"aotopsy/internal/naming"
	"aotopsy/internal/output"
)

// Cross-referencing JSONL outputs (gap-analysis §6).
// All are written by writeXrefJSONL during the pipeline Run.

// StringValueXref maps a string value to all functions that reference it.
type StringValueXref struct {
	StringValue string   `json:"string_value"`
	Functions   []string `json:"functions"`
}

// FieldAccessorXref maps a class+field offset to all functions that access it.
//
// ClassID is part of the record, not just the name: two classes in different
// libraries routinely share a short name (State, Node, Entry), so the name
// alone identifies neither the row nor a stable sort order.
type FieldAccessorXref struct {
	ClassName  string   `json:"class_name"`
	ClassID    int      `json:"class_id"`
	ByteOffset int      `json:"byte_offset"`
	FieldName  string   `json:"field_name,omitempty"`
	Readers    []string `json:"readers"`
	Writers    []string `json:"writers,omitempty"`
}

// SelectorDispatchXref maps a selector offset to all dispatch targets.
type SelectorDispatchXref struct {
	SelectorOffset int      `json:"selector_offset"`
	Targets        []string `json:"targets"`
}

// AddressCallersXref maps a function address to all callers.
type AddressCallersXref struct {
	Target  string   `json:"target"`
	Callers []string `json:"callers"`
}

// writeXrefJSONL writes cross-referencing JSONL files.
func writeXrefJSONL(outDir string, clResult *cluster.Result, pl *naming.PoolLookups, funcs []disasm.FuncRecord, edges []disasm.CallEdgeRecord, stringRefs []disasm.StringRefRecord, selectorTargets map[int][]string, compressedPtrs bool) error {
	// 1. string_value_xref.jsonl — string value → functions
	// Also build from pool string entries if stringRefs is empty.
	stringFuncs := map[string]map[string]bool{}
	for _, sr := range stringRefs {
		if sr.Value == "" {
			continue
		}
		if stringFuncs[sr.Value] == nil {
			stringFuncs[sr.Value] = map[string]bool{}
		}
		stringFuncs[sr.Value][sr.Func] = true
	}
	// Fallback: if stringRefs is empty, build from poolDisplay + functions
	// that reference those pool entries (via string_refs.jsonl PC matching).
	// This ensures string_value_xref is populated even when ExtractStringRefs
	// finds 0 entries (e.g., when pool strings are VM snapshot strings).
	if len(stringFuncs) == 0 && len(stringRefs) == 0 {
		// Build from pool entries: map pool index → string value
		poolStrings := map[int]string{}
		for _, pe := range clResult.Pool {
			if pe.Kind != cluster.PoolTagged {
				continue
			}
			if pl.CT != nil {
				cid, ok := pl.CIDForRef(pe.RefID)
				isString := ok && (cid == pl.CT.String || cid == pl.CT.OneByteString || cid == pl.CT.TwoByteString)
				if isString {
					if s, ok := pl.StringForRef(pe.RefID); ok {
						poolStrings[pe.Index] = s
					}
				}
			}
		}
		// For each pool string, find functions that reference it via string_refs
		// Since stringRefs is empty, we can't map to functions.
		// Instead, emit entries with empty function lists (the string exists
		// in the pool but we don't know which functions reference it).
		for _, val := range poolStrings {
			if val != "" {
				stringFuncs[val] = map[string]bool{}
			}
		}
	}
	if err := writeJSONL(filepath.Join(outDir, "string_value_xref.jsonl"), func() []interface{} {
		var out []interface{}
		for val, fnSet := range stringFuncs {
			var fns []string
			for fn := range fnSet {
				fns = append(fns, fn)
			}
			sort.Strings(fns)
			out = append(out, StringValueXref{StringValue: val, Functions: fns})
		}
		sort.Slice(out, func(i, j int) bool {
			return out[i].(StringValueXref).StringValue < out[j].(StringValueXref).StringValue
		})
		return out
	}()); err != nil {
		return fmt.Errorf("write string_value_xref.jsonl: %w", err)
	}

	// 2. address_callers_xref.jsonl — target function → callers
	targetCallers := map[string]map[string]bool{}
	for _, e := range edges {
		// A polymorphic edge is evidence that the callee is one of Targets,
		// not evidence for one privileged member of the set. Include every
		// recorded candidate as an over-approximate xref rather than silently
		// dropping the site (the old Target-only loop did exactly that).
		for _, target := range e.ResolvedTargets() {
			if target == "" {
				continue
			}
			if targetCallers[target] == nil {
				targetCallers[target] = map[string]bool{}
			}
			targetCallers[target][e.FromFunc] = true
		}
	}
	if err := writeJSONL(filepath.Join(outDir, "address_callers_xref.jsonl"), func() []interface{} {
		var out []interface{}
		for target, callers := range targetCallers {
			var cs []string
			for c := range callers {
				cs = append(cs, c)
			}
			sort.Strings(cs)
			out = append(out, AddressCallersXref{Target: target, Callers: cs})
		}
		sort.Slice(out, func(i, j int) bool {
			return out[i].(AddressCallersXref).Target < out[j].(AddressCallersXref).Target
		})
		return out
	}()); err != nil {
		return fmt.Errorf("write address_callers_xref.jsonl: %w", err)
	}

	// 3. selector_dispatch_xref.jsonl — selector immediate → targets. The type
	// inference stage owns this coordinate because deriving it requires both the
	// dispatch slot and the target owner's class ID. dispatch_table.jsonl only
	// carries the absolute entry index, so reparsing it here used to emit one row
	// per slot while incorrectly labelling that index as a selector.
	if err := writeJSONL(filepath.Join(outDir, "selector_dispatch_xref.jsonl"), func() []interface{} {
		var out []interface{}
		for selector, targets := range selectorTargets {
			copyTargets := append([]string(nil), targets...)
			sort.Strings(copyTargets)
			out = append(out, SelectorDispatchXref{SelectorOffset: selector, Targets: copyTargets})
		}
		sort.Slice(out, func(i, j int) bool {
			return out[i].(SelectorDispatchXref).SelectorOffset < out[j].(SelectorDispatchXref).SelectorOffset
		})
		return out
	}()); err != nil {
		return fmt.Errorf("write selector_dispatch_xref.jsonl: %w", err)
	}

	// 4. field_accessor_xref.jsonl is written by the type-inference stage
	// (writeFieldAccessorXref in typetrack_stage.go), which is where the
	// per-function field-access records live. What stood here built the same
	// file from class layouts alone, with Readers and Writers ALWAYS empty and
	// the field name computed and then thrown away -- a cross-reference file
	// containing no cross-references.

	return nil
}

func writeJSONL(path string, entries []interface{}) error {
	return output.WriteAtomic(path, 0o644, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		for _, e := range entries {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
		return nil
	})
}
