package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"aotopsy/internal/cluster"
	"aotopsy/internal/disasm"
)

// Cross-referencing JSONL outputs (gap-analysis §6).
// All are written by writeXrefJSONL during the pipeline Run.

// StringValueXref maps a string value to all functions that reference it.
type StringValueXref struct {
	StringValue string   `json:"string_value"`
	Functions   []string `json:"functions"`
}

// FieldAccessorXref maps a class+field offset to all functions that access it.
type FieldAccessorXref struct {
	ClassName  string   `json:"class_name"`
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
func writeXrefJSONL(outDir string, clResult *cluster.Result, pl *PoolLookups, funcs []disasm.FuncRecord, edges []disasm.CallEdgeRecord, stringRefs []disasm.StringRefRecord) error {
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
			if pl.CT != nil && pl.RefCID != nil {
				if cid, ok := pl.RefCID[pe.RefID]; ok {
					isString := cid == pl.CT.OneByteString || cid == pl.CT.TwoByteString
					if isString {
						if s, ok := pl.RefToStr[pe.RefID]; ok {
							poolStrings[pe.Index] = s
						} else if s, ok := pl.VmRefToStr[pe.RefID]; ok {
							poolStrings[pe.Index] = s
						}
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
		if e.Target == "" {
			continue
		}
		if targetCallers[e.Target] == nil {
			targetCallers[e.Target] = map[string]bool{}
		}
		targetCallers[e.Target][e.FromFunc] = true
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

	// 3. selector_dispatch_xref.jsonl — selector offset → targets
	// Uses dispatch_table.jsonl if available (written by typetrack stage).
	// The JSONL format uses string kind ("null", "code", "stub") and
	// includes target/slot_info fields, so we use a matching reader struct.
	dispatchPath := filepath.Join(outDir, "dispatch_table.jsonl")
	type dtJSONL struct {
		Index    int    `json:"index"`
		Kind     string `json:"kind"`
		Target   string `json:"target,omitempty"`
		SlotInfo string `json:"slot_info,omitempty"`
	}
	if dtEntries, err := ReadJSONL[dtJSONL](dispatchPath); err == nil && len(dtEntries) > 0 {
		selectorTargets := map[int][]string{}
		for _, entry := range dtEntries {
			if entry.Kind != "code" {
				continue
			}
			name := entry.Target
			if name == "" {
				// Try to extract from slot_info: "code cluster_index=N"
				name = entry.SlotInfo
			}
			if name == "" {
				name = fmt.Sprintf("code_%d", entry.Index)
			}
			selectorTargets[entry.Index] = append(selectorTargets[entry.Index], name)
		}
		if err := writeJSONL(filepath.Join(outDir, "selector_dispatch_xref.jsonl"), func() []interface{} {
			var out []interface{}
			for slot, targets := range selectorTargets {
				sort.Strings(targets)
				out = append(out, SelectorDispatchXref{SelectorOffset: slot, Targets: targets})
			}
			sort.Slice(out, func(i, j int) bool {
				return out[i].(SelectorDispatchXref).SelectorOffset < out[j].(SelectorDispatchXref).SelectorOffset
			})
			return out
		}()); err != nil {
			return fmt.Errorf("write selector_dispatch_xref.jsonl: %w", err)
		}
	}

	// 4. field_accessor_xref.jsonl — class+offset → accessor functions
	// Built from class layouts + string_refs (which functions access which pool entries).
	// A field accessor is a function that loads/stores at a known field offset.
	// We approximate by matching pool-loaded class instances to their accessing functions.
	if len(clResult.Classes) > 0 && len(clResult.Instances) > 0 {
		classByName := map[string]*cluster.ClassInfo{}
		for i := range clResult.Classes {
			ci := &clResult.Classes[i]
			name := ""
			if s, ok := pl.RefToStr[ci.NameRefID]; ok {
				name = s
			}
			if name != "" {
				classByName[name] = ci
			}
		}

		// Build instance CID → (offset → ref) map
		instanceFields := map[int]map[int]int{} // cid → offset → refID
		for _, inst := range clResult.Instances {
			if instanceFields[inst.CID] == nil {
				instanceFields[inst.CID] = map[int]int{}
			}
			for _, f := range inst.Fields {
				instanceFields[inst.CID][int(f.ByteOffset)] = f.Ref
			}
		}

		// For each class, list its field offsets
		type fieldKey struct {
			className string
			offset    int
		}
		fieldReaders := map[fieldKey]map[string]bool{}
		for _, ci := range clResult.Classes {
			name := ""
			if s, ok := pl.RefToStr[ci.NameRefID]; ok {
				name = s
			}
			if name == "" {
				continue
			}
			// Get field offsets from class layout
			for _, fi := range clResult.Fields {
				if fi.OwnerRefID == ci.RefID {
					fname := ""
					if s, ok := pl.RefToStr[fi.NameRefID]; ok {
						fname = s
					}
					key := fieldKey{className: name, offset: int(fi.HostOffset)} //nolint:gosec
					if fieldReaders[key] == nil {
						fieldReaders[key] = map[string]bool{}
					}
					_ = fname // field name available if needed
				}
			}
		}

		// We don't have per-function field access records from disasm,
		// so we emit the class→field mapping as a reference.
		if err := writeJSONL(filepath.Join(outDir, "field_accessor_xref.jsonl"), func() []interface{} {
			var out []interface{}
			for key := range fieldReaders {
				out = append(out, FieldAccessorXref{
					ClassName:  key.className,
					ByteOffset: key.offset,
				})
			}
			sort.Slice(out, func(i, j int) bool {
				a, b := out[i].(FieldAccessorXref), out[j].(FieldAccessorXref)
				if a.ClassName != b.ClassName {
					return a.ClassName < b.ClassName
				}
				return a.ByteOffset < b.ByteOffset
			})
			return out
		}()); err != nil {
			return fmt.Errorf("write field_accessor_xref.jsonl: %w", err)
		}
	}

	return nil
}

func writeJSONL(path string, entries []interface{}) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}
