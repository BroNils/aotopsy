package disasm

import (
	"encoding/json"
	"slices"
	"testing"
)

// jsonKeys marshals v and returns its top-level key set, sorted.
func jsonKeys(t *testing.T, v any) []string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// TestJSONLSchema pins the wire keys of every record type the pipeline
// writes to a .jsonl artifact.
//
// These names are a published interface: functions.jsonl, call_edges.jsonl,
// string_refs.jsonl and unresolved_thr.jsonl are what the Ghidra and IDA
// scripts, and any user tooling, read. Nothing else in the suite notices if
// a tag changes, and the failure mode is silent on both sides -- a renamed
// key does not error, it decodes to the zero value. That is exactly how
// string_refs.jsonl's caller name reached frida_export as "" for as long as
// it did: the writer said "func", the reader asked for "from_func", and
// both were happy.
//
// A field added here is fine; update the list. A field RENAMED here breaks
// consumers, and the test exists to make that a decision rather than an
// accident.
func TestJSONLSchema(t *testing.T) {
	for _, tc := range []struct {
		artifact string
		value    any
		want     []string
	}{
		{
			artifact: "functions.jsonl",
			value:    FuncRecord{PC: "0x1", Size: 1, Name: "n", Owner: "o", ParamCount: 1},
			want:     []string{"name", "owner", "param_count", "pc", "size"},
		},
		{
			artifact: "call_edges.jsonl",
			value: CallEdgeRecord{
				FromFunc: "f", FromPC: "0x1", Kind: "bl", Target: "t",
				Reg: "X16", Via: "v", Targets: []string{"a"}, Candidates: 2,
			},
			want: []string{"candidates", "from_func", "from_pc", "kind", "reg", "target", "targets", "via"},
		},
		{
			artifact: "string_refs.jsonl",
			value:    StringRefRecord{Func: "f", PC: "0x1", Kind: "PP", PoolIdx: 3, Value: "v"},
			want:     []string{"func", "kind", "pc", "pool_idx", "value"},
		},
		{
			artifact: "unresolved_thr.jsonl",
			value: UnresolvedTHRRecord{
				FuncName: "f", PC: "0x1", THROffset: "0x8", Width: 8,
				IsStore: true, Class: "UNKNOWN",
			},
			want: []string{"class", "func_name", "is_store", "pc", "thr_offset", "width"},
		},
	} {
		got := jsonKeys(t, tc.value)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s keys = %v, want %v", tc.artifact, got, tc.want)
		}
	}
}

// TestJSONLOmitEmpty pins which fields disappear when empty, because that
// is a schema property too: a consumer written against a fully-populated
// sample will not see these keys on a sparse record.
func TestJSONLOmitEmpty(t *testing.T) {
	if got := jsonKeys(t, FuncRecord{}); !slices.Equal(got, []string{"name", "pc", "size"}) {
		t.Errorf("empty FuncRecord keys = %v", got)
	}
	if got := jsonKeys(t, CallEdgeRecord{}); !slices.Equal(got, []string{"from_func", "from_pc", "kind"}) {
		t.Errorf("empty CallEdgeRecord keys = %v", got)
	}
	// StringRefRecord has no omitempty at all: every line carries all five
	// keys, which is what makes it safe to read positionally.
	if got := jsonKeys(t, StringRefRecord{}); !slices.Equal(got, []string{"func", "kind", "pc", "pool_idx", "value"}) {
		t.Errorf("empty StringRefRecord keys = %v", got)
	}
}
