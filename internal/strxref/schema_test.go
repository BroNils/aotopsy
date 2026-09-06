package strxref

import (
	"encoding/json"
	"slices"
	"testing"
)

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

// TestReferenceSchema pins the JSON keys `aotopsy _debug strings --xref`
// emits. Reference had no tags before the snake_case pass; nothing pinned
// the old spelling and nothing pinned the new one until now.
//
// No omitempty here, deliberately: a pool cross-reference with FuncVA 0 or
// PoolIndex 0 is a real reference, and dropping the key would make "not
// found" and "found at zero" indistinguishable.
func TestReferenceSchema(t *testing.T) {
	want := []string{"func_name", "func_va", "instr_addr", "pool_index"}

	full := Reference{FuncName: "f", FuncVA: 1, InstrAddr: 2, PoolIndex: 3}
	if got := jsonKeys(t, full); !slices.Equal(got, want) {
		t.Errorf("Reference keys = %v, want %v", got, want)
	}
	if got := jsonKeys(t, Reference{}); !slices.Equal(got, want) {
		t.Errorf("zero Reference keys = %v, want %v (no omitempty expected)", got, want)
	}
}
