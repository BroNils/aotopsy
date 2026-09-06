package ffitrace

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

// TestFindingSchema pins the JSON keys `aotopsy _debug ffi-trace` emits.
//
// Finding carried no tags at all until the snake_case pass, so its wire
// format was whatever Go's default field naming produced (CallerFunc,
// CallSitePC). Renaming them was the right call, but nothing pinned either
// spelling before or after -- the struct is serialised straight to stdout
// and no test looked at the bytes. This is the pin.
func TestFindingSchema(t *testing.T) {
	full := Finding{
		CallerFunc: "f", CallerVA: 1, CallSitePC: 2, Kind: "dynamic_library_call",
		CalleeName: "c", LiteralArg: "l", Resolved: true,
	}
	want := []string{"call_site_pc", "callee_name", "caller_func", "caller_va", "kind", "literal_arg", "resolved"}
	if got := jsonKeys(t, full); !slices.Equal(got, want) {
		t.Errorf("Finding keys = %v, want %v", got, want)
	}

	// The omitempty set is part of the contract: a native_call_site finding
	// is function-level, so it carries no call_site_pc, no callee_name and
	// no literal_arg. A consumer must treat those as absent, not as zero.
	sparse := Finding{CallerFunc: "f", CallerVA: 1, Kind: "native_call_site"}
	wantSparse := []string{"caller_func", "caller_va", "kind", "resolved"}
	if got := jsonKeys(t, sparse); !slices.Equal(got, wantSparse) {
		t.Errorf("sparse Finding keys = %v, want %v", got, wantSparse)
	}
}
