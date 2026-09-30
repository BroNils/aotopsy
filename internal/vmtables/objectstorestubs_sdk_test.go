package vmtables

import (
	"regexp"
	"strings"
	"testing"

	"aotopsy/internal/cmacro"
	"aotopsy/internal/sdktest"
)

// TestObjectStoreStubFieldsMatchSDK regenerates the committed table from
// object_store.h and fails on any drift.
//
// The table is INDICES into the isolate roots section, so drift is silent and
// dangerous in a specific way: a shifted index still resolves to a Code, and
// that Code still gets a confident name -- just the wrong one. Nothing errors,
// the pipeline runs, and a stub is mislabelled in every call site that
// references it.
//
// Regenerate with:
//
//	go run tools/extract_thr.go -write-objectstore-stubs
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/vmtables/ -run ObjectStoreStubFields
func TestObjectStoreStubFieldsMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	for version, want := range objectStoreStubFields {
		src, err := sdktest.SDKFileAtTag("runtime/vm/object_store.h", version)
		if err != nil {
			t.Fatalf("%s: fetch object_store.h: %v", version, err)
		}
		body := src
		if i := strings.Index(src, "class ObjectStore {"); i >= 0 {
			body = src[i:]
		} else if i := strings.Index(src, "class ObjectStore :"); i >= 0 {
			body = src[i:]
		}
		macros, err := cmacro.ParseMacros(src)
		if err != nil {
			t.Fatalf("%s: parse object_store.h macros: %v", version, err)
		}
		rows, err := cmacro.ExpandRawAllCallbacks(macros, "OBJECT_STORE_FIELD_LIST")
		if err != nil {
			t.Fatalf("%s: expand OBJECT_STORE_FIELD_LIST: %v", version, err)
		}
		names := make([]string, 0, len(rows))
		for i, row := range rows {
			if len(row) != 2 {
				t.Fatalf("%s: OBJECT_STORE_FIELD_LIST row %d has %d columns, want 2", version, i, len(row))
			}
			names = append(names, strings.TrimSpace(row[1]))
		}
		fromRe := regexp.MustCompile(`ObjectPtr\* from\(\)\s*\{\s*return[^&]*&(\w+)_\)`)
		aotRe := regexp.MustCompile(`kFullAOT:\s*\n?\s*return[^&]*&(\w+)_\)`)
		fm, am := fromRe.FindStringSubmatch(body), aotRe.FindStringSubmatch(body)
		if fm == nil || am == nil {
			t.Fatalf("%s: could not locate from()/to_snapshot(kFullAOT)", version)
		}
		idx := func(n string) int {
			for i, x := range names {
				if x == n {
					return i
				}
			}
			return -1
		}
		i0, i1 := idx(fm[1]), idx(am[1])
		if i0 < 0 || i1 < 0 {
			t.Fatalf("%s: from/to not found among %d fields", version, len(names))
		}
		sel := names[i0 : i1+1]
		var got []objectStoreStubField
		for i, n := range sel {
			if strings.HasSuffix(n, "_stub") {
				got = append(got, objectStoreStubField{i, n})
			}
		}
		if len(got) != len(want) {
			t.Errorf("%s: SDK has %d stub fields, table has %d", version, len(got), len(want))
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%s: entry %d: SDK {%d,%q}, table {%d,%q}",
					version, i, got[i].Index, got[i].Name, want[i].Index, want[i].Name)
			}
		}
	}
}
