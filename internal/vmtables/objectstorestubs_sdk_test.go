package vmtables

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"

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

	fieldRe := regexp.MustCompile(`^\s*(R_|RW|CW|FW|ARW_RELAXED|ARW_AR|LAZY_[A-Z]+)\(\s*[\w:]+\s*,\s*(\w+)\s*\)`)

	for version, want := range objectStoreStubFields {
		out, err := exec.Command("gh", "api", "-H", "Accept: application/vnd.github.raw+json",
			"repos/dart-lang/sdk/contents/runtime/vm/object_store.h?ref="+version).Output()
		if err != nil {
			t.Fatalf("%s: gh api object_store.h: %v", version, err)
		}
		src := string(out)
		body := src
		if i := strings.Index(src, "class ObjectStore {"); i >= 0 {
			body = src[i:]
		} else if i := strings.Index(src, "class ObjectStore :"); i >= 0 {
			body = src[i:]
		}
		macroList := func(macro string) []string {
			i := strings.Index(src, "#define "+macro)
			if i < 0 {
				return nil
			}
			var names []string
			for _, ln := range strings.Split(src[i:], "\n")[1:] {
				if m := fieldRe.FindStringSubmatch(ln); m != nil {
					names = append(names, m[2])
				}
				if !strings.HasSuffix(strings.TrimSpace(ln), "\\") {
					break
				}
			}
			return names
		}
		declRe := regexp.MustCompile(`(?s)#define DECLARE_OBJECT_STORE_FIELD.*?\n((?:[^\n]*_FIELD_LIST\([^\n]*\n)+)`)
		var order []string
		if m := declRe.FindStringSubmatch(body); m != nil {
			for _, mm := range regexp.MustCompile(`([A-Z_0-9]+_FIELD_LIST)\(`).FindAllStringSubmatch(m[1], -1) {
				order = append(order, mm[1])
			}
		}
		if len(order) == 0 {
			order = []string{"OBJECT_STORE_FIELD_LIST"}
		}
		var names []string
		for _, macro := range order {
			names = append(names, macroList(macro)...)
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
