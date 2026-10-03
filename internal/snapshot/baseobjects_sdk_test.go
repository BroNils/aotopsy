package snapshot

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
)

// TestBaseObjectNamesMatchSDK re-derives every row of baseObjectLayouts from
// dart-lang/sdk's AddBaseObjects and fails on any drift.
//
// The table cannot be validated locally. A wrong row names the wrong object:
// the index of `true` is 9, 10, 11 and then 10 again across 2.12 to 3.12, so
// borrowing a neighbouring version's list silently labels `false` as `true`,
// or `[]` as a bool. The only ground truth is the SDK source the list came
// from.
//
// Network- and gh-dependent, so it is opt-in:
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/snapshot/ -run BaseObjectNamesMatchSDK
func TestBaseObjectNamesMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	checked := 0
	for _, tag := range SupportedVersions() {
		got := BaseObjectNames(tag)
		if got == nil {
			// 2.10 predates the verified base-object naming table. Every later
			// supported release is claimed by baseObjectLayouts and must never
			// disappear from this gate just because a row was omitted.
			if tag != "2.10.0" {
				t.Errorf("supported Dart %s has no verified base-object layout", tag)
			}
			continue
		}
		checked++
		t.Run(tag, func(t *testing.T) {
			sdk, err := sdkBaseObjectNames(tag)
			if err != nil {
				t.Fatalf("could not read AddBaseObjects from the SDK at %s: %v", tag, err)
			}
			if len(sdk) < len(got) {
				t.Fatalf("SDK at %s lists %d base objects, the table claims %d", tag, len(sdk), len(got))
			}
			for i := range got {
				if got[i] != sdk[i] {
					t.Errorf("ref %d at %s: table says %q, SDK says %q\nfull SDK list: %q",
						i+1, tag, got[i], sdk[i], sdk[:len(got)])
					break
				}
			}
		})
	}
	if checked == 0 {
		t.Fatal("base-object drift gate verified zero supported versions")
	}
}

// TestBaseObjectNamesRefusesUnknownVersions guards the deliberate nil: a
// version outside the verified range must NOT borrow a neighbour's list.
func TestBaseObjectNamesRefusesUnknownVersions(t *testing.T) {
	for _, v := range []string{"", "2.11.0", "4.0.0", "3.14.0", "nonsense", "3"} {
		if got := BaseObjectNames(v); got != nil {
			t.Errorf("BaseObjectNames(%q) = %q, want nil -- an unverified version must stay unnamed", v, got)
		}
	}
}

// The whole point of the table: `true` and `false` are not at fixed indices.
func TestBaseObjectBoolIndicesVaryByVersion(t *testing.T) {
	cases := map[string][2]int{ // version -> {true ref, false ref}
		"2.12.0": {9, 10},
		"2.19.0": {9, 10},
		"3.1.0":  {10, 11},
		"3.3.0":  {11, 12},
		"3.9.2":  {10, 11},
		"3.12.2": {10, 11},
		"3.13.0": {3, 2}, // true=ref3, false=ref2 — SWAPPED vs all prior versions
	}
	for v, want := range cases {
		names := BaseObjectNames(v)
		if names == nil {
			t.Fatalf("no table row for %s", v)
		}
		gotTrue, gotFalse := 0, 0
		for i, n := range names {
			switch n {
			case "true":
				gotTrue = i + 1
			case "false":
				gotFalse = i + 1
			}
		}
		if gotTrue != want[0] || gotFalse != want[1] {
			t.Errorf("%s: true=ref%d false=ref%d, want true=ref%d false=ref%d",
				v, gotTrue, gotFalse, want[0], want[1])
		}
	}
}

var addBaseObjectRe = regexp.MustCompile(`AddBaseObject\(([^;]+?)\);`)
var quotedRe = regexp.MustCompile(`"([^"]*)"`)

// sdkBaseObjectNames fetches AddBaseObjects from the SDK at tag and returns
// the display names in reference order.
func sdkBaseObjectNames(tag string) ([]string, error) {
	// The function moved file in 2.13; try both names.
	src, err := sdktest.SDKFileAtTagAny(tag,
		"runtime/vm/app_snapshot.cc",
		"runtime/vm/clustered_snapshot.cc",
	)
	if err != nil {
		return nil, err
	}
	flat := regexp.MustCompile(`\n\s+`).ReplaceAllString(src, " ")
	i := strings.Index(flat, "void AddBaseObjects(Serializer* s)")
	if i < 0 {
		return nil, fmt.Errorf("AddBaseObjects(Serializer* s) not found at %s", tag)
	}
	seg, err := cxxFunctionBody(flat[i:])
	if err != nil {
		return nil, fmt.Errorf("AddBaseObjects at %s: %w", tag, err)
	}
	var out []string
	for _, m := range addBaseObjectRe.FindAllStringSubmatch(seg, -1) {
		q := quotedRe.FindAllStringSubmatch(m[1], -1)
		if len(q) >= 2 {
			out = append(out, q[1][1])
		} else {
			out = append(out, "?")
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("AddBaseObjects at %s contained no AddBaseObject rows", tag)
	}
	return out, nil
}

func cxxFunctionBody(src string) (string, error) {
	open := strings.IndexByte(src, '{')
	if open < 0 {
		return "", fmt.Errorf("opening brace not found")
	}
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open+1 : i], nil
			}
		}
	}
	return "", fmt.Errorf("unterminated function body")
}
