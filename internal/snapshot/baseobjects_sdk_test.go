package snapshot

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
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
	if os.Getenv("AOTOPSY_TEST_SDK") == "" {
		t.Skip("AOTOPSY_TEST_SDK not set (needs network + gh auth), skipping SDK drift check")
	}
	if _, err := exec.LookPath("gh"); err != nil {
		t.Skip("gh not on PATH, skipping SDK drift check")
	}
	// One tag per layout is enough to catch drift in that layout's row, and
	// the boundary tags catch a range that has silently moved.
	probes := []struct {
		tag                string
		wantMajor, wantMin int
	}{
		{"2.12.0", 2, 12},
		{"2.18.0", 2, 18},
		{"2.19.0", 2, 19},
		{"3.0.0", 3, 0},
		{"3.1.0", 3, 1},
		{"3.2.0", 3, 2},
		{"3.4.0", 3, 4},
		{"3.5.0", 3, 5},
		{"3.9.2", 3, 9},
		{"3.12.2", 3, 12},
		{"3.13.0", 3, 13},
	}
	for _, p := range probes {
		t.Run(p.tag, func(t *testing.T) {
			sdk, err := sdkBaseObjectNames(p.tag)
			if err != nil {
				t.Fatalf("could not read AddBaseObjects from the SDK at %s: %v", p.tag, err)
			}
			got := BaseObjectNames(p.tag)
			if got == nil {
				t.Fatalf("no table row covers %s, but the SDK has one: %q", p.tag, sdk)
			}
			if len(sdk) < len(got) {
				t.Fatalf("SDK at %s lists %d base objects, the table claims %d", p.tag, len(sdk), len(got))
			}
			for i := range got {
				if got[i] != sdk[i] {
					t.Errorf("ref %d at %s: table says %q, SDK says %q\nfull SDK list: %q",
						i+1, p.tag, got[i], sdk[i], sdk[:len(got)])
					break
				}
			}
		})
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
	var lastErr error
	for _, path := range []string{"runtime/vm/app_snapshot.cc", "runtime/vm/clustered_snapshot.cc"} {
		src, err := ghFileAtTag(path, tag)
		if err != nil {
			lastErr = err
			continue
		}
		flat := regexp.MustCompile(`\n\s+`).ReplaceAllString(src, " ")
		i := strings.Index(flat, "void AddBaseObjects(Serializer* s)")
		if i < 0 {
			continue
		}
		seg := flat[i:]
		if len(seg) > 4000 {
			seg = seg[:4000]
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
		if len(out) > 0 {
			return out, nil
		}
	}
	if lastErr == nil {
		lastErr = os.ErrNotExist
	}
	return nil, lastErr
}

// ghFileAtTag reads a file from dart-lang/sdk at a tag via the GitHub API.
func ghFileAtTag(path, tag string) (string, error) {
	cmd := exec.Command("gh", "api", "repos/dart-lang/sdk/contents/"+path+"?ref="+tag)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	var payload struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return "", err
	}
	dec, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(payload.Content, "\n", ""))
	if err != nil {
		return "", err
	}
	return string(dec), nil
}
