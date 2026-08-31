package compare

import (
	"testing"

	"aotopsy/internal/snapshot"
)

// TestDarterVersionSupportIsASetDifference pins the behaviour that was broken:
// the function compared version strings with `<` against a hardcoded minimum
// and ignored its argument, so it answered "2.0.0, 2.1.0" and stopped -- every
// version from 2.2.0 to 2.9.0 sorts AFTER "2.10.0" lexicographically.
func TestDarterVersionSupportIsASetDifference(t *testing.T) {
	// Nothing supported: every version darter covers is darter-only.
	all := DarterVersionSupport(nil)
	if len(all) != len(darterVersions) {
		t.Fatalf("with an empty supported set, got %d versions, want all %d: %v",
			len(all), len(darterVersions), all)
	}
	// The regression: 2.2.0-2.9.0 must be present. A string comparison against
	// "2.10.0" drops exactly these eight.
	for _, v := range []string{"2.2.0", "2.3.0", "2.4.0", "2.5.0", "2.6.0", "2.7.0", "2.8.0", "2.9.0"} {
		found := false
		for _, g := range all {
			if g == v {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s missing -- it sorts after \"2.10.0\" as a string, which is "+
				"how the old implementation lost it", v)
		}
	}

	// Overlap is subtracted, and the argument is actually read.
	got := DarterVersionSupport([]string{"2.0.0", "2.5.0", "3.13.0"})
	for _, v := range got {
		if v == "2.0.0" || v == "2.5.0" {
			t.Errorf("%s is supported natively and must not be reported as darter-only", v)
		}
	}
	if len(got) != len(darterVersions)-2 {
		t.Errorf("got %d darter-only versions, want %d", len(got), len(darterVersions)-2)
	}
}

// The real caller passes snapshot.SupportedVersions(), so the two sides have
// to agree on how a version is spelled. If they ever drift, this function
// silently reports coverage gaps that do not exist.
func TestDarterVersionSupportAgainstRealSupportedSet(t *testing.T) {
	supported := snapshot.SupportedVersions()
	if len(supported) == 0 {
		t.Fatal("snapshot.SupportedVersions() is empty")
	}
	// Sorted ascending, numerically -- not as strings.
	for i := 1; i < len(supported); i++ {
		if !versionLess(supported[i-1], supported[i]) {
			t.Errorf("SupportedVersions is not sorted ascending: %q before %q",
				supported[i-1], supported[i])
		}
	}
	// aotopsy starts at 2.10.0, so darter's whole 2.0-2.9 range stays gap.
	if got := DarterVersionSupport(supported); len(got) != len(darterVersions) {
		t.Errorf("got %d darter-only versions, want all %d -- aotopsy supports "+
			"none of Dart 2.0-2.9: %v", len(got), len(darterVersions), got)
	}
}

func versionLess(a, b string) bool {
	pa, pb := triple(a), triple(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func triple(s string) [3]int {
	var v [3]int
	part, idx := 0, 0
	for i := 0; i < len(s) && idx < 3; i++ {
		if s[i] == '.' {
			v[idx] = part
			part, idx = 0, idx+1
			continue
		}
		if s[i] >= '0' && s[i] <= '9' {
			part = part*10 + int(s[i]-'0')
		}
	}
	if idx < 3 {
		v[idx] = part
	}
	return v
}
