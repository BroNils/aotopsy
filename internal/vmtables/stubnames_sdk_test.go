package vmtables

import (
	"testing"

	"aotopsy/internal/cmacro"
	"aotopsy/internal/sdktest"
)

// TestVMStubNamesMatchSDK re-derives every VM stub table from
// dart-lang/sdk's runtime/vm/stub_code_list.h at the matching tag and
// compares it element for element.
//
// This gate exists because a wrong stub table cannot be caught by any
// local test. Stub naming is a zip by INDEX: VMStubNamesInClusterOrder is
// zipped against vmResult.Codes[i], and VMStubNamesInImageOrder against
// address-sorted ranges. One missing or extra entry does not fail — it
// silently shifts every subsequent name by one, producing plausible
// output that points at the wrong stub. Exactly the failure mode
// AGENTS.md's "Two gates that must stay green" describes.
//
// Several real bugs were found by this gate, all of which
// had been invisible:
//
//	stubNames3130  dropped AllocationProbePoint  -> 156 names shifted
//	stubNames2120  included the 9 TTS entries twice -> 9 duplicate names
//	3.1.0 / 3.5.0  borrowed a neighbour's table  -> 67 / 71 names shifted
//	2.10.0         assumed the later nested-TTS shape -> no verified table
//	2.13.0         supported snapshot but no stub table -> every VM stub unnamed
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/vmtables/ -run VMStubNamesMatchSDK
func TestVMStubNamesMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	// Every version VMStubNames claims to know. Keep in sync with the
	// switch there; a version with a table but no probe here is untested.
	tags := []string{
		"2.10.0", "2.12.0", "2.13.0", "2.14.0", "2.15.0", "2.16.0", "2.17.6", "2.18.0", "2.19.0", "3.0.5", "3.1.0", "3.2.5", "3.3.0",
		"3.4.3", "3.5.0", "3.6.2", "3.7.0", "3.8.1", "3.9.2", "3.10.7",
		"3.11.0", "3.12.2", "3.13.0",
	}

	for _, tag := range tags {
		t.Run(tag, func(t *testing.T) {
			ours := VMStubNames(tag)
			if ours == nil {
				t.Fatalf("VMStubNames(%q) = nil, but the tag is listed as supported", tag)
			}
			src, err := sdktest.SDKFileAtTag("runtime/vm/stub_code_list.h", tag)
			if err != nil {
				t.Fatalf("cannot verify stub_code_list.h@%s after SDK gate was enabled: %v", tag, err)
			}
			macros := cmacro.ParseMacros(src)
			full, err := cmacro.Expand(macros, "VM_STUB_CODE_LIST")
			if err != nil {
				t.Fatalf("expand VM_STUB_CODE_LIST@%s: %v", tag, err)
			}
			if len(ours) != len(full) {
				t.Errorf("VMStubNames(%q) has %d entries, SDK exact list has %d", tag, len(ours), len(full))
			}
			for i := 0; i < len(ours) && i < len(full); i++ {
				if ours[i] != full[i] {
					t.Fatalf("VMStubNames(%q) diverges at index %d: ours=%q sdk=%q\n"+
						"every name from here on is shifted; do not 'fix' by editing one entry",
						tag, i, ours[i], full[i])
				}
			}

			// Cluster order is the exact semantic list exposed to naming code.
			composed := VMStubNamesInClusterOrder(tag)
			if len(composed) != len(full) {
				t.Errorf("composed order for %s has %d entries, SDK VM_STUB_CODE_LIST has %d",
					tag, len(composed), len(full))
			}
			for i := 0; i < len(composed) && i < len(full); i++ {
				if composed[i] != full[i] {
					t.Fatalf("composed order for %s diverges at index %d: ours=%q sdk=%q",
						tag, i, composed[i], full[i])
				}
			}
		})
	}
}

// TestVMStubNamesRefusesUnknownVersions guards the deliberate nil: an
// unverified version must NOT borrow a neighbour's list. Borrowing is
// what made 3.1.0 and 3.5.0 wrong for as long as they were supported.
func TestVMStubNamesRefusesUnknownVersions(t *testing.T) {
	for _, v := range []string{"", "2.11.0", "3.14.0", "4.0.0", "nonsense"} {
		if got := VMStubNames(v); got != nil {
			t.Errorf("VMStubNames(%q) returned %d names, want nil", v, len(got))
		}
	}
}

// TestVMStubTablesHaveNoDuplicates is a cheap local invariant that needs
// no network: a stub list is a sequence of distinct stub names, and a
// duplicate means an entry was pasted twice or a nested macro was
// expanded into a list that already contained it.
func TestVMStubTablesHaveNoDuplicates(t *testing.T) {
	tags := []string{
		"2.10.0", "2.12.0", "2.13.0", "2.17.6", "3.0.5", "3.1.0", "3.2.5", "3.3.0",
		"3.4.3", "3.5.0", "3.6.2", "3.7.0", "3.8.1", "3.9.2", "3.10.7",
		"3.11.0", "3.12.2", "3.13.0",
	}
	for _, tag := range tags {
		for _, list := range [][]string{VMStubNames(tag), VMStubNamesInClusterOrder(tag), VMStubNamesInImageOrder(tag)} {
			seen := make(map[string]int, len(list))
			for i, n := range list {
				if prev, dup := seen[n]; dup {
					t.Errorf("%s: duplicate stub name %q at indices %d and %d", tag, n, prev, i)
				}
				seen[n] = i
			}
		}
	}
}

// The stub_code_list.h macro expansion this gate needs now lives in
// internal/sdktest, shared with the other SDK drift gates.
