package vmtables

import (
	"testing"

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
// Three real bugs were found the day this gate was written, all of which
// had been invisible:
//
//	stubNames3130  dropped AllocationProbePoint  -> 156 names shifted
//	stubNames2120  included the 9 TTS entries    -> 9 duplicates after composition
//	3.1.0 / 3.5.0  borrowed a neighbour's table  -> 67 / 71 names shifted
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/vmtables/ -run VMStubNamesMatchSDK
func TestVMStubNamesMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	// Every version VMStubNames claims to know. Keep in sync with the
	// switch there; a version with a table but no probe here is untested.
	tags := []string{
		"2.12.0", "2.14.0", "2.15.0", "2.16.0", "2.17.6", "2.18.0", "2.19.0", "3.0.5", "3.1.0", "3.2.5", "3.3.0",
		"3.4.3", "3.5.0", "3.6.2", "3.7.0", "3.9.2", "3.10.7",
		"3.11.0", "3.12.2", "3.13.0",
	}

	for _, tag := range tags {
		t.Run(tag, func(t *testing.T) {
			ours := VMStubNames(tag)
			if ours == nil {
				t.Fatalf("VMStubNames(%q) = nil, but the tag is listed as supported", tag)
			}
			src, err := sdktest.GHFileAtTag("runtime/vm/stub_code_list.h", tag)
			if err != nil {
				t.Skipf("cannot fetch stub_code_list.h@%s: %v", tag, err)
			}
			macros := sdktest.ParseMacros(src)
			full, err := sdktest.ExpandMacro(macros, "VM_STUB_CODE_LIST")
			if err != nil {
				t.Fatalf("expand VM_STUB_CODE_LIST@%s: %v", tag, err)
			}
			tts, err := sdktest.ExpandMacro(macros, "VM_TYPE_TESTING_STUB_CODE_LIST")
			if err != nil {
				t.Fatalf("expand VM_TYPE_TESTING_STUB_CODE_LIST@%s: %v", tag, err)
			}

			// This file's convention: the type-testing stubs are NOT in the
			// per-version tables; composeVMStubEmissionOrder inserts them
			// after the Subtype7TestCache anchor. So the expected table is
			// the full list minus those entries.
			ttsSet := make(map[string]bool, len(tts))
			for _, n := range tts {
				ttsSet[n] = true
			}
			var want []string
			for _, n := range full {
				if !ttsSet[n] {
					want = append(want, n)
				}
			}

			if len(ours) != len(want) {
				t.Errorf("VMStubNames(%q) has %d entries, SDK has %d", tag, len(ours), len(want))
			}
			for i := 0; i < len(ours) && i < len(want); i++ {
				if ours[i] != want[i] {
					t.Fatalf("VMStubNames(%q) diverges at index %d: ours=%q sdk=%q\n"+
						"every name from here on is shifted; do not 'fix' by editing one entry",
						tag, i, ours[i], want[i])
				}
			}

			// Composition must reproduce the SDK list exactly, including the
			// type-testing stubs at their real position. This is what the
			// naming code actually zips against, so it is the claim that
			// matters. It also catches a table that smuggles the TTS entries
			// in, which would double them here.
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
		"2.12.0", "2.17.6", "3.0.5", "3.1.0", "3.2.5", "3.3.0",
		"3.4.3", "3.5.0", "3.6.2", "3.7.0", "3.9.2", "3.10.7",
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
