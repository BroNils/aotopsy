package vmtables

import (
	"strings"
	"testing"

	"aotopsy/internal/cmacro"
	"aotopsy/internal/sdktest"
)

// SDK drift gate for the runtime-entry name tables.
//
// mergeRuntimeEntries lays these out by index -- offset = base + i*8 --
// so the list is a positional mirror of Thread's RUNTIME_ENTRY_LIST /
// LEAF_RUNTIME_ENTRY_LIST blocks. One inserted or missing name shifts
// every later entry by 8 bytes and renames every runtime call after it,
// silently and plausibly. It is the stubNames failure mode with a
// different table.
//
// The concrete trap this guards: 3.13.0 inserts TypeError partway down
// RUNTIME_ENTRY_LIST rather than appending it, so reusing 3.12.2's list
// for 3.13.0 would misname everything past that point.
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/vmtables/ -run RuntimeEntriesMatchSDK

// runtimeEntryTables maps each SDK tag to the committed tables for it.
//
// Before 3.10.7 the two SDK blocks were flattened into one committed
// list; from 3.10.7 they are separate, because the LEAF block moved away
// from the main one in Thread and needs its own base offset. leaf == nil
// means "flattened", and the gate then compares against runtime ++ leaf.
var runtimeEntryTables = []struct {
	tag     string
	runtime []string
	leaf    []string
}{
	{"2.10.0", runtimeEntriesV2100, nil},
	{"2.12.0", runtimeEntriesV2120, nil},
	{"2.13.0", runtimeEntriesV2130, nil},
	{"2.14.0", runtimeEntriesV2140, nil},
	{"2.15.0", runtimeEntriesV2150, nil},
	{"2.16.0", runtimeEntriesV2160, nil},
	{"2.17.6", runtimeEntriesV217, nil},
	{"2.18.0", runtimeEntriesV2180, nil},
	{"2.19.0", runtimeEntriesV2190, nil},
	{"3.1.0", runtimeEntriesV310, nil},
	{"3.2.5", runtimeEntriesV325, nil},
	{"3.4.3", runtimeEntriesV343, nil},
	{"3.6.2", runtimeEntriesV362, nil},
	{"3.8.1", runtimeEntriesV381, nil},
	{"3.9.2", runtimeEntriesV392, nil},
	{"3.10.7", runtimeEntriesV3107, leafEntriesV3107},
	{"3.11.0", runtimeEntriesV3115, leafEntriesV3115},
	{"3.12.2", runtimeEntriesV3122, leafEntriesV3122},
	{"3.13.0", runtimeEntriesV3130, leafEntriesV3130},
}

func sdkRuntimeEntries(tag string) (runtime, leaf []string, err error) {
	src, err := sdktest.GHFileAtTag("runtime/vm/runtime_entry_list.h", tag)
	if err != nil {
		return nil, nil, err
	}
	macros := cmacro.ParseMacros(src)
	runtime, err = cmacro.Expand(macros, "RUNTIME_ENTRY_LIST")
	if err != nil {
		return nil, nil, err
	}
	// LEAF entries carry the return type first:
	//   V(intptr_t, DeoptimizeCopyFrame, uword, uword)
	// so the name is column 1, not column 0. Reading column 0 yields a list
	// of C types, which compares as "everything diverges at index 0" -- an
	// error that looks like catastrophic drift and is really a parse bug.
	leaf, err = cmacro.Column(macros, "LEAF_RUNTIME_ENTRY_LIST", 1)
	if err != nil {
		return nil, nil, err
	}
	return runtime, leaf, nil
}

func TestRuntimeEntriesMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	for _, rt := range runtimeEntryTables {
		t.Run(rt.tag, func(t *testing.T) {
			runtime, leaf, err := sdkRuntimeEntries(rt.tag)
			if err != nil {
				t.Fatalf("read runtime_entry_list.h@%s: %v", rt.tag, err)
			}
			if rt.leaf == nil {
				want := append(append([]string{}, runtime...), leaf...)
				compareEntryList(t, rt.tag, "runtime+leaf", rt.runtime, want)
				t.Logf("%s: %d entries (%d runtime + %d leaf, flattened)",
					rt.tag, len(rt.runtime), len(runtime), len(leaf))
				return
			}
			compareEntryList(t, rt.tag, "RUNTIME_ENTRY_LIST", rt.runtime, runtime)
			compareEntryList(t, rt.tag, "LEAF_RUNTIME_ENTRY_LIST", rt.leaf, leaf)
			t.Logf("%s: %d runtime + %d leaf entries", rt.tag, len(runtime), len(leaf))
		})
	}
}

func compareEntryList(t *testing.T, tag, which string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s %s: committed has %d entries, SDK has %d", tag, which, len(got), len(want))
	}
	for i := 0; i < len(got) && i < len(want); i++ {
		if got[i] != want[i] {
			t.Fatalf("%s %s: diverges at index %d: committed=%q sdk=%q\n"+
				"  Every entry from here on is 8 bytes off. Do not 'fix' one name --\n"+
				"  the list is positional and the whole tail has moved.",
				tag, which, i, got[i], want[i])
		}
	}
}

// TestRuntimeEntriesCoverSupportedVersions is the check that catches an
// absent table rather than a wrong one. A version whose THR map carries
// no *_entry_point names got no mergeRuntimeEntries call, and every
// runtime call in it renders as an unnamed THR.fNN.
func TestRuntimeEntriesCoverSupportedVersions(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	// Every version THRFieldsWithProfile answers for. Keep in sync with
	// that switch.
	supported := []string{
		"2.10.0", "2.12.0", "2.13.0", "2.14.0", "2.15.0", "2.16.0",
		"2.17.6", "2.18.0", "2.19.0",
		"3.0.5", "3.1.0", "3.2.5", "3.3.0", "3.4.3", "3.5.0",
		"3.6.2", "3.7.0", "3.8.1", "3.9.2",
		"3.10.7", "3.11.0", "3.12.2", "3.13.0",
	}
	for _, v := range supported {
		t.Run(v, func(t *testing.T) {
			fields := THRFields(v, true)
			if fields == nil {
				t.Fatalf("THRFields(%q, arm64) = nil but the version is listed as supported", v)
			}
			runtime, leaf, err := sdkRuntimeEntries(v)
			if err != nil {
				t.Skipf("read runtime_entry_list.h@%s: %v", v, err)
			}
			// The extracted header already names ~31 cached stub entry
			// points, so "has any _entry_point" is satisfied without
			// mergeRuntimeEntries ever running. Counting against the SDK
			// list length is what distinguishes a merged table from a bare
			// one -- 3.13.0 had 31 where it should have had 162.
			n := 0
			for _, name := range fields {
				if strings.HasSuffix(name, "_entry_point") {
					n++
				}
			}
			if want := len(runtime) + len(leaf); n < want {
				t.Errorf("%s: THR map has %d *_entry_point names, SDK lists %d runtime + %d leaf entries.\n"+
					"  mergeRuntimeEntries was never called for this version, so every runtime\n"+
					"  call in it renders as an unnamed THR.fNN.", v, n, len(runtime), len(leaf))
			}
		})
	}
}
