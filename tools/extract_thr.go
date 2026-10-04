// extract_thr.go: Extracts Thread field offset tables from dart-lang/sdk's
// runtime_offsets_extracted.h for all supported Dart versions and architectures.
//
// Usage:
//
//	go run tools/extract_thr.go -tag 3.9.2 -arch x64 -compressed
//	go run tools/extract_thr.go -tag 2.12.0 -arch arm64 -nocompressed
//	go run tools/extract_thr.go -all    # extract all known versions
//	go run tools/extract_thr.go -check  # verify the committed tables
//
// Outputs Go map literals suitable for pasting into thrfields.go.
//
// -check re-extracts every target and compares it against the tables
// committed in internal/vmtables/thrfields*.go, exiting non-zero on any
// unexplained difference. Without it, a new Dart SDK version silently
// shifts Thread offsets and every THR annotation the tool prints becomes
// wrong with no signal at all -- these tables cannot be validated by any
// amount of local testing, only against the SDK that produced them.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"aotopsy/internal/cmacro"
	"aotopsy/internal/sdktest"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/vmtables"
)

type extractTarget struct {
	tag        string
	arch       string // "arm64" or "x64"
	compressed bool
	product    bool // true = PRODUCT, false = non-PRODUCT (Debug/Profile)
}

func vmTargetProfile(t extractTarget) vmtables.TargetProfile {
	arch := vmtables.ArchitectureX64
	if t.arch == "arm64" {
		arch = vmtables.ArchitectureARM64
	}
	mode := snapshot.BuildRelease
	if t.product {
		mode = snapshot.BuildProduct
	}
	return vmtables.TargetProfile{
		DartVersion:        t.tag,
		Architecture:       arch,
		CompressedPointers: t.compressed,
		BuildMode:          mode,
	}
}

// All supported versions and their THR table configurations.
// Each target is a (version, arch, compressed, product) tuple.
// PRODUCT+compressed is the default for release APKs.
// non-PRODUCT and non-compressed variants are needed for debug/profile
// builds and pre-2.18 (non-compressed) builds.
var allTargets = []extractTarget{
	// ARM64 + compressed + PRODUCT (v2.18+)
	{"2.18.0", "arm64", true, true},
	{"2.19.0", "arm64", true, true},
	{"3.0.5", "arm64", true, true},
	{"3.1.0", "arm64", true, true},
	{"3.2.5", "arm64", true, true},
	{"3.3.0", "arm64", true, true},
	{"3.4.3", "arm64", true, true},
	{"3.5.0", "arm64", true, true},
	{"3.6.2", "arm64", true, true},
	{"3.7.0", "arm64", true, true},
	{"3.8.1", "arm64", true, true},
	{"3.9.2", "arm64", true, true},
	{"3.10.7", "arm64", true, true},
	{"3.11.0", "arm64", true, true},
	{"3.12.2", "arm64", true, true},
	{"3.13.0", "arm64", true, true},
	// ARM64 + non-compressed + PRODUCT (v2.x)
	{"2.10.0", "arm64", false, true},
	// 3.x desktop AOT (uncompressed) -- same reason as the x64 entry below.
	{"3.9.2", "arm64", false, true},
	{"2.12.0", "arm64", false, true},
	{"2.13.0", "arm64", false, true},
	{"2.14.0", "arm64", false, true},
	{"2.15.0", "arm64", false, true},
	{"2.16.0", "arm64", false, true},
	{"2.17.6", "arm64", false, true},
	// x86_64 + compressed + PRODUCT (v2.18+)
	{"2.14.0", "x64", true, true},
	{"2.15.0", "x64", true, true},
	{"2.16.0", "x64", true, true},
	{"2.17.6", "x64", true, true},
	{"2.18.0", "x64", true, true},
	{"2.19.0", "x64", true, true},
	{"3.0.5", "x64", true, true},
	{"3.1.0", "x64", true, true},
	{"3.2.5", "x64", true, true},
	{"3.3.0", "x64", true, true},
	{"3.4.3", "x64", true, true},
	{"3.5.0", "x64", true, true},
	{"3.6.2", "x64", true, true},
	{"3.7.0", "x64", true, true},
	{"3.8.1", "x64", true, true},
	{"3.9.2", "x64", true, true},
	{"3.10.7", "x64", true, true},
	{"3.11.0", "x64", true, true},
	{"3.12.2", "x64", true, true},
	{"3.13.0", "x64", true, true},
	// x86_64 + non-compressed + PRODUCT (v2.x)
	{"2.10.0", "x64", false, true},
	{"2.12.0", "x64", false, true},
	{"2.13.0", "x64", false, true},
	{"2.14.0", "x64", false, true},
	{"2.15.0", "x64", false, true},
	{"2.16.0", "x64", false, true},
	{"2.17.6", "x64", false, true},
	// x86_64 + non-compressed + PRODUCT (3.x desktop AOT). Compressed
	// pointers are the Android/iOS default, but a desktop `dart compile exe`
	// / Flutter desktop build is 64-bit uncompressed, and thrfieldsx86.go
	// carries a table for it -- so it must be regenerable and checkable
	// like every other one.
	{"3.9.2", "x64", false, true},
	{"3.12.2", "x64", false, true},
	// ARM64 + compressed + non-PRODUCT (v2.18+)
	{"2.18.0", "arm64", true, false},
	{"2.19.0", "arm64", true, false},
	{"3.0.5", "arm64", true, false},
	{"3.1.0", "arm64", true, false},
	{"3.2.5", "arm64", true, false},
	{"3.3.0", "arm64", true, false},
	{"3.4.3", "arm64", true, false},
	{"3.5.0", "arm64", true, false},
	{"3.6.2", "arm64", true, false},
	{"3.7.0", "arm64", true, false},
	{"3.8.1", "arm64", true, false},
	{"3.9.2", "arm64", true, false},
	{"3.10.7", "arm64", true, false},
	{"3.11.0", "arm64", true, false},
	{"3.12.2", "arm64", true, false},
	// ARM64 + non-compressed + non-PRODUCT (v2.x)
	{"2.12.0", "arm64", false, false},
	{"2.13.0", "arm64", false, false},
	{"2.14.0", "arm64", false, false},
	{"2.15.0", "arm64", false, false},
	{"2.16.0", "arm64", false, false},
	{"2.17.6", "arm64", false, false},
	// x86_64 + compressed + non-PRODUCT (v2.18+)
	{"2.18.0", "x64", true, false},
	{"2.19.0", "x64", true, false},
	{"3.0.5", "x64", true, false},
	{"3.1.0", "x64", true, false},
	{"3.2.5", "x64", true, false},
	{"3.3.0", "x64", true, false},
	{"3.4.3", "x64", true, false},
	{"3.5.0", "x64", true, false},
	{"3.6.2", "x64", true, false},
	{"3.7.0", "x64", true, false},
	{"3.8.1", "x64", true, false},
	{"3.9.2", "x64", true, false},
	{"3.10.7", "x64", true, false},
	{"3.11.0", "x64", true, false},
	{"3.12.2", "x64", true, false},
	// x86_64 + non-compressed + non-PRODUCT (v2.x)
	{"2.12.0", "x64", false, false},
	{"2.13.0", "x64", false, false},
	{"2.14.0", "x64", false, false},
	{"2.15.0", "x64", false, false},
	{"2.16.0", "x64", false, false},
	{"2.17.6", "x64", false, false},
}

// parseOffset parses a C integer literal (hex "0xNNN" or decimal "NNN").
func parseOffset(s string) int {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		var v int
		fmt.Sscanf(s, "0x%x", &v)
		return v
	}
	var v int
	fmt.Sscanf(s, "%d", &v)
	return v
}

func fetchHeader(tag string) (string, error) {
	return fetchSDKFile("runtime/vm/compiler/runtime_offsets_extracted.h", tag)
}

// fetchSDKFile resolves an exact-tag dart-lang/sdk source file through the
// shared drift-gate loader. Keeping extraction and tests on one loader is
// correctness-critical: otherwise one path can prefer a stale cache while the
// other is validating against an exact local checkout.
func fetchSDKFile(path, tag string) (string, error) {
	return sdktest.SDKFileAtTag(path, tag)
}

// parseVMStubCodeList parses the SDK's exact VM_STUB_CODE_LIST expansion
// through the shared cmacro engine. This deliberately returns the final
// emission order, not an implementation-detail split between the main list
// and VM_TYPE_TESTING_STUB_CODE_LIST. Dart 2.10 inlines the type-testing
// stubs, while later SDKs expand a nested macro at the same semantic point.
func parseVMStubCodeList(header string) ([]string, error) {
	macros, err := cmacro.ParseMacros(header)
	if err != nil {
		return nil, err
	}
	return cmacro.Expand(macros, "VM_STUB_CODE_LIST")
}

// runCheckStubs verifies stubnames.go against SDK's stub_code_list.h
// for every supported version. Returns count of mismatches.
func runCheckStubs() int {
	mismatches, verified := 0, 0
	for _, tag := range snapshot.SupportedVersions() {
		header, err := fetchSDKFile("runtime/vm/stub_code_list.h", tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			mismatches++
			continue
		}
		vmStubs, err := parseVMStubCodeList(header)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  MISMATCH %s: parse stub list: %v\n", tag, err)
			mismatches++
			continue
		}
		committed := vmtables.VMStubNames(tag)
		if committed == nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: no committed table\n", tag)
			mismatches++
			continue
		}
		if len(vmStubs) != len(committed) {
			fmt.Fprintf(os.Stderr, "  MISMATCH %s: SDK has %d stubs, committed exact order has %d\n",
				tag, len(vmStubs), len(committed))
			mismatches++
		}
		for i := 0; i < len(vmStubs) && i < len(committed); i++ {
			if vmStubs[i] != committed[i] {
				fmt.Fprintf(os.Stderr, "  MISMATCH %s: index %d SDK=%q committed=%q\n",
					tag, i, vmStubs[i], committed[i])
				mismatches++
				break
			}
		}
		fmt.Fprintf(os.Stderr, "  OK %s: %d exact-order VM stubs\n", tag, len(vmStubs))
		verified++
	}
	if verified == 0 {
		fmt.Fprintln(os.Stderr, "ERROR: stub-name drift gate verified zero SDK versions")
		mismatches++
	}
	if mismatches > 0 {
		fmt.Fprintf(os.Stderr, "\n%d stub mismatch(es) found\n", mismatches)
	} else {
		fmt.Fprintf(os.Stderr, "\nAll stub names match SDK\n")
	}
	return mismatches
}

// runCheckRuntimeEntries verifies that every runtime entry the SDK
// declares at a tag is actually reachable as a THR field annotation for
// that tag, on both architectures.
//
// This used to print counts and return 0 unconditionally, carrying the
// comment "we don't have committed runtime entry tables yet". That
// stopped being true once extract_thr started generating them, but the
// check kept passing either way -- which is the worse failure mode: a
// gate that cannot go red reads exactly like a gate that is green. Its
// counts were still correct, so nothing looked wrong.
//
// The comparison is one-directional by construction. mergeRuntimeEntries
// fills gaps only, so an SDK entry with no committed name is a real hole
// (the call renders as an unnamed THR.fNN), whereas a committed name with
// no SDK entry cannot arise here -- the tables are generated from these
// same headers, and any disagreement about *which* name sits at an offset
// is caught by runtimeEntryConflicts instead.
func runCheckRuntimeEntries() int {
	mismatches, verified := 0, 0
	for _, t := range allTargets {
		fields := vmtables.THRFields(vmTargetProfile(t))
		if len(fields) == 0 {
			continue
		}
		// Deliberately the same derivation -write uses. The gate's
		// first draft called a second, older parser that took the LAST
		// macro argument -- right for roots.h, wrong for
		// LEAF_RUNTIME_ENTRY_LIST, whose shape is V(ret, Name, args...).
		// It reported the SDK as declaring leaf entries named "uword"
		// and "thread". The committed tables were fine; the checker was
		// the broken half. That parser is now gone.
		entries, leafEntries, _, err := sdkRuntimeEntriesFor(t.tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s/%s compressed=%v: %v\n", t.tag, t.arch, t.compressed, err)
			mismatches++
			continue
		}
		named := map[string]bool{}
		for _, n := range fields {
			named[n] = true
		}

		local := 0
		for _, kind := range []struct {
			label string
			names []string
		}{{"runtime", entries}, {"leaf", leafEntries}} {
			for _, n := range kind.names {
				// mergeRuntimeEntries stores the SDK name with an
				// _entry_point suffix: the THR slot holds the entry
				// point, not the RuntimeEntry object.
				if !named[n+"_entry_point"] {
					fmt.Fprintf(os.Stderr, "  MISSING %s/%s: %s entry %q is in the SDK but is not named in the committed THR table\n",
						t.tag, t.arch, kind.label, n)
					local++
				}
			}
		}
		if local == 0 {
			fmt.Fprintf(os.Stderr, "  OK %s/%s compressed=%v: %d runtime + %d leaf entries all named\n",
				t.tag, t.arch, t.compressed, len(entries), len(leafEntries))
		}
		mismatches += local
		verified++
	}
	if verified == 0 {
		fmt.Fprintln(os.Stderr, "ERROR: runtime-entry drift gate verified zero target profiles")
		mismatches++
	}
	if mismatches > 0 {
		fmt.Fprintf(os.Stderr, "\n%d runtime-entry naming gap(s) found\n", mismatches)
	} else {
		fmt.Fprintf(os.Stderr, "\nAll SDK runtime entries are named in the committed tables\n")
	}
	return mismatches
}

// sdkStubStructor matches the class that produces a cached stub entry
// point. CACHED_ADDRESSES_LIST holds three flavours and a tail of
// non-stub constants (predefined_symbols, double_nan, the float masks);
// only the three below are Thread-cached stub entry points.
var reStubCtor = regexp.MustCompile(`\b(?:StubCode|NativeEntry|RuntimeEntry)::(\w+?)(?:Entry)?\(\)`)

// sdkThreadStubNames derives the offset-field -> stub-name mapping from
// thread.h's own macro list at a tag.
//
// Both halves come from the SDK: the field name is argument 1 of the
// CACHED_ADDRESSES_LIST entry, and the stub name is the StubCode:: /
// NativeEntry:: / RuntimeEntry:: constructor in its initialiser. Nothing
// is hand-mapped, so a stub renamed or added upstream shows up here
// instead of being quietly absent from the committed table -- which is
// exactly how MegamorphicCall, SwitchableCallMiss, OptimizeFunction and
// Deoptimize went missing from five tables at once.
func sdkThreadStubNames(tag string) (map[string]string, error) {
	src, err := fetchSDKFile("runtime/vm/thread.h", tag)
	if err != nil {
		return nil, err
	}
	macros, err := cmacro.ParseMacros(src)
	if err != nil {
		return nil, err
	}
	rows, err := cmacro.ExpandRaw(macros, "CACHED_ADDRESSES_LIST")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for i, r := range rows {
		if len(r) != 4 {
			return nil, fmt.Errorf("CACHED_ADDRESSES_LIST row %d has %d columns, want 4", i, len(r))
		}
		m := reStubCtor.FindStringSubmatch(r[2])
		if m == nil {
			continue // predefined_symbols_, double_nan_, float masks: not stubs
		}
		out[strings.TrimSuffix(r[1], "_")] = m[1]
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no cached stub entries found in thread.h@%s", tag)
	}
	return out, nil
}

// runCheckStubOffsets verifies internal/vmtables' ThreadStubOffsets
// tables against the SDK, for every (version, arch) pair those tables
// claim to support.
//
// This gate did not exist, and its absence is why five tables shipped
// missing four entries each: a missing offset is not a wrong annotation,
// it is a silently absent one. The call still resolves, it just prints
// "THR.f248" instead of "THR.MegamorphicCall", so nothing downstream can
// tell the table is short.
func runCheckStubOffsets() int {
	mismatches, verified := 0, 0
	for _, t := range supportedProductTHRTargets() {
		committed := vmtables.ThreadStubOffsets(vmTargetProfile(t))
		if committed == nil {
			// The target list follows the committed THR tables. A nil result here
			// means the selection contract and the gate disagree -- never skip it.
			fmt.Fprintf(os.Stderr, "  ERROR %s/%s compressed=%v: THR target exists but ThreadStubOffsets is nil\n", t.tag, t.arch, t.compressed)
			mismatches++
			continue
		}
		fieldToStub, err := sdkThreadStubNames(t.tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s/%s compressed=%v: %v\n", t.tag, t.arch, t.compressed, err)
			mismatches++
			continue
		}
		header, err := fetchHeader(t.tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s/%s compressed=%v: %v\n", t.tag, t.arch, t.compressed, err)
			mismatches++
			continue
		}
		fields, err := extractTHRFields(header, t.arch, t.compressed, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s/%s compressed=%v: %v\n", t.tag, t.arch, t.compressed, err)
			mismatches++
			continue
		}

		want := map[int64]string{}
		for _, f := range fields {
			name := strings.TrimSuffix(f.name, "_offset")
			if stub, ok := fieldToStub[name]; ok {
				want[int64(f.offset)] = stub
			}
		}
		if len(want) == 0 {
			fmt.Fprintf(os.Stderr, "  ERROR %s/%s: no stub offsets in the %s/compressed=%v PRODUCT block\n",
				t.tag, t.arch, t.arch, t.compressed)
			mismatches++
			continue
		}

		local := 0
		for off, stub := range want {
			got, present := committed[off]
			switch {
			case !present:
				fmt.Fprintf(os.Stderr, "  MISSING %s/%s: 0x%x %s is in the SDK but not in the committed table\n",
					t.tag, t.arch, off, stub)
				local++
			case got != stub:
				fmt.Fprintf(os.Stderr, "  MISMATCH %s/%s: 0x%x committed=%q sdk=%q\n",
					t.tag, t.arch, off, got, stub)
				local++
			}
		}
		for off, stub := range committed {
			if _, present := want[off]; !present {
				fmt.Fprintf(os.Stderr, "  EXTRA %s/%s: 0x%x %s is in the committed table but not in the SDK\n",
					t.tag, t.arch, off, stub)
				local++
			}
		}
		if local == 0 {
			fmt.Fprintf(os.Stderr, "  OK %s/%s compressed=%v: %d stub offsets\n", t.tag, t.arch, t.compressed, len(want))
		}
		mismatches += local
		verified++
	}
	if verified == 0 {
		fmt.Fprintln(os.Stderr, "ERROR: thread-stub drift gate verified zero target profiles")
		mismatches++
	}
	if mismatches > 0 {
		fmt.Fprintf(os.Stderr, "\n%d thread-stub offset mismatch(es) found\n", mismatches)
	} else {
		fmt.Fprintf(os.Stderr, "\nAll thread-stub offsets match SDK; %d target profile(s) verified\n", verified)
	}
	return mismatches
}

// supportedProductTHRTargets is the single source of truth for stub-offset
// verification. ThreadStubOffsets is derived from THRFields, so maintaining a
// second hand-written target list can only make the verifier weaker.
func supportedProductTHRTargets() []extractTarget {
	out := make([]extractTarget, 0, len(allTargets))
	seen := map[string]bool{}
	for _, t := range allTargets {
		if !t.product {
			continue
		}
		profile := vmTargetProfile(t)
		if vmtables.THRFields(profile) == nil {
			continue
		}
		key := fmt.Sprintf("%s/%s/%t", t.tag, t.arch, t.compressed)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}

// runEmitStubNames prints Go source for the exact VM_STUB_CODE_LIST expansion
// of the given tags. Keeping the final emission order as the generated
// contract handles both historical shapes: Dart 2.10 inlines type-testing
// stubs, while later SDKs reference VM_TYPE_TESTING_STUB_CODE_LIST.
//
// This list is zipped by index against the VM snapshot's Code objects,
// so one missing or extra name shifts every later stub. It is generated
// rather than transcribed for that reason.
func runEmitStubNames(tags []string) int {
	failures := 0
	for _, tag := range tags {
		src, err := fetchSDKFile("runtime/vm/stub_code_list.h", tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			failures++
			continue
		}
		full, err := parseVMStubCodeList(src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			failures++
			continue
		}
		id := strings.ReplaceAll(tag, ".", "")
		fmt.Printf("\n// Dart %s -- exact VM_STUB_CODE_LIST@%s expansion, %d entries.\n", tag, tag, len(full))
		fmt.Printf("var stubNames%s = []string{\n", id)
		printGoStrings(full)
		fmt.Printf("}\n")
		fmt.Printf("// switch: case %q: return stubNames%s\n", tag, id)
	}
	return failures
}

// runEmitStubOffsets prints Go source for the Thread-cached stub offset
// tables of the given tags.
//
// Both halves are SDK-derived: the field name and the stub name come from
// thread.h's CACHED_ADDRESSES_LIST entries, the offset from
// runtime_offsets_extracted.h. Emitting one table per (tag, arch) and
// comparing the two lets the caller see whether the arches agree, which
// is the usual case but not one to assume.
func runEmitStubOffsets(tags []string) int {
	failures := 0
	for _, tag := range tags {
		fieldToStub, err := sdkThreadStubNames(tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			failures++
			continue
		}
		header, err := fetchHeader(tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			failures++
			continue
		}
		target, ok := arm64ProductTarget(tag)
		if !ok {
			fmt.Fprintf(os.Stderr, "  ERROR %s: no arm64 PRODUCT target\n", tag)
			failures++
			continue
		}

		perArch := map[string]map[int]string{}
		for _, arch := range []string{"arm64", "x64"} {
			fields, err := extractTHRFields(header, arch, target.compressed, true)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ERROR %s/%s: %v\n", tag, arch, err)
				failures++
				continue
			}
			m := map[int]string{}
			for _, f := range fields {
				if stub, ok := fieldToStub[strings.TrimSuffix(f.name, "_offset")]; ok {
					m[f.offset] = stub
				}
			}
			perArch[arch] = m
		}
		arm, x64 := perArch["arm64"], perArch["x64"]
		if len(arm) == 0 {
			fmt.Fprintf(os.Stderr, "  ERROR %s: no stub offsets in the arm64 PRODUCT block\n", tag)
			failures++
			continue
		}
		if len(x64) == 0 {
			fmt.Fprintf(os.Stderr, "  ERROR %s: no stub offsets in the x64 PRODUCT block\n", tag)
			failures++
			continue
		}
		same := len(arm) == len(x64)
		for off, name := range arm {
			if x64[off] != name {
				same = false
				break
			}
		}

		id := strings.ReplaceAll(tag, ".", "")
		fmt.Printf("\n// Dart %s -- PRODUCT + %s pointers. Names and offsets both from\n",
			tag, map[bool]string{true: "compressed", false: "non-compressed"}[target.compressed])
		fmt.Printf("// thread.h@%s + runtime_offsets_extracted.h@%s.\n", tag, tag)
		if same {
			fmt.Printf("// x86_64 offsets are identical.\n")
		} else {
			fmt.Printf("// NOTE: x86_64 offsets DIFFER; emit and keep a separate table.\n")
		}
		fmt.Printf("threadStubOffsets%s = map[int64]string{\n", id)
		offs := make([]int, 0, len(arm))
		for off := range arm {
			offs = append(offs, off)
		}
		sort.Ints(offs)
		for _, off := range offs {
			fmt.Printf("\t%#x: %q,\n", off, arm[off])
		}
		fmt.Printf("}\n")
		fmt.Printf("// switch: case %q: return threadStubOffsets%s\n", tag, id)
	}
	return failures
}

// runEmitRuntimeEntries prints Go source for the runtime-entry name
// tables of the given tags, plus the mergeRuntimeEntries calls that
// install them.
//
// Both block bases come from the SDK rather than from arithmetic on a
// neighbouring version: Thread_AllocateArray_entry_point_offset is the
// first RUNTIME_ENTRY_LIST slot and Thread_DeoptimizeCopyFrame_entry_point_offset
// the first LEAF one. Whether the two blocks are contiguous changed
// between versions, so it is derived per tag rather than assumed -- 3.12.2
// has a 49-slot gap between them that a "leaf follows runtime" assumption
// would silently write over.
func runEmitRuntimeEntries(tags []string) int {
	failures := 0
	for _, tag := range tags {
		target, ok := arm64ProductTarget(tag)
		if !ok {
			fmt.Fprintf(os.Stderr, "  ERROR %s: no arm64 PRODUCT target\n", tag)
			failures++
			continue
		}
		relSrc, err := fetchSDKFile("runtime/vm/runtime_entry_list.h", tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			failures++
			continue
		}
		macros, err := cmacro.ParseMacros(relSrc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			failures++
			continue
		}
		runtime, err := cmacro.Expand(macros, "RUNTIME_ENTRY_LIST")
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			failures++
			continue
		}
		// LEAF entries put the return type first: V(intptr_t, Name, ...).
		leaf, err := cmacro.Column(macros, "LEAF_RUNTIME_ENTRY_LIST", 1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			failures++
			continue
		}

		header, err := fetchHeader(tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			failures++
			continue
		}
		fields, err := extractTHRFields(header, target.arch, target.compressed, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			failures++
			continue
		}
		offsetOf := func(name string) (int, bool) {
			for _, f := range fields {
				if f.name == name {
					return f.offset, true
				}
			}
			return 0, false
		}
		// extractTHRFields stores the inner name only: the Thread_ prefix
		// and the _offset suffix are both stripped by reSingle.
		rtBase, ok1 := offsetOf("AllocateArray_entry_point")
		leafBase, ok2 := offsetOf("DeoptimizeCopyFrame_entry_point")
		if !ok1 {
			fmt.Fprintf(os.Stderr, "  ERROR %s: AllocateArray entry point not in the extracted header\n", tag)
			failures++
			continue
		}

		id := strings.ReplaceAll(tag, ".", "")

		// Whether the LEAF block follows the runtime block is a property of
		// the Thread struct, not of the offsets header. Up to 2.19 the two
		// DECLARE_MEMBERS expansions are adjacent; by 3.12.2 the LEAF one
		// has moved down past exit_through_ffi_, leaving a gap that a
		// "leaf follows runtime" assumption writes straight over.
		//
		// The offsets header only exports DeoptimizeCopyFrame for the newer
		// tags, so adjacency is read from thread.h and the exported offset,
		// where present, is used as a cross-check.
		contiguous, err := leafFollowsRuntime(tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			failures++
			continue
		}
		switch {
		case contiguous && ok2 && leafBase != rtBase+len(runtime)*8:
			fmt.Fprintf(os.Stderr, "  ERROR %s: thread.h says the blocks are adjacent but the header puts\n"+
				"    DeoptimizeCopyFrame at %#x, not %#x -- resolve before emitting\n",
				tag, leafBase, rtBase+len(runtime)*8)
			failures++
			continue
		case !contiguous && !ok2:
			fmt.Fprintf(os.Stderr, "  ERROR %s: LEAF block is not adjacent to the runtime block and the\n"+
				"    header does not export DeoptimizeCopyFrame_entry_point_offset.\n"+
				"    The leaf base cannot be derived; guessing it would misname the whole block.\n", tag)
			failures++
			continue
		}
		fmt.Printf("\n// Dart %s. Derived from runtime_entry_list.h@%s;\n", tag, tag)
		fmt.Printf("// base offsets from runtime_offsets_extracted.h@%s\n", tag)
		fmt.Printf("// (AllocateArray = %#x", rtBase)
		if ok2 {
			fmt.Printf(", DeoptimizeCopyFrame = %#x", leafBase)
		}
		fmt.Printf(").\n")
		if contiguous {
			fmt.Printf("// The LEAF block follows the runtime block with no gap, so the two\n")
			fmt.Printf("// are stored flattened, matching the pre-3.10.7 convention.\n")
			fmt.Printf("var runtimeEntriesV%s = []string{\n", id)
			printGoStrings(append(append([]string{}, runtime...), leaf...))
			fmt.Printf("}\n")
			fmt.Printf("// merge: mergeRuntimeEntries(thrV%s, %#x, runtimeEntriesV%s)\n", id, rtBase, id)
			continue
		}
		fmt.Printf("var runtimeEntriesV%s = []string{\n", id)
		printGoStrings(runtime)
		fmt.Printf("}\n\n")
		fmt.Printf("var leafEntriesV%s = []string{\n", id)
		printGoStrings(leaf)
		fmt.Printf("}\n")
		fmt.Printf("// merge: mergeRuntimeEntries(thrV%s, %#x, runtimeEntriesV%s)\n", id, rtBase, id)
		if ok2 {
			fmt.Printf("// merge: mergeRuntimeEntries(thrV%s, %#x, leafEntriesV%s)\n", id, leafBase, id)
		}
	}
	return failures
}

func printGoStrings(names []string) {
	const perLine = 3
	for i := 0; i < len(names); i += perLine {
		fmt.Printf("\t")
		for j := i; j < i+perLine && j < len(names); j++ {
			fmt.Printf("%q, ", names[j])
		}
		fmt.Printf("\n")
	}
}

var (
	reRuntimeMembers = regexp.MustCompile(`(?m)^\s*RUNTIME_ENTRY_LIST\(DECLARE_MEMBERS\)`)
	reLeafMembers    = regexp.MustCompile(`(?m)^\s*LEAF_RUNTIME_ENTRY_LIST\(DECLARE_MEMBERS\)`)
	rePreproc        = regexp.MustCompile(`(?m)^\s*#(define|undef)[^\n]*$`)
)

// leafFollowsRuntime reports whether Thread declares the LEAF runtime
// entry points immediately after the ordinary ones, with nothing in
// between -- which is what makes the two blocks one contiguous run of
// offsets.
func leafFollowsRuntime(tag string) (bool, error) {
	src, err := fetchSDKFile("runtime/vm/thread.h", tag)
	if err != nil {
		return false, err
	}
	rt := reRuntimeMembers.FindStringIndex(src)
	lf := reLeafMembers.FindStringIndex(src)
	if rt == nil || lf == nil {
		return false, fmt.Errorf("thread.h@%s: DECLARE_MEMBERS expansions not found", tag)
	}
	if lf[0] < rt[1] {
		return false, fmt.Errorf("thread.h@%s: LEAF block precedes the runtime block", tag)
	}
	between := src[rt[1]:lf[0]]
	between = rePreproc.ReplaceAllString(between, "")
	return strings.TrimSpace(between) == "", nil
}

func arm64ProductTarget(tag string) (extractTarget, bool) {
	for _, t := range allTargets {
		if t.tag == tag && t.arch == "arm64" && t.product {
			return t, true
		}
	}
	return extractTarget{}, false
}

// runCheckRoots verifies RootsPrefixRefCount for Dart 3.13.0+ against the SDK.
// The roots prefix count is the sum of:
//   - |RAW_ROOTS_LIST| + 35 + 4 + 256 (Raw roots)
//   - |HANDLE_ROOTS_LIST| + (kNumPredefinedSymbols + 256) + kNumStubEntries (Handle roots)
//   - |API_HANDLE_ROOTS_LIST| (API handle roots)
//   - (kNumPredefinedCids - kObjectCid) - |IsAbsentCid| (class table entries)
//
// Source: runtime/vm/roots.h, runtime/vm/symbol_list.h,
// runtime/vm/stub_code_list.h, runtime/vm/class_id.h, runtime/vm/app_snapshot.cc.
// Verified via gh api at tag 3.13.0.
// reClassIdTagPosComment matches the pre-3.6 enum form, where the position is
// an expression whose value only exists in the trailing comment:
//
//	kClassIdTagPos = kSizeTagPos + kSizeTagSize,  // = 16
var reClassIdTagPosComment = regexp.MustCompile(`kClassIdTagPos\s*=[^,]*,\s*//\s*=\s*(\d+)`)

// reClassIdTagSizeLiteral matches the same era's width, a plain literal:
//
//	kClassIdTagSize = 16,
var reClassIdTagSizeLiteral = regexp.MustCompile(`kClassIdTagSize\s*=\s*(\d+)\s*,`)

// reClassIdTagBitField matches the 3.6-3.11 form, where the width is the last
// template argument and the position is a computed expression:
//
//	using ClassIdTag =
//	    BitField<decltype(tags_), ClassIdTagType, SizeTagBits::kNextBit, 20>;
var reClassIdTagBitField = regexp.MustCompile(`using ClassIdTag\s*=\s*BitField<[^>]*?,\s*(\d+)>`)
var reSizeTagBits = regexp.MustCompile(`using SizeTagBits\s*=\s*BitField<[^>]*?,\s*kBitsPerInt8\s*,\s*(\d+)>`)
var reInt8SizeLog2 = regexp.MustCompile(`kInt8SizeLog2\s*=\s*(\d+)`)
var reBitsPerByteLog2 = regexp.MustCompile(`kBitsPerByteLog2\s*=\s*(\d+)`)

// reExtractedClassIdTag matches the generated header, which carries both as
// literals from 3.12.2 onwards.
var reExtractedClassIdTagPos = regexp.MustCompile(`UntaggedObject_kClassIdTagPos\s*=\s*(0x[0-9a-fA-F]+|\d+)`)
var reExtractedClassIdTagSize = regexp.MustCompile(`UntaggedObject_kClassIdTagSize\s*=\s*(0x[0-9a-fA-F]+|\d+)`)

// sdkClassIdTagLayout recovers the complete ClassIdTag bitfield layout from
// the exact SDK source at a tag.
//
// Three shapes across the supported range, because the SDK rewrote this twice:
//
//	<= 3.5.0     raw_object.h enum, value in a trailing comment
//	3.6.2-3.11.0 raw_object.h `using ClassIdTag = BitField<..., 20>`
//	>= 3.12.2    runtime_offsets_extracted.h, both as literals
func sdkClassIdTagLayout(tag string) (pos, size int, source string, err error) {
	if src, e := fetchHeader(tag); e == nil {
		mp := reExtractedClassIdTagPos.FindStringSubmatch(src)
		ms := reExtractedClassIdTagSize.FindStringSubmatch(src)
		if mp != nil && ms != nil {
			p, e1 := strconv.ParseInt(mp[1], 0, 32)
			s, e2 := strconv.ParseInt(ms[1], 0, 32)
			if e1 == nil && e2 == nil {
				return int(p), int(s), "runtime_offsets_extracted.h", nil
			}
		}
	}
	raw, e := fetchSDKFile("runtime/vm/raw_object.h", tag)
	if e != nil {
		return 0, 0, "", e
	}
	if mp := reClassIdTagPosComment.FindStringSubmatch(raw); mp != nil {
		if ms := reClassIdTagSizeLiteral.FindStringSubmatch(raw); ms != nil {
			p, _ := strconv.Atoi(mp[1])
			s, _ := strconv.Atoi(ms[1])
			return p, s, "raw_object.h (enum)", nil
		}
	}
	if mb := reClassIdTagBitField.FindStringSubmatch(raw); mb != nil {
		s, _ := strconv.Atoi(mb[1])
		ms := reSizeTagBits.FindStringSubmatch(raw)
		if ms == nil {
			return 0, 0, "", fmt.Errorf("raw_object.h@%s uses ClassIdTag BitField but SizeTagBits is not the expected exact-source form", tag)
		}
		sizeWidth, convErr := strconv.Atoi(ms[1])
		if convErr != nil {
			return 0, 0, "", fmt.Errorf("raw_object.h@%s invalid SizeTagBits width: %w", tag, convErr)
		}
		globals, fetchErr := fetchSDKFile("runtime/platform/globals.h", tag)
		if fetchErr != nil {
			return 0, 0, "", fetchErr
		}
		mi8 := reInt8SizeLog2.FindStringSubmatch(globals)
		mbp := reBitsPerByteLog2.FindStringSubmatch(globals)
		if mi8 == nil || mbp == nil {
			return 0, 0, "", fmt.Errorf("globals.h@%s does not expose kInt8SizeLog2/kBitsPerByteLog2 literals", tag)
		}
		i8Log2, e1 := strconv.Atoi(mi8[1])
		bitsLog2, e2 := strconv.Atoi(mbp[1])
		if e1 != nil || e2 != nil || i8Log2 < 0 || i8Log2 > 8 || bitsLog2 < 0 || bitsLog2 > 8 {
			return 0, 0, "", fmt.Errorf("globals.h@%s has invalid bit-size constants", tag)
		}
		bitsPerInt8 := (1 << i8Log2) * (1 << bitsLog2)
		return bitsPerInt8 + sizeWidth, s, "raw_object.h SizeTagBits::kNextBit + runtime/platform/globals.h", nil
	}
	return 0, 0, "", fmt.Errorf("no recognised ClassIdTag declaration in raw_object.h@%s", tag)
}

// runCheckClassIdTag verifies snapshot.ClassIdTagLayout against the SDK for
// every supported version.
//
// This constant had no gate at all, unlike the Thread fields, the stub names,
// the stub offsets, the runtime entries, the object-store field count and the
// roots prefix. It is a hand-written version boundary of exactly the shape
// that has been wrong four times in this project (see the cross-version
// differential table in AGENTS-local.md), and it decides how every object
// header's class id is read.
func runCheckClassIdTag() int {
	bad, checked := 0, 0
	for _, tag := range snapshot.SupportedVersions() {
		sdkPos, sdkSize, source, err := sdkClassIdTagLayout(tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			bad++
			continue
		}
		wantPos, wantSize, ok := snapshot.ClassIdTagLayout(tag)
		if !ok {
			fmt.Fprintf(os.Stderr, "  ERROR %s: unsupported committed class-id tag layout\n", tag)
			bad++
			continue
		}
		checked++

		if sdkSize != wantSize {
			fmt.Fprintf(os.Stderr, "  MISMATCH %s: size committed=%d sdk=%d (%s)\n",
				tag, wantSize, sdkSize, source)
			bad++
			continue
		}
		if sdkPos != wantPos {
			fmt.Fprintf(os.Stderr, "  MISMATCH %s: pos committed=%d sdk=%d (%s)\n",
				tag, wantPos, sdkPos, source)
			bad++
			continue
		}
		fmt.Fprintf(os.Stderr, "  OK %s: pos %d size %d (%s)\n", tag, sdkPos, sdkSize, source)
	}
	if checked == 0 {
		fmt.Fprintln(os.Stderr, "ERROR: ClassIdTag drift gate verified zero SDK versions")
		bad++
	}
	if bad > 0 {
		fmt.Fprintf(os.Stderr, "\n%d ClassIdTag layout mismatch(es) across %d version(s)\n", bad, checked)
	} else {
		fmt.Fprintf(os.Stderr, "\nClassIdTag layout matches SDK exactly for all %d version(s)\n", checked)
	}
	return bad
}

func runCheckRoots() int {
	mismatches, checked := 0, 0
	for _, tag := range snapshot.SupportedVersions() {
		profile := snapshot.ProfileForVersion(tag)
		if !snapshot.VersionAtLeast(tag, "3.13.0") {
			continue
		}
		if profile == nil || profile.RootsPrefixRefCount <= 0 {
			fmt.Fprintf(os.Stderr, "  ERROR %s: supported 3.13+ profile has no RootsPrefixRefCount\n", tag)
			mismatches++
			continue
		}
		checked++
		// Fetch roots.h to count RAW_ROOTS_LIST + HANDLE_ROOTS_LIST + API_HANDLE_ROOTS_LIST.
		rootsHeader, err := fetchSDKFile("runtime/vm/roots.h", tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			mismatches++
			continue
		}
		rawRoots, err := countMacroEntries(rootsHeader, "RAW_ROOTS_LIST")
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: parse RAW_ROOTS_LIST: %v\n", tag, err)
			mismatches++
			continue
		}
		handleRoots, err := countMacroEntries(rootsHeader, "HANDLE_ROOTS_LIST")
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: parse HANDLE_ROOTS_LIST: %v\n", tag, err)
			mismatches++
			continue
		}
		apiHandleRoots, err := countMacroEntries(rootsHeader, "API_HANDLE_ROOTS_LIST")
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: parse API_HANDLE_ROOTS_LIST: %v\n", tag, err)
			mismatches++
			continue
		}
		argsDescriptors, err := extractArrayExtent(rootsHeader, "cached_args_descriptors_")
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			mismatches++
			continue
		}
		icdataArrays, err := extractArrayExtent(rootsHeader, "cached_icdata_arrays_")
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			mismatches++
			continue
		}
		oneCharSymbols, err := extractArrayExtent(rootsHeader, "one_char_symbols_")
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			mismatches++
			continue
		}

		// Fetch symbol_list.h for kNumPredefinedSymbols.
		symbolHeader, err := fetchSDKFile("runtime/vm/symbol_list.h", tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			mismatches++
			continue
		}
		numSymbols, err := countMacroEntries(symbolHeader, "PREDEFINED_SYMBOLS_LIST")
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: parse PREDEFINED_SYMBOLS_LIST: %v\n", tag, err)
			mismatches++
			continue
		}
		symbolHandleExtra, err := extractArrayExpressionAddend(rootsHeader, "symbol_handles_", "kNumPredefinedSymbols")
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			mismatches++
			continue
		}
		if !regexp.MustCompile(`stub_handles_\s*\[\s*kNumStubEntries\s*\]`).MatchString(rootsHeader) {
			fmt.Fprintf(os.Stderr, "  ERROR %s: roots.h no longer declares stub_handles_[kNumStubEntries]\n", tag)
			mismatches++
			continue
		}

		// Fetch stub_code_list.h for kNumStubEntries.
		stubHeader, err := fetchSDKFile("runtime/vm/stub_code_list.h", tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			mismatches++
			continue
		}
		vmStubs, err := parseVMStubCodeList(stubHeader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: parse stub lists: %v\n", tag, err)
			mismatches++
			continue
		}
		numStubEntries := len(vmStubs)

		// class_id.h owns the final CLASS_ID_LIST enum ordering; app_snapshot.cc
		// owns IsAbsentCid, the exact filter the roots serializer/deserializer use.
		classIDHeader, err := fetchSDKFile("runtime/vm/class_id.h", tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			mismatches++
			continue
		}
		appSnapshot, err := fetchSDKFile("runtime/vm/app_snapshot.cc", tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", tag, err)
			mismatches++
			continue
		}
		numPredefinedCids, kObjectCid, numAbsentCids, err := classTableFacts(classIDHeader, appSnapshot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: derive ClassId roots facts: %v\n", tag, err)
			mismatches++
			continue
		}

		// Compute the expected roots prefix count.
		// Every term, including array extents, is parsed from exact-tag source.
		// sizeof(Raw)/sizeof(ObjectPtr) = |RAW_ROOTS_LIST| + three Raw arrays
		// sizeof(Internal)/sizeof(VMHandle) = |HANDLE_ROOTS_LIST| + symbol handles + stub handles
		// sizeof(Api)/sizeof(ObjectPtr) = |API_HANDLE_ROOTS_LIST|
		// class table = (kNumPredefinedCids - kObjectCid) - |IsAbsentCid|
		rawCount := rawRoots + argsDescriptors + icdataArrays + oneCharSymbols
		handleCount := handleRoots + (numSymbols + symbolHandleExtra) + numStubEntries
		apiCount := apiHandleRoots
		classTableCount := (numPredefinedCids - kObjectCid) - numAbsentCids
		expected := rawCount + handleCount + apiCount + classTableCount
		committed := profile.RootsPrefixRefCount

		if expected != committed || rawRoots == 0 || handleRoots == 0 || numSymbols == 0 || classTableCount <= 0 {
			fmt.Fprintf(os.Stderr, "  MISMATCH %s: SDK roots prefix=%d, committed=%d\n", tag, expected, committed)
			fmt.Fprintf(os.Stderr, "    raw=%d (roots=%d+args=%d+icdata=%d+chars=%d), handle=%d (roots=%d+symbols=%d+extra=%d+stubs=%d), api=%d, classtable=%d (cids=%d-obj=%d-absent=%d)\n",
				rawCount, rawRoots, argsDescriptors, icdataArrays, oneCharSymbols,
				handleCount, handleRoots, numSymbols, symbolHandleExtra, numStubEntries,
				apiCount, classTableCount, numPredefinedCids, kObjectCid, numAbsentCids)
			mismatches++
		} else {
			fmt.Fprintf(os.Stderr, "  OK %s: roots prefix=%d (raw=%d, handle=%d, api=%d, classtable=%d)\n",
				tag, expected, rawCount, handleCount, apiCount, classTableCount)
		}
	}
	if checked == 0 {
		fmt.Fprintln(os.Stderr, "ERROR: roots-prefix drift gate verified zero supported versions")
		mismatches++
	}
	if mismatches > 0 {
		fmt.Fprintf(os.Stderr, "\n%d root prefix mismatch(es) found\n", mismatches)
	} else {
		fmt.Fprintf(os.Stderr, "\nRoots prefix check complete\n")
	}
	return mismatches
}

// countMacroEntries counts entries through the same fail-loud X-macro engine
// used by every other SDK drift gate.
func countMacroEntries(header, macroName string) (int, error) {
	macros, err := cmacro.ParseMacros(header)
	if err != nil {
		return 0, err
	}
	entries, err := cmacro.Expand(macros, macroName)
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

func extractArrayExtent(header, name string) (int, error) {
	re := regexp.MustCompile(regexp.QuoteMeta(name) + `\s*\[\s*(\d+)\s*\]`)
	matches := re.FindAllStringSubmatch(header, -1)
	if len(matches) == 0 {
		return 0, fmt.Errorf("roots.h: array extent for %s not found", name)
	}
	positive := map[int]bool{}
	for _, m := range matches {
		n, err := strconv.Atoi(m[1])
		if err != nil || n < 0 {
			return 0, fmt.Errorf("roots.h: invalid array index/extent for %s: %q", name, m[1])
		}
		// Accessors such as one_char_symbols_[0] are not declarations. The
		// declaration extent is positive; require exactly one distinct value so
		// a future second array shape fails closed rather than picking one.
		if n > 0 {
			positive[n] = true
		}
	}
	if len(positive) != 1 {
		return 0, fmt.Errorf("roots.h: array extent for %s is ambiguous: %v", name, positive)
	}
	for n := range positive {
		return n, nil
	}
	panic("unreachable")
}

func extractArrayExpressionAddend(header, name, base string) (int, error) {
	re := regexp.MustCompile(regexp.QuoteMeta(name) + `\s*\[\s*` + regexp.QuoteMeta(base) + `\s*\+\s*(\d+)\s*\]`)
	m := re.FindStringSubmatch(header)
	if m == nil {
		return 0, fmt.Errorf("roots.h: array expression %s[%s + N] not found", name, base)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n < 0 {
		return 0, fmt.Errorf("roots.h: invalid array addend for %s: %q", name, m[1])
	}
	return n, nil
}

// classTableFacts derives the three ClassId facts used by the 3.13+ roots
// class-table loops directly from class_id.h. It deliberately does not accept a
// committed total as an input: doing that made the old gate prove 1518 from
// 1518 even when the class table changed.
func classTableFacts(classHeader, appSnapshot string) (numPredefined, objectCID, absent int, err error) {
	macros, err := cmacro.ParseMacros(classHeader)
	if err != nil {
		return 0, 0, 0, err
	}
	ids, err := cmacro.ColumnWithCallback(macros, "CLASS_ID_LIST", "CID", 0)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("expand CLASS_ID_LIST: %w", err)
	}
	if len(ids) < 50 {
		return 0, 0, 0, fmt.Errorf("CLASS_ID_LIST expanded to only %d entries", len(ids))
	}
	objectCID = -1
	for i, name := range ids {
		// cmacro preserves token-paste spelling (`Object##Cid`) because drift
		// gates care about row order rather than C preprocessor token spelling.
		// Normalize only for this identifier comparison.
		normalized := strings.ReplaceAll(strings.TrimSpace(name), "##", "")
		if strings.TrimSuffix(normalized, "Cid") == "Object" {
			objectCID = i
			break
		}
	}
	if objectCID < 0 {
		return 0, 0, 0, fmt.Errorf("CLASS_ID_LIST has no Object CID")
	}
	numPredefined = len(ids)

	isAbsent := strings.Index(appSnapshot, "IsAbsentCid(intptr_t cid)")
	if isAbsent < 0 {
		return 0, 0, 0, fmt.Errorf("app_snapshot.cc: IsAbsentCid(intptr_t cid) not found")
	}
	absentBody := appSnapshot[isAbsent:]
	open := strings.IndexByte(absentBody, '{')
	if open < 0 {
		return 0, 0, 0, fmt.Errorf("app_snapshot.cc: IsAbsentCid body has no opening brace")
	}
	depth, close := 0, -1
	for i := open; i < len(absentBody); i++ {
		switch absentBody[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				close = i
				i = len(absentBody)
			}
		}
	}
	if close < 0 {
		return 0, 0, 0, fmt.Errorf("app_snapshot.cc: IsAbsentCid body is unterminated")
	}
	absentBody = absentBody[open+1 : close]
	absentRe := regexp.MustCompile(`\bcase\s+k([A-Za-z0-9_]+)Cid\s*:`)
	seen := map[string]bool{}
	for _, m := range absentRe.FindAllStringSubmatch(absentBody, -1) {
		seen[m[1]] = true
	}
	absent = len(seen)
	if absent == 0 {
		return 0, 0, 0, fmt.Errorf("IsAbsentCid yielded zero excluded CIDs")
	}
	return numPredefined, objectCID, absent, nil
}
func extractTHRFields(header, arch string, compressed, product bool) ([]struct {
	offset int
	name   string
}, error) {
	// For v2.x, DART_COMPRESSED_POINTERS may not exist in the file at all.
	// In that case, match only on PRODUCT + correct arch (ignore compressed flag).
	archUpper := strings.ToUpper(arch)
	var compressedStr string
	if compressed {
		compressedStr = "defined(DART_COMPRESSED_POINTERS)"
	} else {
		compressedStr = "!defined(DART_COMPRESSED_POINTERS)"
	}

	// No productStr here: PRODUCT matching is done via the preprocessor stack
	// below, not by substring-testing the section condition. A plain substring
	// test cannot work, because strings.Contains("!defined(PRODUCT)",
	// "defined(PRODUCT)") is true and because Dart 2.x arch conditions carry
	// no PRODUCT token at all.

	lines := strings.Split(header, "\n")
	var results []struct {
		offset int
		name   string
	}
	seen := map[int]string{} // deduplicate
	var wbEntries []struct {
		offset int
		name   string
	}

	hasCompressedSections := strings.Contains(header, "DART_COMPRESSED_POINTERS")

	reSingle := regexp.MustCompile(`Thread_(\w+)_offset\s*=\s*(0x[0-9a-fA-F]+|\d+)`)
	reMulti := regexp.MustCompile(`Thread_(\w+)_offset\s*=\s*$`)
	reHex := regexp.MustCompile(`^\s*(0x[0-9a-fA-F]+|\d+)\s*;`)
	reWBArray := regexp.MustCompile(`Thread_write_barrier_wrappers_thread_offset\[\]`)
	reWBValue := regexp.MustCompile(`-1|0x[0-9a-fA-F]+|\b\d+\b`)

	// runtime_offsets_extracted.h comes in TWO layouts, and the extractor has
	// to handle both. Verified by fetching the real headers:
	//
	//  A) Dart 3.x (e.g. 3.9.2): PRODUCT is part of each section's own
	//     condition ->
	//       #if defined(PRODUCT) && defined(TARGET_ARCH_ARM64) && defined(DCP)
	//
	//  B) Dart 2.x (e.g. 2.14.0, 2.17.6): one outer guard wraps everything and
	//     the arch conditions carry no PRODUCT token ->
	//       #if !defined(PRODUCT)          <- line 18
	//         #if defined(TARGET_ARCH_ARM64) && !defined(DCP)
	//         ...
	//       #else                          <- PRODUCT half starts here
	//         #if defined(TARGET_ARCH_ARM64) && !defined(DCP)
	//       #endif
	//
	// The previous implementation was wrong for both:
	//
	//   - Layout A, non-PRODUCT: the "track the outer guard" branch matched
	//     `#if ... !defined(PRODUCT) ...` and `continue`d, so a layout-A
	//     non-PRODUCT section header never reached the arch/compression
	//     matcher. Result: 0 entries, which is how four empty "_nonproduct"
	//     tables ended up committed in internal/vmtables.
	//   - Layout B, PRODUCT: an earlier revision handled this via
	//     `inProductBranch` fallbacks, which a later edit deleted in favour of
	//     a plain `isProduct` string test. Since layout-B arch conditions
	//     contain no PRODUCT token, that test can never be true. Result:
	//     2.17.6 went 96 -> 0 entries and 2.14.0 went 92 -> 0, i.e. the 2.x
	//     tables already in the tree could no longer be reproduced.
	//
	// Fix: track the preprocessor nesting with an explicit stack, so "am I in
	// a PRODUCT region?" is answered by the enclosing guards when the section
	// itself is silent about it (layout B) and by the section's own condition
	// when it is not (layout A).
	type frame struct {
		// productState is +1 inside a defined(PRODUCT) region, -1 inside a
		// !defined(PRODUCT) region, 0 when this frame says nothing about it.
		productState int
		// isSection is true when this #if selected an arch/compression block
		// we want to harvest offsets from.
		isSection bool
	}
	var stack []frame

	// enclosingProduct reports the innermost non-zero productState, or 0.
	enclosingProduct := func() int {
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].productState != 0 {
				return stack[i].productState
			}
		}
		return 0
	}
	inSection := func() bool {
		for _, f := range stack {
			if f.isSection {
				return true
			}
		}
		return false
	}

	wantProduct := 1
	if !product {
		wantProduct = -1
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(trimmed, "#if"):
			// Join line-continuations so multi-line conditions are seen whole.
			fullCond := line
			j := i
			for strings.HasSuffix(strings.TrimSpace(lines[j]), "\\") && j+1 < len(lines) {
				j++
				fullCond += " " + strings.TrimSpace(lines[j])
			}
			fullCond = strings.ReplaceAll(fullCond, "\\", " ")

			f := frame{}

			// What does this condition itself say about PRODUCT?
			switch {
			case strings.Contains(fullCond, "!defined(PRODUCT)"):
				f.productState = -1
			case strings.Contains(fullCond, "defined(PRODUCT)"):
				f.productState = 1
			}

			// A harvestable section must name our arch. Layout-B outer guards
			// don't, so they only contribute productState.
			if strings.Contains(fullCond, "defined(TARGET_ARCH_"+archUpper+")") {
				okCompressed := true
				if hasCompressedSections {
					if compressed {
						okCompressed = strings.Contains(fullCond, compressedStr) &&
							!strings.Contains(fullCond, "!"+compressedStr)
					} else {
						okCompressed = strings.Contains(fullCond, compressedStr)
					}
				}
				// Section's own PRODUCT token wins (layout A); otherwise
				// inherit from the enclosing guard (layout B).
				effProduct := f.productState
				if effProduct == 0 {
					effProduct = enclosingProduct()
				}
				if okCompressed && effProduct == wantProduct {
					f.isSection = true
				}
			}

			stack = append(stack, f)
			i = j // skip the continuation lines we consumed
			continue

		case strings.HasPrefix(trimmed, "#else"), strings.HasPrefix(trimmed, "#elif"):
			// Flip the current frame: the #else of `#if !defined(PRODUCT)` is
			// the PRODUCT half (layout B). A section frame stops harvesting
			// once we leave its true-branch.
			if len(stack) > 0 {
				top := &stack[len(stack)-1]
				top.productState = -top.productState
				top.isSection = false
				// Re-evaluate: the #else half of a PRODUCT guard can itself be
				// the half we want, but it contains nested arch #ifs which will
				// be handled when we reach them.
			}
			continue

		case strings.HasPrefix(trimmed, "#endif"):
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}

		if !inSection() {
			continue
		}

		// Try single-line match
		if m := reSingle.FindStringSubmatch(line); m != nil {
			name := m[1]
			offset := parseOffset(m[2])
			if _, exists := seen[offset]; !exists {
				seen[offset] = name
				results = append(results, struct {
					offset int
					name   string
				}{offset, name})
			}
			continue
		}

		// Write-barrier wrappers are exported as an ARRAY indexed by register
		// number, not as one scalar per field:
		//
		//   AOT_Thread_write_barrier_wrappers_thread_offset[] = {
		//       0x678, 0x680, ..., -1, -1, -1, 0x6f0, ...};
		//
		// -1 means that register has no wrapper. The scalar regexes above
		// cannot see any of this, so these offsets used to be hand-added to
		// the ARM64 tables (and were simply missing from the x64 ones).
		if reWBArray.MatchString(line) {
			var body strings.Builder
			for j := i; j < len(lines); j++ {
				body.WriteString(lines[j])
				if strings.Contains(lines[j], "}") {
					break
				}
			}
			// Scan from the opening brace so nothing before it (the type,
			// the name) is mistaken for an element.
			text := body.String()
			if b := strings.Index(text, "{"); b >= 0 {
				text = text[b+1:]
			}
			for reg, v := range reWBValue.FindAllString(text, -1) {
				if v == "-1" {
					continue
				}
				// Merged after the scan, so an explicitly named scalar field
				// at the same offset always wins regardless of which appears
				// first in the header.
				wbEntries = append(wbEntries, struct {
					offset int
					name   string
				}{parseOffset(v), fmt.Sprintf("wb_wrapper_R%d", reg)})
			}
			continue
		}

		// Try multi-line match
		if m := reMulti.FindStringSubmatch(line); m != nil {
			name := m[1]
			for j := i + 1; j < len(lines) && j <= i+3; j++ {
				if hm := reHex.FindStringSubmatch(lines[j]); hm != nil {
					offset := parseOffset(hm[1])
					if _, exists := seen[offset]; !exists {
						seen[offset] = name
						results = append(results, struct {
							offset int
							name   string
						}{offset, name})
					}
					break
				}
			}
		}
	}

	for _, e := range wbEntries {
		if _, exists := seen[e.offset]; exists {
			continue
		}
		seen[e.offset] = e.name
		results = append(results, e)
	}

	return results, nil
}

func generateGoMap(tag, arch string, compressed, product bool, entries []struct {
	offset int
	name   string
}) string {
	sort.Slice(entries, func(i, j int) bool { return entries[i].offset < entries[j].offset })

	var archSuffix string
	if arch == "x64" {
		archSuffix = "_x64"
	}
	compressSuffix := ""
	if !compressed {
		compressSuffix = "_nocompress"
	}
	productSuffix := ""
	if !product {
		productSuffix = "_nonproduct"
	}

	var b strings.Builder
	modeStr := "PRODUCT"
	if !product {
		modeStr = "non-PRODUCT"
	}
	compressStr := "DART_COMPRESSED_POINTERS"
	if !compressed {
		compressStr = "!DART_COMPRESSED_POINTERS"
	}
	fmt.Fprintf(&b, "// v%s: %s + %s + %s\n", tag, modeStr, strings.ToUpper(arch), compressStr)
	fmt.Fprintf(&b, "// Source: dartsdk/v%s/runtime/vm/compiler/runtime_offsets_extracted.h\n", tag)
	fmt.Fprintf(&b, "var thrV%s%s%s%s = map[int]string{\n", strings.ReplaceAll(tag, ".", ""), archSuffix, compressSuffix, productSuffix)
	for _, e := range entries {
		fmt.Fprintf(&b, "\t0x%x: %q,\n", e.offset, e.name)
	}
	fmt.Fprintf(&b, "}\n\n")
	return b.String()
}

// thrTableFiles are the sources holding the committed THR tables.
var thrTableFiles = []string{
	"internal/vmtables/thrfields.go",
	"internal/vmtables/thrfieldsx86.go",
}

// committedNameOverrides maps a generated variable name to the name actually
// used in internal/vmtables. The older ARM64 v2.x tables predate the naming
// convention generateGoMap follows and omit the "_nocompress" suffix because
// those versions have no compressed variant at all. Dart 2.17.6 was later
// committed under the exact generated name, thrV2176_nocompress, so it must
// not be aliased here.
// Without these, -check would report the tables as "NOT CHECKED" -- i.e.
// silently unverified, which is the failure mode this tool exists to prevent.
var committedNameOverrides = map[string]string{
	"thrV2100_nocompress": "thrV2100",
	"thrV2120_nocompress": "thrV2120",
	"thrV2130_nocompress": "thrV2130",
	"thrV2140_nocompress": "thrV2140",
	"thrV2150_nocompress": "thrV2150",
	"thrV2160_nocompress": "thrV2160",
}

// mapName mirrors generateGoMap's naming so a target can be matched to the
// committed variable it is supposed to equal.
func mapName(tag, arch string, compressed, product bool) string {
	name := "thrV" + strings.ReplaceAll(tag, ".", "")
	if arch == "x64" {
		name += "_x64"
	}
	if !compressed {
		name += "_nocompress"
	}
	if !product {
		name += "_nonproduct"
	}
	if override, ok := committedNameOverrides[name]; ok {
		return override
	}
	return name
}

// parseCommittedTables reads `var thrXXX = map[int]string{...}` literals out
// of the given Go files. Parsing the AST rather than grepping means a
// reformat, a comment, or a line split cannot quietly change what -check
// believes is committed.
func parseCommittedTables(files []string) (map[string]map[int]string, error) {
	out := map[string]map[int]string{}
	fset := token.NewFileSet()
	for _, path := range files {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
					continue
				}
				name := vs.Names[0].Name
				if !strings.HasPrefix(name, "thrV") {
					continue
				}
				lit, ok := vs.Values[0].(*ast.CompositeLit)
				if !ok {
					continue
				}
				entries := map[int]string{}
				for _, el := range lit.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					kb, ok := kv.Key.(*ast.BasicLit)
					if !ok || kb.Kind != token.INT {
						continue
					}
					vb, ok := kv.Value.(*ast.BasicLit)
					if !ok || vb.Kind != token.STRING {
						continue
					}
					off, err := strconv.ParseInt(kb.Value, 0, 64)
					if err != nil {
						continue
					}
					val, err := strconv.Unquote(vb.Value)
					if err != nil {
						continue
					}
					entries[int(off)] = val
				}
				out[name] = entries
			}
		}
	}
	return out, nil
}

// extractAll re-extracts every target, returning committed-variable-name →
// offset → field name, plus the names it could not produce.
func extractAll() (map[string]map[int]string, []string) {
	headers := map[string]string{}
	out := map[string]map[int]string{}
	var failed []string
	for _, t := range allTargets {
		header, ok := headers[t.tag]
		if !ok {
			h, err := fetchHeader(t.tag)
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s: fetch: %v", t.tag, err))
				continue
			}
			headers[t.tag] = h
			header = h
		}
		entries, err := extractTHRFields(header, t.arch, t.compressed, t.product)
		if err != nil || len(entries) == 0 {
			failed = append(failed, fmt.Sprintf("%s %s compressed=%v product=%v: no entries",
				t.tag, t.arch, t.compressed, t.product))
			continue
		}
		m := map[int]string{}
		for _, e := range entries {
			m[e.offset] = e.name
		}
		if err := fillDerivedThreadFields(m, t.tag, t.arch); err != nil {
			failed = append(failed, fmt.Sprintf("%s %s compressed=%v product=%v: derived fields: %v",
				t.tag, t.arch, t.compressed, t.product, err))
			continue
		}
		out[mapName(t.tag, t.arch, t.compressed, t.product)] = m
	}
	return out, failed
}

// runWrite rewrites every committed `var thrV... = map[int]string{...}` block
// in place with freshly extracted SDK values, preserving the surrounding
// hand-written code (selection logic, runtime-entry lists, init merges) and
// each table's existing variable name.
//
// Rewriting the literal's own source range -- located via the AST, not by
// pattern-matching text -- is what makes it safe to regenerate these 5000-odd
// lines without touching anything else in the file.
func runWrite() int {
	sdk, failed := extractAll()
	for _, f := range failed {
		fmt.Fprintf(os.Stderr, "write: ERROR %s\n", f)
	}
	if len(failed) > 0 {
		fmt.Fprintf(os.Stderr, "write: refusing partial rewrite after %d extraction failure(s)\n", len(failed))
		return 1
	}
	rewritten, skipped := 0, 0
	for _, path := range thrTableFiles {
		src, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			return 1
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "write: parse %s: %v\n", path, err)
			return 1
		}
		type edit struct {
			start, end int
			text       string
		}
		var edits []edit
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
					continue
				}
				name := vs.Names[0].Name
				if !strings.HasPrefix(name, "thrV") {
					continue
				}
				lit, ok := vs.Values[0].(*ast.CompositeLit)
				if !ok {
					continue
				}
				entries, ok := sdk[name]
				if !ok {
					skipped++
					continue
				}
				offs := make([]int, 0, len(entries))
				for off := range entries {
					offs = append(offs, off)
				}
				sort.Ints(offs)
				var b strings.Builder
				b.WriteString("map[int]string{\n")
				for _, off := range offs {
					fmt.Fprintf(&b, "\t0x%x: %q,\n", off, entries[off])
				}
				b.WriteString("}")
				edits = append(edits, edit{
					start: fset.Position(lit.Pos()).Offset,
					end:   fset.Position(lit.End()).Offset,
					text:  b.String(),
				})
				rewritten++
			}
		}
		sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
		out := string(src)
		for _, e := range edits {
			out = out[:e.start] + e.text + out[e.end:]
		}
		// Format the result the way gofmt would, rather than telling the
		// caller to remember to do it. Splicing map literals back in by byte
		// offset changes key widths, and gofmt aligns map values by the
		// widest key in each run -- so a spliced table is almost always
		// misaligned. Leaving that to a printed reminder is how ~2000 lines
		// of thrfields.go/thrfieldsx86.go ended up committed unformatted.
		formatted, ferr := format.Source([]byte(out))
		if ferr != nil {
			// Keep the unformatted result rather than losing the rewrite;
			// the caller still gets a usable file and a clear diagnostic.
			fmt.Fprintf(os.Stderr, "write: %s: gofmt failed (%v), writing unformatted\n", path, ferr)
			formatted = []byte(out)
		}
		if err := os.WriteFile(path, formatted, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			return 1
		}
	}
	fmt.Fprintf(os.Stderr, "write: %d Thread field table(s) rewritten, %d left untouched (no SDK target)\n", rewritten, skipped)
	// The other three per-version families, so one command regenerates
	// everything derived from the SDK rather than three plus a paste.
	return writeStubTables()
}

// --- ObjectStoreAOTFieldCount verification ---

const versionProfilePath = "internal/snapshot/version.go"

// objectStoreFieldCount counts the ObjectStore roots an AOT snapshot writes
// for one SDK tag.
//
// ProgramSerializationRoots::WriteRoots (runtime/vm/app_snapshot.cc, and
// clustered_snapshot.cc before 2.17) writes exactly:
//
//	ObjectPtr* from = object_store_->from();
//	ObjectPtr* to = object_store_->to_snapshot(s->kind());
//	for (ObjectPtr* p = from; p <= to; p++) { s->WriteRootRef(*p, ...); }
//
// -- inclusive, ObjectStore only. IsolateObjectStore is NOT part of it, which
// is why any "+ N isolate fields" adjustment is wrong. The field order is the
// order OBJECT_STORE_FIELD_LIST expands in, and to_snapshot(kFullAOT) returns
// &slow_tts_stub_ on every supported version.
//
// Getting this count wrong desynchronises the stream right before the
// dispatch table, so the dispatch table parses as garbage and BLR resolution
// silently collapses to zero.
func objectStoreFieldCount(tag string) (int, string, error) {
	names, desc, err := objectStoreFields(tag)
	if err != nil {
		return 0, "", err
	}
	return len(names), desc, nil
}

// objectStoreFields returns the ObjectStore field NAMES an AOT snapshot
// writes, in serialized order -- the same range objectStoreFieldCount counts,
// so index i here is root ref i in ParseDispatchTable.
//
// The names matter as well as the count: 76-89 of them are
// `RW(Code, <name>_stub)`, and those are the only place an isolate stub's
// identity survives. Their Code objects carry a null owner, so every one of
// them otherwise falls through to `sub_<pcOffset>` -- measured at 85 of 8049
// ranges on dart-3.9.2-gt-arm64, all of them `_iso_stub_*` in the ELF symbol
// table.
func objectStoreFields(tag string) ([]string, string, error) {
	src, err := fetchSDKFile("runtime/vm/object_store.h", tag)
	if err != nil {
		return nil, "", fmt.Errorf("fetch object_store.h@%s: %w", tag, err)
	}

	// The OBJECT_STORE_FIELD_LIST macros are defined near the top of the
	// file, well before the class, so they are looked up in the whole
	// source; from()/to_snapshot and the DECLARE_ expansion order are read
	// from the ObjectStore class body only, so IsolateObjectStore's own
	// from() and field list cannot be picked up instead.
	body := src
	if i := strings.Index(src, "class ObjectStore {"); i >= 0 {
		body = src[i:]
	} else if i := strings.Index(src, "class ObjectStore :"); i >= 0 {
		body = src[i:]
	}

	macros, err := cmacro.ParseMacros(src)
	if err != nil {
		return nil, "", fmt.Errorf("%s: parse object_store.h macros: %w", tag, err)
	}
	rows, err := cmacro.ExpandRawAllCallbacks(macros, "OBJECT_STORE_FIELD_LIST")
	if err != nil {
		return nil, "", fmt.Errorf("%s: expand OBJECT_STORE_FIELD_LIST: %w", tag, err)
	}
	names := make([]string, 0, len(rows))
	for i, row := range rows {
		if len(row) != 2 {
			return nil, "", fmt.Errorf("%s: OBJECT_STORE_FIELD_LIST row %d has %d columns, want 2", tag, i, len(row))
		}
		name := strings.TrimSpace(row[1])
		if name == "" {
			return nil, "", fmt.Errorf("%s: OBJECT_STORE_FIELD_LIST row %d has empty field name", tag, i)
		}
		names = append(names, name)
	}

	fromRe := regexp.MustCompile(`ObjectPtr\* from\(\)\s*\{\s*return[^&]*&(\w+)_\)`)
	aotRe := regexp.MustCompile(`kFullAOT:\s*\n?\s*return[^&]*&(\w+)_\)`)
	fm, am := fromRe.FindStringSubmatch(body), aotRe.FindStringSubmatch(body)
	if fm == nil || am == nil {
		return nil, "", fmt.Errorf("%s: could not locate from()/to_snapshot(kFullAOT)", tag)
	}
	idx := func(name string) int {
		for i, n := range names {
			if n == name {
				return i
			}
		}
		return -1
	}
	i0, i1 := idx(fm[1]), idx(am[1])
	if i0 < 0 || i1 < 0 {
		return nil, "", fmt.Errorf("%s: from=%q(%d) aot=%q(%d) not found among %d fields",
			tag, fm[1], i0, am[1], i1, len(names))
	}
	return names[i0 : i1+1], fmt.Sprintf("from=%s to=%s", fm[1], am[1]), nil
}

// committedFieldCounts parses DartVersion -> ObjectStoreAOTFieldCount out of
// the version profile table.
func committedFieldCounts() (map[string]int, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, versionProfilePath, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", versionProfilePath, err)
	}
	out := map[string]int{}
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		version, count, haveCount := "", 0, false
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			bl, ok := kv.Value.(*ast.BasicLit)
			if !ok {
				continue
			}
			switch key.Name {
			case "DartVersion":
				if s, err := strconv.Unquote(bl.Value); err == nil {
					version = s
				}
			case "ObjectStoreAOTFieldCount":
				if v, err := strconv.Atoi(bl.Value); err == nil {
					count, haveCount = v, true
				}
			}
		}
		if version != "" && haveCount {
			out[version] = count
		}
		return true
	})
	return out, nil
}

// runCheckObjectStore verifies every profile's ObjectStoreAOTFieldCount
// against the SDK. Returns the number of mismatches.
func runCheckObjectStore() int {
	bad, checked := 0, 0
	for _, v := range snapshot.SupportedVersions() {
		profile := snapshot.ProfileForVersion(v)
		if profile == nil || !profile.Supported || profile.ObjectStoreAOTFieldCount <= 0 {
			fmt.Fprintf(os.Stderr, "  %-12s ERROR (supported profile has no verified ObjectStoreAOTFieldCount)\n", v)
			bad++
			continue
		}
		got, where, err := objectStoreFieldCount(v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %-12s ERROR (%v)\n", v, err)
			bad++
			continue
		}
		checked++
		if got == profile.ObjectStoreAOTFieldCount {
			fmt.Fprintf(os.Stderr, "  %-12s OK %d (%s)\n", v, got, where)
			continue
		}
		bad++
		fmt.Fprintf(os.Stderr, "  %-12s MISMATCH: committed %d, SDK %d (%s)\n", v, profile.ObjectStoreAOTFieldCount, got, where)
	}
	if checked == 0 {
		fmt.Fprintln(os.Stderr, "check-objectstore: ERROR verified zero SDK versions")
		bad++
	}
	fmt.Fprintf(os.Stderr, "check-objectstore: %d supported version(s) verified, %d mismatch(es)\n", checked, bad)
	return bad
}

// runCheck re-extracts every target and diffs it against the committed
// tables. Returns the number of tables with unexplained differences.
func runCheck() int {
	committed, err := parseCommittedTables(thrTableFiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "check: %d committed THR table(s) found in %s\n",
		len(committed), strings.Join(thrTableFiles, ", "))

	headers := map[string]string{}
	bad, checked, skipped := 0, 0, 0
	covered := map[string]bool{}

	for _, t := range allTargets {
		name := mapName(t.tag, t.arch, t.compressed, t.product)
		want, ok := committed[name]
		if !ok {
			continue // target has no committed table (e.g. non-PRODUCT)
		}
		covered[name] = true
		header, ok := headers[t.tag]
		if !ok {
			h, err := fetchHeader(t.tag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  %-38s SKIP (fetch: %v)\n", name, err)
				skipped++
				continue
			}
			headers[t.tag] = h
			header = h
		}
		entries, err := extractTHRFields(header, t.arch, t.compressed, t.product)
		if err != nil || len(entries) == 0 {
			fmt.Fprintf(os.Stderr, "  %-38s SKIP (no entries extracted)\n", name)
			skipped++
			continue
		}
		got := map[int]string{}
		for _, e := range entries {
			got[e.offset] = e.name
		}
		// Same derivation -write applies, for the same tables. Without
		// it the two halves disagree by construction: the committed
		// tables carry the ~70 runtime entries the header declares only
		// in RUNTIME_ENTRY_LIST order, and comparing them against the
		// raw header alone reports every one of them as "extra".
		if err := fillDerivedThreadFields(got, t.tag, t.arch); err != nil {
			fmt.Fprintf(os.Stderr, "  %-38s ERROR (derived fields: %v)\n", name, err)
			bad++
			checked++
			continue
		}

		var problems []string
		for off, sdkName := range got {
			repoName, present := want[off]
			switch {
			case !present:
				problems = append(problems, fmt.Sprintf("missing 0x%x %q", off, sdkName))
			case repoName != sdkName:
				problems = append(problems, fmt.Sprintf("0x%x: committed %q, SDK %q", off, repoName, sdkName))
			}
		}
		for off, repoName := range want {
			if _, present := got[off]; present {
				continue
			}
			problems = append(problems, fmt.Sprintf("extra 0x%x %q (not in SDK header)", off, repoName))
		}
		sort.Strings(problems)
		checked++
		if len(problems) == 0 {
			fmt.Fprintf(os.Stderr, "  %-38s OK (%d entries)\n", name, len(want))
			continue
		}
		bad++
		fmt.Fprintf(os.Stderr, "  %-38s %d PROBLEM(S)\n", name, len(problems))
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "      %s\n", p)
		}
	}

	notChecked := 0
	for name := range committed {
		if !covered[name] {
			fmt.Fprintf(os.Stderr, "  %-38s NOT CHECKED (no target in allTargets)\n", name)
			notChecked++
		}
	}
	if checked == 0 {
		fmt.Fprintln(os.Stderr, "check: ERROR verified zero committed THR tables")
		bad++
	}
	fmt.Fprintf(os.Stderr, "check: %d table(s) verified, %d with problems, %d skipped, %d not checked\n", checked, bad, skipped, notChecked)
	return bad + skipped + notChecked
}

func main() {
	tagFlag := flag.String("tag", "", "Dart SDK version tag (e.g., 3.9.2)")
	archFlag := flag.String("arch", "arm64", "architecture: arm64 or x64")
	compressedFlag := flag.Bool("compressed", false, "DART_COMPRESSED_POINTERS section")
	nocompressedFlag := flag.Bool("nocompressed", false, "!DART_COMPRESSED_POINTERS section")
	productFlag := flag.Bool("product", false, "PRODUCT build mode (default)")
	nonproductFlag := flag.Bool("nonproduct", false, "non-PRODUCT build mode (Debug/Profile)")
	allFlag := flag.Bool("all", false, "extract all known versions")
	checkFlag := flag.Bool("check", false, "verify the committed THR tables against the SDK headers; exit 1 on any unexplained difference")
	writeFlag := flag.Bool("write", false, "rewrite the committed THR tables in place from the SDK headers (run gofmt afterwards)")
	checkObjectStoreFlag := flag.Bool("check-objectstore", false, "verify every profile's ObjectStoreAOTFieldCount against the SDK's object_store.h; exit 1 on mismatch")
	writeObjectStoreStubsFlag := flag.Bool("write-objectstore-stubs", false, "regenerate internal/vmtables/objectstorestubs.go from the SDK's object_store.h")
	checkStubsFlag := flag.Bool("check-stubs", false, "verify stubnames.go against SDK's stub_code_list.h; exit 1 on mismatch")
	checkRootsFlag := flag.Bool("check-roots", false, "verify RootsPrefixRefCount for Dart 3.13.0+ against SDK's roots.h, symbol_list.h, stub_code_list.h, class_id.h; exit 1 on mismatch")
	checkClassIdTagFlag := flag.Bool("check-classid-tag", false, "verify snapshot.ClassIdTagLayout against SDK's raw_object.h / runtime_offsets_extracted.h for every version; exit 1 on mismatch")
	checkRuntimeEntriesFlag := flag.Bool("check-runtime-entries", false, "verify every runtime entry in SDK's runtime_entry_list.h is named in the committed THR tables; exit 1 on any gap")
	emitStubNamesFlag := flag.String("emit-stub-names", "", "comma-separated tags: print Go source for their VM stub name tables")
	emitStubOffsetsFlag := flag.String("emit-stub-offsets", "", "comma-separated tags: print Go source for their Thread-cached stub offset tables")
	emitRuntimeEntriesFlag := flag.String("emit-runtime-entries", "", "comma-separated tags: print Go source for their runtime-entry tables and the mergeRuntimeEntries calls")
	checkStubOffsetsFlag := flag.Bool("check-stub-offsets", false, "verify threadstubs.go's ThreadStubOffsets tables against SDK's thread.h + runtime_offsets_extracted.h; exit 1 on mismatch")
	flag.Parse()

	if *emitStubNamesFlag != "" {
		os.Exit(runEmitStubNames(strings.Split(*emitStubNamesFlag, ",")))
	}

	if *emitStubOffsetsFlag != "" {
		os.Exit(runEmitStubOffsets(strings.Split(*emitStubOffsetsFlag, ",")))
	}

	if *emitRuntimeEntriesFlag != "" {
		os.Exit(runEmitRuntimeEntries(strings.Split(*emitRuntimeEntriesFlag, ",")))
	}

	if *checkStubOffsetsFlag {
		if runCheckStubOffsets() > 0 {
			os.Exit(1)
		}
		return
	}

	if *checkObjectStoreFlag {
		if runCheckObjectStore() > 0 {
			os.Exit(1)
		}
		return
	}

	if *writeObjectStoreStubsFlag {
		if runWriteObjectStoreStubs() > 0 {
			os.Exit(1)
		}
		return
	}

	if *checkStubsFlag {
		if runCheckStubs() > 0 {
			os.Exit(1)
		}
		return
	}

	if *checkRuntimeEntriesFlag {
		if runCheckRuntimeEntries() > 0 {
			os.Exit(1)
		}
		return
	}

	if *checkRootsFlag {
		if runCheckRoots() > 0 {
			os.Exit(1)
		}
		return
	}

	if *checkClassIdTagFlag {
		if runCheckClassIdTag() > 0 {
			os.Exit(1)
		}
		return
	}

	if *writeFlag {
		if runWrite() > 0 {
			os.Exit(1)
		}
		return
	}

	if *checkFlag {
		if runCheck() > 0 {
			os.Exit(1)
		}
		return
	}

	if *allFlag {
		failures := 0
		for _, t := range allTargets {
			fmt.Fprintf(os.Stderr, "Extracting %s %s compressed=%v product=%v...\n", t.tag, t.arch, t.compressed, t.product)
			header, err := fetchHeader(t.tag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ERROR: %v\n", err)
				failures++
				continue
			}
			entries, err := extractTHRFields(header, t.arch, t.compressed, t.product)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ERROR: %v\n", err)
				failures++
				continue
			}
			if len(entries) == 0 {
				fmt.Fprintf(os.Stderr, "  ERROR: 0 entries found\n")
				failures++
				continue
			}
			complete := make(map[int]string, len(entries))
			for _, e := range entries {
				complete[e.offset] = e.name
			}
			if err := fillDerivedThreadFields(complete, t.tag, t.arch); err != nil {
				fmt.Fprintf(os.Stderr, "  ERROR: derived fields: %v\n", err)
				failures++
				continue
			}
			entries = entries[:0]
			for off, name := range complete {
				entries = append(entries, struct {
					offset int
					name   string
				}{off, name})
			}
			fmt.Fprintf(os.Stderr, "  Found %d entries\n", len(entries))
			fmt.Print(generateGoMap(t.tag, t.arch, t.compressed, t.product, entries))
		}
		if failures > 0 {
			fmt.Fprintf(os.Stderr, "extract-all: refusing success after %d extraction failure(s)\n", failures)
			os.Exit(1)
		}
		return
	}

	if *tagFlag == "" {
		fmt.Fprintln(os.Stderr, "Usage: extract_thr.go -tag <version> -arch <arm64|x64> [-compressed|-nocompressed] [-product|-nonproduct] OR -all")
		os.Exit(1)
	}

	compressed := *compressedFlag
	if *nocompressedFlag {
		compressed = false
	}
	product := !*nonproductFlag
	if *productFlag {
		product = true
	}

	header, err := fetchHeader(*tagFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	entries, err := extractTHRFields(header, *archFlag, compressed, product)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	complete := make(map[int]string, len(entries))
	for _, e := range entries {
		complete[e.offset] = e.name
	}
	if err := fillDerivedThreadFields(complete, *tagFlag, *archFlag); err != nil {
		fmt.Fprintf(os.Stderr, "Error: derived fields: %v\n", err)
		os.Exit(1)
	}
	entries = entries[:0]
	for off, name := range complete {
		entries = append(entries, struct {
			offset int
			name   string
		}{off, name})
	}

	fmt.Fprintf(os.Stderr, "Found %d Thread field entries for %s %s compressed=%v product=%v\n",
		len(entries), *tagFlag, *archFlag, compressed, product)
	fmt.Print(generateGoMap(*tagFlag, *archFlag, compressed, product, entries))
}

// ---------------------------------------------------------------------
// Generated-table writers.
//
// Three of the four per-version table families could only be -emit'ed:
// the tool printed Go source and a human pasted it in. That hand-off is
// where a table drifts, and it is exactly how four Thread field tables
// came to carry their neighbour's offsets for every field the SDK header
// does not export -- the shipped bug that prompted this. -write now
// regenerates all four families in place, so "regenerate" is a command
// rather than a procedure.
// ---------------------------------------------------------------------

// sdkStubNamesFor returns VM_STUB_CODE_LIST minus the type-testing stubs,
// in declaration order -- the same list runEmitStubNames prints.
func sdkStubNamesFor(tag string) ([]string, error) {
	src, err := fetchSDKFile("runtime/vm/stub_code_list.h", tag)
	if err != nil {
		return nil, err
	}
	macros, err := cmacro.ParseMacros(src)
	if err != nil {
		return nil, err
	}
	full, err := cmacro.Expand(macros, "VM_STUB_CODE_LIST")
	if err != nil {
		return nil, err
	}
	// Dart 2.10 predates the split list: the type-testing stubs are inline in
	// VM_STUB_CODE_LIST and therefore are part of the committed storage itself.
	if _, ok := macros["VM_TYPE_TESTING_STUB_CODE_LIST"]; !ok {
		return full, nil
	}
	tts, err := cmacro.Expand(macros, "VM_TYPE_TESTING_STUB_CODE_LIST")
	if err != nil {
		return nil, err
	}
	ttsSet := map[string]bool{}
	for _, n := range tts {
		ttsSet[n] = true
	}
	var want []string
	for _, n := range full {
		if !ttsSet[n] {
			want = append(want, n)
		}
	}
	return want, nil
}

// sdkRuntimeEntriesFor returns the runtime-entry names for a tag, split
// the way the committed tables store them.
//
// Whether the LEAF block follows the runtime block is a property of the
// Thread struct, not of the offsets header: up to 2.19 the two
// DECLARE_MEMBERS expansions are adjacent and the tables store them
// flattened, but by 3.12.2 the LEAF one has moved down past
// exit_through_ffi_, leaving a gap. Flattening unconditionally writes
// straight over that gap and misnames the whole write-barrier wrapper
// block -- 192 offsets on the first attempt at this.
//
// leafFollowsRuntime reads that from thread.h, which is why this defers
// to it rather than deciding from the tag.
func sdkRuntimeEntriesFor(tag string) (runtime, leaf []string, contiguous bool, err error) {
	src, err := fetchSDKFile("runtime/vm/runtime_entry_list.h", tag)
	if err != nil {
		return nil, nil, false, err
	}
	macros, err := cmacro.ParseMacros(src)
	if err != nil {
		return nil, nil, false, err
	}
	runtime, err = cmacro.Expand(macros, "RUNTIME_ENTRY_LIST")
	if err != nil {
		return nil, nil, false, err
	}
	// LEAF entries put the return type first: V(intptr_t, Name, ...).
	leaf, err = cmacro.Column(macros, "LEAF_RUNTIME_ENTRY_LIST", 1)
	if err != nil {
		return nil, nil, false, err
	}
	contiguous, err = leafFollowsRuntime(tag)
	if err != nil {
		return nil, nil, false, err
	}
	return runtime, leaf, contiguous, nil
}

var runtimeEntryCache = map[string]struct {
	runtime, leaf []string
	contiguous    bool
	err           error
}{}

var cachedConstantFieldCache = map[string]struct {
	names []string
	err   error
}{}

// sdkCachedConstantFields expands Thread::CACHED_CONSTANTS_LIST in exact SDK
// declaration order. The list contains cached VM objects/stubs and raw
// addresses. runtime_offsets_extracted.h intentionally exports only the subset
// referenced directly by compiler code, so parsing that generated header alone
// leaves real Thread slots unnamed.
func sdkCachedConstantFields(tag string) ([]string, error) {
	if cached, ok := cachedConstantFieldCache[tag]; ok {
		return cached.names, cached.err
	}
	var cached struct {
		names []string
		err   error
	}
	src, err := fetchSDKFile("runtime/vm/thread.h", tag)
	if err != nil {
		cached.err = err
		cachedConstantFieldCache[tag] = cached
		return nil, err
	}
	macros, err := cmacro.ParseMacros(src)
	if err != nil {
		cached.err = err
		cachedConstantFieldCache[tag] = cached
		return nil, err
	}
	rows, err := cmacro.ExpandRaw(macros, "CACHED_CONSTANTS_LIST")
	if err != nil {
		cached.err = err
		cachedConstantFieldCache[tag] = cached
		return nil, err
	}
	seen := map[string]bool{}
	for i, row := range rows {
		if len(row) != 4 {
			cached.err = fmt.Errorf("thread.h@%s CACHED_CONSTANTS_LIST row %d has %d columns, want 4", tag, i, len(row))
			cachedConstantFieldCache[tag] = cached
			return nil, cached.err
		}
		name := strings.TrimSuffix(strings.TrimSpace(row[1]), "_")
		if name == "" || seen[name] {
			cached.err = fmt.Errorf("thread.h@%s CACHED_CONSTANTS_LIST has invalid/duplicate field %q", tag, name)
			cachedConstantFieldCache[tag] = cached
			return nil, cached.err
		}
		seen[name] = true
		cached.names = append(cached.names, name)
	}
	if len(cached.names) == 0 {
		cached.err = fmt.Errorf("thread.h@%s CACHED_CONSTANTS_LIST expanded to zero fields", tag)
	}
	cachedConstantFieldCache[tag] = cached
	return cached.names, cached.err
}

// fillCachedConstantFields reconstructs the complete CACHED_CONSTANTS_LIST
// layout from exact SDK evidence rather than a per-version handwritten list.
// object_null is the first cached constant and AllocateArray_entry_point is the
// first field immediately after the block. Both offsets are exported by the SDK
// for every supported target, so their distance proves the per-field stride.
// Every header-exported field already present in m is then a conflict check.
func fillCachedConstantFields(m map[int]string, tag, arch string) error {
	names, err := sdkCachedConstantFields(tag)
	if err != nil {
		return err
	}
	byName := make(map[string]int, len(m))
	for off, name := range m {
		byName[name] = off
	}
	base, ok := byName["object_null"]
	if !ok {
		return fmt.Errorf("%s/%s: cached-constant anchor object_null absent from header", tag, arch)
	}
	after, ok := byName["AllocateArray_entry_point"]
	if !ok {
		return fmt.Errorf("%s/%s: cached-constant end anchor AllocateArray_entry_point absent from header", tag, arch)
	}
	span := after - base
	if span <= 0 || span%len(names) != 0 {
		return fmt.Errorf("%s/%s: cached constants span %#x..%#x is not divisible by %d declarations", tag, arch, base, after, len(names))
	}
	stride := span / len(names)
	// Every supported target is 64-bit. A different result means declaration
	// order/layout changed and must be audited rather than silently generalized.
	if stride != 8 {
		return fmt.Errorf("%s/%s: cached constants derived stride %d, want 8 for 64-bit target", tag, arch, stride)
	}
	for i, name := range names {
		off := base + i*stride
		if existing, taken := m[off]; taken && existing != name {
			return fmt.Errorf("%s/%s: cached-constant conflict at 0x%x: header holds %q, thread.h predicts %q", tag, arch, off, existing, name)
		}
		m[off] = name
	}
	return nil
}

var reDeferredMarkingStackBlock = regexp.MustCompile(
	`(?s)MarkingStackBlock\*\s+([A-Za-z0-9_]+)_\s*(?:=\s*nullptr)?\s*;\s*` +
		`MarkingStackBlock\*\s+deferred_marking_stack_block_\s*(?:=\s*nullptr)?\s*;\s*` +
		`uword(?:\s+volatile)?\s+vm_tag_`,
)

// fillDeferredMarkingStackBlock recovers a Thread field that the compiler
// offsets header does not export on some releases. This is still an exact SDK
// fact, not a handwritten exception: thread.h proves the declaration is exactly
// between another MarkingStackBlock* and vm_tag_, while the generated offsets
// header exports both surrounding anchors.
//
// SDK @3.2.5 runtime/vm/thread.h:1208-1213 declares
// marking_stack_block_, deferred_marking_stack_block_, vm_tag_ consecutively;
// runtime/vm/compiler/runtime_offsets_extracted.h:15031,15135 exports the two
// anchors as 0x710 and 0x720 for the PRODUCT ARM64 compressed target. Later SDKs
// use the same shape with new_marking_stack_block_ as the preceding anchor.
func fillDeferredMarkingStackBlock(m map[int]string, tag, arch string) error {
	src, err := fetchSDKFile("runtime/vm/thread.h", tag)
	if err != nil {
		return err
	}
	return fillDeferredMarkingStackBlockFromSource(m, tag, arch, src)
}

func fillDeferredMarkingStackBlockFromSource(m map[int]string, tag, arch, src string) error {
	if !strings.Contains(src, "deferred_marking_stack_block_") {
		return nil
	}
	match := reDeferredMarkingStackBlock.FindStringSubmatch(src)
	if match == nil {
		return fmt.Errorf("%s/%s: deferred_marking_stack_block_ exists but its exact declaration neighborhood is unrecognised", tag, arch)
	}
	prevName := match[1]
	prev, prevOK := -1, false
	vmTag, vmOK := -1, false
	for off, name := range m {
		switch name {
		case prevName:
			prev, prevOK = off, true
		case "vm_tag":
			vmTag, vmOK = off, true
		}
	}
	if !prevOK || !vmOK {
		return fmt.Errorf("%s/%s: deferred marking anchors missing: %s=%v vm_tag=%v", tag, arch, prevName, prevOK, vmOK)
	}
	span := vmTag - prev
	if span != 16 {
		return fmt.Errorf("%s/%s: %s..vm_tag span is %#x, want two 8-byte Thread slots", tag, arch, prevName, span)
	}
	off := prev + 8
	if existing, taken := m[off]; taken && existing != "deferred_marking_stack_block" {
		return fmt.Errorf("%s/%s: deferred marking conflict at 0x%x: header holds %q", tag, arch, off, existing)
	}
	m[off] = "deferred_marking_stack_block"
	return nil
}

func fillDerivedThreadFields(m map[int]string, tag, arch string) error {
	if err := fillCachedConstantFields(m, tag, arch); err != nil {
		return fmt.Errorf("cached constants: %w", err)
	}
	if err := fillRuntimeEntries(m, tag, arch); err != nil {
		return fmt.Errorf("runtime entries: %w", err)
	}
	if err := fillDeferredMarkingStackBlock(m, tag, arch); err != nil {
		return fmt.Errorf("deferred marking stack: %w", err)
	}
	return nil
}

// fillRuntimeEntries names the runtime-entry and leaf-runtime-entry blocks
// of a single extracted Thread table.
//
// runtime_offsets_extracted.h exports only ~31 of the ~100 entry points as
// their own constants -- the ones the compiler references by name. The rest
// exist in the struct but are anonymous in the header, so they can only be
// recovered from RUNTIME_ENTRY_LIST's declaration order. Both blocks are
// laid out contiguously in declaration order, and the SDK does export the
// first name of each block, which gives an exact anchor: no hand-typed base
// offset is involved on either side.
//
// This used to be done by ten hand-written mergeRuntimeEntries calls in
// runtimeentries.go, covering ten of the twenty-three ARM64 tables and none
// of the twenty-seven x64 ones. Every runtime-entry call site on x86_64
// therefore disassembled as an unnamed THR.fNN. Deriving it here instead
// covers both architectures and every variant by construction, because
// extractAll already visits each of them.
//
// Anything already carrying an SDK-exported name is left alone and reported:
// the predicted slot disagreeing with the header means the contiguity
// assumption has broken for that version, which must not be papered over by
// overwriting the header's own answer.
func fillRuntimeEntries(m map[int]string, tag, arch string) error {
	lists, ok := runtimeEntryCache[tag]
	if !ok {
		runtime, leaf, contiguous, err := sdkRuntimeEntriesFor(tag)
		if err != nil {
			lists.err = err
			runtimeEntryCache[tag] = lists
			return err
		}
		lists.runtime, lists.leaf, lists.contiguous = runtime, leaf, contiguous
		runtimeEntryCache[tag] = lists
	}
	if lists.err != nil {
		return lists.err
	}

	// Both target architectures are 64-bit, so entry points are 8 bytes
	// apart. The anchor lookups below are what actually keep this honest:
	// a wrong stride would collide with an SDK-named slot and be reported.
	const stride = 8

	byName := map[string]int{}
	for off, n := range m {
		byName[n] = off
	}
	runtimeAnchor := -1
	for _, block := range []struct {
		label string
		names []string
	}{{"runtime", lists.runtime}, {"leaf", lists.leaf}} {
		if len(block.names) == 0 {
			continue
		}
		anchor, ok := byName[block.names[0]+"_entry_point"]
		ffi, hasFFI := byName["exit_through_ffi"]
		switch {
		case ok:
		case block.label == "leaf" && hasFFI && !lists.contiguous:
			// When the leaf block is not adjacent to the runtime block it
			// starts immediately after exit_through_ffi, the last field
			// thread.h declares before it. On the three versions that do
			// export a leaf anchor, exit_through_ffi+stride reproduces it
			// exactly, so this is a checked rule rather than a guess.
			anchor = ffi + stride
		case block.label == "leaf" && runtimeAnchor >= 0 && lists.contiguous:
			// Most headers export no anchor for the leaf block at all,
			// which left every leaf entry unnamed on x64 even after the
			// runtime block was recovered. thread.h declares the two
			// blocks back to back on these versions -- which is a fact
			// leafFollowsRuntime reads from the SDK, not an assumption
			// about layout -- so the runtime block's own anchor plus its
			// length locates the leaf block exactly.
			anchor = runtimeAnchor + len(lists.runtime)*stride
		default:
			return fmt.Errorf("%s/%s: %s block anchor %q absent from the header",
				tag, arch, block.label, block.names[0]+"_entry_point")
		}
		if block.label == "runtime" {
			runtimeAnchor = anchor
		}
		for i, n := range block.names {
			off := anchor + i*stride
			want := n + "_entry_point"
			existing, taken := m[off]
			switch {
			case !taken:
				m[off] = want
			case existing != want:
				return fmt.Errorf("%s/%s: runtime-entry conflict at 0x%x: header holds %q, %s block predicts %q",
					tag, arch, off, existing, block.label, want)
			}
		}
	}
	return nil
}

// goStringSlice renders names as the body of a []string composite literal.
func goStringSlice(names []string) string {
	var b strings.Builder
	b.WriteString("[]string{\n")
	for i, n := range names {
		if i%3 == 0 {
			b.WriteString("\t")
		}
		fmt.Fprintf(&b, "%q, ", n)
		if i%3 == 2 {
			b.WriteString("\n")
		}
	}
	if len(names)%3 != 0 {
		b.WriteString("\n")
	}
	b.WriteString("}")
	return b.String()
}

// rewriteVarLiterals replaces the composite literal of every `var NAME =
// <literal>` in path for which gen has an entry.
//
// Only variables that already exist are touched. A generated table with
// no committed variable is reported rather than invented: adding one also
// means wiring it into a version switch, which is a decision, not a
// mechanical step.
func rewriteVarLiterals(path string, gen map[string]string) (rewritten int, missing []string, err error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return 0, nil, err
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return 0, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	seen := map[string]bool{}
	type edit struct {
		start, end int
		text       string
	}
	var edits []edit
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			name := vs.Names[0].Name
			text, want := gen[name]
			if !want {
				continue
			}
			lit, ok := vs.Values[0].(*ast.CompositeLit)
			if !ok {
				continue
			}
			seen[name] = true
			edits = append(edits, edit{
				start: fset.Position(lit.Pos()).Offset,
				end:   fset.Position(lit.End()).Offset,
				text:  text,
			})
		}
	}
	for name := range gen {
		if !seen[name] {
			missing = append(missing, name)
		}
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	out := string(src)
	for _, e := range edits {
		out = out[:e.start] + e.text + out[e.end:]
	}
	if len(edits) > 0 {
		// Format before writing, for the same reason runWrite does:
		// splicing literals back in by byte offset changes key widths, and
		// gofmt aligns each run to its widest key. This path was the one
		// that still left the reformatting to the caller, so regenerating
		// put stubnames.go, threadstubs.go and thrfields.go into the tree
		// unformatted -- straight into the CI gofmt gate.
		if formatted, ferr := format.Source([]byte(out)); ferr == nil {
			out = string(formatted)
		} else {
			fmt.Fprintf(os.Stderr, "write: %s: gofmt failed (%v), writing unformatted\n", path, ferr)
		}
		if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
			return 0, nil, err
		}
	}
	sort.Strings(missing)
	return len(edits), missing, nil
}

// writeStubTables regenerates the committed VM stub-name storage. Thread stub
// offsets are derived from THRFields at runtime and therefore have no second
// generated offset table to rewrite.

func stubNameStorageVar(tag string) string {
	switch tag {
	case "2.10.0":
		return "stubNames2100"
	case "2.12.0":
		return "stubNames2120"
	case "2.13.0":
		return "stubNames2130Base"
	case "2.14.0":
		return "stubNames2140"
	case "2.15.0":
		return "stubNames2150"
	case "2.16.0":
		return "stubNames2160"
	case "2.17.6":
		return "stubNames2176"
	case "2.18.0":
		return "stubNames2180"
	case "2.19.0":
		return "stubNames2190"
	case "3.0.5":
		return "stubNames305"
	case "3.1.0":
		return "stubNames310"
	case "3.2.5", "3.3.0":
		return "stubNames325"
	case "3.4.3":
		return "stubNames343"
	case "3.5.0":
		return "stubNames350"
	case "3.6.2":
		return "stubNames362"
	case "3.7.0":
		return "stubNames370"
	case "3.8.1":
		return "stubNames381"
	case "3.9.2":
		return "stubNames392"
	case "3.10.7":
		return "stubNames3109"
	case "3.11.0":
		return "stubNames3115"
	case "3.12.2":
		return "stubNames3122"
	case "3.13.0":
		return "stubNames3130"
	default:
		return ""
	}
}

func writeStubTables() int {
	genStubNames := map[string]string{}
	var failed []string

	for _, tag := range snapshot.SupportedVersions() {
		storage := stubNameStorageVar(tag)
		if storage == "" {
			failed = append(failed, fmt.Sprintf("stub-names %s: no committed storage mapping", tag))
			continue
		}
		if names, err := sdkStubNamesFor(tag); err != nil {
			failed = append(failed, fmt.Sprintf("stub-names %s: %v", tag, err))
		} else {
			generated := goStringSlice(names)
			if prev, exists := genStubNames[storage]; exists && prev != generated {
				failed = append(failed, fmt.Sprintf("stub-names %s: storage %s is shared by releases with different exact lists", tag, storage))
				continue
			}
			genStubNames[storage] = generated
		}
	}
	for _, f := range failed {
		fmt.Fprintf(os.Stderr, "write: ERROR %s\n", f)
	}
	if len(failed) > 0 {
		fmt.Fprintf(os.Stderr, "write: refusing partial stub-name rewrite after %d failure(s)\n", len(failed))
		return 1
	}

	n, missing, err := rewriteVarLiterals("internal/vmtables/stubnames.go", genStubNames)
	if err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		return 1
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "write: refusing incomplete stub-name rewrite; missing variables: %s\n", strings.Join(missing, " "))
		return 1
	}
	fmt.Printf("write: %d VM stub-name table(s) rewritten\n", n)
	return 0
}

// --- ObjectStore stub-field table generation ---

// runWriteObjectStoreStubs regenerates internal/vmtables/objectstorestubs.go:
// for every version whose ObjectStoreAOTFieldCount is committed, the index and
// name of each `RW(Code, <name>_stub)` field inside the serialized root range.
//
// This is the only route to an isolate stub's name. Their Code objects have a
// null owner, so the owner walk and the type-testing-stub namer both find
// nothing and they render as `sub_<pcOffset>` -- 85 of 8049 ranges on
// dart-3.9.2-gt-arm64, every one of them `_iso_stub_*` in the ELF symbol
// table, and called often enough to account for 639 of the 840
// `unresolvedCall` tokens the fidelity census counts.
//
// A version with no entry names nothing, exactly as VMStubNamesInImageOrder
// does: the table is a verified fact per version or it is absent.
func runWriteObjectStoreStubs() int {
	committed, err := committedFieldCounts()
	if err != nil {
		fmt.Fprintf(os.Stderr, "write-objectstore-stubs: %v\n", err)
		return 1
	}
	versions := snapshot.SupportedVersions()

	type entry struct {
		idx  int
		name string
	}
	byVersion := map[string][]entry{}
	recordFieldNamesIndex := map[string]int{}
	var failed []string
	for _, v := range versions {
		wantCount, ok := committed[v]
		if !ok {
			failed = append(failed, fmt.Sprintf("%s: supported version has no committed ObjectStoreAOTFieldCount", v))
			continue
		}
		names, _, err := objectStoreFields(v)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", v, err))
			continue
		}
		if len(names) != wantCount {
			failed = append(failed, fmt.Sprintf("%s: field count %d != committed %d", v, len(names), wantCount))
			continue
		}
		var es []entry
		for i, n := range names {
			if strings.HasSuffix(n, "_stub") {
				es = append(es, entry{i, n})
			}
			if n == "record_field_names" {
				recordFieldNamesIndex[v] = i
			}
		}
		byVersion[v] = es
		fmt.Fprintf(os.Stderr, "  %-12s %d stub fields of %d\n", v, len(es), len(names))
	}
	if len(failed) > 0 {
		for _, f := range failed {
			fmt.Fprintf(os.Stderr, "write-objectstore-stubs: ERROR %s\n", f)
		}
		fmt.Fprintf(os.Stderr, "write-objectstore-stubs: refusing partial output after %d failure(s)\n", len(failed))
		return 1
	}

	var b strings.Builder
	b.WriteString(`// Code generated by tools/extract_thr.go -write-objectstore-stubs. DO NOT EDIT.

package vmtables

// objectStoreStubField is one ` + "`RW(Code, <name>_stub)`" + ` entry in the
// isolate roots section: its index among the serialized ObjectStore fields,
// and the field's name.
type objectStoreStubField struct {
	Index int
	Name  string
}

// objectStoreStubFields is indexed by Dart version. Absent means "not
// verified for this version" -- callers must name nothing rather than guess.
var objectStoreStubFields = map[string][]objectStoreStubField{
`)
	for _, v := range versions {
		es, ok := byVersion[v]
		if !ok || len(es) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\t%q: {\n", v)
		for _, e := range es {
			fmt.Fprintf(&b, "\t\t{%d, %q},\n", e.idx, e.name)
		}
		b.WriteString("\t},\n")
	}
	b.WriteString("}\n\n")
	b.WriteString("// objectStoreRecordFieldNamesIndex is the serialized ObjectStore root\n")
	b.WriteString("// containing RecordShape's field-name arrays. Absent means the field is\n")
	b.WriteString("// outside the Full-AOT root range or does not exist in that SDK.\n")
	b.WriteString("var objectStoreRecordFieldNamesIndex = map[string]int{\n")
	for _, v := range versions {
		idx, ok := recordFieldNamesIndex[v]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "\t%q: %d,\n", v, idx)
	}
	b.WriteString("}\n")

	path := "internal/vmtables/objectstorestubs.go"
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write-objectstore-stubs: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "write-objectstore-stubs: wrote %s for %d version(s)\n", path, len(byVersion))
	return 0
}
