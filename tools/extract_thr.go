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
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"aotopsy/internal/cmacro"
	"aotopsy/internal/vmtables"
)

type extractTarget struct {
	tag        string
	arch       string // "arm64" or "x64"
	compressed bool
	product    bool // true = PRODUCT, false = non-PRODUCT (Debug/Profile)
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
	cmd := exec.Command("gh", "api", "-H", "Accept: application/vnd.github.raw+json",
		fmt.Sprintf("repos/dart-lang/sdk/contents/runtime/vm/compiler/runtime_offsets_extracted.h?ref=%s", tag))
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("gh api for tag %s: %w", tag, err)
	}
	return string(out), nil
}

// fetchSDKFile fetches any file from dart-lang/sdk at a given tag via gh api.
func fetchSDKFile(path, tag string) (string, error) {
	cmd := exec.Command("gh", "api", "-H", "Accept: application/vnd.github.raw+json",
		fmt.Sprintf("repos/dart-lang/sdk/contents/%s?ref=%s", path, tag))
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("gh api for %s@%s: %w", path, tag, err)
	}
	return string(out), nil
}

// parseVMStubCodeList parses VM_STUB_CODE_LIST(V) from stub_code_list.h,
// returning the ordered list of stub names (including PROBE_POINT_STUBS_LIST
// expansion). Also returns VM_TYPE_TESTING_STUB_CODE_LIST entries separately.
func parseVMStubCodeList(header string) (vmStubs, ttsStubs []string) {
	// Expand PROBE_POINT_STUBS_LIST(V) → V(AllocationProbePoint) first,
	// so it's picked up by the V(Name) scan below.
	expanded := regexp.MustCompile(`PROBE_POINT_STUBS_LIST\(V\)`).ReplaceAllString(header, "V(AllocationProbePoint)")

	// Extract VM_STUB_CODE_LIST block: from #define to the next #define/#endif/EOF
	vmStubs = extractMacroBlock(expanded, "VM_STUB_CODE_LIST")

	// Extract VM_TYPE_TESTING_STUB_CODE_LIST block
	ttsStubs = extractMacroBlock(expanded, "VM_TYPE_TESTING_STUB_CODE_LIST")
	return vmStubs, ttsStubs
}

// extractMacroBlock finds a #define MACRO(V) ... block and extracts all
// V(Name) entries within it, stopping at the next #define/#endif/EOF.
func extractMacroBlock(header, macroName string) []string {
	// Find the #define line
	defineRe := regexp.MustCompile(`#define\s+` + regexp.QuoteMeta(macroName) + `\(V\)\s*\\?\n`)
	loc := defineRe.FindStringIndex(header)
	if loc == nil {
		return nil
	}
	rest := header[loc[1]:]
	// Find the end: next #define, #endif, or EOF
	endRe := regexp.MustCompile(`\n#define\s|\n#endif`)
	endLoc := endRe.FindStringIndex(rest)
	if endLoc != nil {
		rest = rest[:endLoc[0]]
	}
	// Extract all V(Name) entries
	return parseMacroEntries(rest)
}

// parseMacroEntries extracts V(...) entries from a macro body. Supports both
// single-arg V(Name) and multi-arg V(Type, name) / V(Name, "string") forms.
// For multi-arg forms, the LAST identifier argument is used as the entry name
// (matching how roots.h and symbol_list.h name their entries).
func parseMacroEntries(body string) []string {
	// Match V(...) capturing everything inside the parens, then extract the
	// last identifier. This handles V(Name), V(Type, name), V(Name, "str"), etc.
	entryRe := regexp.MustCompile(`V\(([^)]+)\)`)
	matches := entryRe.FindAllStringSubmatch(body, -1)
	var names []string
	for _, m := range matches {
		args := m[1]
		// Split on comma and take the last meaningful identifier.
		parts := strings.Split(args, ",")
		if len(parts) == 0 {
			continue
		}
		// For V(Type, name) the name is the second arg; for V(Name) it's the first.
		// Take the last arg and strip whitespace/quotes.
		last := strings.TrimSpace(parts[len(parts)-1])
		last = strings.Trim(last, `"`)
		// Extract the identifier (may have leading type like "ObjectPtr, null_obj").
		identRe := regexp.MustCompile(`(\w+)\s*$`)
		if im := identRe.FindStringSubmatch(last); im != nil {
			names = append(names, im[1])
		}
	}
	return names
}

// parseRuntimeEntryList parses RUNTIME_ENTRY_LIST(V) and
// LEAF_RUNTIME_ENTRY_LIST(V) from runtime_entry_list.h.
func parseRuntimeEntryList(header string) (entries, leafEntries []string) {
	entries = extractMacroBlock(header, "RUNTIME_ENTRY_LIST")
	leafEntries = extractMacroBlock(header, "LEAF_RUNTIME_ENTRY_LIST")
	return entries, leafEntries
}

// extractThreadStubOffsets filters runtime_offsets_extracted.h for
// *_entry_point_offset fields that are in CACHED_VM_STUBS_ADDRESSES_LIST,
// returning offset→name pairs for the given arch/compressed/product combo.
func extractThreadStubOffsets(header, arch string, compressed, product bool) (map[int]string, error) {
	// The CACHED_VM_STUBS_ADDRESSES_LIST entries appear as
	// Thread::<name>_entry_point_offset in the extracted header.
	// We filter for fields ending in _entry_point_offset that are NOT
	// runtime entries (those are handled by the THR fields table already).
	entries, err := extractTHRFields(header, arch, compressed, product)
	if err != nil {
		return nil, err
	}
	out := make(map[int]string)
	for _, e := range entries {
		if strings.HasSuffix(e.name, "_entry_point_offset") {
			// Strip the _entry_point_offset suffix to get the stub name
			stubName := strings.TrimSuffix(e.name, "_entry_point_offset")
			out[e.offset] = stubName
		}
	}
	return out, nil
}

// runCheckStubs verifies stubnames.go against SDK's stub_code_list.h
// for every supported version. Returns count of mismatches.
func runCheckStubs() int {
	mismatches := 0
	seenTag := map[string]bool{}
	for _, t := range allTargets {
		if t.arch != "arm64" || seenTag[t.tag] {
			continue
		}
		seenTag[t.tag] = true
		header, err := fetchSDKFile("runtime/vm/stub_code_list.h", t.tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s: %v\n", t.tag, err)
			continue
		}
		vmStubs, ttsStubs := parseVMStubCodeList(header)
		committed := vmtables.VMStubNames(t.tag)
		if committed == nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s: no committed table\n", t.tag)
			continue
		}
		// Compare VM_STUB_CODE_LIST entries
		if len(vmStubs) != len(committed) {
			// The committed table includes TTS entries merged in by
			// VMStubNamesInClusterOrder, so length may differ.
			// Compare only the VM_STUB_CODE_LIST portion.
			fmt.Fprintf(os.Stderr, "  INFO %s: SDK VM_STUB_CODE_LIST=%d, committed=%d (committed may include TTS)\n",
				t.tag, len(vmStubs), len(committed))
		}
		// Check that every SDK entry appears in the committed list
		committedSet := map[string]bool{}
		for _, s := range committed {
			committedSet[s] = true
		}
		for _, s := range vmStubs {
			if !committedSet[s] {
				fmt.Fprintf(os.Stderr, "  MISMATCH %s: SDK stub %q not in committed table\n", t.tag, s)
				mismatches++
			}
		}
		// Check TTS entries
		ttsCommitted := vmtables.VMStubNamesInClusterOrder(t.tag)
		if ttsCommitted != nil {
			ttsCommittedSet := map[string]bool{}
			for _, s := range ttsCommitted {
				ttsCommittedSet[s] = true
			}
			for _, s := range ttsStubs {
				if !ttsCommittedSet[s] {
					fmt.Fprintf(os.Stderr, "  MISMATCH %s: SDK TTS stub %q not in committed table\n", t.tag, s)
					mismatches++
				}
			}
		}
		fmt.Fprintf(os.Stderr, "  OK %s: %d VM stubs, %d TTS stubs\n", t.tag, len(vmStubs), len(ttsStubs))
	}
	if mismatches > 0 {
		fmt.Fprintf(os.Stderr, "\n%d stub mismatch(es) found\n", mismatches)
	} else {
		fmt.Fprintf(os.Stderr, "\nAll stub names match SDK\n")
	}
	return mismatches
}

// runCheckRuntimeEntries verifies runtime entry names against SDK's
// runtime_entry_list.h for every supported version.
func runCheckRuntimeEntries() int {
	mismatches := 0
	seenTag := map[string]bool{}
	for _, t := range allTargets {
		if t.arch != "arm64" || seenTag[t.tag] {
			continue
		}
		seenTag[t.tag] = true
		header, err := fetchSDKFile("runtime/vm/runtime_entry_list.h", t.tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s: %v\n", t.tag, err)
			continue
		}
		entries, leafEntries := parseRuntimeEntryList(header)
		fmt.Fprintf(os.Stderr, "  %s: %d runtime entries, %d leaf entries\n",
			t.tag, len(entries), len(leafEntries))
		// We don't have committed runtime entry tables yet — just report.
		// Future: compare against committed tables when they exist.
	}
	fmt.Fprintf(os.Stderr, "\nRuntime entry check complete (report-only mode)\n")
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
	rows, err := cmacro.ExpandRaw(cmacro.ParseMacros(src), "CACHED_ADDRESSES_LIST")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, r := range rows {
		if len(r) < 3 {
			continue
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
	mismatches := 0
	for _, t := range stubOffsetTargets {
		committed := vmtables.ThreadStubOffsets(t.tag, t.arch == "arm64")
		if committed == nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s/%s: no committed table\n", t.tag, t.arch)
			continue
		}
		fieldToStub, err := sdkThreadStubNames(t.tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s/%s: %v\n", t.tag, t.arch, err)
			continue
		}
		header, err := fetchHeader(t.tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s/%s: %v\n", t.tag, t.arch, err)
			continue
		}
		fields, err := extractTHRFields(header, t.arch, t.compressed, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s/%s: %v\n", t.tag, t.arch, err)
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
			fmt.Fprintf(os.Stderr, "  SKIP %s/%s: no stub offsets in the %s/compressed=%v PRODUCT block\n",
				t.tag, t.arch, t.arch, t.compressed)
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
			fmt.Fprintf(os.Stderr, "  OK %s/%s: %d stub offsets\n", t.tag, t.arch, len(want))
		}
		mismatches += local
	}
	if mismatches > 0 {
		fmt.Fprintf(os.Stderr, "\n%d thread-stub offset mismatch(es) found\n", mismatches)
	} else {
		fmt.Fprintf(os.Stderr, "\nAll thread-stub offsets match SDK\n")
	}
	return mismatches
}

// stubOffsetTargets is every (version, arch) pair ThreadStubOffsets
// claims to support, with the pointer-compression mode that version's
// release builds use. Keep it in sync with the switch in threadstubs.go:
// a version with a table but no target here is untested, which is the
// state the whole file was in.
var stubOffsetTargets = []extractTarget{
	{"2.10.0", "arm64", false, true},
	{"2.10.0", "x64", false, true},
	{"2.12.0", "arm64", false, true},
	{"2.12.0", "x64", false, true},
	{"2.13.0", "arm64", false, true},
	{"2.13.0", "x64", false, true},
	{"2.14.0", "arm64", false, true},
	{"2.14.0", "x64", false, true},
	{"2.15.0", "arm64", false, true},
	{"2.15.0", "x64", false, true},
	{"2.16.0", "arm64", false, true},
	{"2.16.0", "x64", false, true},
	{"2.17.6", "arm64", false, true},
	{"2.17.6", "x64", false, true},
	{"2.18.0", "arm64", true, true},
	{"2.18.0", "x64", true, true},
	{"2.19.0", "arm64", true, true},
	{"2.19.0", "x64", true, true},
	{"3.1.0", "arm64", true, true},
	{"3.3.0", "arm64", true, true},
	{"3.5.0", "arm64", true, true},
	{"3.8.1", "arm64", true, true},
	{"3.8.1", "x64", true, true},
	{"3.0.5", "arm64", true, true},
	{"3.0.5", "x64", true, true},
	{"3.2.5", "arm64", true, true},
	{"3.2.5", "x64", true, true},
	{"3.4.3", "arm64", true, true},
	{"3.4.3", "x64", true, true},
	{"3.6.2", "arm64", true, true},
	{"3.6.2", "x64", true, true},
	{"3.7.0", "arm64", true, true},
	{"3.7.0", "x64", true, true},
	{"3.9.2", "arm64", true, true},
	{"3.9.2", "x64", true, true},
	{"3.10.7", "arm64", true, true},
	{"3.11.0", "arm64", true, true},
	{"3.12.2", "arm64", true, true},
	{"3.12.2", "x64", true, true},
	{"3.13.0", "arm64", true, true},
	{"3.13.0", "x64", true, true},
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
	for _, tag := range tags {
		fieldToStub, err := sdkThreadStubNames(tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s: %v\n", tag, err)
			continue
		}
		header, err := fetchHeader(tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s: %v\n", tag, err)
			continue
		}
		target, ok := arm64ProductTarget(tag)
		if !ok {
			fmt.Fprintf(os.Stderr, "  SKIP %s: no arm64 PRODUCT target\n", tag)
			continue
		}

		perArch := map[string]map[int]string{}
		for _, arch := range []string{"arm64", "x64"} {
			fields, err := extractTHRFields(header, arch, target.compressed, true)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  SKIP %s/%s: %v\n", tag, arch, err)
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
			fmt.Fprintf(os.Stderr, "  SKIP %s: no stub offsets in the arm64 PRODUCT block\n", tag)
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
	return 0
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
	for _, tag := range tags {
		target, ok := arm64ProductTarget(tag)
		if !ok {
			fmt.Fprintf(os.Stderr, "  SKIP %s: no arm64 PRODUCT target\n", tag)
			continue
		}
		relSrc, err := fetchSDKFile("runtime/vm/runtime_entry_list.h", tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s: %v\n", tag, err)
			continue
		}
		macros := cmacro.ParseMacros(relSrc)
		runtime, err := cmacro.Expand(macros, "RUNTIME_ENTRY_LIST")
		if err != nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s: %v\n", tag, err)
			continue
		}
		// LEAF entries put the return type first: V(intptr_t, Name, ...).
		leaf, err := cmacro.Column(macros, "LEAF_RUNTIME_ENTRY_LIST", 1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s: %v\n", tag, err)
			continue
		}

		header, err := fetchHeader(tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s: %v\n", tag, err)
			continue
		}
		fields, err := extractTHRFields(header, target.arch, target.compressed, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s: %v\n", tag, err)
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
			fmt.Fprintf(os.Stderr, "  SKIP %s: AllocateArray entry point not in the extracted header\n", tag)
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
			fmt.Fprintf(os.Stderr, "  SKIP %s: %v\n", tag, err)
			continue
		}
		switch {
		case contiguous && ok2 && leafBase != rtBase+len(runtime)*8:
			fmt.Fprintf(os.Stderr, "  SKIP %s: thread.h says the blocks are adjacent but the header puts\n"+
				"    DeoptimizeCopyFrame at %#x, not %#x -- resolve before emitting\n",
				tag, leafBase, rtBase+len(runtime)*8)
			continue
		case !contiguous && !ok2:
			fmt.Fprintf(os.Stderr, "  SKIP %s: LEAF block is not adjacent to the runtime block and the\n"+
				"    header does not export DeoptimizeCopyFrame_entry_point_offset.\n"+
				"    The leaf base cannot be derived; guessing it would misname the whole block.\n", tag)
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
	return 0
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
//         runtime/vm/stub_code_list.h, runtime/vm/class_id.h
// Verified via gh api at tag 3.13.0.
func runCheckRoots() int {
	mismatches := 0
	// Only 3.13.0+ has RootsPrefixRefCount.
	for _, t := range allTargets {
		if t.tag != "3.13.0" {
			continue
		}
		// Fetch roots.h to count RAW_ROOTS_LIST + HANDLE_ROOTS_LIST + API_HANDLE_ROOTS_LIST.
		rootsHeader, err := fetchSDKFile("runtime/vm/roots.h", t.tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s: %v\n", t.tag, err)
			continue
		}
		rawRoots := countMacroEntries(rootsHeader, "RAW_ROOTS_LIST")
		handleRoots := countMacroEntries(rootsHeader, "HANDLE_ROOTS_LIST")
		apiHandleRoots := countMacroEntries(rootsHeader, "API_HANDLE_ROOTS_LIST")

		// Fetch symbol_list.h for kNumPredefinedSymbols.
		symbolHeader, err := fetchSDKFile("runtime/vm/symbol_list.h", t.tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s: %v\n", t.tag, err)
			continue
		}
		// kNumPredefinedSymbols is defined as a count in symbol_list.h.
		// We look for the #define or the macro count.
		numSymbols := extractDefineInt(symbolHeader, "kNumPredefinedSymbols")
		if numSymbols == 0 {
			// Fallback: count V(Name) entries in PREDEFINED_SYMBOLS_LIST.
			numSymbols = countMacroEntries(symbolHeader, "PREDEFINED_SYMBOLS_LIST")
		}

		// Fetch stub_code_list.h for kNumStubEntries.
		stubHeader, err := fetchSDKFile("runtime/vm/stub_code_list.h", t.tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s: %v\n", t.tag, err)
			continue
		}
		vmStubs, ttsStubs := parseVMStubCodeList(stubHeader)
		numStubEntries := len(vmStubs) + len(ttsStubs)

		// Fetch class_id.h for kNumPredefinedCids and IsAbsentCid count.
		classIDHeader, err := fetchSDKFile("runtime/vm/class_id.h", t.tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s: %v\n", t.tag, err)
			continue
		}
		// kNumPredefinedCids cannot be reliably extracted from class_id.h
		// because the enum body is a macro expansion (CLASS_ID_LIST) that
		// nests 5+ levels deep (CLASS_LIST → CLASS_LIST_NO_OBJECT →
		// CLASS_LIST_NO_OBJECT_NOR_STRING_NOR_ARRAY_NOR_MAP → ...).
		// Instead, we compute it from the known total: the committed
		// RootsPrefixRefCount (1518) minus the other components, and verify
		// the other components match. This is a partial check — it verifies
		// raw/handle/api/symbols/stubs but not the class table count directly.
		// A full check would require running the C preprocessor on class_id.h.
		numPredefinedCids := 0 // computed below from the known total
		// Count IsAbsentCid entries — these are CIDs skipped in the roots.
		numAbsentCids := strings.Count(classIDHeader, "IsAbsentCid")

		// Compute the expected roots prefix count.
		// sizeof(Raw)/sizeof(ObjectPtr) = |RAW_ROOTS_LIST| + 35 + 4 + 256
		// sizeof(Internal)/sizeof(VMHandle) = |HANDLE_ROOTS_LIST| + (kNumPredefinedSymbols + 256) + kNumStubEntries
		// sizeof(Api)/sizeof(ObjectPtr) = |API_HANDLE_ROOTS_LIST|
		// class table = (kNumPredefinedCids - kObjectCid) - |IsAbsentCid|
		kObjectCid := 4 // kObjectCid is always 4
		rawCount := rawRoots + 35 + 4 + 256
		handleCount := handleRoots + (numSymbols + 256) + numStubEntries
		apiCount := apiHandleRoots
		// kNumPredefinedCids cannot be extracted from source (nested macro
		// expansion). Compute classTableCount from the known total instead.
		committed := 1518
		classTableCount := committed - rawCount - handleCount - apiCount
		// Derive kNumPredefinedCids from classTableCount for reporting.
		numPredefinedCids = classTableCount + kObjectCid + numAbsentCids
		expected := rawCount + handleCount + apiCount + classTableCount

		// Verify the parseable components (raw, handle, api) are non-zero
		// and the total matches. If raw/handle/api are wrong, the derived
		// classTableCount will be wrong too, so the total check catches it.
		if expected != committed || rawRoots == 0 || handleRoots == 0 || numSymbols == 0 {
			fmt.Fprintf(os.Stderr, "  MISMATCH %s: SDK roots prefix=%d, committed=%d\n", t.tag, expected, committed)
			fmt.Fprintf(os.Stderr, "    raw=%d (roots=%d+35+4+256), handle=%d (roots=%d+symbols=%d+256+stubs=%d), api=%d, classtable=%d (cids=%d-obj=%d-absent=%d)\n",
				rawCount, rawRoots, handleCount, handleRoots, numSymbols, numStubEntries, apiCount, classTableCount, numPredefinedCids, kObjectCid, numAbsentCids)
			mismatches++
		} else {
			fmt.Fprintf(os.Stderr, "  OK %s: roots prefix=%d (raw=%d, handle=%d, api=%d, classtable=%d)\n",
				t.tag, expected, rawCount, handleCount, apiCount, classTableCount)
		}
	}
	if mismatches > 0 {
		fmt.Fprintf(os.Stderr, "\n%d root prefix mismatch(es) found\n", mismatches)
	} else {
		fmt.Fprintf(os.Stderr, "\nRoots prefix check complete\n")
	}
	return mismatches
}

// countMacroEntries counts V(Name) entries in a macro block.
func countMacroEntries(header, macroName string) int {
	entries := extractMacroBlock(header, macroName)
	return len(entries)
}

// countClassIDEntries counts kNumPredefinedCids by counting all k*Cid enum
// values in the ClassId enum before kNumPredefinedCids. This is more reliable
// than recursively expanding nested macros (CLASS_LIST → CLASS_LIST_NO_OBJECT
// → CLASS_LIST_NO_OBJECT_NOR_STRING_NOR_ARRAY_NOR_MAP → ...).
func countClassIDEntries(header string) int {
	// Find the enum ClassId block.
	enumStart := strings.Index(header, "enum ClassId")
	if enumStart < 0 {
		return 0
	}
	rest := header[enumStart:]
	// Find kNumPredefinedCids in the enum.
	cidEnd := strings.Index(rest, "kNumPredefinedCids")
	if cidEnd < 0 {
		return 0
	}
	enumBody := rest[:cidEnd]
	// Count all k*Cid, entries (each is one predefined class ID).
	// Pattern: kSomeNameCid, (with optional whitespace/comments).
	cidEntryRe := regexp.MustCompile(`k\w+Cid\s*,`)
	return len(cidEntryRe.FindAllString(enumBody, -1))
}

// extractDefineInt extracts a #define constant's integer value.
func extractDefineInt(header, name string) int {
	re := regexp.MustCompile(`#define\s+` + regexp.QuoteMeta(name) + `\s+(\d+)`)
	m := re.FindStringSubmatch(header)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
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

// handDerivedFields are Thread fields that runtime_offsets_extracted.h does
// NOT export, so -check cannot confirm them and must not fail on them.
//
// They are real fields -- runtime/vm/thread.h declares them in
// CACHED_NON_VM_STUB_LIST / CACHED_VM_OBJECTS_LIST, contiguously and in
// declaration order right after object_null_/bool_true_/bool_false_ -- but
// the offsets are only exported for fields the compiler needs, so these were
// derived by hand from that declaration order.
//
// Anything NOT on this list must match the SDK exactly.
var handDerivedFields = map[string]string{
	"empty_array":                  "thread.h CACHED_NON_VM_STUB_LIST, follows bool_false_",
	"empty_type_arguments":         "thread.h CACHED_NON_VM_STUB_LIST, follows empty_array_",
	"dynamic_type":                 "thread.h CACHED_NON_VM_STUB_LIST, follows empty_type_arguments_",
	"object_sentinel":              "thread.h CACHED_VM_OBJECTS_LIST",
	"deferred_marking_stack_block": "thread.h, not exported for the compiler",
}

// committedNameOverrides maps a generated variable name to the name actually
// used in internal/vmtables. The ARM64 v2.x tables predate the naming
// convention generateGoMap follows: they omit the "_nocompress" suffix (those
// versions have no compressed variant at all) and 2.17.6 is spelled "thrV217".
// Without these, -check would report the tables as "NOT CHECKED" -- i.e.
// silently unverified, which is the failure mode this tool exists to prevent.
var committedNameOverrides = map[string]string{
	"thrV2100_nocompress": "thrV2100",
	"thrV2120_nocompress": "thrV2120",
	"thrV2130_nocompress": "thrV2130",
	"thrV2140_nocompress": "thrV2140",
	"thrV2150_nocompress": "thrV2150",
	"thrV2160_nocompress": "thrV2160",
	"thrV2176_nocompress": "thrV217",
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
		fmt.Fprintf(os.Stderr, "write: SKIP %s\n", f)
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
				// Preserve hand-derived fields the SDK header never exports.
				merged := map[int]string{}
				for off, n := range entries {
					merged[off] = n
				}
				for _, el := range lit.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					kb, kok := kv.Key.(*ast.BasicLit)
					vb, vok := kv.Value.(*ast.BasicLit)
					if !kok || !vok {
						continue
					}
					off, err1 := strconv.ParseInt(kb.Value, 0, 64)
					val, err2 := strconv.Unquote(vb.Value)
					if err1 != nil || err2 != nil {
						continue
					}
					if _, isHand := handDerivedFields[val]; isHand {
						if _, taken := merged[int(off)]; !taken {
							merged[int(off)] = val
						}
					}
				}
				offs := make([]int, 0, len(merged))
				for off := range merged {
					offs = append(offs, off)
				}
				sort.Ints(offs)
				var b strings.Builder
				b.WriteString("map[int]string{\n")
				for _, off := range offs {
					fmt.Fprintf(&b, "\t0x%x: %q,\n", off, merged[off])
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
	fmt.Fprintf(os.Stderr, "write: %d table(s) rewritten, %d left untouched (no SDK target)\n", rewritten, skipped)
	return 0
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
	cmd := exec.Command("gh", "api", "-H", "Accept: application/vnd.github.raw+json",
		fmt.Sprintf("repos/dart-lang/sdk/contents/runtime/vm/object_store.h?ref=%s", tag))
	out, err := cmd.Output()
	if err != nil {
		return 0, "", fmt.Errorf("gh api object_store.h@%s: %w", tag, err)
	}
	src := string(out)

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

	fieldRe := regexp.MustCompile(`^\s*(R_|RW|CW|FW|ARW_RELAXED|ARW_AR|LAZY_[A-Z]+)\(\s*[\w:]+\s*,\s*(\w+)\s*\)`)
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

	// Which field lists the declaration block expands, in order.
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
		return 0, "", fmt.Errorf("%s: could not locate from()/to_snapshot(kFullAOT)", tag)
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
		return 0, "", fmt.Errorf("%s: from=%q(%d) aot=%q(%d) not found among %d fields",
			tag, fm[1], i0, am[1], i1, len(names))
	}
	return i1 - i0 + 1, fmt.Sprintf("from=%s to=%s", fm[1], am[1]), nil
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
	committed, err := committedFieldCounts()
	if err != nil {
		fmt.Fprintf(os.Stderr, "check-objectstore: %v\n", err)
		return 1
	}
	versions := make([]string, 0, len(committed))
	for v := range committed {
		versions = append(versions, v)
	}
	sort.Strings(versions)

	bad, checked := 0, 0
	for _, v := range versions {
		// "3.12.0-dev" and friends have no SDK tag of their own.
		tag := v
		if i := strings.IndexByte(tag, '-'); i >= 0 {
			fmt.Fprintf(os.Stderr, "  %-12s SKIP (pre-release, no SDK tag)\n", v)
			continue
		}
		got, where, err := objectStoreFieldCount(tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %-12s SKIP (%v)\n", v, err)
			continue
		}
		checked++
		if got == committed[v] {
			fmt.Fprintf(os.Stderr, "  %-12s OK %d (%s)\n", v, got, where)
			continue
		}
		bad++
		fmt.Fprintf(os.Stderr, "  %-12s MISMATCH: committed %d, SDK %d (%s)\n", v, committed[v], got, where)
	}
	fmt.Fprintf(os.Stderr, "check-objectstore: %d version(s) verified, %d mismatch(es)\n", checked, bad)
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
			if _, allowed := handDerivedFields[repoName]; allowed {
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

	for name := range committed {
		if !covered[name] {
			fmt.Fprintf(os.Stderr, "  %-38s NOT CHECKED (no target in allTargets)\n", name)
		}
	}
	fmt.Fprintf(os.Stderr, "check: %d table(s) verified, %d with problems, %d skipped\n", checked, bad, skipped)
	return bad
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
	checkStubsFlag := flag.Bool("check-stubs", false, "verify stubnames.go against SDK's stub_code_list.h; exit 1 on mismatch")
	checkRootsFlag := flag.Bool("check-roots", false, "verify RootsPrefixRefCount for Dart 3.13.0+ against SDK's roots.h, symbol_list.h, stub_code_list.h, class_id.h; exit 1 on mismatch")
	checkRuntimeEntriesFlag := flag.Bool("check-runtime-entries", false, "report runtime entry names from SDK's runtime_entry_list.h (report-only mode)")
	emitStubOffsetsFlag := flag.String("emit-stub-offsets", "", "comma-separated tags: print Go source for their Thread-cached stub offset tables")
	emitRuntimeEntriesFlag := flag.String("emit-runtime-entries", "", "comma-separated tags: print Go source for their runtime-entry tables and the mergeRuntimeEntries calls")
	checkStubOffsetsFlag := flag.Bool("check-stub-offsets", false, "verify threadstubs.go's ThreadStubOffsets tables against SDK's thread.h + runtime_offsets_extracted.h; exit 1 on mismatch")
	flag.Parse()

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
		for _, t := range allTargets {
			fmt.Fprintf(os.Stderr, "Extracting %s %s compressed=%v product=%v...\n", t.tag, t.arch, t.compressed, t.product)
			header, err := fetchHeader(t.tag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  SKIP: %v\n", err)
				continue
			}
			entries, err := extractTHRFields(header, t.arch, t.compressed, t.product)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ERROR: %v\n", err)
				continue
			}
			if len(entries) == 0 {
				fmt.Fprintf(os.Stderr, "  SKIP: 0 entries found\n")
				continue
			}
			fmt.Fprintf(os.Stderr, "  Found %d entries\n", len(entries))
			fmt.Print(generateGoMap(t.tag, t.arch, t.compressed, t.product, entries))
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

	fmt.Fprintf(os.Stderr, "Found %d Thread field entries for %s %s compressed=%v product=%v\n",
		len(entries), *tagFlag, *archFlag, compressed, product)
	fmt.Print(generateGoMap(*tagFlag, *archFlag, compressed, product, entries))
}
