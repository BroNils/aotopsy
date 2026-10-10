package sdk

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
	"aotopsy/internal/snapshot"
)

var reAOTClosureEntry = regexp.MustCompile(`AOT_Closure_entry_point_offset\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;`)

// TestClosureEntryPointDispMatchesSDK re-derives ClosureEntryPointDisp from
// runtime/vm/compiler/runtime_offsets_extracted.h at every supported tag:
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/sdk/ -run ClosureEntryPointDispMatchesSDK
//
// The header spells the value per architecture and per DART_COMPRESSED_POINTERS;
// the untagged AOT_Closure_entry_point_offset is 56/32 up to 3.12.2 and 8 from
// 3.13.0, and the symbol does not exist before 2.14.0 (no cached entry point).
func TestClosureEntryPointDispMatchesSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	for _, tag := range snapshot.SupportedVersions() {
		tag := tag
		t.Run(tag, func(t *testing.T) {
			src, err := sdktest.SDKFileAtTag("runtime/vm/compiler/runtime_offsets_extracted.h", tag)
			if err != nil {
				t.Fatal(err)
			}
			values := aotClosureEntryOffsets(src)
			if !snapshot.VersionAtLeast(tag, "2.14.0") {
				if len(values) != 0 {
					t.Fatalf("%s: SDK defines AOT_Closure_entry_point_offset but ClosureEntryPointDisp reports none: %v", tag, values)
				}
				for _, compressed := range []bool{false, true} {
					if _, ok := ClosureEntryPointDisp(tag, compressed); ok {
						t.Fatalf("ClosureEntryPointDisp(%s, %v) reported a displacement before Closure.entry_point_ exists", tag, compressed)
					}
				}
				return
			}
			for _, key := range []string{"x64/uncompressed", "arm64/uncompressed", "x64/compressed", "arm64/compressed"} {
				got, ok := values[key]
				if !ok || len(got) != 1 {
					t.Fatalf("%s: %s AOT_Closure_entry_point_offset = %v, want exactly one value", tag, key, got)
				}
				var want int
				for v := range got {
					want = v
				}
				disp, ok := ClosureEntryPointDisp(tag, strings.HasSuffix(key, "/compressed"))
				if !ok || disp != want-HeapObjectTag {
					t.Fatalf("%s %s: ClosureEntryPointDisp = %d (ok=%v), SDK says untagged %d -> tagged %d", tag, key, disp, ok, want, want-HeapObjectTag)
				}
			}
		})
	}
}

// aotClosureEntryOffsets maps "<arch>/<compression>" to the set of untagged
// AOT_Closure_entry_point_offset values defined under matching #if blocks.
func aotClosureEntryOffsets(src string) map[string]map[int]bool {
	out := map[string]map[int]bool{}
	lines := strings.Split(src, "\n")
	cond := ""
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if strings.HasPrefix(line, "#if") || strings.HasPrefix(line, "#elif") {
			c := line
			for strings.HasSuffix(c, "\\") && i+1 < len(lines) {
				i++
				c = strings.TrimSuffix(c, "\\") + " " + strings.TrimSpace(lines[i])
			}
			cond = c
			continue
		}
		if !strings.Contains(line, "AOT_Closure_entry_point_offset") {
			continue
		}
		text := line
		if !reAOTClosureEntry.MatchString(text) && i+1 < len(lines) {
			text += " " + lines[i+1]
		}
		m := reAOTClosureEntry.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		v, err := strconv.ParseInt(m[1], 0, 64)
		if err != nil {
			continue
		}
		arch := ""
		switch {
		case strings.Contains(cond, "TARGET_ARCH_X64"):
			arch = "x64"
		case strings.Contains(cond, "TARGET_ARCH_ARM64"):
			arch = "arm64"
		default:
			continue
		}
		comp := "uncompressed"
		if strings.Contains(cond, "defined(DART_COMPRESSED_POINTERS)") && !strings.Contains(cond, "!defined(DART_COMPRESSED_POINTERS)") {
			comp = "compressed"
		}
		key := arch + "/" + comp
		if out[key] == nil {
			out[key] = map[int]bool{}
		}
		out[key][int(v)] = true
	}
	return out
}
