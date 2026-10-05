package typetrack

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"aotopsy/internal/sdk"
	"aotopsy/internal/sdktest"
	"aotopsy/internal/snapshot"
)

var (
	aotArgsDescCountRE = regexp.MustCompile(`AOT_ArgumentsDescriptor_count_offset\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)\s*;`)
	aotClosureFuncRE   = regexp.MustCompile(`AOT_Closure_function_offset\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)\s*;`)
	aotClosureEntryRE  = regexp.MustCompile(`AOT_Closure_entry_point_offset\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)\s*;`)
)

// TestArgumentsDescriptorCountOffsetMatchesSDK guards the tagged displacement
// used by receiver recovery against the generated AOT runtime-offset tables.
// In particular, 64-bit compressed snapshots use 0x14 rather than the 0x10
// offset of a true 32-bit target.
func TestArgumentsDescriptorCountOffsetMatchesSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	for _, tag := range snapshot.SupportedVersions() {
		tag := tag
		t.Run(tag, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(tag)
			if profile == nil {
				t.Fatalf("missing profile %s", tag)
			}
			src, err := sdktest.SDKFileAtTag("runtime/vm/compiler/runtime_offsets_extracted.h", tag)
			if err != nil {
				t.Fatal(err)
			}
			for _, arch := range []string{"ARM64", "X64"} {
				want, err := sdkAOTArgumentsDescriptorCountOffset(src, arch, false)
				if err != nil {
					t.Fatal(err)
				}
				ctx := &TypeContext{WordSize: 8, DartVersion: tag}
				disp, ok := argumentsDescriptorCountDisp(ctx)
				if !ok || disp+sdk.HeapObjectTag != want {
					t.Fatalf("%s uncompressed count offset = %#x, SDK=%#x", arch, disp+sdk.HeapObjectTag, want)
				}

				if profile.CompressionFeatures == snapshot.CompressionFeatureFixedUncompressed {
					continue
				}
				wantCompressed, err := sdkAOTArgumentsDescriptorCountOffset(src, arch, true)
				if err != nil {
					t.Fatal(err)
				}
				ctx = &TypeContext{DartVersion: tag, WordSize: 4, CompressedPointers: true}
				disp, ok = argumentsDescriptorCountDisp(ctx)
				if !ok || disp+sdk.HeapObjectTag != wantCompressed {
					t.Fatalf("%s compressed count offset = %#x, SDK=%#x", arch, disp+sdk.HeapObjectTag, wantCompressed)
				}
			}
		})
	}
}

func TestClosureFunctionOffsetMatchesSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	for _, tag := range snapshot.SupportedVersions() {
		tag := tag
		t.Run(tag, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(tag)
			if profile == nil {
				t.Fatalf("missing profile %s", tag)
			}
			src, err := sdktest.SDKFileAtTag("runtime/vm/compiler/runtime_offsets_extracted.h", tag)
			if err != nil {
				t.Fatal(err)
			}
			for _, arch := range []string{"ARM64", "X64"} {
				want, err := sdkAOTRuntimeOffset(src, arch, false, aotClosureFuncRE, "Closure_function")
				if err != nil {
					t.Fatal(err)
				}
				ctx := &TypeContext{DartVersion: tag, WordSize: 8}
				if got := closureFunctionOffset(ctx) + sdk.HeapObjectTag; got != want {
					t.Fatalf("%s uncompressed Closure.function offset = %#x, SDK=%#x", arch, got, want)
				}
				if snapshot.VersionAtLeast(tag, "2.14.0") {
					wantEntry, err := sdkAOTRuntimeOffset(src, arch, false, aotClosureEntryRE, "Closure_entry_point")
					if err != nil {
						t.Fatal(err)
					}
					if got := closureEntryPointOffset(ctx) + sdk.HeapObjectTag; got != wantEntry {
						t.Fatalf("%s uncompressed Closure.entry_point offset = %#x, SDK=%#x", arch, got, wantEntry)
					}
				}
				if profile.CompressionFeatures == snapshot.CompressionFeatureFixedUncompressed {
					continue
				}
				wantCompressed, err := sdkAOTRuntimeOffset(src, arch, true, aotClosureFuncRE, "Closure_function")
				if err != nil {
					t.Fatal(err)
				}
				ctx = &TypeContext{WordSize: 4, CompressedPointers: true, DartVersion: tag}
				if got := closureFunctionOffset(ctx) + sdk.HeapObjectTag; got != wantCompressed {
					t.Fatalf("%s compressed Closure.function offset = %#x, SDK=%#x", arch, got, wantCompressed)
				}
				if snapshot.VersionAtLeast(tag, "2.14.0") {
					wantEntry, err := sdkAOTRuntimeOffset(src, arch, true, aotClosureEntryRE, "Closure_entry_point")
					if err != nil {
						t.Fatal(err)
					}
					if got := closureEntryPointOffset(ctx) + sdk.HeapObjectTag; got != wantEntry {
						t.Fatalf("%s compressed Closure.entry_point offset = %#x, SDK=%#x", arch, got, wantEntry)
					}
				}
			}
		})
	}
}

func sdkAOTArgumentsDescriptorCountOffset(src, arch string, compressed bool) (int, error) {
	return sdkAOTRuntimeOffset(src, arch, compressed, aotArgsDescCountRE, "ArgumentsDescriptor_count")
}

func sdkAOTRuntimeOffset(src, arch string, compressed bool, fieldRE *regexp.Regexp, fieldName string) (int, error) {
	logical := strings.ReplaceAll(src, "\\\r\n", "")
	logical = strings.ReplaceAll(logical, "\\\n", "")
	// Newer generated headers wrap some `name = value;` assignments after the
	// equals sign without a C preprocessor continuation. Collapse only that
	// formatting newline so the condition stack can remain line-oriented.
	logical = regexp.MustCompile(`=\s*\r?\n\s*`).ReplaceAllString(logical, "= ")
	var conditions []string
	for _, line := range strings.Split(logical, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "#if "):
			conditions = append(conditions, strings.TrimSpace(strings.TrimPrefix(trimmed, "#if")))
			continue
		case strings.HasPrefix(trimmed, "#ifdef "):
			conditions = append(conditions, "defined("+strings.TrimSpace(strings.TrimPrefix(trimmed, "#ifdef"))+")")
			continue
		case strings.HasPrefix(trimmed, "#ifndef "):
			conditions = append(conditions, "!defined("+strings.TrimSpace(strings.TrimPrefix(trimmed, "#ifndef"))+")")
			continue
		case strings.HasPrefix(trimmed, "#elif "):
			if len(conditions) == 0 {
				return 0, fmt.Errorf("unexpected #elif while finding %s %s offset", arch, fieldName)
			}
			conditions[len(conditions)-1] = strings.TrimSpace(strings.TrimPrefix(trimmed, "#elif"))
			continue
		case strings.HasPrefix(trimmed, "#else"):
			if len(conditions) == 0 {
				return 0, fmt.Errorf("unexpected #else while finding %s %s offset", arch, fieldName)
			}
			conditions[len(conditions)-1] = invertSDKCondition(conditions[len(conditions)-1])
			continue
		case strings.HasPrefix(trimmed, "#endif"):
			if len(conditions) > 0 {
				conditions = conditions[:len(conditions)-1]
			}
			continue
		}
		m := fieldRE.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		active := strings.Join(conditions, " && ")
		if !strings.Contains(active, "defined(PRODUCT)") || !strings.Contains(active, "defined(TARGET_ARCH_"+arch+")") {
			continue
		}
		hasNegative := strings.Contains(active, "!defined(DART_COMPRESSED_POINTERS)")
		hasPositive := !hasNegative && strings.Contains(active, "defined(DART_COMPRESSED_POINTERS)")
		if compressed {
			if !hasPositive || hasNegative {
				continue
			}
		} else if hasPositive || (!hasNegative && strings.Contains(active, "DART_COMPRESSED_POINTERS")) {
			continue
		}
		v, err := strconv.ParseInt(m[1], 0, 64)
		if err != nil {
			return 0, fmt.Errorf("parse %s count offset %q: %w", arch, m[1], err)
		}
		return int(v), nil
	}
	return 0, fmt.Errorf("SDK AOT %s_offset block not found for arch=%s compressed=%v", fieldName, arch, compressed)
}

func invertSDKCondition(condition string) string {
	condition = strings.TrimSpace(condition)
	if strings.HasPrefix(condition, "!defined(") && strings.HasSuffix(condition, ")") {
		return strings.TrimPrefix(condition, "!")
	}
	if strings.HasPrefix(condition, "defined(") && strings.HasSuffix(condition, ")") {
		return "!" + condition
	}
	return "!(" + condition + ")"
}
