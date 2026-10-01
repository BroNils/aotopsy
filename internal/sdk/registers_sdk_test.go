package sdk

import (
	"regexp"
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
	"aotopsy/internal/snapshot"
)

// SDK drift gate for DartRegisterCallingConvention.
//
// The register lists and the version they start at were hand-written; nothing
// re-derived them, and the stated start (3.4.3) was wrong as a fact about the
// SDK: DartCallingConvention is already in runtime/vm/constants_{arm64,x64}.h
// at 3.4.0 (absent at 3.3.4), and compiler/backend/dart_calling_conventions.cc
// is byte-identical at 3.4.0 and 3.4.3 with --use_register_cc defaulting to
// true. 3.4.3 is the first SUPPORTED profile of that line (the analyzer maps its
// one 3.4.x snapshot hash to "3.4.3"), not the SDK boundary.
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/sdk/ -run MatchesSDK

var (
	reDartCC  = regexp.MustCompile(`(?s)struct DartCallingConvention \{(.*?)\n\};`)
	reCPURegs = regexp.MustCompile(`(?s)kCpuRegistersForArgs\[\]\s*=\s*\{([^}]*)\}`)
	reFPURegs = regexp.MustCompile(`(?s)kFpuRegistersForArgs\[\]\s*=\s*\{([^}]*)\}`)
)

func sdkRegisterList(t *testing.T, body string, re *regexp.Regexp) []string {
	t.Helper()
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("%s not found in DartCallingConvention", re)
	}
	var out []string
	for _, r := range strings.Split(m[1], ",") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

func upperAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToUpper(s)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDartCallingConventionMatchesSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	for _, v := range snapshot.SupportedVersions() {
		t.Run(v, func(t *testing.T) {
			for _, arch := range []struct {
				file  string
				arm64 bool
			}{{"runtime/vm/constants_arm64.h", true}, {"runtime/vm/constants_x64.h", false}} {
				src, err := sdktest.SDKFileAtTag(arch.file, v)
				if err != nil {
					t.Fatalf("fetch %s: %v", arch.file, err)
				}
				m := reDartCC.FindStringSubmatch(src)
				cc, ok := DartRegisterCallingConvention(v, arch.arm64)
				if m == nil {
					if ok {
						t.Fatalf("%s: table reports a register calling convention but the SDK has no DartCallingConvention", arch.file)
					}
					continue
				}
				if !ok {
					t.Fatalf("%s: SDK has DartCallingConvention at %s but the table reports none", arch.file, v)
				}
				gpr := upperAll(cc.GPRNames)
				if arch.arm64 {
					// The SDK spells ARM64 general registers R<n>; the table uses x<n>.
					for i, r := range gpr {
						gpr[i] = "R" + strings.TrimPrefix(r, "X")
					}
				}
				if got, want := gpr, sdkRegisterList(t, m[1], reCPURegs); !equalStrings(got, want) {
					t.Errorf("%s CPU arg registers = %v, SDK %v", arch.file, got, want)
				}
				if got, want := upperAll(cc.FPUName), sdkRegisterList(t, m[1], reFPURegs); !equalStrings(got, want) {
					t.Errorf("%s FPU arg registers = %v, SDK %v", arch.file, got, want)
				}
			}
		})
	}
}

// The SDK boundary itself: absent through 3.3.4, present from 3.4.0. Patch tags
// are fetched from the local trees (or the mirror), so this is a fact about the
// SDK, not about which profiles the analyzer happens to ship.
func TestDartCallingConventionBoundaryMatchesSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	for tag, want := range map[string]bool{"3.3.4": false, "3.4.0": true, "3.4.2": true} {
		for _, f := range []string{"runtime/vm/constants_arm64.h", "runtime/vm/constants_x64.h"} {
			src, err := sdktest.SDKFileAtTag(f, tag)
			if err != nil {
				t.Fatalf("fetch %s@%s: %v", f, tag, err)
			}
			if got := reDartCC.MatchString(src); got != want {
				t.Errorf("%s@%s: DartCallingConvention present = %v, want %v", f, tag, got, want)
			}
		}
	}
}
