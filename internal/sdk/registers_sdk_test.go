package sdk

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
	"aotopsy/internal/snapshot"
)

func requireSDKText(t *testing.T, src, needle, fact string) {
	t.Helper()
	if !strings.Contains(src, needle) {
		t.Errorf("%s: SDK source no longer contains %q", fact, needle)
	}
}

func requireOrderedSDKText(t *testing.T, src, fact string, needles ...string) {
	t.Helper()
	last := -1
	for _, needle := range needles {
		i := strings.Index(src, needle)
		if i < 0 {
			t.Errorf("%s: SDK source missing %q", fact, needle)
			return
		}
		if i <= last {
			t.Errorf("%s: %q moved before a preceding field", fact, needle)
			return
		}
		last = i
	}
}

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
	reDartCC        = regexp.MustCompile(`(?s)struct DartCallingConvention \{(.*?)\n\};`)
	reCPURegs       = regexp.MustCompile(`(?s)kCpuRegistersForArgs\[\]\s*=\s*\{([^}]*)\}`)
	reFPURegs       = regexp.MustCompile(`(?s)kFpuRegistersForArgs\[\]\s*=\s*\{([^}]*)\}`)
	reReservedRegs  = regexp.MustCompile(`(?s)kReservedCpuRegisters\s*=\s*(.*?);`)
	reWrappedReg    = regexp.MustCompile(`R\(\s*([A-Za-z0-9_]+)\s*\)`)
	reShiftedReg    = regexp.MustCompile(`1\s*<<\s*([A-Za-z0-9_]+)`)
	reRegisterAlias = regexp.MustCompile(
		`(?m)\b(?:const|constexpr)\s+Register\s+([A-Za-z0-9_]+)\s*=\s*([A-Za-z0-9_]+)\s*;`,
	)
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

func equalInts(a, b []int) bool {
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

func sdkRegisterAliases(src string) map[string]string {
	out := make(map[string]string)
	for _, m := range reRegisterAlias.FindAllStringSubmatch(src, -1) {
		out[m[1]] = m[2]
	}
	return out
}

func sdkRegisterNumber(name string, arm64 bool, aliases map[string]string) (int, bool) {
	seen := map[string]bool{}
	for name != "" && !seen[name] {
		seen[name] = true
		if arm64 {
			switch name {
			case "FP":
				return 29, true
			case "LR":
				return 30, true
			case "ZR", "CSP":
				return 31, true
			}
			if strings.HasPrefix(name, "R") {
				if n, err := strconv.Atoi(strings.TrimPrefix(name, "R")); err == nil && n >= 0 && n <= 31 {
					return n, true
				}
			}
		} else {
			for i, reg := range x86Name {
				if strings.EqualFold(name, reg) {
					return i, true
				}
			}
			if strings.HasPrefix(name, "R") {
				if n, err := strconv.Atoi(strings.TrimPrefix(name, "R")); err == nil && n >= 8 && n <= 15 {
					return n, true
				}
			}
		}
		next, ok := aliases[name]
		if !ok {
			return 0, false
		}
		name = next
	}
	return 0, false
}

func sdkDartAvailableCPURegs(t *testing.T, src string, arm64 bool) []int {
	t.Helper()
	m := reReservedRegs.FindStringSubmatch(src)
	if m == nil {
		t.Fatal("kReservedCpuRegisters definition not found")
	}
	aliases := sdkRegisterAliases(src)
	reserved := make(map[int]bool)
	for _, re := range []*regexp.Regexp{reWrappedReg, reShiftedReg} {
		for _, rm := range re.FindAllStringSubmatch(m[1], -1) {
			n, ok := sdkRegisterNumber(rm[1], arm64, aliases)
			if !ok {
				t.Fatalf("cannot resolve reserved register %q from exact SDK source", rm[1])
			}
			reserved[n] = true
		}
	}
	maxReg := 15
	if arm64 {
		maxReg = 30 // R31 is ZR/CSP, not an allocatable CPU register.
	}
	var out []int
	for reg := 0; reg <= maxReg; reg++ {
		if !reserved[reg] {
			out = append(out, reg)
		}
	}
	return out
}

func TestDartCallClobberedGPRsMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	for _, v := range snapshot.SupportedVersions() {
		v := v
		t.Run(v, func(t *testing.T) {
			for _, arch := range []struct {
				file  string
				arm64 bool
			}{{"runtime/vm/constants_arm64.h", true}, {"runtime/vm/constants_x64.h", false}} {
				src, err := sdktest.SDKFileAtTag(arch.file, v)
				if err != nil {
					t.Fatal(err)
				}
				want := sdkDartAvailableCPURegs(t, src, arch.arm64)
				got, ok := DartCallClobberedGPRs(v, arch.arm64)
				if !ok || !equalInts(got, want) {
					t.Errorf("DartCallClobberedGPRs(%s, arm64=%v) = %v,%v; exact SDK kDartAvailableCpuRegs = %v", v, arch.arm64, got, ok, want)
				}
			}
		})
	}
}

func TestARM64PointerDecompressionSpecMatchesSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	for _, v := range snapshot.SupportedVersions() {
		v := v
		t.Run(v, func(t *testing.T) {
			src, err := sdktest.SDKFileAtTag("runtime/vm/compiler/assembler/assembler_arm64.cc", v)
			if err != nil {
				t.Fatal(err)
			}
			wantReg, wantShift, wantOK := 0, 0, false
			switch {
			case strings.Contains(src, "Operand(HEAP_BASE)"):
				wantReg, wantShift, wantOK = ARM64HeapBaseLegacy, 0, true
			case strings.Contains(src, "Operand(HEAP_BITS, LSL, 32)"):
				wantReg, wantShift, wantOK = ARM64HeapBits, 32, true
			}
			gotReg, gotShift, gotOK := ARM64PointerDecompressionSpec(v)
			if gotReg != wantReg || gotShift != wantShift || gotOK != wantOK {
				t.Errorf("ARM64PointerDecompressionSpec(%s) = (%d,%d,%v), exact assembler source = (%d,%d,%v)",
					v, gotReg, gotShift, gotOK, wantReg, wantShift, wantOK)
			}
		})
	}
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

// The supported-profile boundary is absent at 3.3.0 and present at 3.4.3.
// Upstream's exact source boundary is 3.4.0; that non-supported tag is checked
// separately during release-source corroboration rather than making this local
// drift gate silently fall through to a cache/network source.
func TestDartCallingConventionSupportedBoundaryMatchesSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	for tag, want := range map[string]bool{"3.3.0": false, "3.4.3": true} {
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

// TestCoreRegisterFactsMatchSDK checks the fixed register roles and the
// versioned heap/dispatch facts for EVERY supported exact SDK tree. These
// values are especially dangerous to sample: a wrong register still contains
// plausible bits and therefore tends to fail consistently rather than loudly.
func TestCoreRegisterFactsMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	for _, v := range snapshot.SupportedVersions() {
		v := v
		t.Run(v, func(t *testing.T) {
			arm, err := sdktest.SDKFileAtTag("runtime/vm/constants_arm64.h", v)
			if err != nil {
				t.Fatal(err)
			}
			x64, err := sdktest.SDKFileAtTag("runtime/vm/constants_x64.h", v)
			if err != nil {
				t.Fatal(err)
			}

			for fact, needle := range map[string]string{
				"ARM64 PP":              "const Register PP = R27;",
				"ARM64 dispatch table":  "const Register DISPATCH_TABLE_REG = R21;",
				"ARM64 Code":            "const Register CODE_REG = R24;",
				"ARM64 SP":              "const Register SPREG = R15;",
				"ARM64 args descriptor": "const Register ARGS_DESC_REG = R4;",
				"ARM64 Thread":          "const Register THR = R26;",
				"ARM64 null":            "const Register NULL_REG = R22;",
				"ARM64 FP alias":        "FP = R29,",
				"ARM64 LR alias":        "LR = R30,",
			} {
				requireSDKText(t, arm, needle, fact)
			}
			for fact, needle := range map[string]string{
				"x64 PP":              "const Register PP = R15;",
				"x64 SP":              "const Register SPREG = RSP;",
				"x64 FP":              "const Register FPREG = RBP;",
				"x64 args descriptor": "const Register ARGS_DESC_REG = R10;",
				"x64 Code":            "const Register CODE_REG = R12;",
				"x64 Thread":          "const Register THR = R14;",
			} {
				requireSDKText(t, x64, needle, fact)
			}

			if snapshot.VersionAtLeast(v, "2.14.0") {
				requireSDKText(t, arm, "const Register HEAP_BITS = R28;", "ARM64 HEAP_BITS")
			} else {
				requireSDKText(t, arm, "const Register BARRIER_MASK = R28;", "ARM64 BARRIER_MASK")
			}
			if v == "2.13.0" {
				requireSDKText(t, arm, "const Register HEAP_BASE = R23;", "ARM64 legacy HEAP_BASE")
			}

			originARM, okARM := DispatchTableOriginElement(v, ArchARM64)
			originX64, okX64 := DispatchTableOriginElement(v, ArchX86)
			if !okARM || !okX64 || originARM != 4096 || originX64 != 16 {
				t.Fatalf("dispatch origins = arm(%d,%v) x64(%d,%v)", originARM, okARM, originX64, okX64)
			}
			if snapshot.VersionAtLeast(v, "2.19.0") {
				dispatch, err := sdktest.SDKFileAtTag("runtime/vm/dispatch_table.h", v)
				if err != nil {
					t.Fatal(err)
				}
				requireSDKText(t, dispatch, "static constexpr intptr_t kOriginElement = 16;", "x64 dispatch origin")
				requireSDKText(t, dispatch, "static constexpr intptr_t kOriginElement = 4096;", "ARM64 dispatch origin")
			} else {
				dispatch, err := sdktest.SDKFileAtTag("runtime/vm/dispatch_table.cc", v)
				if err != nil {
					t.Fatal(err)
				}
				requireSDKText(t, dispatch, "intptr_t DispatchTable::OriginElement()", "legacy dispatch origin function")
				requireSDKText(t, dispatch, "return 16;", "legacy x64 dispatch origin")
				requireSDKText(t, dispatch, "return 4096;", "legacy ARM64 dispatch origin")
			}

			if _, ok := DartRegisterCallingConvention(v, ArchARM64); ok {
				requireSDKText(t, arm, "const Register IC_DATA_REG = R5;", "ARM64 IC_DATA_REG")
				requireSDKText(t, x64, "const Register IC_DATA_REG = RBX;", "x64 IC_DATA_REG")
				if got, ok := ICDataArgRegIndex(v, ArchARM64); !ok || got != 3 {
					t.Errorf("ARM64 ICDataArgRegIndex = (%d,%v), want (3,true)", got, ok)
				}
				if got, ok := ICDataArgRegIndex(v, ArchX86); !ok || got != 3 {
					t.Errorf("x64 ICDataArgRegIndex = (%d,%v), want (3,true)", got, ok)
				}
			}
		})
	}
}

// TestStableObjectFactsMatchSDK proves the handful of intentionally global
// 64-bit AOT facts structurally instead of trusting a magic number. Pointer
// compression changes pointer fields, but not target kWordSize, Code's uword
// caches, or ObjectPool::Entry (whose union contains a uword).
func TestStableObjectFactsMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	for _, v := range snapshot.SupportedVersions() {
		v := v
		t.Run(v, func(t *testing.T) {
			ptr, err := sdktest.SDKFileAtTag("runtime/vm/pointer_tagging.h", v)
			if err != nil {
				t.Fatal(err)
			}
			requireSDKText(t, ptr, "kHeapObjectTag = 1", "heap object tag")
			requireSDKText(t, ptr, "kObjectAlignment = 2 * word_size", "object alignment")
			requireSDKText(t, ptr, "kTrueOffsetFromNull = kObjectAlignment * 2", "true offset from null")
			requireSDKText(t, ptr, "kFalseOffsetFromNull = kObjectAlignment * 3", "false offset from null")
			if got, ok := BoolFromNullOffset(v, 32); !ok || got != "true" {
				t.Errorf("true offset = (%q,%v)", got, ok)
			}
			if got, ok := BoolFromNullOffset(v, 48); !ok || got != "false" {
				t.Errorf("false offset = (%q,%v)", got, ok)
			}

			runtimeAPI, err := sdktest.SDKFileAtTag("runtime/vm/compiler/runtime_api.h", v)
			if err != nil {
				t.Fatal(err)
			}
			requireSDKText(t, runtimeAPI, "TARGET_ARCH_IS_64_BIT", "64-bit target branch")
			requireSDKText(t, runtimeAPI, "kWordSizeLog2 = 3", "64-bit target word size")
			requireSDKText(t, runtimeAPI, "using ObjectAlignment = dart::ObjectAlignment<kWordSize, kWordSizeLog2>", "target object alignment")

			raw, err := sdktest.SDKFileAtTag("runtime/vm/raw_object.h", v)
			if err != nil {
				t.Fatal(err)
			}
			codeClass := "class UntaggedCode : public UntaggedObject {"
			poolClass := "class UntaggedObjectPool : public UntaggedObject {"
			if v == "2.10.0" {
				codeClass = "class CodeLayout : public ObjectLayout {"
				poolClass = "class ObjectPoolLayout : public ObjectLayout {"
			}
			ci := strings.Index(raw, codeClass)
			if ci < 0 {
				t.Fatalf("Code raw layout class not found: %s", codeClass)
			}
			codeBody := raw[ci:]
			requireOrderedSDKText(t, codeBody, "Code entry-point cache ordering",
				"uword entry_point_;", "uword monomorphic_entry_point_;",
				"uword unchecked_entry_point_;", "uword monomorphic_unchecked_entry_point_;")
			for _, off := range []int{0x7, 0xf, 0x17, 0x1f} {
				if !IsCodeEntryPointDisp(off) {
					t.Errorf("Code displacement %#x missing", off)
				}
			}

			pi := strings.Index(raw, poolClass)
			if pi < 0 {
				t.Fatalf("ObjectPool raw layout class not found: %s", poolClass)
			}
			poolBody := raw[pi:]
			requireOrderedSDKText(t, poolBody, "ObjectPool layout", "intptr_t length_;", "struct Entry {", "uword raw_value_", "Entry* data()")
			obj, err := sdktest.SDKFileAtTag("runtime/vm/object.h", v)
			if err != nil {
				t.Fatal(err)
			}
			requireSDKText(t, obj, "sizeof(", "ObjectPool element-size formula")
			requireSDKText(t, obj, "::Entry) * index", "ObjectPool element-size formula")
			if PoolElementsStartOffset != 16 || PoolElementSize != 8 {
				t.Fatalf("committed 64-bit pool layout = start %d size %d, want 16/8 from uword header+length/Entry", PoolElementsStartOffset, PoolElementSize)
			}

		})
	}
}
