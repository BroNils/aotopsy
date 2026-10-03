package sdk

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
	"aotopsy/internal/snapshot"
)

// SDK drift gate for special stub ABIs. Presence is part of the fact: a modern
// register assignment must not be projected backwards onto a release where the
// ABI struct did not exist yet.

var regNumber = map[string]int{
	"ZR": 31, "CSP": 31,
	"RAX": 0, "RCX": 1, "RDX": 2, "RBX": 3,
	"RSP": 4, "RBP": 5, "RSI": 6, "RDI": 7,
}

func init() {
	for i := 0; i <= 30; i++ {
		regNumber[fmt.Sprintf("R%d", i)] = i
	}
}

var reABIField = regexp.MustCompile(`static const(?:expr)? Register (k\w+)\s*=\s*(\w+);`)

func sdkABI(src, structName string) (map[string]int, error) {
	i := strings.Index(src, "struct "+structName+" {")
	if i < 0 {
		return nil, fmt.Errorf("struct %s not found", structName)
	}
	rest := src[i:]
	end := strings.Index(rest, "\n};")
	if end < 0 {
		return nil, fmt.Errorf("struct %s unterminated", structName)
	}
	out := map[string]int{}
	for _, m := range reABIField.FindAllStringSubmatch(rest[:end], -1) {
		field, reg := m[1], m[2]
		if n, ok := regNumber[reg]; ok {
			out[field] = n
			continue
		}
		if n, ok := out[reg]; ok {
			out[field] = n
			continue
		}
		return nil, fmt.Errorf("struct %s: cannot resolve %s = %s", structName, field, reg)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("struct %s: no register fields parsed", structName)
	}
	return out, nil
}

func checkSDKABI(t *testing.T, src, structName string, present bool, want map[string]int) {
	t.Helper()
	hasStruct := strings.Contains(src, "struct "+structName+" {")
	if hasStruct != present {
		t.Fatalf("%s presence = %v, committed presence = %v", structName, hasStruct, present)
	}
	if !present {
		return
	}
	got, err := sdkABI(src, structName)
	if err != nil {
		t.Fatal(err)
	}
	for field, w := range want {
		g, ok := got[field]
		if w == AbsentRegister {
			if ok {
				t.Errorf("%s.%s unexpectedly exists as register %d", structName, field, g)
			}
			continue
		}
		if !ok {
			t.Errorf("%s.%s missing; committed register=%d", structName, field, w)
			continue
		}
		if g != w {
			t.Errorf("%s.%s = register %d in SDK, committed %d", structName, field, g, w)
		}
	}
}

func TestRegisterABIMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	for _, version := range snapshot.SupportedVersions() {
		version := version
		t.Run(version, func(t *testing.T) {
			for _, arch := range []struct {
				name, header string
				isARM64      bool
			}{
				{"arm64", "runtime/vm/constants_arm64.h", true},
				{"x64", "runtime/vm/constants_x64.h", false},
			} {
				arch := arch
				t.Run(arch.name, func(t *testing.T) {
					src, err := sdktest.SDKFileAtTag(arch.header, version)
					if err != nil {
						t.Fatalf("verify %s@%s: %v", arch.header, version, err)
					}

					tt, ok := TypeTestRegs(version, arch.isARM64)
					if !ok {
						t.Fatal("TypeTestABI missing for supported version")
					}
					checkSDKABI(t, src, "TypeTestABI", true, map[string]int{
						"kInstanceReg": tt.InstanceReg, "kDstTypeReg": tt.DstTypeReg,
						"kInstantiatorTypeArgumentsReg": tt.InstantiatorTypeArgumentsReg,
						"kFunctionTypeArgumentsReg":     tt.FunctionTypeArgumentsReg,
						"kSubtypeTestCacheReg":          tt.SubtypeTestCacheReg, "kScratchReg": tt.ScratchReg,
						"kResultReg":                 tt.ResultReg,
						"kSubtypeTestCacheResultReg": tt.SubtypeTestCacheResultReg,
					})

					in, ok := InstantiationRegs(version, arch.isARM64)
					if !ok {
						t.Fatal("InstantiationABI missing for supported version")
					}
					checkSDKABI(t, src, "InstantiationABI", true, map[string]int{
						"kUninstantiatedTypeArgumentsReg": in.UninstantiatedTypeArgumentsReg,
						"kInstantiatorTypeArgumentsReg":   in.InstantiatorTypeArgumentsReg,
						"kFunctionTypeArgumentsReg":       in.FunctionTypeArgumentsReg,
						"kResultTypeArgumentsReg":         in.ResultTypeArgumentsReg,
						"kResultTypeReg":                  in.ResultTypeReg, "kScratchReg": in.ScratchReg,
					})

					as, asOK := AssertSubtypeRegs(version, arch.isARM64)
					asWant := map[string]int{}
					if asOK {
						asWant = map[string]int{
							"kSubTypeReg": as.SubTypeReg, "kSuperTypeReg": as.SuperTypeReg,
							"kInstantiatorTypeArgumentsReg": as.InstantiatorTypeArgumentsReg,
							"kFunctionTypeArgumentsReg":     as.FunctionTypeArgumentsReg, "kDstNameReg": as.DstNameReg,
						}
					}
					checkSDKABI(t, src, "AssertSubtypeABI", asOK, asWant)

					alloc, allocOK := AllocateObjectRegs(version, arch.isARM64)
					if !allocOK {
						t.Fatal("allocation-stub ABI missing for supported version")
					}
					if snapshot.VersionAtLeast(version, "2.14.0") {
						checkSDKABI(t, src, "AllocateObjectABI", true, map[string]int{
							"kResultReg": alloc.ResultReg, "kTypeArgumentsReg": alloc.TypeArgumentsReg, "kTagsReg": alloc.TagsReg,
						})
					} else {
						// Before 2.14 the same contract is split between the
						// kAllocationStubTypeArgumentsReg constant and the generated
						// allocation helper rather than named AllocateObjectABI.
						checkSDKABI(t, src, "AllocateObjectABI", false, nil)
						wantTypeArgs := "RDX"
						if arch.isARM64 {
							wantTypeArgs = "R1"
						}
						needle := "const Register kAllocationStubTypeArgumentsReg = " + wantTypeArgs + ";"
						if !strings.Contains(src, needle) {
							t.Errorf("legacy allocation ABI missing %q", needle)
						}
						stubFile := "runtime/vm/compiler/stub_code_compiler_x64.cc"
						if arch.isARM64 {
							stubFile = "runtime/vm/compiler/stub_code_compiler_arm64.cc"
						}
						stubSrc, err := sdktest.SDKFileAtTag(stubFile, version)
						if err != nil {
							t.Fatalf("verify %s@%s: %v", stubFile, version, err)
						}
						if arch.isARM64 {
							if !strings.Contains(stubSrc, "const Register kInstanceReg = R0;") {
								t.Error("legacy ARM64 allocation helper no longer returns its instance in R0")
							}
						} else if !strings.Contains(stubSrc, "movq(RAX, Address(THR, target::Thread::top_offset()))") {
							t.Error("legacy x64 allocation helper no longer allocates/returns through RAX")
						}
					}

					suspend, suspendOK := SuspendStubRegs(version, arch.isARM64)
					suspendWant := map[string]int{}
					if suspendOK {
						suspendWant = map[string]int{"kArgumentReg": suspend.ArgumentReg, "kTypeArgsReg": suspend.TypeArgsReg}
					}
					checkSDKABI(t, src, "SuspendStubABI", suspendOK, suspendWant)

					dispatch, dispatchOK := DispatchTableNullErrorRegs(version, arch.isARM64)
					dispatchWant := map[string]int{}
					if dispatchOK {
						dispatchWant["kClassIdReg"] = dispatch.ClassIDReg
					}
					checkSDKABI(t, src, "DispatchTableNullErrorABI", dispatchOK, dispatchWant)
				})
			}
		})
	}
}

func TestABIFactsRejectUnknownVersion(t *testing.T) {
	for _, arm := range []bool{true, false} {
		if _, ok := TypeTestRegs("3.99.0", arm); ok {
			t.Error("TypeTestRegs accepted unknown version")
		}
		if _, ok := InstantiationRegs("3.99.0", arm); ok {
			t.Error("InstantiationRegs accepted unknown version")
		}
		if _, ok := AssertSubtypeRegs("3.99.0", arm); ok {
			t.Error("AssertSubtypeRegs accepted unknown version")
		}
		if _, ok := AllocateObjectRegs("3.99.0", arm); ok {
			t.Error("AllocateObjectRegs accepted unknown version")
		}
		if _, ok := SuspendStubRegs("3.99.0", arm); ok {
			t.Error("SuspendStubRegs accepted unknown version")
		}
		if _, ok := DispatchTableNullErrorRegs("3.99.0", arm); ok {
			t.Error("DispatchTableNullErrorRegs accepted unknown version")
		}
		if _, ok := DispatchTableClassIDReg("3.99.0", arm); ok {
			t.Error("DispatchTableClassIDReg accepted unknown version")
		}
	}
}

func TestDispatchClassIDRegBoundary(t *testing.T) {
	for _, tc := range []struct {
		version string
		ok      bool
	}{
		{"2.10.0", false}, {"2.12.0", false}, {"2.13.0", true},
		{"2.18.0", true}, {"2.19.0", true}, {"3.13.0", true},
	} {
		for _, arm := range []bool{true, false} {
			reg, ok := DispatchTableClassIDReg(tc.version, arm)
			if ok != tc.ok {
				t.Fatalf("DispatchTableClassIDReg(%s, arm=%v) ok=%v, want %v", tc.version, arm, ok, tc.ok)
			}
			if !ok {
				continue
			}
			want := 1
			if arm {
				want = 0
			}
			if reg != want {
				t.Errorf("DispatchTableClassIDReg(%s, arm=%v)=%d, want %d", tc.version, arm, reg, want)
			}
		}
	}
}

func TestDispatchClassIDRegEligibility(t *testing.T) {
	for _, tc := range []struct {
		version string
		arm     bool
		reg     int
		want    bool
	}{
		{"2.10.0", false, 2, true},
		{"2.12.0", false, 7, true},
		{"2.12.0", true, 5, true},
		{"2.12.0", true, 31, false},
		{"2.13.0", false, 1, true},
		{"2.13.0", false, 2, false},
		{"2.13.0", true, 0, true},
		{"2.13.0", true, 1, false},
		{"3.99.0", false, 1, false},
	} {
		if got := IsDispatchTableClassIDReg(tc.version, tc.arm, tc.reg); got != tc.want {
			t.Errorf("IsDispatchTableClassIDReg(%s, arm=%v, reg=%d)=%v, want %v", tc.version, tc.arm, tc.reg, got, tc.want)
		}
	}
}

func TestARM64DispatchIndexBoundary(t *testing.T) {
	for _, tc := range []struct {
		version  string
		dst, src int
		wantReg  bool
		wantComp bool
	}{
		{"2.10.0", 5, 5, true, true},
		{"2.12.0", 7, 7, true, true},
		{"2.12.0", 30, 0, true, false},
		{"2.12.0", 31, 31, false, false},
		{"2.13.0", 30, 0, true, true},
		{"2.13.0", 30, 1, true, false},
		{"2.13.0", 7, 7, false, false},
		{"3.13.0", 30, 0, true, true},
		{"3.99.0", 30, 0, false, false},
	} {
		if got := IsARM64DispatchTableIndexReg(tc.version, tc.dst); got != tc.wantReg {
			t.Errorf("IsARM64DispatchTableIndexReg(%s,%d)=%v, want %v", tc.version, tc.dst, got, tc.wantReg)
		}
		if got := IsARM64DispatchTableIndexComputation(tc.version, tc.dst, tc.src); got != tc.wantComp {
			t.Errorf("IsARM64DispatchTableIndexComputation(%s,%d,%d)=%v, want %v", tc.version, tc.dst, tc.src, got, tc.wantComp)
		}
	}
}

func TestDispatchClassIDRegisterBoundaryMatchesSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	legacyCIDParam := regexp.MustCompile(`EmitDispatchTableCall\s*\(\s*Register\s+cid_reg\b`)
	legacyIndex := regexp.MustCompile(`AddImmediate\s*\(\s*cid_reg\s*,\s*cid_reg\s*,\s*offset\s*\)`)
	modernIndex := regexp.MustCompile(`AddImmediate\s*\(\s*LR\s*,\s*cid_reg\s*,\s*offset\s*\)`)
	for _, version := range snapshot.SupportedVersions() {
		version := version
		t.Run(version, func(t *testing.T) {
			legacy := version == "2.10.0" || version == "2.12.0"
			for _, arch := range []string{"arm64", "x64"} {
				path := "runtime/vm/compiler/backend/flow_graph_compiler_" + arch + ".cc"
				src, err := sdktest.SDKFileAtTag(path, version)
				if err != nil {
					t.Fatalf("verify %s@%s: %v", path, version, err)
				}
				hasLegacyParam := legacyCIDParam.MatchString(src)
				hasFixedABIUse := strings.Contains(src, "DispatchTableNullErrorABI::kClassIdReg")
				if legacy {
					if !hasLegacyParam {
						t.Errorf("%s no longer passes an arbitrary cid_reg into EmitDispatchTableCall", arch)
					}
					if hasFixedABIUse {
						t.Errorf("%s unexpectedly uses the fixed DispatchTableNullErrorABI class-id register", arch)
					}
					if arch == "arm64" && !legacyIndex.MatchString(src) {
						t.Errorf("arm64 no longer computes the dispatch index in-place in cid_reg")
					}
					continue
				}
				if hasLegacyParam {
					t.Errorf("%s still exposes legacy arbitrary cid_reg semantics", arch)
				}
				if !hasFixedABIUse {
					t.Errorf("%s no longer uses DispatchTableNullErrorABI::kClassIdReg", arch)
				}
				if arch == "arm64" && !modernIndex.MatchString(src) {
					t.Errorf("arm64 no longer computes the dispatch index in LR")
				}
			}
		})
	}
}
