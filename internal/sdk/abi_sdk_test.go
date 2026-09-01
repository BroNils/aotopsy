package sdk

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
)

// SDK drift gate for the stub calling conventions.
//
// These are register numbers, so a wrong one does not fail -- it reads a
// different register and reports whatever was in it. The frida dispatch
// probe spent its whole life reading a class id out of the wrong place
// for exactly this reason, and the value it produced (-1, or a small
// integer) looked like a plausible answer.
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/sdk/ -run RegisterABIMatchSDK

// abiTags are the versions to check. The ABI structs move rarely, so a
// spread across the supported range is enough to catch a change; every
// one of them is checked in full.
var abiTags = []string{"2.17.6", "3.0.5", "3.6.2", "3.9.2", "3.12.2", "3.13.0"}

// regNumber maps an SDK register spelling to its encoding number.
var regNumber = map[string]int{
	// ARM64: R0..R30 plus the aliases the ABI structs use.
	"ZR": 31, "CSP": 31,
	// x86_64, in encoding order.
	"RAX": 0, "RCX": 1, "RDX": 2, "RBX": 3,
	"RSP": 4, "RBP": 5, "RSI": 6, "RDI": 7,
}

func init() {
	for i := 0; i <= 30; i++ {
		regNumber[fmt.Sprintf("R%d", i)] = i
	}
	// R8..R15 on x86_64 share the Rn spelling and the same numbering, so
	// the loop above already covers them.
}

// `static const Register` up to 2.19, `static constexpr Register` from
// 3.x. Matching only the newer spelling parses the older headers as
// having no ABI at all.
var reABIField = regexp.MustCompile(`static const(?:expr)? Register (k\w+)\s*=\s*(\w+);`)

// sdkABI returns the register assignments of one `struct <name>ABI` in a
// constants_<arch>.h.
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
		// Fields defined in terms of another field (kInstanceOfResultReg =
		// kInstanceReg) resolve through what has been read so far.
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

func TestRegisterABIMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	for _, tag := range abiTags {
		t.Run(tag, func(t *testing.T) {
			for _, arch := range []struct {
				name    string
				header  string
				isARM64 bool
			}{
				{"arm64", "runtime/vm/constants_arm64.h", true},
				{"x64", "runtime/vm/constants_x64.h", false},
			} {
				src, err := sdktest.GHFileAtTag(arch.header, tag)
				if err != nil {
					t.Skipf("fetch %s@%s: %v", arch.header, tag, err)
				}

				check := func(structName string, want map[string]int) {
					got, err := sdkABI(src, structName)
					if err != nil {
						t.Errorf("%s/%s: %v", tag, arch.name, err)
						return
					}
					for field, w := range want {
						g, ok := got[field]
						if !ok {
							// The ABI structs gained fields over time --
							// kSubtypeTestCacheResultReg is not in 2.17.6 --
							// and the committed struct is a superset. A field
							// the SDK does not have at this tag is not drift;
							// a field it has with a different number is.
							t.Logf("%s/%s %s: %s absent at this tag",
								tag, arch.name, structName, field)
							continue
						}
						if g != w {
							t.Errorf("%s/%s %s.%s = R%d in the SDK, committed R%d\n"+
								"  A wrong register number does not fail, it reads a different\n"+
								"  register and reports whatever was in it.",
								tag, arch.name, structName, field, g, w)
						}
					}
				}

				tt := TypeTestRegs(arch.isARM64)
				check("TypeTestABI", map[string]int{
					"kInstanceReg":                  tt.InstanceReg,
					"kDstTypeReg":                   tt.DstTypeReg,
					"kInstantiatorTypeArgumentsReg": tt.InstantiatorTypeArgumentsReg,
					"kFunctionTypeArgumentsReg":     tt.FunctionTypeArgumentsReg,
					"kSubtypeTestCacheReg":          tt.SubtypeTestCacheReg,
					"kScratchReg":                   tt.ScratchReg,
					"kSubtypeTestCacheResultReg":    tt.SubtypeTestCacheResultReg,
				})

				in := InstantiationRegs(arch.isARM64)
				check("InstantiationABI", map[string]int{
					"kUninstantiatedTypeArgumentsReg": in.UninstantiatedTypeArgumentsReg,
					"kInstantiatorTypeArgumentsReg":   in.InstantiatorTypeArgumentsReg,
					"kFunctionTypeArgumentsReg":       in.FunctionTypeArgumentsReg,
					"kResultTypeArgumentsReg":         in.ResultTypeArgumentsReg,
					"kResultTypeReg":                  in.ResultTypeReg,
					"kScratchReg":                     in.ScratchReg,
				})

				as := AssertSubtypeRegs(arch.isARM64)
				check("AssertSubtypeABI", map[string]int{
					"kSubTypeReg":                   as.SubTypeReg,
					"kSuperTypeReg":                 as.SuperTypeReg,
					"kInstantiatorTypeArgumentsReg": as.InstantiatorTypeArgumentsReg,
					"kFunctionTypeArgumentsReg":     as.FunctionTypeArgumentsReg,
					"kDstNameReg":                   as.DstNameReg,
				})

				wantCid := ARM64ClassIdReg
				if !arch.isARM64 {
					wantCid = X86ClassIdReg
				}
				check("DispatchTableNullErrorABI", map[string]int{"kClassIdReg": wantCid})
			}
		})
	}
}

// TestClassIdRegNameMatchesNumber keeps the string form the frida script
// emits in step with the number the ABI records. They are read by
// different consumers and drifted apart once already.
func TestClassIdRegNameMatchesNumber(t *testing.T) {
	if got, want := ClassIdRegName(true), "x0"; got != want {
		t.Errorf("ClassIdRegName(arm64) = %q, want %q (R%d)", got, want, ARM64ClassIdReg)
	}
	if got, want := ClassIdRegName(false), "rcx"; got != want {
		t.Errorf("ClassIdRegName(x64) = %q, want %q (RCX = %d)", got, want, X86ClassIdReg)
	}
}
