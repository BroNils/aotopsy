package decompiler

import (
	"strings"
	"testing"

	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
)

// callSites stands in for the deserialized CallSiteData objects of the pool.
func callSites(sites map[int]CallSite) func(int) (CallSite, bool) {
	return func(idx int) (CallSite, bool) {
		s, ok := sites[idx]
		return s, ok
	}
}

func call(selector string, count int) CallSite {
	return CallSite{Selector: selector, Count: count, Positional: count}
}

// 3.9.2 arm64 (real encodings; pool pair at PP+0x298 = indices 81/82):
//
//	MOV X1,#5; MOV X2,#7; STR X1,[X15,#8]; STR X2,[X15]
//	MOV X4,#0; LDR X0,[X15,#8]; ADD X16,X27,#0x298; LDP X5,X30,[X16]; BLR X30
func switchableArm64(ldpRaw uint32, ldpText string) []disasm.Inst {
	return []disasm.Inst{
		inst(0x1000, 0xD28000A1, "mov", "x1, #0x5"),
		inst(0x1004, 0xD28000E2, "mov", "x2, #0x7"),
		inst(0x1008, 0xF90005E1, "str", "x1, [x15, #8]"),
		inst(0x100C, 0xF90001E2, "str", "x2, [x15]"),
		inst(0x1010, 0xD2800004, "mov", "x4, #0x0"),
		inst(0x1014, 0xF94005E0, "ldr", "x0, [x15, #8]"),
		inst(0x1018, 0x910A6370, "add", "x16, x27, #0x298"),
		inst(0x101C, ldpRaw, "ldp", ldpText),
		inst(0x1020, 0xD63F03C0, "blr", "x30"),
		inst(0x1024, 0xD65F03C0, "ret", ""),
	}
}

func emitSwitchable(t *testing.T, version string, insts []disasm.Inst, sites map[int]CallSite) string {
	t.Helper()
	fir := BuildARM64IR("f", version, false, insts, sdk.RegisterCallingConvention{})
	fir.CallSiteAt = callSites(sites)
	return EmitPseudocode(fir, func(uint64) (string, bool) { return "", false }, nil).Source
}

func TestSwitchableCallNamesTheSelectorAndBindsReceiver(t *testing.T) {
	got := emitSwitchable(t, "3.9.2", switchableArm64(0xA9407A05, "x5, x30, [x16]"),
		map[int]CallSite{81: call("foo", 2)})
	if !strings.Contains(got, "5.foo(7)") {
		t.Fatalf("switchable call not rendered as recv.foo(arg):\n%s", got)
	}
	if strings.Contains(got, "dynamicCall") {
		t.Fatalf("still a dynamicCall:\n%s", got)
	}
}

// From 3.10.7 the pair is loaded as {stub -> LR, UnlinkedCall -> R5}: the stub
// is the first element of the pair and the UnlinkedCall the second.
func TestSwitchableCallPoolPairOrderFlipsAt3107(t *testing.T) {
	got := emitSwitchable(t, "3.10.7", switchableArm64(0xA940161E, "x30, x5, [x16]"),
		map[int]CallSite{82: call("foo", 2)})
	if !strings.Contains(got, "5.foo(7)") {
		t.Fatalf("3.10.7 pair order not honoured (UnlinkedCall is the SECOND element):\n%s", got)
	}
}

// The descriptor's argument count must equal the bound arguments: a getter
// descriptor (count 1) cannot describe a call with two arguments.
func TestSwitchableCallRejectsACountMismatch(t *testing.T) {
	got := emitSwitchable(t, "3.10.7", switchableArm64(0xA940161E, "x30, x5, [x16]"),
		map[int]CallSite{82: call("get:bar", 1)})
	if strings.Contains(got, ".bar") {
		t.Fatalf("a getter was rendered with an extra argument:\n%s", got)
	}
}

// A pool slot that is not CallSiteData (a string, a closure, ...) is never a
// switchable call, however its display prints.
func TestSwitchableCallRequiresACallSiteObject(t *testing.T) {
	got := emitSwitchable(t, "3.9.2", switchableArm64(0xA9407A05, "x5, x30, [x16]"), map[int]CallSite{})
	if !strings.Contains(got, "dynamicCall") {
		t.Fatalf("a call without CallSiteData was rewritten:\n%s", got)
	}
}

func TestSwitchableCallDynPrefixAndOperators(t *testing.T) {
	got := emitSwitchable(t, "3.9.2", switchableArm64(0xA9407A05, "x5, x30, [x16]"),
		map[int]CallSite{81: call("dyn:+", 2)})
	if !strings.Contains(got, "(12) /* dynamic */") { // 5 + 7, folded by the expression layer
		t.Fatalf("operator call not rendered:\n%s", got)
	}
}

// call(a, {x}): count 2, one positional (the receiver), argument 1 is named x.
func TestSwitchableCallNamedArguments(t *testing.T) {
	site := CallSite{Selector: "foo", Count: 2, Positional: 1, NamedArgs: map[int]string{1: "x"}}
	got := emitSwitchable(t, "3.9.2", switchableArm64(0xA9407A05, "x5, x30, [x16]"), map[int]CallSite{81: site})
	if !strings.Contains(got, "5.foo(x: 7)") {
		t.Fatalf("named argument lost:\n%s", got)
	}
	// A named position that is not a passed argument is malformed: keep the call opaque.
	bad := CallSite{Selector: "foo", Count: 2, Positional: 1, NamedArgs: map[int]string{5: "x"}}
	if got := emitSwitchable(t, "3.9.2", switchableArm64(0xA9407A05, "x5, x30, [x16]"), map[int]CallSite{81: bad}); strings.Contains(got, ".foo(") {
		t.Fatalf("malformed descriptor rendered:\n%s", got)
	}
}

// x86_64 3.9.2: mov rdx,[rsp+8]; mov rcx,[r15+0x37]; mov rbx,[r15+0x3f]; call rcx
// with the stack arguments stored at [rsp+8] (receiver) and [rsp] (argument).
func TestSwitchableCallX64(t *testing.T) {
	code := []byte{
		0x48, 0x89, 0x74, 0x24, 0x08, // mov [rsp+8], rsi
		0x48, 0x89, 0x3c, 0x24, // mov [rsp], rdi
		0x48, 0x8b, 0x54, 0x24, 0x08, // mov rdx, [rsp+8]
		0x49, 0x8b, 0x4f, 0x37, // mov rcx, [r15+0x37]   (pool 5: stub)
		0x49, 0x8b, 0x5f, 0x3f, // mov rbx, [r15+0x3f]   (pool 6: UnlinkedCall)
		0xff, 0xd1, // call rcx
		0xc3,
	}
	insts, err := DecodeX86Range(code, 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	cc, _ := sdk.DartRegisterCallingConvention("3.9.2", sdk.ArchX86)
	fir := BuildX86IR("f", "3.9.2", insts, cc)
	fir.CallSiteAt = callSites(map[int]CallSite{6: call("foo", 2)})
	got := EmitPseudocode(fir, func(uint64) (string, bool) { return "", false }, nil).Source
	if !strings.Contains(got, ".foo(") {
		t.Fatalf("x64 switchable call not named:\n%s", got)
	}
}
