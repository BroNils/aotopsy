package decompiler

import (
	"strings"
	"testing"

	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
)

func switchablePool(unlinked, stub int, name string) PoolLookup {
	return func(idx int) (string, bool) {
		switch idx {
		case unlinked:
			return name, true
		case stub:
			return "Empty", true
		}
		return "", false
	}
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

func emitSwitchable(t *testing.T, version string, insts []disasm.Inst, pool PoolLookup) string {
	t.Helper()
	fir := BuildARM64IR("f", version, false, insts, sdk.RegisterCallingConvention{})
	return EmitPseudocode(fir, func(uint64) (string, bool) { return "", false }, pool).Source
}

func TestSwitchableCallNamesTheSelectorAndBindsReceiver(t *testing.T) {
	got := emitSwitchable(t, "3.9.2", switchableArm64(0xA9407A05, "x5, x30, [x16]"),
		switchablePool(81, 82, "foo"))
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
		switchablePool(82, 81, "foo"))
	if !strings.Contains(got, "5.foo(7)") {
		t.Fatalf("3.10.7 pair order not honoured (UnlinkedCall is the SECOND element):\n%s", got)
	}
	// A getter with an extra argument is not a recognisable shape: keep the
	// opaque call rather than print a wrong one.
	got = emitSwitchable(t, "3.10.7", switchableArm64(0xA940161E, "x30, x5, [x16]"),
		switchablePool(82, 81, "get:bar"))
	if strings.Contains(got, ".bar") {
		t.Fatalf("a getter was rendered with an argument:\n%s", got)
	}
}

func TestSwitchableCallDynPrefixAndOperators(t *testing.T) {
	got := emitSwitchable(t, "3.9.2", switchableArm64(0xA9407A05, "x5, x30, [x16]"),
		switchablePool(81, 82, "dyn:+"))
	if !strings.Contains(got, "(12) /* dynamic */") { // 5 + 7, folded by the expression layer
		t.Fatalf("operator call not rendered:\n%s", got)
	}
}

// A string that is not a selector must never be taken for an UnlinkedCall name.
func TestSwitchableNameRejectsNonSelectors(t *testing.T) {
	for _, d := range []string{`"hello"`, "pool[3]", "Foo.bar@123", "<Instance_1>", "TypeArgs: <int>", ""} {
		if switchableName(d) != "" {
			t.Errorf("%q accepted as a selector", d)
		}
	}
	for _, d := range []string{"foo", "dyn:call", "get:x", "set:x", "[]", "[]=", "+", "dyn:=="} {
		if switchableName(d) == "" {
			t.Errorf("%q rejected", d)
		}
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
	got := EmitPseudocode(fir, func(uint64) (string, bool) { return "", false }, switchablePool(6, 5, "foo")).Source
	if !strings.Contains(got, ".foo(") {
		t.Fatalf("x64 switchable call not named:\n%s", got)
	}
}
