package decompiler

import (
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestUnsignedAndSignedBranchConditionsRemainDistinct(t *testing.T) {
	if !x86CondUnsigned(x86asm.JB) || x86CondUnsigned(x86asm.JL) {
		t.Fatal("x86 JB/JL signedness classification collapsed")
	}
	if !arm64CondUnsigned("lo") || arm64CondUnsigned("lt") {
		t.Fatal("ARM64 LO/LT signedness classification collapsed")
	}

	s := newLiftState("")
	s.LastCmp = [2]string{"a", "b"}
	s.HasCmp = true
	s.CmpBits = 32
	u, ok := rememberedCmpCondition(s, "<", true)
	if !ok || !strings.Contains(u, "0xffffffff") {
		t.Fatalf("unsigned 32-bit comparison was not masked: %q ok=%v", u, ok)
	}
	signed, ok := rememberedCmpCondition(s, "<", false)
	if !ok || signed != "a < b" {
		t.Fatalf("signed comparison changed unexpectedly: %q ok=%v", signed, ok)
	}
	if u == signed {
		t.Fatalf("signed and unsigned conditions rendered identically: %q", u)
	}
}

func TestUnsignedConditionWithoutWidthDegradesToUnknown(t *testing.T) {
	s := newLiftState("")
	s.LastCmp = [2]string{"memoryValue", "7"}
	s.HasCmp = true
	if got, ok := rememberedCmpCondition(s, ">", true); ok || got != "" {
		t.Fatalf("unknown-width unsigned comparison was guessed: %q ok=%v", got, ok)
	}
}
