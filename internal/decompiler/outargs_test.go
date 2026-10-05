package decompiler

import (
	"strings"
	"testing"

	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
)

// MOV X1,#5; MOV X0,#7; STR X1,[X15,#8]; STR X0,[X15]; BL callee; RET
// Real encodings. The last stack argument is at SP+0, the first (deepest) at SP+8.
func outArgsInsts() []disasm.Inst {
	return []disasm.Inst{
		inst(0x1000, 0xD28000A1, "mov", "x1, #0x5"),
		inst(0x1004, 0xD28000E0, "mov", "x0, #0x7"),
		inst(0x1008, 0xF90005E1, "str", "x1, [x15, #8]"),
		inst(0x100C, 0xF90001E0, "str", "x0, [x15]"),
		inst(0x1010, 0x940003FC, "bl", "#0x2000"),
		inst(0x1014, 0xD65F03C0, "ret", ""),
	}
}

func emitOutArgs(t *testing.T, version string) string {
	t.Helper()
	fir := BuildARM64IR("f", version, false, outArgsInsts(), sdk.RegisterCallingConvention{})
	sym := func(va uint64) (string, bool) {
		if va == 0x2000 {
			return "callee", true
		}
		return "", false
	}
	return EmitPseudocode(fir, sym, nil).Source
}

// MoveArgument model (>= 3.0.5): the SP-relative slots written before the call
// are its stack arguments, deepest slot first, and the slot stores disappear.
func TestStackArgumentsAreBoundToTheCall(t *testing.T) {
	got := emitOutArgs(t, "3.1.0")
	if !strings.Contains(got, "callee(5, 7)") {
		t.Fatalf("stack arguments not bound in source order:\n%s", got)
	}
	if strings.Contains(got, "stack_sp") || strings.Contains(got, "stack_p8") {
		t.Fatalf("slot stores must be removed once they are the argument list:\n%s", got)
	}
}

// <= 2.19.0 pushes arguments (and the drop after the call carries the count): this
// model is not bound, so the slot statements are left exactly as before.
func TestStackArgumentsAreNotBoundBeforeTheMoveArgumentModel(t *testing.T) {
	got := emitOutArgs(t, "2.12.0")
	if strings.Contains(got, "callee(5, 7)") {
		t.Fatalf("bound a push-model call:\n%s", got)
	}
}
