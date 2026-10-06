package decompiler

import (
	"strings"
	"testing"

	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
)

// MOV X1,#5; MOV X0,#7; STP X0,X1,[X15,#-16]!; BL callee; ADD X15,X15,#0x10; RET
// Push model: in STP Xa,Xb the second register is the earlier argument.
func pushInsts() []disasm.Inst {
	return []disasm.Inst{
		inst(0x1000, 0xD28000A1, "mov", "x1, #0x5"),
		inst(0x1004, 0xD28000E0, "mov", "x0, #0x7"),
		inst(0x1008, 0xA9BF05E0, "stp", "x0, x1, [x15, #-0x10]!"),
		inst(0x100C, 0x940003FD, "bl", "#0x2000"),
		inst(0x1010, 0x910041EF, "add", "x15, x15, #0x10"),
		inst(0x1014, 0xD65F03C0, "ret", ""),
	}
}

func emitPush(t *testing.T, version string) string {
	t.Helper()
	fir := BuildARM64IR("f", version, false, pushInsts(), sdk.RegisterCallingConvention{})
	sym := func(va uint64) (string, bool) {
		if va == 0x2000 {
			return "callee", true
		}
		return "", false
	}
	return EmitPseudocode(fir, sym, nil).Source
}

func TestPushedArgumentsAreBoundToTheCall(t *testing.T) {
	got := emitPush(t, "2.12.0")
	if !strings.Contains(got, "callee(5, 7)") {
		t.Fatalf("pushed arguments not bound in source order:\n%s", got)
	}
	if strings.Contains(got, "push(") {
		t.Fatalf("push statements must disappear:\n%s", got)
	}
}

func TestPushedArgumentsAreNotBoundInTheMoveArgumentModel(t *testing.T) {
	if strings.Contains(emitPush(t, "3.1.0"), "callee(5, 7)") {
		t.Fatal("bound a push as a MoveArgument-era call")
	}
}
