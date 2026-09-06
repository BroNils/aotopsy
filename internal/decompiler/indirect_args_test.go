package decompiler

import (
	"strings"
	"testing"

	"aotopsy/internal/sdk"
)

// TestIndirectCallDoesNotDumpICDataRegister pins the bound on an indirect
// call's argument list.
//
// An AOT switchable call passes its arguments on the STACK
// (FlowGraphCompiler::EmitInstanceCallAOT reads the receiver back out with
// `movq RDX, [RSP + …]` / `LoadFromOffset(R0, SP, …)` and ends with
// EmitDropArguments). The register at sdk.ICDataArgRegIndex holds the
// UnlinkedCall/MegamorphicCache the sequence just loaded, so it is not an
// argument, and arguments being positional, nothing above it is either.
func TestIndirectCallDoesNotDumpICDataRegister(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fir     *FuncIR
		poisonV string
	}{
		{"x86_64", firX64(), "rbx"},
		{"arm64", firARM64(), "x5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &emitter{fir: tc.fir, state: newLiftState(tc.fir.NullReg)}
			// Fill every argument register with a distinguishable value, so a
			// dump of all six is visible.
			for i := 0; i < len(tc.fir.ArgRegs); i++ {
				e.state.setReg(tc.fir.ArgRegs[i], "V"+string(rune('0'+i)))
			}

			// calleeVA 0 == indirect.
			got := e.callArgExprs(len(tc.fir.ArgRegs), 0)

			if len(got) > sdk.ICDataArgRegIndex {
				t.Errorf("indirect call kept %d args, want at most %d: %v",
					len(got), sdk.ICDataArgRegIndex, got)
			}
			// The IC data register's value must not appear at all.
			for _, a := range got {
				if a == "V"+string(rune('0'+sdk.ICDataArgRegIndex)) {
					t.Errorf("IC_DATA_REG value presented as an argument: %v", got)
				}
			}
		})
	}
}

// TestDirectCallKeepsItsArguments is the other half: the cap applies to
// indirect calls only. A direct call really does pass arguments in registers.
func TestDirectCallKeepsItsArguments(t *testing.T) {
	fir := firX64()
	e := &emitter{fir: fir, state: newLiftState(fir.NullReg)}
	for i := 0; i < len(fir.ArgRegs); i++ {
		e.state.setReg(fir.ArgRegs[i], "V"+string(rune('0'+i)))
	}
	got := e.callArgExprs(len(fir.ArgRegs), 0x1000)
	if len(got) <= sdk.ICDataArgRegIndex {
		t.Errorf("direct call truncated to %d args: %v", len(got), got)
	}
	if !strings.Contains(strings.Join(got, ","), "V4") {
		t.Errorf("direct call lost a real argument: %v", got)
	}
}

func firX64() *FuncIR {
	return &FuncIR{
		ArgRegs:   sdk.DartArgRegNames(sdk.ArchX86),
		FrameReg:  "rbp",
		ReturnReg: "rax",
		StackReg:  "rsp",
	}
}

func firARM64() *FuncIR {
	return &FuncIR{
		ArgRegs:   sdk.DartArgRegNames(sdk.ArchARM64),
		FrameReg:  sdk.ARM64FrameRegStr,
		ReturnReg: sdk.ARM64ReturnRegStr,
		StackReg:  sdk.ARM64StackRegStr,
		NullReg:   sdk.ARM64NullRegStr,
	}
}
