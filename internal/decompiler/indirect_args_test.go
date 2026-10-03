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

			idx, ok := sdk.ICDataArgRegIndex(tc.fir.DartVersion, tc.fir.LinkReg != "")
			if !ok {
				t.Fatal("IC_DATA_REG position unavailable for test profile")
			}
			if len(got) > idx {
				t.Errorf("indirect call kept %d args, want at most %d: %v",
					len(got), idx, got)
			}
			// The IC data register's value must not appear at all.
			for _, a := range got {
				if a == "V"+string(rune('0'+idx)) {
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
	idx, ok := sdk.ICDataArgRegIndex(fir.DartVersion, false)
	if !ok {
		t.Fatal("IC_DATA_REG position unavailable for test profile")
	}
	if len(got) <= idx {
		t.Errorf("direct call truncated to %d args: %v", len(got), got)
	}
	if !strings.Contains(strings.Join(got, ","), "V4") {
		t.Errorf("direct call lost a real argument: %v", got)
	}
}

func TestIndirectCallTargetRegisterIsLiveIn(t *testing.T) {
	for _, tt := range []struct {
		name string
		ins  Instr
		reg  string
	}{
		{"x86", Instr{Op: OpCall, Src: "call rdi", Target: "rdi"}, "rdi"},
		{"arm64", Instr{Op: OpCall, Src: "blr x1", Target: "x1"}, "x1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reads, writes := inspectInstrRegUsage(tt.ins, "")
			if !containsString(reads, tt.reg) {
				t.Fatalf("reads = %v, want %s", reads, tt.reg)
			}
			if containsString(writes, tt.reg) {
				t.Fatalf("writes = %v: indirect call target must not be a destination", writes)
			}
		})
	}
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func firX64() *FuncIR {
	cc, _ := sdk.DartRegisterCallingConvention("3.12.2", sdk.ArchX86)
	return &FuncIR{
		DartVersion: "3.12.2",
		ArgRegs:     cc.GPRNames,
		FrameReg:    "rbp",
		ReturnReg:   "rax",
		StackReg:    "rsp",
	}
}

func firARM64() *FuncIR {
	cc, _ := sdk.DartRegisterCallingConvention("3.12.2", sdk.ArchARM64)
	return &FuncIR{
		DartVersion: "3.12.2",
		ArgRegs:     cc.GPRNames,
		FrameReg:    sdk.ARM64FrameRegStr,
		ReturnReg:   sdk.ARM64ReturnRegStr,
		StackReg:    sdk.ARM64StackRegStr,
		NullReg:     sdk.ARM64NullRegStr,
	}
}
