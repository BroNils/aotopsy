package disasm

import (
	"golang.org/x/arch/x86/x86asm"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/arch/x86"
	"aotopsy/internal/sdk"
)

// ClosureEntryVia is the call-edge provenance of a Full-AOT closure call. It
// stays inside the object_field namespace so every consumer that already treats
// object-field targets as "callee read out of a heap object" (render, frida
// probes, signal graph) keeps doing so, but names the exact SDK field instead of
// a raw displacement.
const ClosureEntryVia = ObjectFieldVia + "(Closure.entry_point)"

// ClosureEntry describes the closure-call shape of one target configuration.
// The zero value (OK == false) disables recognition, which is what versions
// without Closure.entry_point_ (before Dart 2.14.0) get.
type ClosureEntry struct {
	Disp int  // tagged displacement of Closure.entry_point_
	OK   bool // Disp is meaningful
}

// ClosureEntryFor returns the closure-call shape for a version/compression pair
// from the SDK table in sdk.ClosureEntryPointDisp.
func ClosureEntryFor(dartVersion string, compressedPointers bool) ClosureEntry {
	d, ok := sdk.ClosureEntryPointDisp(dartVersion, compressedPointers)
	return ClosureEntry{Disp: d, OK: ok}
}

// closureCallArgsDescWindow is how many instructions before the entry-point
// load may define ARGS_DESC_REG. ClosureCallInstr::EmitNativeCode starts with
// LoadObject(ARGS_DESC_REG, descriptor) (one pool load, occasionally two
// instructions) and then loads the entry point, so the definition is adjacent.
const closureCallArgsDescWindow = 4

// closureCallARM64 reports whether insts[i] is the entry-point load of a Full-AOT
// ClosureCallInstr (il_arm64.cc ClosureCallInstr::EmitNativeCode, 2.14.0 ..
// 3.13.0 -- bodies Read at every md5 boundary):
//
//	LoadObject(ARGS_DESC_REG=R4, descriptor)
//	LDR R2, [R0, #Closure::entry_point_offset]   ; R0 is pinned by ASSERT(in(0)==R0)
//	BLR R2
//
// The registers are fixed by the SDK, so the shape needs no provenance on R0.
// ARGS_DESC_REG being written shortly before keeps the displacement from matching
// an unrelated `ldr x2,[x0,#d]; blr x2`.
func closureCallARM64(insts []Inst, i int, entry ClosureEntry) bool {
	if !entry.OK || i+1 >= len(insts) || insts[i].Bad || insts[i+1].Bad {
		return false
	}
	mem, ok := arm64.Load64Immediate(insts[i].Raw)
	if !ok || mem.Mode != arm64.AddressOffset || mem.BaseReg != 0 || mem.Reg != 2 || mem.ByteOffset != entry.Disp {
		return false
	}
	if rn, ok := arm64.BLR(insts[i+1].Raw); !ok || rn != 2 {
		return false
	}
	for j := i - 1; j >= 0 && j >= i-closureCallArgsDescWindow; j-- {
		if insts[j].Bad {
			continue
		}
		for _, rd := range arm64.DstRegsOfInst(insts[j].Raw) {
			if rd == sdk.ARM64ArgsDesc {
				return true
			}
		}
	}
	return false
}

// ClosureCallAnnotator labels the entry-point load of every Full-AOT closure call
// in insts with ClosureEntryVia. It is an ordinary Annotator, so the label shows
// in the asm listing and flows through the register-provenance dataflow to the
// BLR that consumes it (call_edges.jsonl `via`).
func ClosureCallAnnotator(insts []Inst, entry ClosureEntry) Annotator {
	if !entry.OK {
		return func(Inst) string { return "" }
	}
	loads := make(map[uint64]bool)
	for i := range insts {
		if closureCallARM64(insts, i, entry) {
			loads[insts[i].Addr] = true
		}
	}
	return func(inst Inst) string {
		if loads[inst.Addr] {
			return ClosureEntryVia
		}
		return ""
	}
}

// closureCallX86 reports whether decoded[i] is the CALL of a Full-AOT closure
// call (il_x64.cc ClosureCallInstr::EmitNativeCode):
//
//	LoadObject(ARGS_DESC_REG=R10, descriptor)
//	MOV RCX, [RAX + Closure::entry_point_offset]   ; RAX pinned by ASSERT(in(0)==RAX)
//	CALL RCX
func closureCallX86(decoded []x86.Decoded, i int, entry ClosureEntry) bool {
	if !entry.OK || i < 1 || decoded[i].Bad || decoded[i-1].Bad || decoded[i].Inst.Op != x86asm.CALL {
		return false
	}
	call := decoded[i].Inst
	if call.Args[0] == nil {
		return false
	}
	target, ok := call.Args[0].(x86asm.Reg)
	if !ok || x86.CanonReg(target) != 1 { // RCX
		return false
	}
	load := decoded[i-1].Inst
	if load.Op != x86asm.MOV || load.Args[0] == nil || load.Args[1] == nil {
		return false
	}
	dst, ok := load.Args[0].(x86asm.Reg)
	if !ok || x86.CanonReg(dst) != 1 {
		return false
	}
	mem, ok := load.Args[1].(x86asm.Mem)
	if !ok || x86.CanonReg(mem.Base) != 0 || mem.Index != 0 || mem.Disp != int64(entry.Disp) { // RAX
		return false
	}
	for j := i - 2; j >= 0 && j >= i-1-closureCallArgsDescWindow; j-- {
		if decoded[j].Bad {
			continue
		}
		for _, rd := range x86.DstRegsOfInst(decoded[j].Inst) {
			if rd == sdk.X86ArgsDesc {
				return true
			}
		}
	}
	return false
}
