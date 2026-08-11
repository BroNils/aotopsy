package main

import (
	"fmt"
	"os"

	"golang.org/x/arch/x86/x86asm"

	"aotopsy/internal/cluster"
	"aotopsy/internal/disasm"
)

// Ground truth for the x86_64 GDT (global dispatch table) call pattern,
// confirmed against the real Dart SDK source (not guessed):
//
//	runtime/vm/compiler/backend/flow_graph_compiler_x64.cc, EmitDispatchTableCall():
//	    const Register table_reg = RAX;
//	    __ LoadDispatchTable(table_reg);
//	    __ call(compiler::Address(table_reg, cid_reg, TIMES_8, offset));
//
//	runtime/vm/compiler/assembler/assembler_x64.cc, LoadDispatchTable():
//	    movq(dst, Address(THR, Thread::dispatch_table_array_offset()));
//
//	runtime/vm/constants_x64.h: DispatchTableNullErrorABI::kClassIdReg = RCX
//
// So the concrete instruction sequence is:
//
//	mov  <table_reg>, [r14 + dispatch_table_array_offset]   ; THR field load
//	call [<table_reg> + rcx*8 + disp]                       ; indirect, Mem operand
//
// x64refs.go's existing findCallersOf only matches `CALL` with a Rel
// (rip-relative immediate) operand -- direct calls. A GDT call is a CALL
// with a Mem operand and is therefore INVISIBLE to that scan entirely.
// Since GDT calls are how Dart AOT compiles virtual/dynamic-dispatch
// method invocations, any Map/List mutation performed through an
// overridden method (operator[]=, a subclass override, etc.) would never
// show up as a caller of anything via direct-call scanning alone.

// regProvenance tracks, per canonical 64-bit register family (0-15,
// RAX..R15), the last known origin of its value within a small window of
// instructions. Mirrors internal/disasm/calledge.go's RegTracker but for
// x86_64 registers/instructions instead of ARM64.
type regProvenance struct {
	note string
	age  int
}

type x64RegTracker struct {
	defs [16]regProvenance
	w    int
}

func newX64RegTracker(w int) *x64RegTracker {
	return &x64RegTracker{w: w}
}

func (rt *x64RegTracker) tick() {
	for i := range rt.defs {
		if rt.defs[i].note != "" {
			rt.defs[i].age++
			if rt.defs[i].age > rt.w {
				rt.defs[i] = regProvenance{}
			}
		}
	}
}

func (rt *x64RegTracker) define(idx int, note string) {
	if idx < 0 || idx > 15 {
		return
	}
	rt.defs[idx] = regProvenance{note: note}
}

func (rt *x64RegTracker) kill(idx int) {
	if idx < 0 || idx > 15 {
		return
	}
	rt.defs[idx] = regProvenance{}
}

func (rt *x64RegTracker) lookup(idx int) string {
	if idx < 0 || idx > 15 {
		return ""
	}
	return rt.defs[idx].note
}

// canon64 maps any-width GP register operand to a canonical family index
// 0..15 (RAX..R15), or -1 if not a plain GP register we track (segment
// regs, XMM, high-byte AH/CH/DH/BH, etc.)
func canon64(r x86asm.Reg) int {
	switch r {
	case x86asm.RAX, x86asm.EAX, x86asm.AX, x86asm.AL:
		return 0
	case x86asm.RCX, x86asm.ECX, x86asm.CX, x86asm.CL:
		return 1
	case x86asm.RDX, x86asm.EDX, x86asm.DX, x86asm.DL:
		return 2
	case x86asm.RBX, x86asm.EBX, x86asm.BX, x86asm.BL:
		return 3
	case x86asm.RSP, x86asm.ESP, x86asm.SP, x86asm.SPB:
		return 4
	case x86asm.RBP, x86asm.EBP, x86asm.BP, x86asm.BPB:
		return 5
	case x86asm.RSI, x86asm.ESI, x86asm.SI, x86asm.SIB:
		return 6
	case x86asm.RDI, x86asm.EDI, x86asm.DI, x86asm.DIB:
		return 7
	case x86asm.R8, x86asm.R8L, x86asm.R8W, x86asm.R8B:
		return 8
	case x86asm.R9, x86asm.R9L, x86asm.R9W, x86asm.R9B:
		return 9
	case x86asm.R10, x86asm.R10L, x86asm.R10W, x86asm.R10B:
		return 10
	case x86asm.R11, x86asm.R11L, x86asm.R11W, x86asm.R11B:
		return 11
	case x86asm.R12, x86asm.R12L, x86asm.R12W, x86asm.R12B:
		return 12
	case x86asm.R13, x86asm.R13L, x86asm.R13W, x86asm.R13B:
		return 13
	case x86asm.R14, x86asm.R14L, x86asm.R14W, x86asm.R14B:
		return 14
	case x86asm.R15, x86asm.R15L, x86asm.R15W, x86asm.R15B:
		return 15
	}
	return -1
}

const canonR14 = 14 // THR
const canonR15 = 15 // PP
const canonRCX = 1  // DispatchTableNullErrorABI::kClassIdReg

// IndirectCall represents one CALL site whose target is NOT a plain
// rip-relative immediate (Rel arg) -- i.e. a register or memory operand.
type IndirectCall struct {
	FuncName string
	FuncVA   uint64
	Addr     uint64
	Text     string
	Kind     string // "gdt", "pool-indirect", "unresolved-reg", "unresolved-mem"
	Detail   string
}

// scanIndirectCalls disassembles every function in ranges and reports
// every CALL whose operand is a Reg or Mem (never a Rel), classifying GDT
// calls per the exact pattern above and annotating pool/THR-sourced
// register calls where the provenance is still in the tracking window.
func scanIndirectCalls(ranges []cluster.CodeRange, code []byte, codeOff, codeVA uint64, pl *poolLookups, poolDisplay map[int]string, maxHits int) ([]IndirectCall, error) {
	var out []IndirectCall
	hits := 0

	for _, r := range ranges {
		if r.Size == 0 {
			continue
		}
		funcStart := uint64(r.PCOffset) - codeOff
		funcEnd := funcStart + uint64(r.Size)
		if funcEnd > uint64(len(code)) {
			funcEnd = uint64(len(code))
		}
		if funcStart >= funcEnd {
			continue
		}
		funcCode := code[funcStart:funcEnd]
		funcVA := codeVA + funcStart

		var funcName string
		if r.RefID >= 0 {
			funcName = qualifiedCodeNameLocal(r.RefID, pl, r.PCOffset)
		} else {
			funcName = fmt.Sprintf("stub_%x", r.PCOffset)
		}

		rt := newX64RegTracker(12)

		for off := 0; off < len(funcCode); {
			addr := funcVA + uint64(off)
			inst, err := x86asm.Decode(funcCode[off:], 64)
			length := inst.Len
			if err != nil || length <= 0 {
				length = 1
				off += length
				rt.tick()
				continue
			}

			if inst.Op == x86asm.CALL {
				handled := false
				for _, arg := range inst.Args {
					if arg == nil {
						continue
					}
					if _, ok := arg.(x86asm.Rel); ok {
						handled = true // direct call, already covered by findCallersOf
						break
					}
					if reg, ok := arg.(x86asm.Reg); ok {
						idx := canon64(reg)
						note := rt.lookup(idx)
						ic := IndirectCall{FuncName: funcName, FuncVA: funcVA, Addr: addr, Text: inst.String()}
						if note != "" {
							ic.Kind = "pool-indirect"
							ic.Detail = note
						} else {
							ic.Kind = "unresolved-reg"
							ic.Detail = reg.String()
						}
						out = append(out, ic)
						hits++
						handled = true
						break
					}
					if mem, ok := arg.(x86asm.Mem); ok {
						baseNote := rt.lookup(canon64(mem.Base))
						ic := IndirectCall{FuncName: funcName, FuncVA: funcVA, Addr: addr, Text: inst.String()}
						if canon64(mem.Index) == canonRCX && mem.Scale == 8 && baseNote == "dispatch_table" {
							ic.Kind = "gdt"
							ic.Detail = fmt.Sprintf("GDT call, selector-derived offset=0x%x (cid via RCX)", mem.Disp)
						} else if baseNote != "" {
							ic.Kind = "pool-indirect"
							ic.Detail = fmt.Sprintf("base=%s", baseNote)
						} else {
							ic.Kind = "unresolved-mem"
							ic.Detail = fmt.Sprintf("base=%s index=%s scale=%d disp=0x%x", mem.Base, mem.Index, mem.Scale, mem.Disp)
						}
						out = append(out, ic)
						hits++
						handled = true
						break
					}
				}
				_ = handled
				rt.tick()
				off += length
				if maxHits > 0 && hits >= maxHits {
					fmt.Fprintf(os.Stderr, "stopping at --max=%d indirect-call hits\n", maxHits)
					return out, nil
				}
				continue
			}

			// Track MOV dst, [R14+disp] (THR field load) / [R15+disp] (pool load)
			// so a later indirect CALL through dst can be annotated. Mirrors
			// LoadDispatchTable's exact shape: movq(dst, Address(THR, dispatch_table_array_offset())).
			if (inst.Op == x86asm.MOV || inst.Op == x86asm.LEA) && len(inst.Args) >= 2 {
				dstReg, dstOK := inst.Args[0].(x86asm.Reg)
				if srcReg, ok := inst.Args[1].(x86asm.Reg); ok && dstOK && inst.Op == x86asm.MOV {
					// Register-to-register copy: propagate provenance so a
					// closure/function pointer loaded a few instructions
					// earlier (e.g. into RAX) and then shuffled into RCX
					// before the CALL is still resolved.
					dstIdx, srcIdx := canon64(dstReg), canon64(srcReg)
					if note := rt.lookup(srcIdx); note != "" {
						rt.define(dstIdx, note)
					} else {
						rt.kill(dstIdx)
					}
					rt.tick()
					off += length
					continue
				}
				if mem, ok := inst.Args[1].(x86asm.Mem); ok && dstOK {
					dstIdx := canon64(dstReg)
					if canon64(mem.Base) == canonR14 && mem.Index == 0 {
						// Any THR-relative field load. We cannot know the exact
						// dispatch_table_array_offset without the live Thread
						// layout for this build, so treat every THR-sourced
						// register as a dispatch-table candidate; the CALL-site
						// classifier above confirms it via the RCX*8 index
						// shape, which only the real dispatch table load
						// produces on the call side.
						rt.define(dstIdx, "dispatch_table")
					} else if canon64(mem.Base) == canonR15 {
						poolIdx, _ := disasm.X64PoolIndex(mem.Disp)
						if disp, ok := poolDisplay[poolIdx]; ok {
							rt.define(dstIdx, fmt.Sprintf("pp[%d] %s", poolIdx, disp))
						} else {
							rt.define(dstIdx, fmt.Sprintf("pp[%d]", poolIdx))
						}
					} else {
						rt.kill(dstIdx)
					}
					rt.tick()
					off += length
					continue
				}
				if dstOK {
					rt.kill(canon64(dstReg))
				}
			} else if len(inst.Args) >= 1 {
				if dstReg, ok := inst.Args[0].(x86asm.Reg); ok {
					rt.kill(canon64(dstReg))
				}
			}

			rt.tick()
			off += length
		}
	}

	return out, nil
}
