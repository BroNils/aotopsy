package frida

import (
	"aotopsy/internal/arch/x86"
	"fmt"
	"os"

	"golang.org/x/arch/x86/x86asm"

	"aotopsy/internal/cluster"
	"aotopsy/internal/disasm"
	"aotopsy/internal/naming"
	"aotopsy/internal/sdk"
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

// X86RegTracker tracks register provenance for x86_64 indirect-call
// classification.
type X86RegTracker struct {
	defs [16]regProvenance
	w    int
}

func NewX86RegTracker(w int) *X86RegTracker {
	return &X86RegTracker{w: w}
}

func (rt *X86RegTracker) tick() {
	for i := range rt.defs {
		if rt.defs[i].note != "" {
			rt.defs[i].age++
			if rt.defs[i].age > rt.w {
				rt.defs[i] = regProvenance{}
			}
		}
	}
}

func (rt *X86RegTracker) define(idx int, note string) {
	if idx < 0 || idx > 15 {
		return
	}
	rt.defs[idx] = regProvenance{note: note}
}

func (rt *X86RegTracker) kill(idx int) {
	if idx < 0 || idx > 15 {
		return
	}
	rt.defs[idx] = regProvenance{}
}

func (rt *X86RegTracker) lookup(idx int) string {
	if idx < 0 || idx > 15 {
		return ""
	}
	return rt.defs[idx].note
}

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

// ScanIndirectCalls disassembles every function in ranges and reports
// every CALL whose operand is a Reg or Mem (never a Rel), classifying GDT
// calls per the exact pattern above and annotating pool/THR-sourced
// register calls where the provenance is still in the tracking window.
func ScanIndirectCalls(ranges []cluster.CodeRange, code []byte, codeOff, codeVA uint64, pl *naming.PoolLookups, poolDisplay map[int]string, maxHits int) ([]IndirectCall, error) {
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
			funcName = naming.QualifiedCodeName(r.RefID, pl, r.PCOffset)
		} else {
			funcName = fmt.Sprintf("stub_%x", r.PCOffset)
		}

		rt := NewX86RegTracker(12)

		maxHitReached := false
		x86.Walk(funcCode, funcVA, func(d x86.Decoded) bool {
			addr := d.VA
			inst := d.Inst
			if d.Bad {
				rt.tick()
				return true
			}

			if inst.Op == x86asm.CALL {
				for _, arg := range inst.Args {
					if arg == nil {
						continue
					}
					if _, ok := arg.(x86asm.Rel); ok {
						break // direct call, already covered by findCallersOf
					}
					if reg, ok := arg.(x86asm.Reg); ok {
						idx := x86.CanonReg(reg)
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
						break
					}
					if mem, ok := arg.(x86asm.Mem); ok {
						baseNote := rt.lookup(x86.CanonReg(mem.Base))
						ic := IndirectCall{FuncName: funcName, FuncVA: funcVA, Addr: addr, Text: inst.String()}
						if x86.CanonReg(mem.Index) == sdk.X86ClassIdReg && mem.Scale == 8 && baseNote == "dispatch_table" {
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
						break
					}
				}
				rt.tick()
				if maxHits > 0 && hits >= maxHits {
					fmt.Fprintf(os.Stderr, "stopping at --max=%d indirect-call hits\n", maxHits)
					maxHitReached = true
					return false
				}
				return true
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
					dstIdx, srcIdx := x86.CanonReg(dstReg), x86.CanonReg(srcReg)
					if note := rt.lookup(srcIdx); note != "" {
						rt.define(dstIdx, note)
					} else {
						rt.kill(dstIdx)
					}
					rt.tick()
					return true
				}
				if mem, ok := inst.Args[1].(x86asm.Mem); ok && dstOK {
					dstIdx := x86.CanonReg(dstReg)
					if x86.CanonReg(mem.Base) == sdk.X86THR && mem.Index == 0 {
						// Any THR-relative field load. We cannot know the exact
						// dispatch_table_array_offset without the live Thread
						// layout for this build, so treat every THR-sourced
						// register as a dispatch-table candidate; the CALL-site
						// classifier above confirms it via the RCX*8 index
						// shape, which only the real dispatch table load
						// produces on the call side.
						rt.define(dstIdx, "dispatch_table")
					} else if x86.CanonReg(mem.Base) == sdk.X86PP {
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
					return true
				}
				if dstOK {
					rt.kill(x86.CanonReg(dstReg))
				}
			} else if len(inst.Args) >= 1 {
				if dstReg, ok := inst.Args[0].(x86asm.Reg); ok {
					rt.kill(x86.CanonReg(dstReg))
				}
			}

			rt.tick()
			return true
		})
		if maxHitReached {
			// Original stopped ALL processing (not just this function) at the cap.
			return out, nil
		}
	}

	return out, nil
}
