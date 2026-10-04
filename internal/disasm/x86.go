package disasm

import (
	"aotopsy/internal/arch/x86"
	"fmt"

	"golang.org/x/arch/x86/x86asm"

	"aotopsy/internal/sdk"
	"aotopsy/internal/thraudit"
)

// x86_64 Dart AOT reserved-register roles are now shared from internal/sdk.

// x86RegProvenance records a register's last known origin. Note: no
// time-based expiry field -- that was the old fixed-window design
// (see MODIFICATIONS.md / ARCHITECTURE.md's "x86_64 port status");
// ScanX86FunctionCFG (dataflowx86.go) tracks provenance via a real
// CFG-wide dataflow instead, and only uses x86RegTracker as a small
// read-only adapter so classifyX86Call below doesn't need two lookup
// call shapes.
type x86RegProvenance struct {
	note string
}

type x86RegTracker struct {
	defs [16]x86RegProvenance
}

func (rt *x86RegTracker) lookup(idx int) string {
	if idx < 0 || idx > 15 {
		return ""
	}
	return rt.defs[idx].note
}

// x86RegWidthBytes returns the width in bytes of a register-sized argument
// (8 for RAX, 4 for EAX, 2 for AX, 1 for AL), or 0 if arg is not a register.
// Used to recover the memory access width for MOV instructions whose
// DataSize is 0.
func x86RegWidthBytes(arg x86asm.Arg) int {
	r, ok := arg.(x86asm.Reg)
	if !ok {
		return 0
	}
	switch r {
	case x86asm.RAX, x86asm.RCX, x86asm.RDX, x86asm.RBX,
		x86asm.RSP, x86asm.RBP, x86asm.RSI, x86asm.RDI,
		x86asm.R8, x86asm.R9, x86asm.R10, x86asm.R11,
		x86asm.R12, x86asm.R13, x86asm.R14, x86asm.R15:
		return 8
	case x86asm.EAX, x86asm.ECX, x86asm.EDX, x86asm.EBX,
		x86asm.ESP, x86asm.EBP, x86asm.ESI, x86asm.EDI,
		x86asm.R8L, x86asm.R9L, x86asm.R10L, x86asm.R11L,
		x86asm.R12L, x86asm.R13L, x86asm.R14L, x86asm.R15L:
		return 4
	case x86asm.AX, x86asm.CX, x86asm.DX, x86asm.BX,
		x86asm.SP, x86asm.BP, x86asm.SI, x86asm.DI,
		x86asm.R8W, x86asm.R9W, x86asm.R10W, x86asm.R11W,
		x86asm.R12W, x86asm.R13W, x86asm.R14W, x86asm.R15W:
		return 2
	case x86asm.AL, x86asm.CL, x86asm.DL, x86asm.BL,
		x86asm.SPB, x86asm.BPB, x86asm.SIB, x86asm.DIB,
		x86asm.R8B, x86asm.R9B, x86asm.R10B, x86asm.R11B,
		x86asm.R12B, x86asm.R13B, x86asm.R14B, x86asm.R15B:
		return 1
	}
	return 0
}

// X86ScanResult carries call edges and string references extracted from
// one function in a single instruction-decode pass.
type X86ScanResult struct {
	Edges      []CallEdge
	StringRefs []StringRefRecord
}

// x86ArgRegCanon lists Dart's calling-convention argument registers, in
// parameter order, as canonical indices (RDI=7, RSI=6, RDX=2, RBX=3,
// R8=8, R9=9). This is Dart's OWN convention
// (DartCallingConvention::kCpuRegistersForArgs in constants_x64.h), NOT
// the SysV C ABI — the C ABI's 4th arg is RCX, but Dart uses RBX.
// On every release that has this register calling convention, RCX is the
// fixed dispatch kClassIdReg, not an argument register.
// Shared via sdk.DartRegisterCallingConvention at the first SDK version that
// actually has the convention. This table only maps hardware registers to mask
// positions; callers must still decide whether the analyzed function/version
// uses register arguments at all.
var x86ArgRegCanon = func() [6]int {
	cc, ok := sdk.DartRegisterCallingConvention(sdk.RegisterCallingConventionReferenceVersion, sdk.ArchX86)
	if !ok {
		panic("sdk: x86_64 register calling convention missing at first supported version")
	}
	r := cc.GPR
	var arr [6]int
	copy(arr[:], r)
	return arr
}()

// x86ArgRegBitPos returns which bit of an inferCallArgRegMaskLocal-style
// mask a canonical register index corresponds to (its position in
// x86ArgRegCanon/x86ArgRegs), or -1 if it isn't one of the 6 argument
// registers.
func x86ArgRegBitPos(canonIdx int) int {
	for i, c := range x86ArgRegCanon {
		if c == canonIdx {
			return i
		}
	}
	return -1
}

// maxX86ArgSetupBack bounds inferX86CallArgRegMaskLocal's backward scan --
// same rationale as ARM64's maxArgSetupBack (calledge.go): argument setup
// is a short, contiguous span immediately before the call.
const maxX86ArgSetupBack = 16

// inferX86CallArgRegMaskLocal is inferCallArgRegMaskLocal's x86_64
// counterpart: scans backward from insts[callIdx] (a CALL instruction)
// counting which of RDI/RSI/RDX/RBX/R8/R9 (bit i = x86ArgRegCanon[i]) were
// freshly defined via MOV/LEA in the immediate lead-up to this call. Stops
// at the first earlier CALL (a previous, unrelated call's own setup) or
// after maxX86ArgSetupBack instructions. Same caveats as the ARM64
// version: a single call site's mask is register-allocator noise prone
// (e.g. a value preserved across the call for later use can share a
// register with a real argument at a DIFFERENT call site) -- callers must
// aggregate across every call site targeting the same callee and take the
// bitwise-AND intersection, not trust one site alone (see
// cmd/aotopsy/decompile_native_cmd.go's resolveArgRegIndices and its
// doc comment for why intersection, not exact-equality or majority).
func inferX86CallArgRegMaskLocal(insts []x86.Decoded, callIdx, blockStart int) uint8 {
	var mask uint8
	if blockStart < 0 {
		blockStart = 0
	}
	for i, steps := callIdx-1, 0; i >= blockStart && steps < maxX86ArgSetupBack; i, steps = i-1, steps+1 {
		d := insts[i]
		if d.Inst.Op == x86asm.CALL {
			break
		}
		for _, reg := range x86.DstRegsOfInst(d.Inst) {
			pos := x86ArgRegBitPos(reg)
			if pos >= 0 {
				mask |= 1 << uint(pos)
			}
		}
	}
	return mask
}

func classifyX86Call(dartVersion string, inst x86asm.Inst, addr uint64, length int, symbols SymbolLookup, rt *x86RegTracker, poolDisplay map[int]string, thrFields map[int]string) CallEdge {
	e := CallEdge{FromPC: addr, Kind: "call"}
	for _, arg := range inst.Args {
		if arg == nil {
			continue
		}
		if rel, ok := arg.(x86asm.Rel); ok {
			target, valid := x86.RelTarget(inst, addr, length)
			if !valid {
				return e
			}
			_ = rel // the type check above distinguishes direct from indirect CALL
			e.TargetPC = target
			e.TargetValid = true
			// Nil-safe, matching ARM64: arm64.go's Format and
			// dataflowarm64.go's touchInstrEffect both guard their lookup,
			// so the same call with the same arguments worked on one
			// architecture and panicked on the other.
			if symbols != nil {
				if name, ok := symbols(target); ok {
					e.TargetName = name
				}
			}
			return e
		}
		if reg, ok := arg.(x86asm.Reg); ok {
			e.Kind = "call_indirect"
			e.Reg = reg.String()
			e.Via = rt.lookup(x86.CanonReg(reg))
			return e
		}
		if mem, ok := arg.(x86asm.Mem); ok {
			e.Kind = "call_indirect"
			e.Reg = x86.FormatMemoryTarget(mem)
			// CALL [reg+disp] can address the dispatch table / object pool
			// directly as the call's own memory operand -- e.g. `call
			// [r14+0x238]` -- with no prior MOV loading it into a plain
			// register first. rt.lookup only knows provenance for registers
			// that were *defined* by an earlier instruction; R14/R15
			// themselves are never "defined" that way, so check the base
			// register's fixed role before falling back to the tracker.
			var baseNote string
			switch x86.CanonReg(mem.Base) {
			case sdk.X86THR:
				// A THR-relative call with NO index register is a call
				// through a Thread slot -- a stub entry point -- not a
				// dispatch-table call. This used to claim `dispatch_table`
				// for both shapes, on the reasoning that "THR-relative calls
				// are dispatch table calls regardless of whether an index
				// register is present". The disassembly says otherwise: the
				// x86_64 dispatch sequence loads the table out of Thread
				// first and then indexes the LOADED register,
				//
				//	MOV  RAX, [R14+0x70]        ; THR.dispatch_table_array
				//	CALL [RAX+8*RCX+0xd700]     ; the dispatch call
				//
				// so the base register at a real dispatch call is RAX, never
				// R14. On the 3.12.2 x86_64 sample all 3371 dispatch calls
				// have that shape, and all 6348 `CALL [R14+disp]` sites had
				// no index at all -- yet every one was labelled
				// `dispatch_table` and resolved to nothing. 5979 of them are
				// a single displacement, the stack-overflow check stub that
				// sits in almost every function prologue.
				//
				// Naming them off the Thread field table is the same thing
				// the MOV path next door already does (dataflowx86.go), and
				// it makes them resolve as stubs, which is what ARM64's
				// `LDR lr, [THR, #off]; BLR lr` sites have always done.
				if _, static := x86.StaticBaseDisp(mem, sdk.X86THR); static {
					if name, ok := thrFields[int(mem.Disp)]; ok {
						baseNote = "THR." + name
					} else {
						// An offset the table does not cover names nothing.
						// Report the slot rather than inventing a category.
						baseNote = fmt.Sprintf("THR+0x%x", mem.Disp)
					}
				}
			case sdk.X86PP:
				if _, static := x86.StaticBaseDisp(mem, sdk.X86PP); !static {
					break
				}
				poolIdx, poolIdxOK := X64PoolIndex(mem.Disp)
				if disp, ok := poolDisplay[poolIdx]; poolIdxOK && ok {
					baseNote = fmt.Sprintf("pp[%d] %s", poolIdx, disp)
				} else if poolIdxOK {
					baseNote = fmt.Sprintf("pp[%d]", poolIdx)
				}
			default:
				baseNote = rt.lookup(x86.CanonReg(mem.Base))
			}
			if sdk.IsDispatchTableClassIDReg(dartVersion, sdk.ArchX86, x86.CanonReg(mem.Index)) && mem.Scale == 8 && baseNote == "dispatch_table" {
				e.Via = "dispatch_table"
			} else {
				e.Via = baseNote
			}
			return e
		}
	}
	return e
}

// X86Inst is a minimal decoded-instruction record (address + text) used
// for thr-audit's context window, sitting alongside ScanX86Function's
// CallEdge/StringRefRecord-oriented output above.
type X86Inst struct {
	VA   uint64
	Text string
}

// DecodeX86Simple disassembles a function's raw bytes into address+text
// pairs only -- everything ExtractX86THRAccesses/BuildAuditRecords need,
// without the register-provenance bookkeeping ScanX86Function carries.
func DecodeX86Simple(funcCode []byte, funcVA uint64) []X86Inst {
	decoded := x86.Decode(funcCode, funcVA)
	out := make([]X86Inst, 0, len(decoded))
	for _, d := range decoded {
		if d.Bad {
			out = append(out, X86Inst{VA: d.VA, Text: "<bad>"})
			continue
		}
		out = append(out, X86Inst{VA: d.VA, Text: x86.InstText(d.Inst)})
	}
	return out
}

// ExtractX86THRAccesses scans decoded instructions for static THR-relative
// memory operands ([R14+disp]), mirroring ExtractTHRAccesses's ARM64 X26 scan.
// Access direction is retained, including read-modify-write operations; GPR
// roles are recorded only when the instruction semantics actually transfer the
// memory value to/from that register. fields is optional (marks exact matches).
func ExtractX86THRAccesses(funcCode []byte, funcVA uint64, fields map[int]string) []THRAccess {
	var out []THRAccess
	x86.Walk(funcCode, funcVA, func(d x86.Decoded) bool {
		if d.Bad {
			return true
		}
		addr := d.VA
		inst := d.Inst
		if inst.Op == x86asm.LEA {
			// LEA's memory syntax is an address expression, not a Thread read.
			return true
		}

		for argIdx, arg := range inst.Args {
			if arg == nil {
				continue
			}
			mem, ok := arg.(x86asm.Mem)
			if !ok {
				continue
			}
			if _, static := x86.StaticBaseDisp(mem, sdk.X86THR); !static {
				continue
			}

			width := inst.MemBytes
			if width <= 0 {
				for _, a := range inst.Args {
					if a != nil {
						if r, isReg := a.(x86asm.Reg); isReg {
							width = x86RegWidthBytes(r)
							if width > 0 {
								break
							}
						}
					}
				}
			}
			if width <= 0 {
				width = inst.DataSize / 8
			}

			disp := mem.Disp
			fieldName, resolved := resolveTHRField(fields, disp)
			acc := THRAccess{
				PC:        addr,
				InsnText:  inst.String(),
				THROffset: disp,
				Access:    thraudit.AccessRead,
				Width:     width,
				Resolved:  resolved,
				FieldName: fieldName,
			}

			if inst.Op == x86asm.XCHG {
				// XCHG reads and writes both operands regardless of which operand
				// happens to be the memory one.
				acc.Access = thraudit.AccessReadWrite
			} else if argIdx == 0 {
				acc.Access = x86MemDestinationAccess(inst.Op)
			}
			if acc.Access == thraudit.AccessWrite || acc.Access == thraudit.AccessReadWrite {
				acc.SrcReg = x86ExplicitGPROtherThanMemory(inst, argIdx)
			} else {
				acc.DstReg = x86DirectLoadGPR(inst, argIdx)
			}
			if acc.Access == thraudit.AccessReadWrite {
				acc.DstReg = x86ReadWriteResultGPR(inst, argIdx)
			}

			out = append(out, acc)
			break
		}
		return true
	})
	return out
}

// x86MemDestinationAccess classifies instructions whose first operand is a THR
// memory operand. Read-modify-write instructions remain read_write; collapsing
// them to a store loses the fact that the old Thread value also influenced the
// instruction.
func x86MemDestinationAccess(op x86asm.Op) thraudit.AccessMode {
	switch op {
	case x86asm.MOV,
		x86asm.MOVSD_XMM, x86asm.MOVSS, x86asm.MOVUPS, x86asm.MOVAPS,
		x86asm.MOVDQU, x86asm.VMOVDQU, x86asm.POP:
		return thraudit.AccessWrite
	case x86asm.ADD, x86asm.ADC, x86asm.SUB, x86asm.SBB,
		x86asm.AND, x86asm.OR, x86asm.XOR,
		x86asm.INC, x86asm.DEC, x86asm.NEG, x86asm.NOT,
		x86asm.XADD, x86asm.XCHG, x86asm.CMPXCHG,
		x86asm.BTC, x86asm.BTR, x86asm.BTS:
		return thraudit.AccessReadWrite
	default:
		return thraudit.AccessRead
	}
}

func x86ExplicitGPROtherThanMemory(inst x86asm.Inst, memArgIdx int) *int {
	for i, arg := range inst.Args {
		if i == memArgIdx || arg == nil {
			continue
		}
		reg, ok := arg.(x86asm.Reg)
		if !ok {
			continue
		}
		if idx := x86.CanonReg(reg); idx >= 0 {
			out := idx
			return &out
		}
	}
	return nil
}

// x86DirectLoadGPR returns a register only when the instruction copies or
// extends the THR memory value into operand 0. Comparisons and arithmetic reads
// intentionally return nil: e.g. ADD RAX,[R14+off] does not make RAX equal to
// the Thread field and therefore must not seed indirect-call provenance.
func x86DirectLoadGPR(inst x86asm.Inst, memArgIdx int) *int {
	if memArgIdx == 0 {
		return nil
	}
	switch inst.Op {
	case x86asm.MOV, x86asm.MOVSX, x86asm.MOVSXD, x86asm.MOVZX:
	default:
		return nil
	}
	reg, ok := inst.Args[0].(x86asm.Reg)
	if !ok {
		return nil
	}
	idx := x86.CanonReg(reg)
	if idx < 0 {
		return nil
	}
	out := idx
	return &out
}

// x86ReadWriteResultGPR records the architectural register that receives the
// old memory value for RMW instructions. Dart's x64 safepoint transition uses
// LOCK CMPXCHG on Thread::safepoint_state and immediately consumes RAX, exactly
// as specified by CMPXCHG (SDK 3.12.2 assembler_x64.cc:155-163,229-239).
func x86ReadWriteResultGPR(inst x86asm.Inst, memArgIdx int) *int {
	switch inst.Op {
	case x86asm.XADD, x86asm.XCHG:
		return x86ExplicitGPROtherThanMemory(inst, memArgIdx)
	case x86asm.CMPXCHG:
		rax := 0
		return &rax
	default:
		return nil
	}
}

// BuildX86AuditRecords is ExtractX86THRAccesses's counterpart to
// BuildAuditRecords, operating on []X86Inst instead of []Inst for
// context-window lookup.
func BuildX86AuditRecords(accesses []THRAccess, allInsts []X86Inst, provenance thraudit.Provenance, funcName string) []thraudit.THRAuditRecord {
	pcIdx := make(map[uint64]int, len(allInsts))
	for i, inst := range allInsts {
		pcIdx[inst.VA] = i
	}

	records := make([]thraudit.THRAuditRecord, 0, len(accesses))
	for _, a := range accesses {
		var ctx []string
		if idx, ok := pcIdx[a.PC]; ok {
			for d := -2; d <= 2; d++ {
				j := idx + d
				if j >= 0 && j < len(allInsts) {
					prefix := "  "
					if d == 0 {
						prefix = "> "
					}
					ctx = append(ctx, fmt.Sprintf("%s0x%x: %s", prefix, allInsts[j].VA, allInsts[j].Text))
				}
			}
		}

		rec := thraudit.THRAuditRecord{
			Provenance: provenance, SchemaVersion: thraudit.SchemaV1, PC: fmt.Sprintf("0x%x", a.PC),
			Insn: a.InsnText, THROffset: a.THROffset, Access: a.Access,
			DstReg: a.DstReg, SrcReg: a.SrcReg, Width: a.Width, FuncName: funcName,
			Resolved: a.Resolved, FieldName: a.FieldName, Context: ctx,
		}
		records = append(records, rec)
	}
	return records
}
