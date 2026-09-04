package disasm

import (
	"aotopsy/internal/arch/x86"
	"fmt"
	"strconv"

	"golang.org/x/arch/x86/x86asm"

	"aotopsy/internal/sdk"
)

// ScanX86FunctionCFG is ScanX86Function's CFG-wide replacement, exactly
// mirroring ExtractCallEdgesCFG's rationale above: the old x86RegTracker
// (W=12) ages out register provenance after a fixed instruction count,
// which can lose it across a branch well before the use site. This
// builds a real (if minimal) x86_64 CFG -- leaders at function start,
// jump/conditional-jump targets, and instructions following a
// terminator -- and runs the same reaching-definitions dataflow as
// ExtractCallEdgesCFG (sharing its lvalue/meetLvalue lattice, just sized
// for x86_64's 16 GP registers instead of ARM64's 31).
//
// internal/disasm cannot import internal/decompiler's own x86 CFG lifter
// (BuildX86IR) -- the dependency runs the other way, decompiler already
// imports disasm for ARM64 -- so the leader/block partitioning here is a
// separate, minimal implementation, using the same JMP/Jcc classification
// internal/decompiler/x86.go's isX86CondJump already uses (duplicated,
// not shared, same reasoning as canonX86Reg's duplication from
// cmd/aotopsy/gdtcall.go).
// H-3 fix: thrFields parameter added to annotate THR loads with field names.
func ScanX86FunctionCFG(funcCode []byte, funcVA uint64, symbols SymbolLookup, poolDisplay map[int]string, funcName string, thrFields map[int]string) X86ScanResult {
	insts := decodeX86Flat(funcCode, funcVA)
	if len(insts) == 0 {
		return X86ScanResult{}
	}
	blocks := buildX86Blocks(insts)

	effects := make([]provBlockEffect, len(blocks))
	for bi, blk := range blocks {
		var regs x86NoWindowRegs
		var touched [16]bool
		for i := blk.Start; i < blk.End; i++ {
			touchX86InstrEffect(insts[i], &regs, &touched, poolDisplay, thrFields)
		}
		eff := provBlockEffect{
			touched: touched[:],
			final:   make([]lvalue, 16),
		}
		for r := 0; r < 16; r++ {
			if touched[r] {
				if v := regs[r]; v != "" {
					eff.final[r] = lvalue{kind: lvKnown, note: v}
				} else {
					eff.final[r] = lvalue{kind: lvBottom}
				}
			}
		}
		effects[bi] = eff
	}

	entryState := runProvFixpoint(len(blocks), 16, func(b int) []Succ {
		return blocks[b].Succs
	}, effects)

	var res X86ScanResult
	for bi, blk := range blocks {
		var regs x86NoWindowRegs
		for r := 0; r < 16; r++ {
			if entryState[bi][r].kind == lvKnown {
				regs[r] = entryState[bi][r].note
			}
		}
		fakeRT := &x86RegTracker{}
		for r := 0; r < 16; r++ {
			if regs[r] != "" {
				fakeRT.defs[r] = x86RegProvenance{note: regs[r]}
			}
		}
		for i := blk.Start; i < blk.End; i++ {
			d := insts[i]
			if d.Inst.Op == x86asm.CALL {
				e := classifyX86Call(d.Inst, d.VA, d.Len, symbols, fakeRT, poolDisplay, thrFields)
				if e.TargetPC != 0 {
					argMask := inferX86CallArgRegMaskLocal(insts, i)
					e.ArgRegMask = argMask
					e.ArgCountHint = popcount8(argMask)
				}
				res.Edges = append(res.Edges, e)
				continue
			}
			touchX86InstrEffect(d, &regs, &[16]bool{}, poolDisplay, thrFields)
			for r := 0; r < 16; r++ {
				fakeRT.defs[r] = x86RegProvenance{note: regs[r]}
			}
			if pd, ok := poolStringRefFor(d, poolDisplay); ok {
				res.StringRefs = append(res.StringRefs, StringRefRecord{
					Func: funcName, PC: fmt.Sprintf("0x%x", d.VA),
					Kind: "PP", PoolIdx: pd.idx, Value: pd.value,
				})
			}
		}
	}
	return res
}

// x86NoWindowRegs mirrors noWindowRegs above but sized for x86_64's 16 GP
// registers instead of ARM64's 31.
type x86NoWindowRegs [16]string

type x86BlockCFG struct {
	Start, End int // indices into the flat decoded-instruction slice
	Succs      []Succ
}

func decodeX86Flat(funcCode []byte, funcVA uint64) []x86.Decoded {
	return x86.Decode(funcCode, funcVA)
}

// buildX86Blocks partitions a flat instruction slice into basic blocks:
// leaders are the function start, JMP/Jcc targets, and instructions
// following a terminator (RET/JMP/Jcc) -- CALL is deliberately NOT a
// leader-inducing instruction, matching ARM64's BuildCFG (BL doesn't
// split blocks there either), so provenance flows through call sites
// exactly like it does across ARM64 BLs.
func buildX86Blocks(insts []x86.Decoded) []x86BlockCFG {
	if len(insts) == 0 {
		return nil
	}

	blocks := PartitionBlocks(
		len(insts),
		func(i int) uint64 { return insts[i].VA },
		func(i int) int { return insts[i].Len },
		func(i int) FlowInfo {
			d := insts[i]
			switch {
			case d.Inst.Op == x86asm.RET:
				return FlowInfo{Kind: FlowRet}
			case d.Inst.Op == x86asm.JMP:
				if t, ok := x86.RelTarget(d.Inst, d.VA, d.Len); ok {
					return FlowInfo{Kind: FlowJump, Target: t, HasTarget: true}
				}
				return FlowInfo{Kind: FlowIndirect}
			case x86.IsCondJump(d.Inst.Op):
				if t, ok := x86.RelTarget(d.Inst, d.VA, d.Len); ok {
					return FlowInfo{Kind: FlowCondJump, Target: t, HasTarget: true}
				}
				return FlowInfo{Kind: FlowNormal}
			default:
				return FlowInfo{Kind: FlowNormal}
			}
		},
	)

	x86Blocks := make([]x86BlockCFG, len(blocks))
	for i, b := range blocks {
		x86Blocks[i] = x86BlockCFG{
			Start: b.Start,
			End:   b.End,
			Succs: b.Succs,
		}
	}
	return x86Blocks
}

// BuildX86CFG constructs a FuncCFG for an x86_64 function's byte stream.
func BuildX86CFG(name string, funcCode []byte, funcVA uint64) FuncCFG {
	decInsts := decodeX86Flat(funcCode, funcVA)
	if len(decInsts) == 0 {
		return FuncCFG{Name: name}
	}
	x86Blocks := buildX86Blocks(decInsts)
	insts := make([]Inst, len(decInsts))
	for i, d := range decInsts {
		insts[i] = Inst{Addr: d.VA, Text: x86.InstText(d.Inst)}
	}
	blocks := make([]BasicBlock, len(x86Blocks))
	for i, b := range x86Blocks {
		blocks[i] = BasicBlock{
			ID:      i,
			Start:   b.Start,
			End:     b.End,
			Succs:   b.Succs,
			IsEntry: i == 0,
			IsTerm:  len(b.Succs) == 0,
		}
	}
	return FuncCFG{
		Name:   name,
		Blocks: blocks,
		Insts:  insts,
	}
}

// touchX86InstrEffect applies one instruction's register-definition
// effect to regs -- the CALL classification itself is handled by the
// caller (ScanX86FunctionCFG), since CALL doesn't define a register the
// way MOV/LEA do.
func touchX86InstrEffect(d x86.Decoded, regs *x86NoWindowRegs, touched *[16]bool, poolDisplay map[int]string, thrFields map[int]string) {
	inst := d.Inst
	if (inst.Op == x86asm.MOV || inst.Op == x86asm.LEA) && len(inst.Args) >= 2 {
		dstReg, dstOK := inst.Args[0].(x86asm.Reg)
		if !dstOK {
			return
		}
		if srcReg, ok := inst.Args[1].(x86asm.Reg); ok && inst.Op == x86asm.MOV {
			dstIdx, srcIdx := x86.CanonReg(dstReg), x86.CanonReg(srcReg)
			if srcIdx >= 0 && srcIdx < 16 && regs[srcIdx] != "" {
				x86Define(regs, touched, dstIdx, regs[srcIdx])
			} else {
				x86Kill(regs, touched, dstIdx)
			}
			return
		}
		if mem, ok := inst.Args[1].(x86asm.Mem); ok {
			dstIdx := x86.CanonReg(dstReg)
			switch x86.CanonReg(mem.Base) {
			case sdk.X86THR:
				// H-3 fix: annotate THR loads with field names when available.
				if thrFields != nil {
					if name, ok := thrFields[int(mem.Disp)]; ok {
						x86Define(regs, touched, dstIdx, "THR."+name)
					} else {
						x86Define(regs, touched, dstIdx, fmt.Sprintf("THR.f%d", mem.Disp))
					}
				} else {
					x86Define(regs, touched, dstIdx, fmt.Sprintf("THR.f%d", mem.Disp))
				}
			case sdk.X86PP:
				poolIdx, poolIdxOK := X64PoolIndex(mem.Disp)
				if disp, ok := poolDisplay[poolIdx]; poolIdxOK && ok {
					x86Define(regs, touched, dstIdx, fmt.Sprintf("pp[%d] %s", poolIdx, disp))
				} else if poolIdxOK {
					x86Define(regs, touched, dstIdx, fmt.Sprintf("pp[%d]", poolIdx))
				}
			default:
				// Generic memory-dereference load (vtable/closure-style calls
				// off a non-PP/THR base). Mirrors ARM64's LDUR64 fallback in
				// touchInstrEffect (dataflow.go) -- annotate rather than kill,
				// so call sites indirecting through it still get a `via`.
				// A Code entry-point load inherits its base's provenance --
				// the entry point OF Code X is X. Same rule as ARM64's
				// touchInstrEffect; see IsCodeEntryPointDisp.
				baseIdx := x86.CanonReg(mem.Base)
				if IsCodeEntryPointDisp(int(mem.Disp)) && baseIdx >= 0 && baseIdx < len(regs) && regs[baseIdx] != "" {
					x86Define(regs, touched, dstIdx, regs[baseIdx])
				} else {
					x86Define(regs, touched, dstIdx, ObjectFieldViaAt(int(mem.Disp)))
				}
			}
			return
		}
		x86Kill(regs, touched, x86.CanonReg(dstReg))
		return
	}
	for _, reg := range x86.DstRegsOfInst(inst) {
		x86Kill(regs, touched, reg)
	}
}

func x86Define(regs *x86NoWindowRegs, touched *[16]bool, idx int, note string) {
	if idx < 0 || idx > 15 {
		return
	}
	regs[idx] = note
	touched[idx] = true
}

func x86Kill(regs *x86NoWindowRegs, touched *[16]bool, idx int) {
	if idx < 0 || idx > 15 {
		return
	}
	regs[idx] = ""
	touched[idx] = true
}

type poolStringRef struct {
	idx   int
	value string
}

// poolStringRefFor reports whether instruction d is a pool load ([R15+
// disp]) whose resolved display value is a quoted string, for
// string_refs.jsonl -- split out from touchX86InstrEffect so the
// local-effect precompute pass (which doesn't need string refs, only
// register touch/kill bookkeeping) doesn't pay for it twice.
func poolStringRefFor(d x86.Decoded, poolDisplay map[int]string) (poolStringRef, bool) {
	inst := d.Inst
	if inst.Op != x86asm.MOV || len(inst.Args) < 2 {
		return poolStringRef{}, false
	}
	if _, dstOK := inst.Args[0].(x86asm.Reg); !dstOK {
		return poolStringRef{}, false
	}
	mem, ok := inst.Args[1].(x86asm.Mem)
	if !ok || x86.CanonReg(mem.Base) != sdk.X86PP {
		return poolStringRef{}, false
	}
	poolIdx, poolIdxOK := X64PoolIndex(mem.Disp)
	if !poolIdxOK {
		return poolStringRef{}, false
	}
	disp, ok := poolDisplay[poolIdx]
	if !ok || len(disp) < 2 || disp[0] != '"' {
		return poolStringRef{}, false
	}
	val, err := strconv.Unquote(disp)
	if err != nil {
		return poolStringRef{}, false
	}
	return poolStringRef{idx: poolIdx, value: val}, true
}
