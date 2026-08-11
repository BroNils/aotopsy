package typetrack

import (
	"sort"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/disasm"
	"golang.org/x/arch/x86/x86asm"
)

// x86_64 register constants (matching dart-lang/sdk constants_x64.h).
const (
	x86RegPP  = 15 // R15 = object pool pointer
	x86RegTHR = 14 // R14 = thread pointer
	x86RegRCX = 1  // kClassIdReg (DispatchTableNullErrorABI)
	x86RegRAX = 0  // return value / allocation result
	x86RegRDI = 7  // SysV arg 0 (receiver for instance methods)
)

// x86ArgRegCanon lists the SysV AMD64 ABI integer argument registers
// in calling-convention order (RDI, RSI, RDX, RCX, R8, R9).
var x86ArgRegCanon = [6]int{7, 6, 2, 1, 8, 9}

// X86DecodedInst is a decoded x86_64 instruction with its address.
type X86DecodedInst struct {
	Addr uint64
	Inst x86asm.Inst
	Len  int
}

// AnalyzeFunctionX86 runs intra-procedural type dataflow on one x86_64 function.
// It mirrors AnalyzeFunction (ARM64) but uses x86_64 instruction decoders.
func AnalyzeFunctionX86(
	insts []X86DecodedInst,
	ctx *TypeContext,
	entryTypes [31]TypeLattice,
) *IntraResult {
	result := &IntraResult{
		EntryTypes: entryTypes,
	}

	// Pre-scan: find x86_64 dispatch table call patterns.
	// Pattern from SDK (flow_graph_compiler_x64.cc):
	//   MOV RAX, [R14 + dispatch_table_array_offset]  (LoadDispatchTable)
	//   CALL [RAX + RCX*8 + disp32]                    (dispatch table call)
	// disp32 = (selector_offset - kOriginElement) * kWordSize
	//
	// SelectorOffsets stores the SELECTOR IMMEDIATE -- the same quantity the
	// ARM64 side records, i.e. `selector_offset - kOriginElement`, which here
	// is simply disp32/kWordSize. It must NOT have kOriginElement added back:
	// the consumer (TypeContext.selectorCandidates) computes
	// `cid = slotKey - imm`, where slotKey is already register-relative
	// (DispatchBySlot is keyed by entry.Index - kOriginElement, and the
	// dispatch-table register points at array[kOriginElement] --
	// DispatchTable::ArrayOrigin()). Adding the origin here shifted every
	// implied class ID by kOriginElement.
	// We store it keyed by the CALL's address.
	for i := 0; i < len(insts); i++ {
		inst := insts[i]
		if inst.Inst.Op != x86asm.CALL {
			continue
		}
		mem, ok := inst.Inst.Args[0].(x86asm.Mem)
		if !ok {
			continue
		}
		baseReg := canonX86RegLocal(mem.Base)
		idxReg := canonX86RegLocal(mem.Index)
		// Check: CALL [RAX + RCX*8 + disp32]
		if baseReg == x86RegRAX && idxReg == x86RegRCX && mem.Scale == 8 {
			ctx.SelectorOffsets[inst.Addr] = int(mem.Disp / 8)
		}
	}

	blocks := buildBlocksX86(insts)
	if len(blocks) == 0 {
		return result
	}

	// H-7 fix: per-block stack types (matching ARM64's PHASE A fix).
	// Prevents cross-block stack type pollution.
	blockStackEntry := make([]map[int]TypeLattice, len(blocks))
	blockStackExit := make([]map[int]TypeLattice, len(blocks))
	for i := range blockStackEntry {
		blockStackEntry[i] = make(map[int]TypeLattice)
		blockStackExit[i] = make(map[int]TypeLattice)
	}

	blockEntry := make([][31]TypeLattice, len(blocks))
	blockExit := make([][31]TypeLattice, len(blocks))
	blockEntry[0] = entryTypes

	lca := func(a, b int) int { return LCA(a, b, ctx.SuperClass) }

	worklist := make([]int, 0, len(blocks))
	worklist = append(worklist, 0)
	inWorklist := make(map[int]bool, len(blocks))
	inWorklist[0] = true

	for len(worklist) > 0 {
		idx := worklist[0]
		worklist = worklist[1:]
		inWorklist[idx] = false

		state := blockEntry[idx]
		blk := blocks[idx]
		// H-7 fix: use per-block stack types (copy from entry, modify during transfer).
		stackTypes := make(map[int]TypeLattice, len(blockStackEntry[idx]))
		for k, v := range blockStackEntry[idx] {
			stackTypes[k] = v
		}

		// prevInst is the previous instruction in this block (nil at block
		// start). Used by the SHR/AND handler to detect the header-load →
		// class-ID-extract pattern and preserve Bottom, mirroring ARM64's
		// prevRaw UBFX fix (which unlocked 11550 field hits). Without this,
		// x86_64 kills Bottom on the header load and the selector-offset-scan
		// dispatch path never fires, explaining the BLR gap vs ARM64.
		var prevInst *X86DecodedInst
		for _, inst := range blk.insts {
			transferInstructionX86(&state, inst, prevInst, ctx, result, lca, stackTypes)
			prevInst = &inst
		}

		blockExit[idx] = state
		blockStackExit[idx] = stackTypes

		for _, succ := range blk.successors {
			var newEntry [31]TypeLattice
			if isFirstVisit := allTop(blockEntry[succ]) && succ != 0; isFirstVisit {
				newEntry = state
			} else {
				for r := 0; r < 31; r++ {
					newEntry[r] = meetType(blockEntry[succ][r], state[r], lca)
				}
			}

			changed := !typesEqual(newEntry, blockEntry[succ])

			// H-7 fix: propagate stack types to successor (merge/meet).
			newStackEntry := blockStackEntry[succ]
			for k, v := range stackTypes {
				oldV, exists := newStackEntry[k]
				if !exists {
					newStackEntry[k] = v
					changed = true
				} else if !v.Equal(oldV) {
					meetV := meetType(oldV, v, lca)
					if !meetV.Equal(oldV) {
						newStackEntry[k] = meetV
						changed = true
					}
				}
			}

			if changed {
				blockEntry[succ] = newEntry
				if !inWorklist[succ] {
					worklist = append(worklist, succ)
					inWorklist[succ] = true
				}
			}
		}
	}

	for i := range blocks {
		if len(blocks[i].successors) == 0 {
			for r := 0; r < 31; r++ {
				result.ExitTypes[r] = meetType(result.ExitTypes[r], blockExit[i][r], lca)
			}
		}
	}

	result.ParamTypes = entryTypes
	return result
}

// x86BasicBlock is a straight-line sequence of x86_64 instructions with successors.
type x86BasicBlock struct {
	insts      []X86DecodedInst
	successors []int // block indices
}

// buildBlocksX86 partitions x86_64 instructions into basic blocks.
// Leaders are at: function start, JMP/Jcc targets, instruction after JMP/RET.
func buildBlocksX86(insts []X86DecodedInst) []x86BasicBlock {
	if len(insts) == 0 {
		return nil
	}
	funcStart := insts[0].Addr
	funcEnd := insts[len(insts)-1].Addr + uint64(insts[len(insts)-1].Len)

	addrToIdx := make(map[uint64]int, len(insts))
	for i, d := range insts {
		addrToIdx[d.Addr] = i
	}

	leaders := map[int]bool{0: true}
	for i, d := range insts {
		isBranch := false
		switch d.Inst.Op {
		case x86asm.RET:
			isBranch = true
		case x86asm.JMP:
			isBranch = true
			if t, ok := x86RelTarget(d); ok && t >= funcStart && t < funcEnd {
				if idx, ok2 := addrToIdx[t]; ok2 {
					leaders[idx] = true
				}
			}
		default:
			if isX86CondJump(d.Inst.Op) {
				isBranch = true
				if t, ok := x86RelTarget(d); ok && t >= funcStart && t < funcEnd {
					if idx, ok2 := addrToIdx[t]; ok2 {
						leaders[idx] = true
					}
				}
			}
		}
		if isBranch && i+1 < len(insts) {
			leaders[i+1] = true
		}
	}

	sorted := make([]int, 0, len(leaders))
	for idx := range leaders {
		sorted = append(sorted, idx)
	}
	sort.Ints(sorted)

	leaderToBlock := make(map[int]int, len(sorted))
	blocks := make([]x86BasicBlock, len(sorted))
	for i, start := range sorted {
		end := len(insts)
		if i+1 < len(sorted) {
			end = sorted[i+1]
		}
		blocks[i] = x86BasicBlock{insts: insts[start:end]}
		leaderToBlock[start] = i
	}

	for bi := range blocks {
		blk := &blocks[bi]
		if len(blk.insts) == 0 {
			continue
		}
		last := blk.insts[len(blk.insts)-1]
		switch last.Inst.Op {
		case x86asm.RET:
			// terminal
		case x86asm.JMP:
			if t, ok := x86RelTarget(last); ok {
				if idx, ok2 := addrToIdx[t]; ok2 {
					if tb, ok3 := leaderToBlock[idx]; ok3 {
						blk.successors = append(blk.successors, tb)
						continue
					}
				}
			}
		default:
			if isX86CondJump(last.Inst.Op) {
				if t, ok := x86RelTarget(last); ok {
					if idx, ok2 := addrToIdx[t]; ok2 {
						if tb, ok3 := leaderToBlock[idx]; ok3 {
							blk.successors = append(blk.successors, tb)
						}
					}
				}
			}
			// Fall-through successor (for non-jump and cond-jump false branch).
			lastInst := blk.insts[len(blk.insts)-1]
			fallThroughAddr := lastInst.Addr + uint64(lastInst.Len)
			if idx, ok := addrToIdx[fallThroughAddr]; ok {
				if nb, ok2 := leaderToBlock[idx]; ok2 {
					blk.successors = append(blk.successors, nb)
				}
			} else if bi+1 < len(blocks) {
				blk.successors = append(blk.successors, bi+1)
			}
		}
	}

	return blocks
}

// x86RelTarget returns the absolute target address of a rel32 branch.
func x86RelTarget(d X86DecodedInst) (uint64, bool) {
	for _, arg := range d.Inst.Args {
		if arg == nil {
			continue
		}
		if rel, ok := arg.(x86asm.Rel); ok {
			return d.Addr + uint64(d.Len) + uint64(int64(rel)), true
		}
	}
	return 0, false
}

// isX86CondJump returns true for conditional jump opcodes.
func isX86CondJump(op x86asm.Op) bool {
	switch op {
	case x86asm.JA, x86asm.JAE, x86asm.JB, x86asm.JBE, x86asm.JCXZ, x86asm.JECXZ, x86asm.JRCXZ,
		x86asm.JE, x86asm.JG, x86asm.JGE, x86asm.JL, x86asm.JLE, x86asm.JNE, x86asm.JNO, x86asm.JNP,
		x86asm.JNS, x86asm.JO, x86asm.JP, x86asm.JS:
		return true
	}
	return false
}

// canonX86RegLocal maps any-width GP register operand to a canonical family
// index 0..15 (RAX..R15), or -1 for anything else.
func canonX86RegLocal(r x86asm.Reg) int {
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

// isX86HeaderLoad reports whether prev was a header load writing dstIdx:
// `MOV dstReg, [base-1]` where -1 is kHeapObjectTag. This is the x86_64
// equivalent of ARM64's `LDUR Xt, [Xn, #-1]`, used to detect the header-load →
// class-ID-extract pattern so a subsequent SHR/AND preserves Bottom.
func isX86HeaderLoad(prev *X86DecodedInst, dstIdx int) bool {
	if prev == nil {
		return false
	}
	p := prev.Inst
	if p.Op != x86asm.MOV || len(p.Args) < 2 {
		return false
	}
	dstReg, ok := p.Args[0].(x86asm.Reg)
	if !ok {
		return false
	}
	if canonX86RegLocal(dstReg) != dstIdx {
		return false
	}
	mem, ok := p.Args[1].(x86asm.Mem)
	if !ok {
		return false
	}
	return mem.Disp == -1
}

// transferInstructionX86 updates the register type state for one x86_64 instruction.
// H-4 fix: added stack type tracking, field type lookup, LEA dispatch slot
// computation, and fixed allocation stub detection.
// L-3 fix: stackTypes is now passed as a parameter instead of using a package global.
// prevInst is the previous instruction in the block (nil at block start); used
// by the SHR/AND handler to detect the header-load → class-ID-extract pattern
// and preserve Bottom, mirroring ARM64's prevRaw UBFX fix.
func transferInstructionX86(
	state *[31]TypeLattice,
	inst X86DecodedInst,
	prevInst *X86DecodedInst,
	ctx *TypeContext,
	result *IntraResult,
	lca func(int, int) int,
	stackTypes map[int]TypeLattice,
) {
	ins := inst.Inst

	// H-4 fix 1: Stack store: MOV [RBP+disp], reg → save reg's type to stack.
	if ins.Op == x86asm.MOV && len(ins.Args) >= 2 {
		if mem, ok := ins.Args[0].(x86asm.Mem); ok {
			baseIdx := canonX86RegLocal(mem.Base)
			if baseIdx == 5 { // RBP = frame register
				if srcReg, srcOK := ins.Args[1].(x86asm.Reg); srcOK {
					srcIdx := canonX86RegLocal(srcReg)
					if srcIdx >= 0 && srcIdx < 31 {
						stackTypes[int(mem.Disp)] = state[srcIdx]
					}
				}
				return
			}
		}
	}

	// H-4 fix 1b: Stack load: MOV reg, [RBP+disp] → load type from stack.
	if (ins.Op == x86asm.MOV || ins.Op == x86asm.MOVZX) && len(ins.Args) >= 2 {
		if dstReg, dstOK := ins.Args[0].(x86asm.Reg); dstOK {
			dstIdx := canonX86RegLocal(dstReg)
			if dstIdx >= 0 && dstIdx < 31 {
				if mem, ok := ins.Args[1].(x86asm.Mem); ok {
					baseIdx := canonX86RegLocal(mem.Base)
					if baseIdx == 5 { // RBP
						if t, ok2 := stackTypes[int(mem.Disp)]; ok2 {
							state[dstIdx] = t
						} else {
							state[dstIdx] = Top()
						}
						return
					}
				}
			}
		}
	}

	// MOV/MOVZX reg, [mem] — memory load (PP, THR, or object header/field).
	if (ins.Op == x86asm.MOV || ins.Op == x86asm.MOVZX) && len(ins.Args) >= 2 {
		dstReg, dstOK := ins.Args[0].(x86asm.Reg)
		if !dstOK {
			return
		}
		dstIdx := canonX86RegLocal(dstReg)
		if dstIdx < 0 || dstIdx >= 31 {
			return
		}
		// MOV/MOVZX reg, [mem] — memory load.
		if mem, ok := ins.Args[1].(x86asm.Mem); ok {
			baseIdx := canonX86RegLocal(mem.Base)
			// PP load: MOV reg, [R15+disp] → KnownClass.
			if baseIdx == x86RegPP {
				poolIdx, poolIdxOK := disasm.X64PoolIndex(mem.Disp)
				if !poolIdxOK {
					return
				}
				if classID, ok2 := ctx.PoolClassByIndex[poolIdx]; ok2 && classID >= 0 {
					state[dstIdx] = KnownClass(classID)
					ctx.PPHits++
				} else if ctx.PoolClosureClass != nil {
					// Closure consumer: same as ARM64, resolve Closure →
					// ClosureData.parent_function → owner class.
					if classID, ok3 := ctx.PoolClosureClass[poolIdx]; ok3 && classID >= 0 {
						state[dstIdx] = KnownClass(classID)
						ctx.PPHits++
						return
					}
					state[dstIdx] = Top()
				} else {
					state[dstIdx] = Top()
				}
				return
			}
			// THR load: MOV reg, [R14+disp] → KnownStub.
			if baseIdx == x86RegTHR {
				byteOff := int(mem.Disp)
				stubName := ""
				if ctx.AllocStubOffsets != nil {
					if name, found := ctx.AllocStubOffsets[int64(byteOff)]; found {
						stubName = name
					}
				}
				if stubName == "" && ctx.THRFields != nil {
					if name, found := ctx.THRFields[byteOff]; found {
						stubName = name
					}
				}
				// Dispatch table array load: MOV reg, [THR + dispatch_table_array_offset]
				// SDK (flow_graph_compiler_x64.cc): LoadDispatchTable = movq(dst, [THR + offset])
				// This is a MOV, not LEA — so the LEA handler below never fires.
				// Set KnownDispatch(0) so subsequent CALL [reg + RCX*8 + disp] can resolve.
				if stubName == "dispatch_table_array" {
					state[dstIdx] = KnownDispatch(0)
					return
				}
				state[dstIdx] = KnownStub(stubName, byteOff)
				return
			}
			// H-4 fix 2: Field type lookup — MOV reg, [reg+offset] where base
			// has KnownClass. Look up the field at this offset for the class.
			if baseIdx >= 0 && baseIdx < 31 && state[baseIdx].Kind == LatticeKnownClass {
				// First check if this is a header load (offset -1 = tag field).
				if mem.Disp == -1 { // M-12 fix: was `|| mem.Disp == 0` — too broad, match ARM64 which only checks -1
					// Object header load: class ID extraction.
					state[dstIdx] = KnownClass(state[baseIdx].ClassID)
					ctx.HeaderHits++
					return
				}
				// Field type: declared type first, then the type observed in
				// const Instance objects. Shared with the ARM64 handlers via
				// TypeContext.FieldValueClass so the precedence rule has one
				// definition.
				if classID, ok2 := ctx.FieldValueClass(state[baseIdx].ClassID, int32(mem.Disp)); ok2 {
					state[dstIdx] = KnownClass(classID)
					return
				}
				// Unknown field — keep KnownClass as approximation.
				state[dstIdx] = KnownClass(state[baseIdx].ClassID)
				ctx.HeaderHits++
				return
			}
			// Other memory load — kill dst.
			state[dstIdx] = Top()
			return
		}
		// MOV reg, reg — copy type.
		if srcReg, ok := ins.Args[1].(x86asm.Reg); ok {
			srcIdx := canonX86RegLocal(srcReg)
			if srcIdx >= 0 && srcIdx < 31 {
				state[dstIdx] = state[srcIdx]
			} else {
				state[dstIdx] = Top()
			}
			return
		}
		// MOV reg, imm — kill.
		state[dstIdx] = Top()
		return
	}

	// H-4 fix 3: LEA reg, [reg+imm] — dispatch table slot computation.
	// LEA reg, [R14+disp] loads the dispatch table base from THR.
	// LEA reg, [reg+imm] where base is KnownClass → dispatch slot.
	if ins.Op == x86asm.LEA && len(ins.Args) >= 2 {
		dstReg, dstOK := ins.Args[0].(x86asm.Reg)
		if !dstOK {
			return
		}
		dstIdx := canonX86RegLocal(dstReg)
		if dstIdx < 0 || dstIdx >= 31 {
			return
		}
		if mem, ok := ins.Args[1].(x86asm.Mem); ok {
			baseIdx := canonX86RegLocal(mem.Base)
			// LEA reg, [THR+disp] → load dispatch table base.
			if baseIdx == x86RegTHR && mem.Disp != 0 {
				// This loads the dispatch table array from Thread.
				// Mark as KnownDispatchIndex(0) so subsequent CALL [reg+RCX*8+disp]
				// can compute the slot.
				state[dstIdx] = KnownDispatch(0)
				return
			}
			// LEA reg, [reg+imm] where base is KnownClass → dispatch slot.
			if baseIdx >= 0 && baseIdx < 31 && state[baseIdx].Kind == LatticeKnownClass {
				slot := state[baseIdx].ClassID + int(mem.Disp/8)
				state[dstIdx] = KnownDispatch(slot)
				ctx.ADDClassHits++
				return
			}
			// LEA reg, [reg+imm] where base is KnownDispatchIndex → adjust slot.
			if baseIdx >= 0 && baseIdx < 31 && state[baseIdx].Kind == LatticeKnownDispatchIndex {
				slot := state[baseIdx].DispatchIndex + int(mem.Disp/8)
				state[dstIdx] = KnownDispatch(slot)
				return
			}
		}
		state[dstIdx] = Top()
		return
	}

	// SHR/AND reg, imm — bitfield extract (class ID extraction from header).
	// If the source has KnownClass, preserve it (same as ARM64 UBFX).
	// If the source is Bottom AND the previous instruction was a header load
	// (MOV reg, [base-1], the x86 equivalent of ARM64's LDUR Xt, [Xn, #-1]),
	// preserve Bottom — the SHR/AND extracts the class ID from an unknown
	// receiver, and Bottom lets the selector-offset-scan dispatch path fire.
	// This mirrors the ARM64 prevRaw UBFX fix that unlocked 11550 field hits;
	// without it x86_64 killed Bottom here and dispatch resolution was
	// severely degraded vs ARM64.
	if (ins.Op == x86asm.SHR || ins.Op == x86asm.AND) && len(ins.Args) >= 2 {
		dstReg, dstOK := ins.Args[0].(x86asm.Reg)
		if !dstOK {
			return
		}
		dstIdx := canonX86RegLocal(dstReg)
		if dstIdx < 0 || dstIdx >= 31 {
			return
		}
		if srcReg, ok := ins.Args[0].(x86asm.Reg); ok {
			srcIdx := canonX86RegLocal(srcReg)
			if srcIdx >= 0 && srcIdx < 31 {
				if state[srcIdx].Kind == LatticeKnownClass {
					// SHR/AND on KnownClass preserves KnownClass (class ID extraction).
					state[dstIdx] = state[srcIdx]
					ctx.UBFXHits++
					return
				}
				if state[srcIdx].Kind == LatticeBottom && prevInst != nil {
					// Check if prevInst was a header load: MOV srcReg, [base-1].
					// The x86 header load pattern is MOV reg, [reg-1] where -1
					// is kHeapObjectTag (same as ARM64 LDUR Xt, [Xn, #-1]).
					if isX86HeaderLoad(prevInst, srcIdx) {
						state[dstIdx] = Bottom()
						ctx.UBFXHits++
						return
					}
				}
			}
		}
		state[dstIdx] = Top()
		return
	}

	// CALL — dispatch table call, allocation stub, or direct call.
	if ins.Op == x86asm.CALL && len(ins.Args) >= 1 {
		// H-7 fix: capture call-site state before CALL kills arg regs.
		callTarget := uint64(0)
		if rel, ok := ins.Args[0].(x86asm.Rel); ok {
			callTarget = inst.Addr + uint64(inst.Len) + uint64(int64(rel))
		}
		if callTarget != 0 {
			if result.BLCallSiteTypes == nil {
				result.BLCallSiteTypes = make(map[uint64][31]TypeLattice)
			}
			result.BLCallSiteTypes[callTarget] = *state
		}

		// CALL [mem] — indirect call (dispatch table or object field).
		if mem, ok := ins.Args[0].(x86asm.Mem); ok {
			idxReg := canonX86RegLocal(mem.Index)
			baseReg := canonX86RegLocal(mem.Base)
			// H-4 fix 5: Dispatch table call via LEA-computed base:
			// CALL [lea_reg + RCX*8 + disp] where lea_reg has KnownDispatchIndex(0).
			if baseReg >= 0 && baseReg < 31 && state[baseReg].Kind == LatticeKnownDispatchIndex {
				if idxReg == x86RegRCX && state[x86RegRCX].Kind == LatticeKnownClass {
					slot := int(state[x86RegRCX].ClassID) + int(mem.Disp/8)
					resolveX86Dispatch(state, slot, inst, ctx, result)
				} else if idxReg == x86RegRCX {
					// P2.1: RCX is Bottom or Top — try selector offset scan.
					resolveX86DispatchSelectorOffset(state, inst, ctx, result)
				}
			} else if idxReg == x86RegRCX && state[x86RegRCX].Kind == LatticeKnownClass {
				// Direct dispatch table call: CALL [reg + RCX*8 + disp].
				slot := int(state[x86RegRCX].ClassID) + int(mem.Disp/8)
				resolveX86Dispatch(state, slot, inst, ctx, result)
			} else if idxReg == x86RegRCX && mem.Scale == 8 {
				// P2.1: RCX is Bottom or Top, but pattern matches dispatch table call.
				// Try selector offset scan.
				resolveX86DispatchSelectorOffset(state, inst, ctx, result)
			}
			// Kill return value + arg regs.
			state[x86RegRAX] = Top()
			killX86ArgRegs(state)
			return
		}
		// CALL rel32 — direct call (allocation stub or regular function).
		if rel, ok := ins.Args[0].(x86asm.Rel); ok {
			callTarget = inst.Addr + uint64(inst.Len) + uint64(int64(rel))
			// H-4 fix 4: Allocation stub detection via KnownStub in RAX.
			// If RAX holds a KnownStub with "Allocate" prefix, this is an
			// allocation call. The allocation returns a new object of the
			// class that was in RDI (receiver/first arg) before the call.
			if state[x86RegRAX].Kind == LatticeKnownStub {
				sn := state[x86RegRAX].StubName
				if strings.HasPrefix(sn, "Allocate") || strings.HasPrefix(sn, "allocate") {
					// Preserve RDI's KnownClass — allocation returns new object
					// of the same class.
					if state[x86RegRDI].Kind == LatticeKnownClass {
						state[x86RegRAX] = state[x86RegRDI]
					} else {
						state[x86RegRAX] = Top()
					}
					killX86ArgRegs(state)
					return
				}
			}
			// H-7 fix: restore callee exit types if available.
			if calleeAllExit, hasFull := ctx.CalleeAllExitTypes[callTarget]; hasFull {
				for r := 0; r < 31; r++ {
					if calleeAllExit[r].Kind != LatticeTop {
						state[r] = calleeAllExit[r]
					}
				}
			} else if calleeExit, hasExit := ctx.CalleeExitTypes[callTarget]; hasExit {
				state[x86RegRAX] = calleeExit
			} else {
				state[x86RegRAX] = Top()
			}
			killX86ArgRegs(state)
			return
		}
		// CALL reg — indirect call through register.
		// H-4 fix: Check if the register holds KnownStub (THR-cached stub).
		if reg, ok := ins.Args[0].(x86asm.Reg); ok {
			regIdx := canonX86RegLocal(reg)
			if regIdx >= 0 && regIdx < 31 && state[regIdx].Kind == LatticeKnownStub {
				sn := state[regIdx].StubName
				if strings.HasPrefix(sn, "Allocate") || strings.HasPrefix(sn, "allocate") {
					if state[x86RegRDI].Kind == LatticeKnownClass {
						state[x86RegRAX] = state[x86RegRDI]
						killX86ArgRegs(state)
						return
					}
				}
			}
		}
		state[x86RegRAX] = Top()
		killX86ArgRegs(state)
		return
	}

	// Default: if this instruction defines a register, kill its type.
	if len(ins.Args) >= 1 {
		if dstReg, ok := ins.Args[0].(x86asm.Reg); ok {
			dstIdx := canonX86RegLocal(dstReg)
			if dstIdx >= 0 && dstIdx < 31 {
				state[dstIdx] = Top()
			}
		}
	}
}

// resolveX86Dispatch resolves a dispatch table call to a target function.
func resolveX86Dispatch(
	state *[31]TypeLattice,
	slot int,
	inst X86DecodedInst,
	ctx *TypeContext,
	result *IntraResult,
) {
	res := BlrResolution{
		PC:        inst.Addr,
		SlotIndex: slot,
	}
	if name, ok := ctx.ResolveDispatchTarget(slot); ok {
		res.TargetName = name
		res.Resolved = true
		ctx.DispatchHits++
	} else {
		// P4 reverse dispatch scan: if the slot doesn't directly resolve,
		// scan nearby slots for monomorphic targets (same as ARM64).
		// This handles cases where the dispatch table entry is null/stub
		// but a nearby slot has a valid Code target.
		if ctx.DispatchBySlot != nil {
			candidates := 0
			var candidateName string
			var allCandidates []string
			for offset := 0; offset < 128; offset++ {
				s := slot + offset
				entry, ok := ctx.DispatchBySlot[s]
				if !ok || entry.Kind != cluster.DispatchCode {
					continue
				}
				if name, ok2 := ctx.DispatchCodeIndexToName[entry.ClusterIndex]; ok2 && name != "" {
					candidates++
					candidateName = name
					allCandidates = append(allCandidates, name)
				}
			}
			if candidates == 1 {
				res.TargetName = candidateName
				res.Resolved = true
			} else if candidates > 1 {
				uniqueNames := map[string]bool{}
				for _, n := range allCandidates {
					uniqueNames[n] = true
				}
				if len(uniqueNames) == 1 {
					res.TargetName = allCandidates[0]
					res.Resolved = true
				} else {
					res.TargetName = strings.Join(allCandidates, " | ")
					res.Resolved = true
				}
			}
		}
	}
	result.BLRResolutions = append(result.BLRResolutions, res)
}

// resolveX86DispatchSelectorOffset resolves a dispatch table call using
// the pre-scanned selector offset, without needing the receiver class ID.
// Scans all dispatch table entries at the selector offset to find unique targets.
func resolveX86DispatchSelectorOffset(
	state *[31]TypeLattice,
	inst X86DecodedInst,
	ctx *TypeContext,
	result *IntraResult,
) {
	selectorImm, ok := ctx.SelectorOffsets[inst.Addr]
	if !ok {
		return
	}
	// Same arithmetic and the same candidate cap as the ARM64 path: this
	// used to be a second copy with its own (wrong) implied-CID formula and
	// an unbounded " | "-join of every match.
	res := BlrResolution{
		PC:        inst.Addr,
		SlotIndex: -1,
	}
	applySelectorCandidates(&res, ctx.selectorCandidates(selectorImm))
	result.BLRResolutions = append(result.BLRResolutions, res)
}

// killX86ArgRegs kills all argument registers (RDI, RSI, RDX, RCX, R8, R9).
func killX86ArgRegs(state *[31]TypeLattice) {
	for _, r := range x86ArgRegCanon {
		if r < 31 {
			state[r] = Top()
		}
	}
}

// DecodeX86Function decodes a function's raw bytes into X86DecodedInst slice.
func DecodeX86Function(funcCode []byte, funcVA uint64) []X86DecodedInst {
	var out []X86DecodedInst
	for off := 0; off < len(funcCode); {
		addr := funcVA + uint64(off)
		inst, err := x86asm.Decode(funcCode[off:], 64)
		length := inst.Len
		if err != nil || length <= 0 {
			out = append(out, X86DecodedInst{Addr: addr, Len: 1})
			off++
			continue
		}
		out = append(out, X86DecodedInst{Addr: addr, Inst: inst, Len: length})
		off += length
	}
	return out
}
