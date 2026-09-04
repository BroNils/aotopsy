package typetrack

import (
	"aotopsy/internal/arch/x86"
	"sort"
	"strings"

	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
	"golang.org/x/arch/x86/x86asm"
)

// x86_64 register constants — PP/THR/SP now shared from internal/sdk.
// The ones below are typetrack-specific (not in the SDK's reserved-register
// set, but used by the type lattice for class-id and allocation tracking).
const (
	x86RegRCX = sdk.X86ClassIdReg // kClassIdReg (DispatchTableNullErrorABI)
	x86RegRAX = 0                 // return value / allocation result
	x86RegRDI = 7                 // SysV arg 0 (receiver for instance methods)
)

// x86ArgRegCanon lists Dart's OWN calling-convention integer argument
// registers as canonical indices, parameter 0 first. This is NOT the
// SysV C ABI — Dart declares its own convention (verified via gh api to
// constants_x64.h @3.9.2):
//
//	DartCallingConvention::kCpuRegistersForArgs[] = {RDI, RSI, RDX, RBX, R8, R9}
//
// The previous value used RCX (1) for parameter 3 instead of RBX (3) —
// the SysV C ABI order. RCX is DispatchTableNullErrorABI::kClassIdReg
// in Dart, not an argument register. killX86ArgRegs was killing RCX
// (losing class-id type info needed for dispatch resolution) and NOT
// killing RBX (leaving stale type info after calls that could propagate
// incorrect types).
var x86ArgRegCanon = func() [6]int {
	r := sdk.DartArgRegisters(sdk.ArchX86)
	var arr [6]int
	copy(arr[:], r)
	return arr
}()

// AnalyzeFunctionX86 runs intra-procedural type dataflow on one x86_64 function.
// It mirrors AnalyzeFunction (ARM64) but uses x86_64 instruction decoders.
func AnalyzeFunctionX86(
	insts []x86.Decoded,
	ctx *TypeContext,
	entryTypes [31]TypeLattice,
	entryStack map[int]TypeLattice,
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
		baseReg := x86.CanonReg(mem.Base)
		idxReg := x86.CanonReg(mem.Index)
		// Check: CALL [RAX + RCX*8 + disp32]
		if baseReg == x86RegRAX && idxReg == x86RegRCX && mem.Scale == 8 {
			ctx.SelectorOffsets[inst.VA] = int(mem.Disp / 8)
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

	for off, t := range entryStack {

		blockStackEntry[0][off] = t

	}

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
		var prevInst *x86.Decoded
		// Flow-sensitive narrowing, the x86 counterpart of the ARM64 rule in
		// intraproc.go: a `CMP reg, #imm` against a class id means that on
		// the edge where the comparison SUCCEEDED, the register holds
		// exactly that class. It is step 3 of the chain that turns a header
		// load into a resolved dispatch -- header load gives Bottom, the
		// SHR extract preserves it, the compare turns it into a real class,
		// the dispatch call consumes it -- and x86 had steps 1, 2 and 4 but
		// not this one, which is why supplying the Bottom producer alone
		// moved nothing.
		var cmpReg, cmpImm int
		var hasCmp bool
		for _, inst := range blk.insts {
			if r, imm, ok := isX86CmpRegImm(inst); ok {
				cmpReg, cmpImm, hasCmp = r, imm, true
			}
			transferInstructionX86(&state, inst, prevInst, ctx, result, lca, stackTypes)
			prevInst = &inst
		}

		blockExit[idx] = state
		blockStackExit[idx] = stackTypes

		// Which successor edge proves equality; -1 for none. Ported with the
		// branch-condition check the ARM64 version originally lacked, rather
		// than with the bug.
		eqSucc := -1
		if hasCmp && cmpReg >= 0 && cmpReg < 31 && len(blk.insts) > 0 {
			eqSucc = x86.EqualitySuccessor(blk.insts[len(blk.insts)-1].Inst.Op, len(blk.successors))
		}
		if eqSucc >= 0 {
			ctx.NarrowShape++
			if state[cmpReg].Kind != LatticeBottom && state[cmpReg].Kind != LatticeKnownClass {
				ctx.NarrowNoType++
			}
		}
		for succIdx, succ := range blk.successors {
			var newEntry [31]TypeLattice
			narrowedState := state
			if succIdx == eqSucc &&
				(state[cmpReg].Kind == LatticeBottom || state[cmpReg].Kind == LatticeKnownClass) {
				narrowedState[cmpReg] = KnownClass(cmpImm)
				ctx.NarrowHits++
			}
			if isFirstVisit := allTop(blockEntry[succ]) && succ != 0; isFirstVisit {
				newEntry = narrowedState
			} else {
				for r := 0; r < 31; r++ {
					newEntry[r] = meetType(blockEntry[succ][r], narrowedState[r], lca)
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
	insts      []x86.Decoded
	successors []int // block indices
}

// buildBlocksX86 partitions x86_64 instructions into basic blocks.
// Leaders are at: function start, JMP/Jcc targets, instruction after JMP/RET.
//
// NOT merged with ARM64 buildBlocks — see the comment there for why
// (different instruction/block types, branch classification, and
// partition approach make a generic version worse than the duplication).
func buildBlocksX86(insts []x86.Decoded) []x86BasicBlock {
	if len(insts) == 0 {
		return nil
	}
	funcStart := insts[0].VA
	funcEnd := insts[len(insts)-1].VA + uint64(insts[len(insts)-1].Len)

	addrToIdx := make(map[uint64]int, len(insts))
	for i, d := range insts {
		addrToIdx[d.VA] = i
	}

	leaders := map[int]bool{0: true}
	for i, d := range insts {
		isBranch := false
		switch d.Inst.Op {
		case x86asm.RET:
			isBranch = true
		case x86asm.JMP:
			isBranch = true
			if t, ok := x86.RelTarget(d.Inst, d.VA, d.Len); ok && t >= funcStart && t < funcEnd {
				if idx, ok2 := addrToIdx[t]; ok2 {
					leaders[idx] = true
				}
			}
		default:
			if x86.IsCondJump(d.Inst.Op) {
				isBranch = true
				if t, ok := x86.RelTarget(d.Inst, d.VA, d.Len); ok && t >= funcStart && t < funcEnd {
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
			if t, ok := x86.RelTarget(last.Inst, last.VA, last.Len); ok {
				if idx, ok2 := addrToIdx[t]; ok2 {
					if tb, ok3 := leaderToBlock[idx]; ok3 {
						blk.successors = append(blk.successors, tb)
						continue
					}
				}
			}
		default:
			if x86.IsCondJump(last.Inst.Op) {
				if t, ok := x86.RelTarget(last.Inst, last.VA, last.Len); ok {
					if idx, ok2 := addrToIdx[t]; ok2 {
						if tb, ok3 := leaderToBlock[idx]; ok3 {
							blk.successors = append(blk.successors, tb)
						}
					}
				}
			}
			// Fall-through successor (for non-jump and cond-jump false branch).
			lastInst := blk.insts[len(blk.insts)-1]
			fallThroughAddr := lastInst.VA + uint64(lastInst.Len)
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

// isX86CmpRegImm matches `CMP reg, imm`, returning the canonical register
// index and the immediate. Intel order puts the compared register first.
func isX86CmpRegImm(inst x86.Decoded) (reg, imm int, ok bool) {
	if inst.Inst.Op != x86asm.CMP || len(inst.Inst.Args) < 2 {
		return 0, 0, false
	}
	r, isReg := inst.Inst.Args[0].(x86asm.Reg)
	if !isReg {
		return 0, 0, false
	}
	idx := x86.CanonReg(r)
	if idx < 0 || idx >= 31 {
		return 0, 0, false
	}
	v, isImm := inst.Inst.Args[1].(x86asm.Imm)
	if !isImm {
		return 0, 0, false
	}
	return idx, int(v), true
}

// transferInstructionX86 updates the register type state for one x86_64 instruction.
// H-4 fix: added stack type tracking, field type lookup, LEA dispatch slot
// computation, and fixed allocation stub detection.
// L-3 fix: stackTypes is now passed as a parameter instead of using a package global.
// prevInst is the previous instruction in the block (nil at block start); used
// by the SHR/AND handler to detect the header-load → class-ID-extract pattern
// and preserve Bottom, mirroring ARM64's prevRaw UBFX fix.
type transferCtxX86 struct {
	state      *[31]TypeLattice
	inst       x86.Decoded
	prevInst   *x86.Decoded
	ctx        *TypeContext
	result     *IntraResult
	lca        func(int, int) int
	stackTypes map[int]TypeLattice
}

// handleX86Store handles stack stores and object field stores.
func handleX86Store(tc *transferCtxX86) bool {
	ins := tc.inst.Inst
	if ins.Op == x86asm.MOV && len(ins.Args) >= 2 {
		if mem, ok := ins.Args[0].(x86asm.Mem); ok {
			baseIdx := x86.CanonReg(mem.Base)
			if baseIdx == 5 { // RBP = frame register
				if srcReg, srcOK := ins.Args[1].(x86asm.Reg); srcOK {
					srcIdx := x86.CanonReg(srcReg)
					if srcIdx >= 0 && srcIdx < 31 {
						tc.stackTypes[int(mem.Disp)] = tc.state[srcIdx]
					}
				}
				return true
			}
			// Not the frame, not a reserved register: an object field.
			if baseIdx >= 0 && baseIdx < 31 &&
				baseIdx != sdk.X86PP && baseIdx != sdk.X86THR && baseIdx != sdk.X86SPReg &&
				tc.state[baseIdx].Kind == LatticeKnownClass {
				recordFieldAccess(tc.result, tc.state[baseIdx].ClassID, int32(mem.Disp), true, tc.inst.VA)
				if srcReg, srcOK := ins.Args[1].(x86asm.Reg); srcOK {
					srcIdx := x86.CanonReg(srcReg)
					if srcIdx >= 0 && srcIdx < 31 && tc.state[srcIdx].Kind == LatticeKnownClass {
						recordFieldStore(tc.ctx, tc.state[baseIdx].ClassID, int32(mem.Disp), tc.state[srcIdx].ClassID)
					}
				}
			}
		}
	}
	return false
}

// handleX86Load handles stack loads, PP loads, THR loads, closure fields, class IDs, and field type lookups.
func handleX86Load(tc *transferCtxX86) bool {
	ins := tc.inst.Inst
	// Stack load: MOV reg, [RBP+disp] → load type from stack.
	if (ins.Op == x86asm.MOV || ins.Op == x86asm.MOVZX) && len(ins.Args) >= 2 {
		if dstReg, dstOK := ins.Args[0].(x86asm.Reg); dstOK {
			dstIdx := x86.CanonReg(dstReg)
			if dstIdx >= 0 && dstIdx < 31 {
				if mem, ok := ins.Args[1].(x86asm.Mem); ok {
					baseIdx := x86.CanonReg(mem.Base)
					if baseIdx == 5 { // RBP
						if t, ok2 := tc.stackTypes[int(mem.Disp)]; ok2 {
							tc.state[dstIdx] = t
						} else {
							tc.state[dstIdx] = Top()
						}
						return true
					}
				}
			}
		}
	}

	// MOV/MOVZX reg, [mem] — memory load (PP, THR, or object header/field).
	if (ins.Op == x86asm.MOV || ins.Op == x86asm.MOVZX) && len(ins.Args) >= 2 {
		dstReg, dstOK := ins.Args[0].(x86asm.Reg)
		if !dstOK {
			return false
		}
		dstIdx := x86.CanonReg(dstReg)
		if dstIdx < 0 || dstIdx >= 31 {
			return false
		}
		if mem, ok := ins.Args[1].(x86asm.Mem); ok {
			baseIdx := x86.CanonReg(mem.Base)
			// PP load: MOV reg, [R15+disp] → KnownClass.
			if baseIdx == sdk.X86PP {
				poolIdx, poolIdxOK := disasm.X64PoolIndex(mem.Disp)
				if !poolIdxOK {
					return true
				}
				lat, hit := ResolvePoolEntry(tc.ctx, poolIdx, int(mem.Disp))
				tc.state[dstIdx] = lat
				if hit {
					tc.ctx.PPHits++
				}
				return true
			}
			// THR load: MOV reg, [R14+disp] → KnownStub.
			if baseIdx == sdk.X86THR {
				byteOff := int(mem.Disp)
				stubName := ""
				if tc.ctx.AllocStubOffsets != nil {
					if name, found := tc.ctx.AllocStubOffsets[int64(byteOff)]; found {
						stubName = name
					}
				}
				if stubName == "" && tc.ctx.THRFields != nil {
					if name, found := tc.ctx.THRFields[byteOff]; found {
						stubName = name
					}
				}
				if stubName == "dispatch_table_array" {
					tc.state[dstIdx] = KnownDispatch(0)
					return true
				}
				tc.state[dstIdx] = KnownStub(stubName, byteOff)
				return true
			}
			// Closure field load: MOV reg, [closure + function/entry_point].
			if baseIdx >= 0 && baseIdx < 31 {
				if lat, ok := ResolveClosureField(tc.ctx, tc.state[baseIdx], int(mem.Disp)); ok {
					tc.state[dstIdx] = lat
					return true
				}
			}
			// Class-id load, Dart <= 2.18 form: MOVZX reg, word [obj + 1].
			if tc.ctx.ClassIDIsHalfWord && ins.Op == x86asm.MOVZX && mem.Disp == 1 && baseIdx >= 0 && baseIdx < 31 &&
				baseIdx != sdk.X86PP && baseIdx != sdk.X86THR {
				if tc.state[baseIdx].Kind == LatticeKnownClass {
					tc.state[dstIdx] = KnownClass(tc.state[baseIdx].ClassID)
				} else {
					tc.state[dstIdx] = Bottom()
				}
				tc.ctx.HeaderHits++
				return true
			}
			// Field type lookup — MOV reg, [reg+offset] where base has KnownClass.
			if baseIdx >= 0 && baseIdx < 31 && tc.state[baseIdx].Kind == LatticeKnownClass {
				if mem.Disp == -1 {
					tc.state[dstIdx] = KnownClass(tc.state[baseIdx].ClassID)
					tc.ctx.HeaderHits++
					return true
				}
				recordFieldAccess(tc.result, tc.state[baseIdx].ClassID, int32(mem.Disp), false, tc.inst.VA)
				if classID, ok2 := tc.ctx.FieldValueClass(tc.state[baseIdx].ClassID, int32(mem.Disp)); ok2 {
					tc.state[dstIdx] = KnownClass(classID)
					return true
				}
			}
			if mem.Disp == -1 && baseIdx >= 0 && baseIdx < 31 {
				tc.state[dstIdx] = Bottom()
				tc.ctx.HeaderHits++
				return true
			}
			// Other memory load — kill dst.
			tc.state[dstIdx] = Top()
			return true
		}
		// MOV reg, reg — copy type.
		if srcReg, ok := ins.Args[1].(x86asm.Reg); ok {
			srcIdx := x86.CanonReg(srcReg)
			if srcIdx >= 0 && srcIdx < 31 {
				tc.state[dstIdx] = tc.state[srcIdx]
			} else {
				tc.state[dstIdx] = Top()
			}
			return true
		}
		// MOV reg, imm — kill.
		tc.state[dstIdx] = Top()
		return true
	}
	return false
}

// handleX86LEA handles dispatch table base loading and slot arithmetic.
func handleX86LEA(tc *transferCtxX86) bool {
	ins := tc.inst.Inst
	if ins.Op == x86asm.LEA && len(ins.Args) >= 2 {
		dstReg, dstOK := ins.Args[0].(x86asm.Reg)
		if !dstOK {
			return false
		}
		dstIdx := x86.CanonReg(dstReg)
		if dstIdx < 0 || dstIdx >= 31 {
			return false
		}
		if mem, ok := ins.Args[1].(x86asm.Mem); ok {
			baseIdx := x86.CanonReg(mem.Base)
			// LEA reg, [THR+disp] → load dispatch table base.
			if baseIdx == sdk.X86THR && mem.Disp != 0 {
				tc.state[dstIdx] = KnownDispatch(0)
				return true
			}
			// LEA reg, [reg+imm] where base is KnownClass → dispatch slot.
			if baseIdx >= 0 && baseIdx < 31 && tc.state[baseIdx].Kind == LatticeKnownClass {
				slot := tc.state[baseIdx].ClassID + int(mem.Disp/8)
				tc.state[dstIdx] = KnownDispatch(slot)
				tc.ctx.ADDClassHits++
				return true
			}
			// LEA reg, [reg+imm] where base is KnownDispatchIndex → adjust slot.
			if baseIdx >= 0 && baseIdx < 31 && tc.state[baseIdx].Kind == LatticeKnownDispatchIndex {
				slot := tc.state[baseIdx].DispatchIndex + int(mem.Disp/8)
				tc.state[dstIdx] = KnownDispatch(slot)
				return true
			}
		}
		tc.state[dstIdx] = Top()
		return true
	}
	return false
}

// handleX86Bitwise handles class ID bitfield extraction from headers.
func handleX86Bitwise(tc *transferCtxX86) bool {
	ins := tc.inst.Inst
	if (ins.Op == x86asm.SHR || ins.Op == x86asm.AND) && len(ins.Args) >= 2 {
		dstReg, dstOK := ins.Args[0].(x86asm.Reg)
		if !dstOK {
			return false
		}
		dstIdx := x86.CanonReg(dstReg)
		if dstIdx < 0 || dstIdx >= 31 {
			return false
		}
		if srcReg, ok := ins.Args[0].(x86asm.Reg); ok {
			srcIdx := x86.CanonReg(srcReg)
			if srcIdx >= 0 && srcIdx < 31 {
				if tc.state[srcIdx].Kind == LatticeKnownClass {
					tc.state[dstIdx] = tc.state[srcIdx]
					tc.ctx.UBFXHits++
					return true
				}
				if tc.state[srcIdx].Kind == LatticeBottom {
					tc.state[dstIdx] = Bottom()
					tc.ctx.UBFXHits++
					return true
				}
			}
		}
		tc.state[dstIdx] = Top()
		return true
	}
	return false
}

// handleX86Call handles dispatch calls, allocation stubs, and direct calls.
func handleX86Call(tc *transferCtxX86) bool {
	ins := tc.inst.Inst
	if ins.Op == x86asm.CALL && len(ins.Args) >= 1 {
		callTarget := uint64(0)
		if rel, ok := ins.Args[0].(x86asm.Rel); ok {
			callTarget = tc.inst.VA + uint64(tc.inst.Len) + uint64(int64(rel))
		}
		if callTarget != 0 {
			if tc.result.BLCallSiteTypes == nil {
				tc.result.BLCallSiteTypes = make(map[uint64][31]TypeLattice)
			}
			tc.result.BLCallSiteTypes[tc.inst.VA] = *tc.state
		}

		// CALL [mem] — indirect call (dispatch table or object field).
		if mem, ok := ins.Args[0].(x86asm.Mem); ok {
			idxReg := x86.CanonReg(mem.Index)
			baseReg := x86.CanonReg(mem.Base)
			if idxReg == x86RegRCX && mem.Scale == 8 {
				tc.ctx.X86DispatchShape++
				tableKnown := baseReg >= 0 && baseReg < 31 &&
					tc.state[baseReg].Kind == LatticeKnownDispatchIndex
				classKnown := tc.state[x86RegRCX].Kind == LatticeKnownClass
				switch {
				case tableKnown && classKnown:
					tc.ctx.X86DispatchResolved++
				case !classKnown:
					tc.ctx.X86DispatchNoClass++
					switch tc.state[x86RegRCX].Kind {
					case LatticeTop:
						tc.ctx.X86DispatchClassTop++
					case LatticeBottom:
						tc.ctx.X86DispatchClassBottom++
					default:
						tc.ctx.X86DispatchClassOther++
					}
				default:
					tc.ctx.X86DispatchNoTable++
				}
			}
			if baseReg >= 0 && baseReg < 31 && tc.state[baseReg].Kind == LatticeKnownDispatchIndex {
				if idxReg == x86RegRCX && tc.state[x86RegRCX].Kind == LatticeKnownClass {
					slot := int(tc.state[x86RegRCX].ClassID) + int(mem.Disp/8)
					resolveX86Dispatch(tc.state, slot, tc.inst, tc.ctx, tc.result)
				} else if idxReg == x86RegRCX {
					resolveX86DispatchSelectorOffset(tc.state, tc.inst, tc.ctx, tc.result)
				}
			} else if idxReg == x86RegRCX && tc.state[x86RegRCX].Kind == LatticeKnownClass {
				slot := int(tc.state[x86RegRCX].ClassID) + int(mem.Disp/8)
				resolveX86Dispatch(tc.state, slot, tc.inst, tc.ctx, tc.result)
			} else if idxReg == x86RegRCX && mem.Scale == 8 {
				resolveX86DispatchSelectorOffset(tc.state, tc.inst, tc.ctx, tc.result)
			}
			tc.state[x86RegRAX] = Top()
			killX86ArgRegs(tc.state)
			return true
		}
		// CALL rel32 — direct call (allocation stub or regular function).
		if rel, ok := ins.Args[0].(x86asm.Rel); ok {
			callTarget = tc.inst.VA + uint64(tc.inst.Len) + uint64(int64(rel))
			if tc.state[x86RegRAX].Kind == LatticeKnownStub {
				sn := tc.state[x86RegRAX].StubName
				if strings.HasPrefix(sn, "Allocate") || strings.HasPrefix(sn, "allocate") {
					if tc.state[x86RegRDI].Kind == LatticeKnownClass {
						tc.state[x86RegRAX] = tc.state[x86RegRDI]
					} else {
						tc.state[x86RegRAX] = Top()
					}
					killX86ArgRegs(tc.state)
					return true
				}
			}
			if calleeAllExit, hasFull := tc.ctx.CalleeAllExitTypes[callTarget]; hasFull {
				for r := 0; r < 31; r++ {
					if calleeAllExit[r].Kind != LatticeTop {
						tc.state[r] = calleeAllExit[r]
					}
				}
			} else if calleeExit, hasExit := tc.ctx.CalleeExitTypes[callTarget]; hasExit {
				tc.state[x86RegRAX] = calleeExit
			} else {
				tc.state[x86RegRAX] = Top()
			}
			killX86ArgRegs(tc.state)
			return true
		}
		// CALL reg — indirect call through register.
		if reg, ok := ins.Args[0].(x86asm.Reg); ok {
			regIdx := x86.CanonReg(reg)
			if regIdx >= 0 && regIdx < 31 && tc.state[regIdx].Kind == LatticeKnownStub {
				sn := tc.state[regIdx].StubName
				if strings.HasPrefix(sn, "Allocate") || strings.HasPrefix(sn, "allocate") {
					if tc.state[x86RegRDI].Kind == LatticeKnownClass {
						tc.state[x86RegRAX] = tc.state[x86RegRDI]
						killX86ArgRegs(tc.state)
						return true
					}
				}
				if strings.HasPrefix(sn, "UnlinkedCall:") {
					methodName := sn[len("UnlinkedCall:"):]
					if selectorOffsets, hasOffsets := tc.ctx.MethodNameToSelectorOffsets[methodName]; hasOffsets && len(selectorOffsets) > 0 {
						res := BlrResolution{PC: tc.inst.VA, Reg: regIdx, SlotIndex: -1, Confidence: "static_inferred"}
						var allTargets []string
						for _, selOff := range selectorOffsets {
							allTargets = append(allTargets, tc.ctx.selectorCandidates(selOff)...)
						}
						applySelectorCandidates(&res, allTargets)
						if res.Polymorphic {
							res.Confidence = "polymorphic"
						}
						tc.result.BLRResolutions = append(tc.result.BLRResolutions, res)
					} else {
						tc.result.BLRResolutions = append(tc.result.BLRResolutions, BlrResolution{
							PC: tc.inst.VA, Reg: regIdx, TargetName: methodName, Resolved: true,
							Confidence: "stub",
						})
					}
				}
			}
		}
		tc.state[x86RegRAX] = Top()
		killX86ArgRegs(tc.state)
		return true
	}
	return false
}

// handleX86Decompress handles compressed-pointer decompression.
func handleX86Decompress(tc *transferCtxX86) bool {
	ins := tc.inst.Inst
	if ins.Op == x86asm.ADD && len(ins.Args) >= 2 && tc.ctx.THRFields != nil {
		if mem, memOK := ins.Args[1].(x86asm.Mem); memOK &&
			x86.CanonReg(mem.Base) == sdk.X86THR {
			if name, found := tc.ctx.THRFields[int(mem.Disp)]; found && name == "heap_base" {
				return true
			}
		}
	}
	return false
}

func transferInstructionX86(
	state *[31]TypeLattice,
	inst x86.Decoded,
	prevInst *x86.Decoded,
	ctx *TypeContext,
	result *IntraResult,
	lca func(int, int) int,
	stackTypes map[int]TypeLattice,
) {
	tc := &transferCtxX86{
		state:      state,
		inst:       inst,
		prevInst:   prevInst,
		ctx:        ctx,
		result:     result,
		lca:        lca,
		stackTypes: stackTypes,
	}

	if handleX86Store(tc) {
		return
	}
	if handleX86Load(tc) {
		return
	}
	if handleX86LEA(tc) {
		return
	}
	if handleX86Bitwise(tc) {
		return
	}
	if handleX86Call(tc) {
		return
	}
	if handleX86Decompress(tc) {
		return
	}

	// Default: if this instruction defines registers, kill their types.
	for _, dstIdx := range x86.DstRegsOfInst(inst.Inst) {
		if dstIdx >= 0 && dstIdx < 31 {
			state[dstIdx] = Top()
		}
	}
}

// resolveX86Dispatch resolves a dispatch table call to a target function.
func resolveX86Dispatch(
	state *[31]TypeLattice,
	slot int,
	inst x86.Decoded,
	ctx *TypeContext,
	result *IntraResult,
) {
	res := BlrResolution{
		PC:         inst.VA,
		SlotIndex:  slot,
		Confidence: "unknown",
	}
	if name, ok := ctx.ResolveDispatchTarget(slot); ok {
		res.TargetName = name
		res.Resolved = true
		res.Confidence = "exact"
		ctx.DispatchHits++
	} else {
		// When selector offset is known, check CHA first for receiver class
		if selectorImm, ok := ctx.SelectorOffsets[inst.VA]; ok && state[x86RegRCX].Kind == LatticeKnownClass {
			chaTargets := ctx.ResolveDispatchCHA(state[x86RegRCX].ClassID, selectorImm)
			if len(chaTargets) > 0 {
				applySelectorCandidates(&res, chaTargets)
				if res.Polymorphic {
					res.Confidence = "polymorphic"
				} else if res.Resolved {
					res.Confidence = "static_inferred"
				}
			}
		}
		if !res.Resolved && !res.Polymorphic {
			// P4 reverse dispatch scan: if the slot doesn't directly resolve,
			// scan nearby slots for monomorphic targets (same as ARM64).
			candidates, candidateName, allCandidates := scanDispatchSlots(ctx, slot)
			applyDispatchCandidates(&res, candidates, candidateName, allCandidates)
			if res.Polymorphic {
				res.Confidence = "polymorphic"
			} else if res.Resolved {
				res.Confidence = "static_inferred"
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
	inst x86.Decoded,
	ctx *TypeContext,
	result *IntraResult,
) {
	selectorImm, ok := ctx.SelectorOffsets[inst.VA]
	if !ok {
		return
	}
	// Same arithmetic and the same candidate cap as the ARM64 path: this
	// used to be a second copy with its own (wrong) implied-CID formula and
	// an unbounded " | "-join of every match.
	res := BlrResolution{
		PC:         inst.VA,
		SlotIndex:  -1,
		Confidence: "static_inferred",
	}
	applySelectorCandidates(&res, ctx.selectorCandidates(selectorImm))
	if res.Polymorphic {
		res.Confidence = "polymorphic"
	}
	result.BLRResolutions = append(result.BLRResolutions, res)
}

// killX86ArgRegs kills all Dart calling-convention argument registers
// (RDI, RSI, RDX, RBX, R8, R9) after a CALL instruction.
func killX86ArgRegs(state *[31]TypeLattice) {
	for _, r := range x86ArgRegCanon {
		if r < 31 {
			state[r] = Top()
		}
	}
}

// DecodeX86Function decodes a function's raw bytes into x86.Decoded slice.
func DecodeX86Function(funcCode []byte, funcVA uint64) []x86.Decoded {
	decoded := x86.Decode(funcCode, funcVA)
	out := make([]x86.Decoded, 0, len(decoded))
	for _, d := range decoded {
		out = append(out, x86.Decoded{VA: d.VA, Inst: d.Inst, Len: d.Len, Bad: d.Bad})
	}
	return out
}
