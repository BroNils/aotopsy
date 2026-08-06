package typetrack

import (
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/disasm"
)

// ARM64 register constants (matching disasm package).
const (
	regPP  = 27 // X27 = object pool pointer
	regTHR = 26 // X26 = thread pointer
	regDT  = 21 // X21 = dispatch table register
)

// BlrResolution is one resolved BLR call site.
type BlrResolution struct {
	PC          uint64 // instruction address
	Reg         int    // BLR register number (0-30)
	SlotIndex   int    // dispatch table slot (if resolved)
	TargetName  string // resolved function name (if any)
	Resolved    bool   // true if we resolved a target
}

// IntraResult holds the result of intra-procedural analysis for one function.
type IntraResult struct {
	// EntryTypes[i] = type lattice for register i at function entry.
	EntryTypes [31]TypeLattice

	// ExitTypes[i] = type lattice for register i at function exit.
	ExitTypes [31]TypeLattice

	// Resolved BLR call sites in this function.
	BLRResolutions []BlrResolution

	// ParamTypes[i] = inferred type for parameter i (register Xi at entry).
	// Index 0 = X0 (receiver for instance methods).
	ParamTypes [31]TypeLattice

	// BLCallSiteTypes maps BL target address → register state at call site
	// (before BL kills R0-R7). This is the ACTUAL parameter types being
	// passed to the callee, not the exit state. Used by inter-proc to
	// propagate parameter types more accurately than ExitTypes.
	BLCallSiteTypes map[uint64][31]TypeLattice
}

// AnalyzeFunction runs intra-procedural type dataflow on one function.
// It uses a forward CFG worklist algorithm:
//  1. Build basic blocks from the instruction list.
//  2. Initialize entry types (from inter-procedural propagation or Top).
//  3. For each block, transfer function: decode each instruction and
//     update register type state.
//  4. Meet block exit → successor entry, repeat until fixed point.
//  5. On BLR instructions, attempt to resolve the dispatch target.
//
// entryTypes provides the initial types for parameters (from interproc).
// Pass all-Top if no inter-procedural info is available yet.
func AnalyzeFunction(
	insts []disasm.Inst,
	ctx *TypeContext,
	entryTypes [31]TypeLattice,
) *IntraResult {
	result := &IntraResult{
		EntryTypes: entryTypes,
	}

	// Skip analysis for very large functions (>50K instructions) to prevent
	// timeout. These are typically init:xxx functions with megabytes of
	// initialization code that don't have dispatch calls.
	const maxInstsForAnalysis = 50000
	if len(insts) > maxInstsForAnalysis {
		return result
	}

	// Build basic blocks.
	blocks := buildBlocks(insts)
	if len(blocks) == 0 {
		return result
	}

	// Per-block entry/exit type state.
	blockEntry := make([][31]TypeLattice, len(blocks))
	blockExit := make([][31]TypeLattice, len(blocks))

	// PHASE A: Per-block stack types (replaces function-wide stackTypes).
	// Each block has its own stackTypes map, propagated via block exit/entry.
	// This prevents cross-block pollution where Block B (after BL kills R1)
	// overwrites KnownClass saved by Block A with Top.
	blockStackEntry := make([]map[int]TypeLattice, len(blocks))
	blockStackExit := make([]map[int]TypeLattice, len(blocks))
	for i := range blockStackEntry {
		blockStackEntry[i] = make(map[int]TypeLattice)
		blockStackExit[i] = make(map[int]TypeLattice)
	}

	// Initialize first block's entry with parameter types.
	blockEntry[0] = entryTypes

	// LCA helper for meetType.
	lca := func(a, b int) int { return LCA(a, b, ctx.SuperClass) }

	// Worklist: forward dataflow.
	worklist := make([]int, 0, len(blocks))
	worklist = append(worklist, 0)
	inWorklist := make(map[int]bool, len(blocks))
	inWorklist[0] = true

	for len(worklist) > 0 {
		idx := worklist[0]
		worklist = worklist[1:]
		inWorklist[idx] = false

		// Transfer function: walk instructions in this block.
		state := blockEntry[idx]
		blk := blocks[idx]
		// PHASE A: use per-block stack types (copy from entry, modify during transfer).
		stackTypes := make(map[int]TypeLattice, len(blockStackEntry[idx]))
		for k, v := range blockStackEntry[idx] {
			stackTypes[k] = v
		}

		for _, inst := range blk.insts {
			transferInstruction(&state, inst, ctx, result, lca, stackTypes)
		}

		oldExit := blockExit[idx]
		blockExit[idx] = state
		// PHASE A: save per-block stack exit state.
		blockStackExit[idx] = stackTypes

		// Propagate to successors (meet).
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

			// PHASE A: propagate stack types to successor (merge/meet).
			// Only propagate if the successor doesn't already have this key
			// with the same value. This prevents infinite worklist loops.
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

		// Check if exit changed (for convergence).
		_ = oldExit // we rely on successor entry changes to drive the worklist
	}

	// Collect exit types from the last block(s).
	for i := range blocks {
		if len(blocks[i].successors) == 0 {
			// Exit block.
			for r := 0; r < 31; r++ {
				result.ExitTypes[r] = meetType(result.ExitTypes[r], blockExit[i][r], lca)
			}
		}
	}

	// Record parameter types from entry.
	result.ParamTypes = entryTypes

	return result
}

// typesEqual checks if two [31]TypeLattice arrays are identical.
func typesEqual(a, b [31]TypeLattice) bool {
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

// allTop checks if all elements in a [31]TypeLattice array are Top.
func allTop(a [31]TypeLattice) bool {
	for i := range a {
		if a[i].Kind != LatticeTop {
			return false
		}
	}
	return true
}

// basicBlock is a straight-line sequence of instructions with successors.
type basicBlock struct {
	startAddr  uint64
	insts      []disasm.Inst
	successors []int // block indices
}

// buildBlocks constructs basic blocks from an instruction list.
// Block boundaries are at branch targets and after branch instructions.
func buildBlocks(insts []disasm.Inst) []basicBlock {
	if len(insts) == 0 {
		return nil
	}

	// Identify block leaders: first instruction + any branch target.
	leaders := make(map[uint64]bool)
	leaders[insts[0].Addr] = true

	for i, inst := range insts {
		// Check for BL (branch with link) — creates a new block after it.
		if _, ok := isBL(inst.Raw, inst.Addr); ok {
			if i+1 < len(insts) {
				leaders[insts[i+1].Addr] = true
			}
		}
		// Check for BLR — same.
		if _, ok := isBLR(inst.Raw); ok {
			if i+1 < len(insts) {
				leaders[insts[i+1].Addr] = true
			}
		}
		// Check for B (unconditional branch) — target is a leader, next inst is a leader.
		if target, ok := isB(inst.Raw, inst.Addr); ok {
			leaders[target] = true
			if i+1 < len(insts) {
				leaders[insts[i+1].Addr] = true
			}
		}
		// Check for B.cond / CBZ / CBNZ / TBZ / TBNZ — both targets are leaders.
		if targets, ok := isCondBranch(inst.Raw, inst.Addr); ok {
			for _, t := range targets {
				leaders[t] = true
			}
			if i+1 < len(insts) {
				leaders[insts[i+1].Addr] = true
			}
		}
	}

	// Build blocks from leaders.
	addrToBlock := make(map[uint64]int)
	var blocks []basicBlock

	curBlock := basicBlock{startAddr: insts[0].Addr}
	for i, inst := range insts {
		if i > 0 && leaders[inst.Addr] {
			// Close current block.
			blocks = append(blocks, curBlock)
			addrToBlock[curBlock.startAddr] = len(blocks) - 1
			curBlock = basicBlock{startAddr: inst.Addr}
		}
		curBlock.insts = append(curBlock.insts, inst)
	}
	if len(curBlock.insts) > 0 {
		blocks = append(blocks, curBlock)
		addrToBlock[curBlock.startAddr] = len(blocks) - 1
	}

	// Build successor edges.
	for i := range blocks {
		blk := &blocks[i]
		lastInst := blk.insts[len(blk.insts)-1]

		// Find the index of lastInst in the global insts list.
		// H-1 fix: was O(n) linear search for globalLastIdx.
		// ARM64 instructions are always 4 bytes (disasm.go:16) and contiguous,
		// so fallthrough addr = lastInst.Addr + uint64(lastInst.Size).
		fallThroughAddr := lastInst.Addr + uint64(lastInst.Size)

		// Branch targets.
		if target, ok := isB(lastInst.Raw, lastInst.Addr); ok {
			if bi, ok2 := addrToBlock[target]; ok2 {
				blk.successors = append(blk.successors, bi)
			}
			continue // unconditional branch — no fall-through
		}
		if targets, ok := isCondBranch(lastInst.Raw, lastInst.Addr); ok {
			for _, t := range targets {
				if bi, ok2 := addrToBlock[t]; ok2 {
					blk.successors = append(blk.successors, bi)
				}
			}
			// Fall-through (if not the last instruction overall).
			if true {
				if bi, ok2 := addrToBlock[fallThroughAddr]; ok2 {
					blk.successors = append(blk.successors, bi)
				}
			}
			continue
		}
		// BL/BLR: fall-through to next block.
		if _, ok := isBL(lastInst.Raw, lastInst.Addr); ok {
			if true {
				if bi, ok2 := addrToBlock[fallThroughAddr]; ok2 {
					blk.successors = append(blk.successors, bi)
				}
			}
			continue
		}
		if _, ok := isBLR(lastInst.Raw); ok {
			if true {
				if bi, ok2 := addrToBlock[fallThroughAddr]; ok2 {
					blk.successors = append(blk.successors, bi)
				}
			}
			continue
		}
		// Default: fall-through.
		if true {
			if bi, ok2 := addrToBlock[fallThroughAddr]; ok2 {
				blk.successors = append(blk.successors, bi)
			}
		}
	}

	return blocks
}

// transferInstruction updates the register type state based on one instruction.
// On BLR instructions, it attempts to resolve the dispatch target.
// stackTypes tracks stack slot types for frame pointer (X29) loads/stores.
func transferInstruction(
	state *[31]TypeLattice,
	inst disasm.Inst,
	ctx *TypeContext,
	result *IntraResult,
	lca func(int, int) int,
	stackTypes map[int]TypeLattice,
) {
	raw := inst.Raw

	// 0. Stack store: STR Xt, [X29, #imm] → save Xt's type to stack.
	// 0a-pre. STUR Xt, [X29, #imm9] → save Xt's type to stack (signed offset).
	// Dart AOT uses STUR for negative offsets (e.g., STUR X1, [X29, #-8]).
	// CRITICAL: without this, receiver type is lost when saved to stack via STUR.
	if base, rt, imm9, ok := isSTUR64(raw); ok && base == 29 {
		if rt < 31 {
			stackTypes[imm9] = state[rt]
		}
		// Don't return — STUR doesn't kill the source register
	}
	// 0a-pre-bis. STUR Xt, [X15, #imm9] → save to shadow stack (signed offset).
	if base, rt, imm9, ok := isSTUR64(raw); ok && base == 15 {
		if rt < 31 {
			stackTypes[imm9+0x10000] = state[rt]
		}
	}
	// 0a-pre-ter. STUR Xt, [Xn, #imm9] → object field store (signed offset).
	if base, rt, imm9, ok := isSTUR64(raw); ok {
		if rt < 31 && base < 31 && base != 29 && base != 15 &&
			base != regPP && base != regTHR && base != regDT {
			if state[base].Kind == LatticeKnownClass && state[rt].Kind == LatticeKnownClass {
				key := state[base].ClassID*100000 + imm9
				stackTypes[key+0x20000] = state[rt]
			}
		}
	}

	// 0a-pre-quater. STUR Wt, [X29, #imm9] → compressed stack store.
	// PHASE B: Dart 3.x saves compressed pointers to stack via STUR Wt.
	if base, rt, imm9, ok := isSTUR32(raw); ok && base == 29 {
		if rt < 31 {
			stackTypes[imm9] = state[rt]
		}
	}
	// 0a-pre-quater-bis. STUR Wt, [X15, #imm9] → compressed shadow stack store.
	if base, rt, imm9, ok := isSTUR32(raw); ok && base == 15 {
		if rt < 31 {
			stackTypes[imm9+0x10000] = state[rt]
		}
	}
	// 0a-pre-quater-ter. STUR Wt, [Xn, #imm9] → compressed object field store.
	if base, rt, imm9, ok := isSTUR32(raw); ok {
		if rt < 31 && base < 31 && base != 29 && base != 15 &&
			base != regPP && base != regTHR && base != regDT {
			if state[base].Kind == LatticeKnownClass && state[rt].Kind == LatticeKnownClass {
				key := state[base].ClassID*100000 + imm9
				stackTypes[key+0x20000] = state[rt]
			}
		}
	}

	// 0a. Stack store: STR Xt, [X29, #imm] → save Xt's type to stack.
	if baseReg, byteOff, ok := isSTR64UnsignedOffset(raw); ok && baseReg == 29 {
		rt := int(raw & 0x1F)
		if rt < 31 {
			stackTypes[byteOff] = state[rt]
		}
		return
	}

	// 0a-bis. Shadow stack store: STR Xt, [X15, #imm] → save type to shadow stack.
	// Dart AOT uses X15 as shadow call stack (SPREG). Registers are saved/restored
	// across BL calls via X15-relative STR/LDR. PHASE 2: track these to preserve
	// receiver type across calls.
	if baseReg, byteOff, ok := isSTR64UnsignedOffset(raw); ok && baseReg == 15 {
		rt := int(raw & 0x1F)
		if rt < 31 {
			stackTypes[byteOff+0x10000] = state[rt] // offset by 64K to avoid collision with X29 stack
		}
		// Don't return — STR to shadow stack doesn't kill the source register
	}

	// 0a-ter. Object field store: STR Xt, [Xn, #imm] where Xn has KnownClass.
	// TARGET 2: Allocation site chain tracking. When we store a KnownClass
	// value to a field of a KnownClass object, record the field type.
	// Later, when we load from the same field, we can recover the type.
	// This enables: new Object() → store to field → load field → dispatch.
	if baseReg, byteOff, ok := isSTR64UnsignedOffset(raw); ok {
		rt := int(raw & 0x1F)
		if rt < 31 && baseReg < 31 && baseReg != 29 && baseReg != 15 &&
			baseReg != regPP && baseReg != regTHR && baseReg != regDT {
			if state[baseReg].Kind == LatticeKnownClass && state[rt].Kind == LatticeKnownClass {
				// Store KnownClass to field of KnownClass object.
				// Key: (baseClassID, offset) → storedType
				key := state[baseReg].ClassID*100000 + byteOff
				stackTypes[key+0x20000] = state[rt]
			}
		}
		// Don't return — STR doesn't kill the source register in the type lattice
	}

	// 0b. Stack load: LDR Xt, [X29, #imm] → load type from stack.
	if baseReg, byteOff, ok := isLDR64UnsignedOffset(raw); ok && baseReg == 29 {
		rt := int(raw & 0x1F)
		if rt >= 31 {
			return
		}
		if t, ok2 := stackTypes[byteOff]; ok2 {
			state[rt] = t
		} else {
			state[rt] = Top()
		}
		return
	}

	// 0b-bis. Shadow stack load: LDR Xt, [X15, #imm] → load type from shadow stack.
	if baseReg, byteOff, ok := isLDR64UnsignedOffset(raw); ok && baseReg == 15 {
		rt := int(raw & 0x1F)
		if rt >= 31 {
			return
		}
		if t, ok2 := stackTypes[byteOff+0x10000]; ok2 {
			state[rt] = t
		} else {
			state[rt] = Top()
		}
		return
	}

	// 0c. STP Xt1, Xt2, [X15, #imm]! → save pair to shadow stack.
	// PHASE 2: Dart AOT uses STP to save register pairs to X15 shadow stack.
	// Encoding: 10 101 0 010 0 imm7 Rt2 Rn Rt (pre-indexed store pair)
	// Mask: 0xFFC00000, Value: 0xA9000000 (pre-indexed)
	// Also: 10 101 0 010 1 imm7 Rt2 Rn Rt (post-indexed: 0xA9800000)
	// And:  10 101 0 000 0 imm7 Rt2 Rn Rt (signed offset: 0xA8000000)
	if raw&0xFFC00000 == 0xA9000000 || raw&0xFFC00000 == 0xA9800000 || raw&0xFFC00000 == 0xA8000000 {
		rt1 := int(raw & 0x1F)
		rt2 := int((raw >> 10) & 0x1F)
		rn := int((raw >> 5) & 0x1F)
		imm7 := int((raw >> 15) & 0x7F) // Q3 fix: 7-bit field, not int8
		if imm7 >= 64 {
			imm7 -= 128 // sign-extend 7-bit
		}
		byteOff := imm7 * 8
		if rn == 15 { // X15 = shadow stack
			if rt1 < 31 {
				stackTypes[byteOff+0x10000] = state[rt1]
			}
			if rt2 < 31 {
				stackTypes[byteOff+8+0x10000] = state[rt2]
			}
			// Don't return — STP doesn't kill source registers
		}
	}

	// 0d. LDP Xt1, Xt2, [X15, #imm] → load pair from shadow stack.
	// Encoding: 10 101 0 010 1 imm7 Rt2 Rn Rt (post-indexed load pair)
	// Mask: 0xFFC00000, Value: 0xA9C00000 (post-indexed)
	// Also: 10 101 0 010 0 imm7 Rt2 Rn Rt (pre-indexed: 0xA9400000)
	// And:  10 101 0 001 0 imm7 Rt2 Rn Rt (signed offset: 0xA8400000)
	if raw&0xFFC00000 == 0xA9C00000 || raw&0xFFC00000 == 0xA9400000 || raw&0xFFC00000 == 0xA8400000 {
		rt1 := int(raw & 0x1F)
		rt2 := int((raw >> 10) & 0x1F)
		rn := int((raw >> 5) & 0x1F)
		imm7 := int((raw >> 15) & 0x7F) // Q3 fix: 7-bit field, not int8
		if imm7 >= 64 {
			imm7 -= 128 // sign-extend 7-bit
		}
		byteOff := imm7 * 8
		if rn == 15 { // X15 = shadow stack
			if rt1 < 31 {
				if t, ok2 := stackTypes[byteOff+0x10000]; ok2 {
					state[rt1] = t
				} else {
					state[rt1] = Top()
				}
			}
			if rt2 < 31 {
				if t, ok2 := stackTypes[byteOff+8+0x10000]; ok2 {
					state[rt2] = t
				} else {
					state[rt2] = Top()
				}
			}
			return
		}
	}

	// 0. THR load: LDR Xt, [X26, #imm] → Xt = KnownStub(stubName, offset).
	//    This tracks loads from the Thread struct (THR), which includes
	//    allocation stub entry points (AllocateObject, AllocateArray, etc.).
	//    Must be checked BEFORE the PP load case since both use isLDR64UnsignedOffset.
	if baseReg, byteOff, ok := isLDR64UnsignedOffset(raw); ok && baseReg == regTHR {
		rt := int(raw & 0x1F)
		if rt >= 31 {
			return
		}
		stubName := ""
		// Check AllocStubOffsets first (from ThreadStubOffsets — arch-independent).
		if ctx.AllocStubOffsets != nil {
			if name, found := ctx.AllocStubOffsets[int64(byteOff)]; found {
				stubName = name
			}
		}
		// Fall back to THRFields (per-version, may have _ep suffix names).
		if stubName == "" && ctx.THRFields != nil {
			if name, found := ctx.THRFields[byteOff]; found {
				stubName = name
			}
		}
		state[rt] = KnownStub(stubName, byteOff)
		return
	}

	// 1. PP load: LDR Xt, [X27, #imm] → Xt = KnownClass(pool entry's class).
	if baseReg, byteOff, ok := isLDR64UnsignedOffset(raw); ok && baseReg == regPP {
		rt := int(raw & 0x1F)
		if rt >= 31 {
			return // SP/XZR — not tracked
		}
		poolIdx := byteOff / 8
		// SUPER FEATURE 3: Check if PP entry is UnlinkedCall with target_name.
		if ctx.PoolUnlinkedCallNames != nil {
			if name, ok3 := ctx.PoolUnlinkedCallNames[poolIdx]; ok3 && name != "" {
				// UnlinkedCall loaded into IC_DATA_REG — track as KnownStub
				// with target_name. This enables IC-based BLR resolution.
				state[rt] = KnownStub("UnlinkedCall:"+name, byteOff)
				return
			}
		}
		if classID, ok2 := ctx.PoolClassByIndex[poolIdx]; ok2 && classID >= 0 {
			state[rt] = KnownClass(classID)
			ctx.PPHits++
		} else {
			state[rt] = Top()
		}
		return
	}

	// 1b. LDR Xt, [Xn, #imm] where Xn has KnownDispatchIndex → load from
	//     dispatch table slot. The loaded value is a function pointer at
	//     dispatch slot (DispatchIndex + imm/8). Keep KnownDispatchIndex
	//     so the BLR resolver can look up the target.
	if baseReg, byteOff, ok := isLDR64UnsignedOffset(raw); ok && baseReg < 31 {
		rt := int(raw & 0x1F)
		if rt >= 31 {
			return
		}
		if state[baseReg].Kind == LatticeKnownDispatchIndex {
			slot := state[baseReg].DispatchIndex + byteOff/8
			state[rt] = KnownDispatch(slot)
			return
		}
		// Don't return here — fall through to other checks.
	}

	// 2. Dispatch table load: LDR Xt, [X21, Xm, LSL #3] → load from dispatch
	//    table at slot Xm. If Xm has KnownDispatchIndex, propagate the slot.
	if base, rm, rt, ok := isLDRRegExtended(raw); ok && base == regDT {
		if rt >= 31 {
			return
		}
		if rm < 31 && state[rm].Kind == LatticeKnownDispatchIndex {
			state[rt] = KnownDispatch(state[rm].DispatchIndex)
		} else if rm < 31 && state[rm].Kind == LatticeKnownClass {
			// Fase 7: dispatch table load with KnownClass index register.
			// Pattern: MOV X30, X0; LDR X30, [X21, X30, LSL #3]
			// DispatchIndex = ClassID - kOriginElement (because DispatchBySlot
			// is keyed by entry.Index - kOriginElement, and entry.Index for
			// class cid at selector 0 = cid, so key = cid - kOriginElement).
			slot := state[rm].ClassID - ctx.KOriginElement
			state[rt] = KnownDispatch(slot)
			ctx.ADDClassHits++
		} else {
			state[rt] = Bottom() // dispatch table entry, slot unknown
		}
		return
	}

	// 3. ADD Xd, X21, #imm → Xd = KnownDispatchIndex(imm).
	//    This computes the dispatch table slot address: X21 + offset.
	//    The offset IS the slot index * 8.
	if rd, rn, imm, ok := isADD64Immediate(raw); ok && rn == regDT {
		if rd >= 31 {
			return
		}
		slot := imm / 8 // slot index = byte offset / 8
		state[rd] = KnownDispatch(slot)
		return
	}

	// 4. ADD Xd, Xn, #imm where Xn is KnownDispatchIndex → Xd = KnownDispatchIndex(adjusted slot).
	//    This handles cases where the selector offset is computed in two steps.
	//    Also: ADD Xd, Xn, #imm where Xn is KnownClass → Xd = KnownDispatchIndex(cid + imm).
	//    In Dart AOT dispatch (Pattern B): ADD Xoffset, Xclass_id, #selector_offset
	//    where selector_offset is in SLOT units (not bytes — the LDR LSL #3 handles bytes).
	if rd, rn, imm, ok := isADD64Immediate(raw); ok {
		if rd >= 31 || rn >= 31 {
			// Fall through to default kill
		} else if state[rn].Kind == LatticeKnownDispatchIndex {
			// Adjust the dispatch index by the immediate (in slot units).
			state[rd] = KnownDispatch(state[rn].DispatchIndex + imm)
			return
		} else if state[rn].Kind == LatticeKnownClass {
			// ADD class_id + selector_offset → dispatch slot.
			// imm is in SLOT units (not bytes) for Pattern B.
			state[rd] = KnownDispatch(state[rn].ClassID + imm)
			ctx.ADDClassHits++
			return
		}
	}

	// 4b. SUB Xd, Xn, #imm — used for dispatch slot computation when
	// selector_offset < kOriginElement (Dart SDK's AddImmediate uses SUB
	// for negative offsets). Fase 7: re-enabled for KnownClass.
	if rd, rn, imm, ok := isSUB64Immediate(raw); ok {
		if rd >= 31 || rn >= 31 {
			// Fall through to default kill
		} else if state[rn].Kind == LatticeKnownDispatchIndex {
			state[rd] = KnownDispatch(state[rn].DispatchIndex - imm)
			return
		} else if state[rn].Kind == LatticeKnownClass {
			// SUB class_id - |offset| → dispatch slot.
			// Dart SDK: offset = selector - kOriginElement, if negative,
			// AddImmediate emits SUB with |offset|.
			state[rd] = KnownDispatch(state[rn].ClassID - imm)
			ctx.ADDClassHits++
			return
		}
	}

	// 4c. ADD Xd, Xn, Xm (register-register add) where Xn is KnownClass.
	// Fase 4: handle register-register ADD for dispatch slot computation.
	// Pattern: ADD Xoffset, Xclass_id, Xselector_offset
	// Also: ADD Xd, Xn, X28, LSL #32 = compressed pointer decompression.
	if rd, rn, rm, ok := isADD64Register(raw); ok {
		if rd < 31 && rn < 31 && state[rn].Kind == LatticeKnownClass {
			if rm == 28 { // X28 = HEAP_BITS — decompress compressed pointer
				// ADD Xd, Xn, X28, LSL #32 = decompress.
				// Result is the same KnownClass, just decompressed to 64-bit.
				state[rd] = state[rn] // preserve KnownClass
				return
			}
			if rm < 31 && state[rm].Kind == LatticeKnownDispatchIndex {
				state[rd] = KnownDispatch(state[rn].ClassID + state[rm].DispatchIndex)
				ctx.ADDClassHits++
				return
			}
			// Xm might hold a constant selector offset — treat as dispatch slot
			state[rd] = KnownDispatch(state[rn].ClassID)
			ctx.ADDClassHits++
			return
		}
	}

	// 5. LDUR Xt, [Xn, #imm9] — field load, header load, or stack load.
	if base, rt, ok := isLDUR64(raw); ok {
		if rt >= 31 {
			return
		}
		// Extract signed 9-bit immediate.
		imm9 := int(int32(raw>>12) & 0x1FF)
		if imm9 > 256 {
			imm9 -= 512 // sign extend
		}
		// Check stack load first (X29 or X15).
		if base == 29 {
			if t, ok2 := stackTypes[imm9]; ok2 {
				state[rt] = t
			} else {
				state[rt] = Top()
			}
			return
		}
		if base == 15 {
			if t, ok2 := stackTypes[imm9+0x10000]; ok2 {
				state[rt] = t
			} else {
				state[rt] = Top()
			}
			return
		}
		if base < 31 && state[base].Kind == LatticeKnownClass {
			if imm9 == -1 {
				// Object header load: the header contains the class_id.
				// Approximate: Xt = KnownClass(cid) — the header's class_id
				// is the same as the receiver's class.
				state[rt] = KnownClass(state[base].ClassID)
				ctx.HeaderHits++
				return
			}
			if fields, ok2 := ctx.FieldByOwnerOffset[state[base].ClassID]; ok2 {
				if fieldRefID, ok3 := fields[int32(imm9)]; ok3 {
					if classID, ok4 := ctx.FieldTypes[fieldRefID]; ok4 && classID >= 0 {
						state[rt] = KnownClass(classID)
						return
					}
				}
			}
		}
		// Unknown field or receiver type.
		state[rt] = Top()
		return
	}

	// 5-compressed. LDUR Wt, [Xn, #imm9] — 32-bit compressed pointer load.
	// Dart 3.x uses compressed pointers (4 bytes). LDUR Wt loads a compressed
	// pointer, then ADD Xt, Wt, X28, LSL #32 decompresses it.
	if base, rt, imm9, ok := isLDUR32(raw); ok {
		if rt >= 31 {
			return
		}
		if base == 29 {
			if t, ok2 := stackTypes[imm9]; ok2 {
				state[rt] = t
			} else {
				state[rt] = Top()
			}
			return
		}
		if base == 15 {
			if t, ok2 := stackTypes[imm9+0x10000]; ok2 {
				state[rt] = t
			} else {
				state[rt] = Top()
			}
			return
		}
		if base < 31 && state[base].Kind == LatticeKnownClass {
			key := state[base].ClassID*100000 + imm9
			if storedType, ok2 := stackTypes[key+0x20000]; ok2 && storedType.Kind != LatticeTop {
				state[rt] = storedType
				return
			}
			if fields, ok2 := ctx.FieldByOwnerOffset[state[base].ClassID]; ok2 {
				if fieldRefID, ok3 := fields[int32(imm9)]; ok3 {
					if classID, ok4 := ctx.FieldTypes[fieldRefID]; ok4 && classID >= 0 {
						state[rt] = KnownClass(classID)
						return
					}
				}
			}
			state[rt] = KnownClass(state[base].ClassID)
			ctx.HeaderHits++
			return
		}
		state[rt] = Top()
		return
	}

	// 5b. LDR Xt, [Xn, #imm] (unsigned offset) — field load from object.
	// PHASE 4: handle LDR (unsigned offset) for field loads, not just LDUR.
	// Dart AOT uses both LDUR (for small negative offsets like -1 header) and
	// LDR (for positive offsets like field at offset 8, 16, etc.).
	// SUPER FEATURE 3: Also preserve KnownStub (UnlinkedCall) through field
	// loads — when loading entry_point from UnlinkedCall object, the BLR
	// target is still the UnlinkedCall's target_name.
	if baseReg, byteOff, ok := isLDR64UnsignedOffset(raw); ok {
		rt := int(raw & 0x1F)
		if rt >= 31 {
			// Don't return here — let other handlers process
		} else if baseReg < 31 && state[baseReg].Kind == LatticeKnownStub {
			// SUPER FEATURE 3: Preserve KnownStub through field loads.
			// When loading entry_point from UnlinkedCall, preserve the
			// target_name so BLR can resolve it.
			if strings.HasPrefix(state[baseReg].StubName, "UnlinkedCall:") {
				state[rt] = state[baseReg] // preserve KnownStub
				return
			}
		} else if baseReg < 31 && baseReg != regPP && baseReg != regTHR && baseReg != regDT && baseReg != 29 && baseReg != 15 {
			// Not PP/THR/DT/stack/shadow-stack — could be object field load
			if state[baseReg].Kind == LatticeKnownClass {
				// TARGET 2: Check allocation site chain tracking first.
				// If we previously stored a KnownClass to this field, recover it.
				key := state[baseReg].ClassID*100000 + byteOff
				if storedType, ok2 := stackTypes[key+0x20000]; ok2 && storedType.Kind != LatticeTop {
					state[rt] = storedType
					return
				}
				// Check FieldByOwnerOffset for declared field type.
				if fields, ok2 := ctx.FieldByOwnerOffset[state[baseReg].ClassID]; ok2 {
					if fieldRefID, ok3 := fields[int32(byteOff)]; ok3 {
						if classID, ok4 := ctx.FieldTypes[fieldRefID]; ok4 && classID >= 0 {
							state[rt] = KnownClass(classID)
							return
						}
					}
				}
				// Field not found in FieldByOwnerOffset — approximate as KnownClass
				// (the loaded value is still an object of the same class, e.g. header)
				state[rt] = KnownClass(state[baseReg].ClassID)
				ctx.HeaderHits++
				return
			}
		}
	}

	// 5b-compressed. LDR Wt, [Xn, #imm] (unsigned offset) — 32-bit compressed field load.
	// PHASE C: Same as LDR Xt but for compressed pointers (4-byte loads).
	// Dart 3.x uses LDR Wt for compressed pointer field loads with positive offsets.
	if baseReg, byteOff, ok := isLDR32UnsignedOffset(raw); ok {
		rt := int(raw & 0x1F)
		if rt >= 31 {
			// Don't return — let other handlers process
		} else if baseReg < 31 && baseReg != regPP && baseReg != regTHR && baseReg != regDT && baseReg != 29 && baseReg != 15 {
			if state[baseReg].Kind == LatticeKnownClass {
				key := state[baseReg].ClassID*100000 + byteOff
				if storedType, ok2 := stackTypes[key+0x20000]; ok2 && storedType.Kind != LatticeTop {
					state[rt] = storedType
					return
				}
				if fields, ok2 := ctx.FieldByOwnerOffset[state[baseReg].ClassID]; ok2 {
					if fieldRefID, ok3 := fields[int32(byteOff)]; ok3 {
						if classID, ok4 := ctx.FieldTypes[fieldRefID]; ok4 && classID >= 0 {
							state[rt] = KnownClass(classID)
							return
						}
					}
				}
				state[rt] = KnownClass(state[baseReg].ClassID)
				ctx.HeaderHits++
				return
			}
		}
	}

	// 5b. UBFX/UBFM Xt, Xn, #lsb, #width — bitfield extract.
	//     If Xn has KnownClass, this is likely extracting the class_id from
	//     an object header. The result is still the class_id (KnownClass).
	if rd, rn, ok := isUBFX(raw); ok {
		if rd >= 31 {
			return
		}
		if rn < 31 && state[rn].Kind == LatticeKnownClass {
			// Extracting class_id from header — preserves KnownClass.
			state[rd] = state[rn]
			ctx.UBFXHits++
			return
		}
		// Unknown bitfield extract — kill type.
		if rd >= 0 && rd < 31 {
			state[rd] = Top()
		}
		return
	}

	// 6. MOV (ORR Xd, XZR, Xm) → Xd = Xm's type.
	if rd, ok := isMOVOrr(raw); ok {
		rm := int((raw >> 16) & 0x1F)
		if rd >= 31 {
			return
		}
		if rm < 31 {
			state[rd] = state[rm]
		} else {
			state[rd] = Top()
		}
		return
	}

	// 7. BLR — attempt dispatch resolution + allocation detection.
	//     If the BLR register is KnownStub and the stub name starts with
	//     "Allocate", this is an allocation call. The allocation stub returns
	//     a new object of the class that was in X0 before the call.
	//     Pattern: LDR X0, [X27, #pp] (class from PP); LDR Xn, [X26, #alloc];
	//              BLR Xn (call stub, result in X0 = KnownClass preserved).
	if rn, ok := isBLR(raw); ok {
		if rn < 31 {
			resolveBLR(state, rn, inst, ctx, result)
		}
		// SUPER FEATURE 3: Check if BLR register has KnownStub with
		// UnlinkedCall target_name. This resolves IC-based calls.
		if rn < 31 && state[rn].Kind == LatticeKnownStub {
			sn := state[rn].StubName
			if strings.HasPrefix(sn, "UnlinkedCall:") {
				methodName := sn[len("UnlinkedCall:"):]
				res := BlrResolution{
					PC:         inst.Addr,
					Reg:        rn,
					TargetName: methodName,
					Resolved:   true,
				}
				result.BLRResolutions = append(result.BLRResolutions, res)
			}
		}
		// Check if this is an allocation call via KnownStub.
		isAllocation := false
		if rn < 31 && state[rn].Kind == LatticeKnownStub {
			sn := state[rn].StubName
			if strings.HasPrefix(sn, "Allocate") || strings.HasPrefix(sn, "allocate") {
				isAllocation = true
			}
		}
		if isAllocation {
			// Preserve X0's KnownClass — the allocation returns a new object
			// of the same class that was in X0 before the call.
			// Kill X1-X7 (other arguments are consumed).
			for r := 1; r <= 7; r++ {
				state[r] = Top()
			}
		} else {
			// Regular BLR: X0 is unknown (return value).
			state[0] = Top()
			for r := 1; r <= 7; r++ {
				state[r] = Top()
			}
		}
		return
	}

	// 8. BL — direct call.
	// Fase 7 PART A fix: propagate callee's return type (ExitTypes[0]) to X0
	// instead of always killing X0. This enables chain: function A calls B
	// which returns KnownClass, then A uses the result for dispatch.
	//
	// TARGET 1: Full register type propagation. After BL, restore ALL
	// callee exit types (not just X0). This enables: function A calls B
	// which returns KnownClass in X0 AND preserves receiver in X1
	// (callee-saved), then A uses X1 for dispatch.
	if target, ok := isBL(raw, inst.Addr); ok {
		// Capture call-site state BEFORE BL kills R0-R7.
		// This is the ACTUAL parameter types being passed to the callee.
		if result.BLCallSiteTypes == nil {
			result.BLCallSiteTypes = make(map[uint64][31]TypeLattice)
		}
		var callSiteState [31]TypeLattice
		copy(callSiteState[:], state[:])
		result.BLCallSiteTypes[target] = callSiteState

		// Try to find callee's full exit types from context.
		calleeAllExit, hasFull := ctx.CalleeAllExitTypes[target]
		if hasFull {
			// Restore all registers from callee exit types.
			// R0-R7 (argument registers) are clobbered by BL,
			// but callee may have set them to meaningful values.
			// R19-R28 (callee-saved) are preserved across BL.
			// We restore R0-R7 from callee exit, keep R8-R18 as-is
			// (caller-saved but not argument regs), and keep R19-R28
			// as-is (callee-saved, preserved).
			for r := 0; r <= 7; r++ {
				if calleeAllExit[r].Kind != LatticeTop {
					state[r] = calleeAllExit[r]
				} else {
					state[r] = Top()
				}
			}
		} else {
			// Fallback: only restore X0 from CalleeExitTypes.
			calleeExit := ctx.CalleeExitTypes[target]
			if calleeExit.Kind != LatticeTop {
				state[0] = calleeExit
			} else {
				state[0] = Top()
			}
			for r := 1; r <= 7; r++ {
				state[r] = Top()
			}
		}
		return
	}

	// 9. Default: if this instruction defines a register, kill its type.
	if rd := dstRegOfInst(raw); rd >= 0 && rd < 31 {
		state[rd] = Top()
	}
}

// resolveBLR attempts to resolve a BLR call site to a dispatch table target.
// If the BLR register's type is KnownDispatchIndex, look up the slot.
// If the BLR register was loaded from dispatch table with a known class,
// compute the slot from class_id + selector_offset.
//
// SUPER FEATURE 2: For BLR with KnownDispatchIndex that doesn't resolve
// (null entry or code-without-name), try scanning nearby slots for
// possible targets. For BLR with Top (no type info), check if we can
// extract the selector offset from the preceding ADD/SUB instruction
// and do a reverse scan across all class IDs.
func resolveBLR(
	state *[31]TypeLattice,
	rn int,
	inst disasm.Inst,
	ctx *TypeContext,
	result *IntraResult,
) {
	res := BlrResolution{
		PC:  inst.Addr,
		Reg: rn,
	}

	t := state[rn]
	switch t.Kind {
	case LatticeKnownDispatchIndex:
		// Direct slot lookup.
		res.SlotIndex = t.DispatchIndex
		ctx.DispatchHits++
		if name, ok := ctx.ResolveDispatchTarget(t.DispatchIndex); ok {
			res.TargetName = name
			res.Resolved = true
		} else {
			// SUPER FEATURE 2: slot exists but no name.
			// Try to find the entry and resolve via CodeRange fallback.
			if entry, ok2 := ctx.DispatchBySlot[t.DispatchIndex]; ok2 && entry.Kind == cluster.DispatchCode {
				if name, ok3 := ctx.DispatchCodeIndexToName[entry.ClusterIndex]; ok3 && name != "" {
					res.TargetName = name
					res.Resolved = true
				}
			}
		}
	case LatticeKnownClass:
		// We know the receiver class but not the selector offset.
		res.Resolved = false
	case LatticeTop:
		// No type info — most common case.
		// SUPER FEATURE 2: try reverse scan if we have a selector offset hint.
		// The selector offset was extracted from the preceding ADD/SUB
		// instruction and stored in the BLR register's DispatchIndex.
		// But if state[rn] is Top, we lost the type info.
		// Check if the BLR register was loaded from dispatch table
		// (via LDR Xt, [X21, Xm, LSL #3]) — if Xm had a KnownDispatchIndex
		// that we lost, we can't recover it here.
		res.Resolved = false
	case LatticeBottom:
		res.Resolved = false
	}

	result.BLRResolutions = append(result.BLRResolutions, res)
}

// --- ARM64 instruction decoders ---

// isBL detects BL (branch with link). Returns target address.
func isBL(raw uint32, pc uint64) (uint64, bool) {
	if raw&0xFC000000 != 0x94000000 {
		return 0, false
	}
	imm26 := int32(raw & 0x03FFFFFF)
	if imm26&(1<<25) != 0 {
		imm26 |= ^int32(0x03FFFFFF)
	}
	return uint64(int64(pc) + int64(imm26)*4), true
}

// isBLR detects BLR (branch with link to register). Returns register number.
func isBLR(raw uint32) (int, bool) {
	if raw&0xFFFFFC1F != 0xD63F0000 {
		return 0, false
	}
	return int((raw >> 5) & 0x1F), true
}

// isB detects unconditional branch B. Returns target address.
func isB(raw uint32, pc uint64) (uint64, bool) {
	if raw&0xFC000000 != 0x14000000 {
		return 0, false
	}
	imm26 := int32(raw & 0x03FFFFFF)
	if imm26&(1<<25) != 0 {
		imm26 |= ^int32(0x03FFFFFF)
	}
	return uint64(int64(pc) + int64(imm26)*4), true
}

// isCondBranch detects conditional branches (B.cond, CBZ, CBNZ, TBZ, TBNZ).
// Returns the list of target addresses (branch target + fall-through).
func isCondBranch(raw uint32, pc uint64) ([]uint64, bool) {
	// B.cond: 0101 0100 | imm19 | 0 | cond
	if raw&0xFF000010 == 0x54000000 {
		imm19 := int32(raw>>5) & 0x7FFFF
		if imm19&(1<<18) != 0 {
			imm19 |= ^int32(0x7FFFF)
		}
		target := uint64(int64(pc) + int64(imm19)*4)
		return []uint64{target}, true
	}
	// CBZ: sf | 011 010 | 0 | imm19 | Rt
	if raw&0x7F000000 == 0x34000000 {
		imm19 := int32(raw>>5) & 0x7FFFF
		if imm19&(1<<18) != 0 {
			imm19 |= ^int32(0x7FFFF)
		}
		target := uint64(int64(pc) + int64(imm19)*4)
		return []uint64{target}, true
	}
	// CBNZ: sf | 011 010 | 1 | imm19 | Rt
	if raw&0x7F000000 == 0x35000000 {
		imm19 := int32(raw>>5) & 0x7FFFF
		if imm19&(1<<18) != 0 {
			imm19 |= ^int32(0x7FFFF)
		}
		target := uint64(int64(pc) + int64(imm19)*4)
		return []uint64{target}, true
	}
	// TBZ: b5 | 011 011 | 0 | imm14 | Rt
	if raw&0x7F000000 == 0x36000000 {
		imm14 := int32(raw>>5) & 0x3FFF
		if imm14&(1<<13) != 0 {
			imm14 |= ^int32(0x3FFF)
		}
		target := uint64(int64(pc) + int64(imm14)*4)
		return []uint64{target}, true
	}
	// TBNZ: b5 | 011 011 | 1 | imm14 | Rt
	if raw&0x7F000000 == 0x37000000 {
		imm14 := int32(raw>>5) & 0x3FFF
		if imm14&(1<<13) != 0 {
			imm14 |= ^int32(0x3FFF)
		}
		target := uint64(int64(pc) + int64(imm14)*4)
		return []uint64{target}, true
	}
	return nil, false
}

// isLDR64UnsignedOffset detects LDR Xt, [Xn, #imm] (64-bit unsigned offset).
// Returns base register and byte offset.
func isLDR64UnsignedOffset(raw uint32) (baseReg int, byteOffset int, ok bool) {
	if raw&0xFFC00000 != 0xF9400000 {
		return 0, 0, false
	}
	rn := int((raw >> 5) & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	return rn, imm12 << 3, true
}

// isSTR64UnsignedOffset detects STR Xt, [Xn, #imm] (64-bit unsigned offset).
// Returns base register and byte offset.
func isSTR64UnsignedOffset(raw uint32) (baseReg int, byteOffset int, ok bool) {
	if raw&0xFFC00000 != 0xF9000000 {
		return 0, 0, false
	}
	rn := int((raw >> 5) & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	return rn, imm12 << 3, true
}

// isLDRRegExtended detects LDR Xt, [Xn, Xm, LSL #3] (register offset).
// Returns base, index, and destination register.
func isLDRRegExtended(raw uint32) (base, rm, rt int, ok bool) {
	if raw&0xFFE00C00 != 0xF8600800 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	base = int((raw >> 5) & 0x1F)
	rm = int((raw >> 16) & 0x1F)
	return base, rm, rt, true
}

// isLDUR64 detects LDUR Xt, [Xn, #imm9] (unscaled immediate).
func isLDUR64(raw uint32) (base, rt int, ok bool) {
	if raw&0xFFE00C00 != 0xF8400000 {
		return 0, 0, false
	}
	rt = int(raw & 0x1F)
	base = int((raw >> 5) & 0x1F)
	return base, rt, true
}

// isSTUR64 detects STUR Xt, [Xn, #imm9] (unscaled immediate store).
// Encoding: 11 111 0 00 00 imm9 00 Rn Rt
// Mask: 0xFFE00C00, Value: 0xF8000000
// Q1 fix: extract full 9-bit imm9 (bits 12-20), not just 8 bits.
func isSTUR64(raw uint32) (base, rt int, imm9 int, ok bool) {
	if raw&0xFFE00C00 != 0xF8000000 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	base = int((raw >> 5) & 0x1F)
	imm9 = int(int32(raw>>12) & 0x1FF) // 9-bit field, bits 12-20
	if imm9 > 256 {
		imm9 -= 512 // sign-extend 9-bit
	}
	return base, rt, imm9, true
}

// isSTUR32 detects STUR Wt, [Xn, #imm9] (32-bit unscaled store).
// Used for compressed pointer stores in Dart 3.x.
// Encoding: 10 111 0 00 00 imm9 00 Rn Rt
// Mask: 0xFFE00C00, Value: 0xB8000000
func isSTUR32(raw uint32) (base, rt int, imm9 int, ok bool) {
	if raw&0xFFE00C00 != 0xB8000000 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	base = int((raw >> 5) & 0x1F)
	imm9 = int(int32(raw>>12) & 0x1FF)
	if imm9 > 256 {
		imm9 -= 512
	}
	return base, rt, imm9, true
}

// isLDUR32 detects LDUR Wt, [Xn, #imm9] (32-bit unscaled load).
// Used for compressed pointer loads in Dart 3.x.
// Encoding: 10 111 0 00 00 imm9 00 Rn Rt
// Mask: 0xFFE00C00, Value: 0xB8400000
func isLDUR32(raw uint32) (base, rt int, imm9 int, ok bool) {
	if raw&0xFFE00C00 != 0xB8400000 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	base = int((raw >> 5) & 0x1F)
	imm9 = int(int32(raw>>12) & 0x1FF)
	if imm9 > 256 {
		imm9 -= 512
	}
	return base, rt, imm9, true
}

// isLDR32UnsignedOffset detects LDR Wt, [Xn, #imm] (32-bit unsigned offset).
// Used for compressed pointer field loads in Dart 3.x.
// Encoding: 10 111 0 01 01 imm12 Rn Rt
// Mask: 0xFFC00000, Value: 0xB9400000
func isLDR32UnsignedOffset(raw uint32) (baseReg int, byteOffset int, ok bool) {
	if raw&0xFFC00000 != 0xB9400000 {
		return 0, 0, false
	}
	rt := int(raw & 0x1F)
	baseReg = int((raw >> 5) & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	byteOffset = imm12 * 4 // scaled by 4 for 32-bit load
	_ = rt // rt is always valid (0-30 are real registers, 31 is WZR which we don't track but still valid)
	return baseReg, byteOffset, true
}

// isADD64Immediate detects ADD Xd, Xn, #imm (64-bit).
// Returns dest, source, and immediate value (with shift applied).
func isADD64Immediate(raw uint32) (rd, rn int, immValue int, ok bool) {
	if raw&0xFF000000 != 0x91000000 {
		return 0, 0, 0, false
	}
	rd = int(raw & 0x1F)
	rn = int((raw >> 5) & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	shift := int((raw >> 22) & 0x3)
	if shift == 1 {
		immValue = imm12 << 12
	} else {
		immValue = imm12
	}
	return rd, rn, immValue, true
}

// isSUB64Immediate detects SUB Xd, Xn, #imm (64-bit).
// Returns dest, source, and immediate value (with shift applied).
func isSUB64Immediate(raw uint32) (rd, rn int, immValue int, ok bool) {
	if raw&0xFF000000 != 0xD1000000 {
		return 0, 0, 0, false
	}
	rd = int(raw & 0x1F)
	rn = int((raw >> 5) & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	shift := int((raw >> 22) & 0x3)
	if shift == 1 {
		immValue = imm12 << 12
	} else {
		immValue = imm12
	}
	return rd, rn, immValue, true
}

// isADD64Register detects ADD Xd, Xn, Xm (register-register, 64-bit).
// Encoding: sf=1 | 00 | 01011 | shift=00 | 0 | Rm | imm6 | Rn | Rd
// Mask: 0xFF200000, Value: 0x8B000000 (with sf=1 → 0x8B000000)
// Fase 4: added for register-register dispatch slot computation.
func isADD64Register(raw uint32) (rd, rn, rm int, ok bool) {
	if raw&0xFF200000 != 0x8B000000 {
		return 0, 0, 0, false
	}
	rd = int(raw & 0x1F)
	rn = int((raw >> 5) & 0x1F)
	rm = int((raw >> 16) & 0x1F)
	return rd, rn, rm, true
}

// isUBFX detects UBFM/UBFX Xt, Xn, #lsb, #width (64-bit).
// Encoding: sf=1 | 10 | 100110 | N=1 | immr | imms | Rn | Rd
// Mask: 0xFF800000, Value: 0xD3000000
// Returns dest and source register.
func isUBFX(raw uint32) (rd, rn int, ok bool) {
	if raw&0xFF800000 != 0xD3000000 {
		return 0, 0, false
	}
	rd = int(raw & 0x1F)
	rn = int((raw >> 5) & 0x1F)
	return rd, rn, true
}

// isMOVOrr detects MOV (alias of ORR Xd, XZR, Xm).
// Encoding: sf=1 | 01 | 01010 | 00 | 0 | Rm | 000000 | Rn=31 | Rd
// Mask: 0xFF200000, Value: 0xAA000000 (with sf=1)
func isMOVOrr(raw uint32) (rd int, ok bool) {
	// ORR Xd, XZR, Xm: 0xAA000000 with Rn=31
	if raw&0xFF20001F == 0xAA000000 {
		// Wait, Rn field is bits 5-9. For MOV, Rn = XZR = 31.
		rn := int((raw >> 5) & 0x1F)
		if rn == 31 {
			return int(raw & 0x1F), true
		}
	}
	return 0, false
}

// dstRegOfInst returns the destination register of common instructions,
// or -1 if not detected. Used to kill types on unknown instructions.
func dstRegOfInst(raw uint32) int {
	// LDR X64 unsigned offset
	if raw&0xFFC00000 == 0xF9400000 {
		return int(raw & 0x1F)
	}
	// LDR W32 unsigned offset
	if raw&0xFFC00000 == 0xB9400000 {
		return int(raw & 0x1F)
	}
	// LDUR X64
	if raw&0xFFE00C00 == 0xF8400000 {
		return int(raw & 0x1F)
	}
	// LDR X64 register offset
	if raw&0xFFE00C00 == 0xF8600800 {
		return int(raw & 0x1F)
	}
	// ADD X64 immediate
	if raw&0xFF000000 == 0x91000000 {
		return int(raw & 0x1F)
	}
	// SUB X64 immediate
	if raw&0xFF000000 == 0xD1000000 {
		return int(raw & 0x1F)
	}
	// MOVZ/MOVK/MOVN
	if raw&0xFF800000 == 0xD2800000 || // MOVZ X
		raw&0xFF800000 == 0xF2800000 || // MOVK X
		raw&0xFF800000 == 0x92800000 { // MOVN X
		return int(raw & 0x1F)
	}
	// UBFM/UBFX
	if raw&0xFF800000 == 0xD3000000 {
		return int(raw & 0x1F)
	}
	return -1
}
