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
func transferInstructionX86(
	state *[31]TypeLattice,
	inst x86.Decoded,
	prevInst *x86.Decoded,
	ctx *TypeContext,
	result *IntraResult,
	lca func(int, int) int,
	stackTypes map[int]TypeLattice,
) {
	ins := inst.Inst

	// H-4 fix 1: Stack store: MOV [RBP+disp], reg → save reg's type to stack.
	// Object field store: MOV [base+disp], reg where base has a known class.
	//
	// Only the RBP case existed here. An object field store was not handled
	// at all, which meant two things on x86_64 that were true on ARM64:
	// field_accessor_xref.jsonl had no store rows, and
	// TypeContext.FieldStoreTypes -- the whole-program field-store to
	// field-load type channel -- was never written to. It stayed empty on
	// every x86_64 run, so one of the three type sources FieldValueClass
	// consults simply did not exist for this architecture.
	if ins.Op == x86asm.MOV && len(ins.Args) >= 2 {
		if mem, ok := ins.Args[0].(x86asm.Mem); ok {
			baseIdx := x86.CanonReg(mem.Base)
			if baseIdx == 5 { // RBP = frame register
				if srcReg, srcOK := ins.Args[1].(x86asm.Reg); srcOK {
					srcIdx := x86.CanonReg(srcReg)
					if srcIdx >= 0 && srcIdx < 31 {
						stackTypes[int(mem.Disp)] = state[srcIdx]
					}
				}
				return
			}
			// Not the frame, not a reserved register: an object field.
			// PP/THR/SP bases address the pool, Thread and stack, none of
			// which are Dart objects with fields -- the same exclusions
			// ARM64's STUR handler applies.
			if baseIdx >= 0 && baseIdx < 31 &&
				baseIdx != sdk.X86PP && baseIdx != sdk.X86THR && baseIdx != sdk.X86SPReg &&
				state[baseIdx].Kind == LatticeKnownClass {
				recordFieldAccess(result, state[baseIdx].ClassID, int32(mem.Disp), true, inst.VA)
				if srcReg, srcOK := ins.Args[1].(x86asm.Reg); srcOK {
					srcIdx := x86.CanonReg(srcReg)
					if srcIdx >= 0 && srcIdx < 31 && state[srcIdx].Kind == LatticeKnownClass {
						recordFieldStore(ctx, state[baseIdx].ClassID, int32(mem.Disp), state[srcIdx].ClassID)
					}
				}
			}
		}
	}

	// H-4 fix 1b: Stack load: MOV reg, [RBP+disp] → load type from stack.
	if (ins.Op == x86asm.MOV || ins.Op == x86asm.MOVZX) && len(ins.Args) >= 2 {
		if dstReg, dstOK := ins.Args[0].(x86asm.Reg); dstOK {
			dstIdx := x86.CanonReg(dstReg)
			if dstIdx >= 0 && dstIdx < 31 {
				if mem, ok := ins.Args[1].(x86asm.Mem); ok {
					baseIdx := x86.CanonReg(mem.Base)
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
		dstIdx := x86.CanonReg(dstReg)
		if dstIdx < 0 || dstIdx >= 31 {
			return
		}
		// MOV/MOVZX reg, [mem] — memory load.
		if mem, ok := ins.Args[1].(x86asm.Mem); ok {
			baseIdx := x86.CanonReg(mem.Base)
			// PP load: MOV reg, [R15+disp] → KnownClass.
			if baseIdx == sdk.X86PP {
				poolIdx, poolIdxOK := disasm.X64PoolIndex(mem.Disp)
				if !poolIdxOK {
					return
				}
				// Same resolver as ARM64. This used to check
				// PoolClassByIndex and PoolClosureClass only -- missing
				// every source that produces a NAME (unlinked calls, Code
				// objects, type-testing stubs), and storing closures as
				// KnownClass, which loses the pool index a later
				// Closure.function load needs.
				lat, hit := ResolvePoolEntry(ctx, poolIdx, int(mem.Disp))
				state[dstIdx] = lat
				if hit {
					ctx.PPHits++
				}
				return
			}
			// THR load: MOV reg, [R14+disp] → KnownStub.
			if baseIdx == sdk.X86THR {
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
			// Closure field load: MOV reg, [closure + function/entry_point].
			// The pool resolver above already carries closures as a
			// KnownStub whose StubOff is the pool index, which is exactly
			// what ResolveClosureField needs -- x86_64 preserved that
			// index and then never consumed it, so every tear-off
			// receiver went Top here while ARM64 resolved it.
			if baseIdx >= 0 && baseIdx < 31 {
				if lat, ok := ResolveClosureField(ctx, state[baseIdx], int(mem.Disp)); ok {
					state[dstIdx] = lat
					return
				}
			}
			// Class-id load, Dart <= 2.18 form: MOVZX reg, word [obj + 1].
			//
			// Assembler::LoadClassId emits a 16-bit zero-extending load there,
			// because kClassIdTagPos is 16 and kClassIdTagSize is 16, so the
			// class id occupies the high half-word of the tags word and can be
			// read whole:
			//
			//	movzxw(result, FieldAddress(object, tags_offset + 16 / 8))
			//
			// FieldAddress subtracts the heap-object tag, so tags_offset 0
			// becomes displacement +1. From 2.19.0 the field is 20 bits at
			// position 12 and no longer half-word aligned, so the SDK switched
			// to movl + shrl -- the form this handler already knew.
			//
			// Missing this shape left the class-id register Top on every
			// dispatch call: 83415 of 83415 sites on the 2.18.0 x64 sample,
			// against 83417 Bottom on 2.19.0. Bottom is what makes the
			// selector-offset scan possible, so x86_64 dispatch resolution was
			// dead on every version up to 2.18.
			if ctx.ClassIDIsHalfWord && ins.Op == x86asm.MOVZX && mem.Disp == 1 && baseIdx >= 0 && baseIdx < 31 &&
				baseIdx != sdk.X86PP && baseIdx != sdk.X86THR {
				if state[baseIdx].Kind == LatticeKnownClass {
					state[dstIdx] = KnownClass(state[baseIdx].ClassID)
				} else {
					// "A class id, but not known which" -- exactly what the
					// 32-bit path yields, and what narrowing and the
					// selector-offset scan both consume.
					state[dstIdx] = Bottom()
				}
				ctx.HeaderHits++
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
				// Record the access for field_accessor_xref.jsonl. ARM64 has
				// done this since the file existed; x86_64 never called
				// recordFieldAccess at all, which is why the file was simply
				// absent from an x86_64 run rather than empty.
				recordFieldAccess(result, state[baseIdx].ClassID, int32(mem.Disp), false, inst.VA)
				// Field type: declared type first, then the type observed in
				// const Instance objects. Shared with the ARM64 handlers via
				// TypeContext.FieldValueClass so the precedence rule has one
				// definition.
				if classID, ok2 := ctx.FieldValueClass(state[baseIdx].ClassID, int32(mem.Disp)); ok2 {
					state[dstIdx] = KnownClass(classID)
					return
				}
				// An unknown field types NOTHING. This used to fall through
				// to `state[dstIdx] = KnownClass(state[baseIdx].ClassID)`,
				// commented "keep KnownClass as approximation" -- which
				// claims a field's value has the same class as the object
				// holding it. That is true for a linked-list `next` and
				// false for almost everything else, and KnownClass is
				// treated as authoritative downstream: it selects dispatch
				// targets. ARM64 has no such fallback and never did.
				//
				// It also incremented HeaderHits, so the counter that was
				// supposed to measure header loads was partly measuring
				// this guess.
			}
			// Header load with an UNKNOWN receiver type. ARM64 sets Bottom
			// here (its "P1.2" rule) rather than Top, and that distinction
			// is load-bearing: the SHR/AND handler below only recognises a
			// class-ID extraction when its source is Bottom AND the previous
			// instruction was a header load, which is what keeps the
			// selector-offset scan alive when the receiver class is unknown.
			//
			// x86 had the consumer of that signal (isX86HeaderLoad plus the
			// LatticeBottom branch) but never the producer -- this path fell
			// through to Top, so the check could not fire. Measured
			// consequence: 91.6% of x86_64 dispatch calls reach the call site
			// with no class in cid_reg. See docs/roadmap/arch-parity.md P-1.
			if mem.Disp == -1 && baseIdx >= 0 && baseIdx < 31 {
				state[dstIdx] = Bottom()
				ctx.HeaderHits++
				return
			}
			// Other memory load — kill dst.
			state[dstIdx] = Top()
			return
		}
		// MOV reg, reg — copy type.
		if srcReg, ok := ins.Args[1].(x86asm.Reg); ok {
			srcIdx := x86.CanonReg(srcReg)
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
		dstIdx := x86.CanonReg(dstReg)
		if dstIdx < 0 || dstIdx >= 31 {
			return
		}
		if mem, ok := ins.Args[1].(x86asm.Mem); ok {
			baseIdx := x86.CanonReg(mem.Base)
			// LEA reg, [THR+disp] → load dispatch table base.
			if baseIdx == sdk.X86THR && mem.Disp != 0 {
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
		dstIdx := x86.CanonReg(dstReg)
		if dstIdx < 0 || dstIdx >= 31 {
			return
		}
		if srcReg, ok := ins.Args[0].(x86asm.Reg); ok {
			srcIdx := x86.CanonReg(srcReg)
			if srcIdx >= 0 && srcIdx < 31 {
				if state[srcIdx].Kind == LatticeKnownClass {
					// SHR/AND on KnownClass preserves KnownClass (class ID extraction).
					state[dstIdx] = state[srcIdx]
					ctx.UBFXHits++
					return
				}
				if state[srcIdx].Kind == LatticeBottom {
					// SHR/AND from Bottom: extracting class ID bits
					// from an unknown header still yields Bottom, not
					// Top. Same fix as ARM64 UBFX: don't require the
					// previous instruction to be a header load — any
					// Bottom source means "class ID, unknown which".
					state[dstIdx] = Bottom()
					ctx.UBFXHits++
					return
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
			callTarget = inst.VA + uint64(inst.Len) + uint64(int64(rel))
		}
		if callTarget != 0 {
			if result.BLCallSiteTypes == nil {
				result.BLCallSiteTypes = make(map[uint64][31]TypeLattice)
			}
			result.BLCallSiteTypes[inst.VA] = *state
		}

		// CALL [mem] — indirect call (dispatch table or object field).
		if mem, ok := ins.Args[0].(x86asm.Mem); ok {
			idxReg := x86.CanonReg(mem.Index)
			baseReg := x86.CanonReg(mem.Base)
			// Diagnose the dispatch-call shape before trying to resolve it,
			// so a failure says WHICH half was unknown. Resolving needs both
			// the table register and cid_reg typed; the counters separate
			// those two causes.
			if idxReg == x86RegRCX && mem.Scale == 8 {
				ctx.X86DispatchShape++
				tableKnown := baseReg >= 0 && baseReg < 31 &&
					state[baseReg].Kind == LatticeKnownDispatchIndex
				classKnown := state[x86RegRCX].Kind == LatticeKnownClass
				switch {
				case tableKnown && classKnown:
					ctx.X86DispatchResolved++
				case !classKnown:
					ctx.X86DispatchNoClass++
					switch state[x86RegRCX].Kind {
					case LatticeTop:
						ctx.X86DispatchClassTop++
					case LatticeBottom:
						ctx.X86DispatchClassBottom++
					default:
						ctx.X86DispatchClassOther++
					}
				default:
					ctx.X86DispatchNoTable++
				}
			}
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
			callTarget = inst.VA + uint64(inst.Len) + uint64(int64(rel))
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
			regIdx := x86.CanonReg(reg)
			if regIdx >= 0 && regIdx < 31 && state[regIdx].Kind == LatticeKnownStub {
				sn := state[regIdx].StubName
				if strings.HasPrefix(sn, "Allocate") || strings.HasPrefix(sn, "allocate") {
					if state[x86RegRDI].Kind == LatticeKnownClass {
						state[x86RegRAX] = state[x86RegRDI]
						killX86ArgRegs(state)
						return
					}
				}
				// FP-8: UnlinkedCall BLR resolution on x86_64.
				// When the call register holds a KnownStub with "UnlinkedCall:"
				// prefix, use MethodNameToSelectorOffsets to resolve via the
				// dispatch table, same as ARM64's handleBLR.
				if strings.HasPrefix(sn, "UnlinkedCall:") {
					methodName := sn[len("UnlinkedCall:"):]
					if selectorOffsets, hasOffsets := ctx.MethodNameToSelectorOffsets[methodName]; hasOffsets && len(selectorOffsets) > 0 {
						res := BlrResolution{PC: inst.VA, Reg: regIdx, SlotIndex: -1, Confidence: "static_inferred"}
						var allTargets []string
						for _, selOff := range selectorOffsets {
							allTargets = append(allTargets, ctx.selectorCandidates(selOff)...)
						}
						applySelectorCandidates(&res, allTargets)
						if res.Polymorphic {
							res.Confidence = "polymorphic"
						}
						result.BLRResolutions = append(result.BLRResolutions, res)
					} else {
						result.BLRResolutions = append(result.BLRResolutions, BlrResolution{
							PC: inst.VA, Reg: regIdx, TargetName: methodName, Resolved: true,
							Confidence: "stub",
						})
					}
				}
			}
		}
		state[x86RegRAX] = Top()
		killX86ArgRegs(state)
		return
	}

	// Compressed-pointer decompression is IDENTITY on the type lattice.
	//
	// x86_64 spells it as a 32-bit load followed by adding Thread.heap_base
	// (assembler_x64.cc: `movl(dest, slot); addq(dest, Address(THR,
	// heap_base_offset()))`). ARM64 spells it `add Xd, Xn, HEAP_BITS,
	// LSL #32`, and intraproc.go has preserved KnownClass across that since
	// it was written.
	//
	// x86 had no ADD handling at all, so this fell to the default kill
	// below and wiped the type of every decompressed pointer -- which, on a
	// compressed-pointer build, is EVERY field load. The dominant dispatch
	// sequence in the 3.12.2 x86_64 sample is
	//
	//	MOV EAX, [RSI+0x7]      ; load a field, compressed
	//	ADD RAX, [R14+0x58]     ; + THR.heap_base -> decompress
	//	MOV [RBP-0x8], RAX      ; spill
	//	MOV RAX, [RBP-0x8]      ; reload as the receiver
	//	MOV ECX, [RAX-0x1]      ; header
	//	SHR ECX, 0xc            ; class id
	//	CALL [RAX+8*RCX+disp]   ; dispatch
	//
	// so the class died at instruction two, every time, and everything
	// downstream saw an untyped receiver.
	if ins.Op == x86asm.ADD && len(ins.Args) >= 2 && ctx.THRFields != nil {
		if mem, memOK := ins.Args[1].(x86asm.Mem); memOK &&
			x86.CanonReg(mem.Base) == sdk.X86THR {
			if name, found := ctx.THRFields[int(mem.Disp)]; found && name == "heap_base" {
				return // same object, wider register: leave the lattice alone
			}
		}
	}

	// Default: if this instruction defines registers, kill their types.
	for _, dstIdx := range x86.DstRegsOfInst(ins) {
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
