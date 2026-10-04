package typetrack

import (
	"aotopsy/internal/arch/x86"
	"sort"

	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
	"golang.org/x/arch/x86/x86asm"
)

// x86_64 register constants — PP/THR/SP now shared from internal/sdk.
// The ones below are typetrack-specific (not in the SDK's reserved-register
// set, but used by the type lattice for class-id and allocation tracking).
const (
	x86RegRAX = 0 // return value / allocation result
)

// x86RegRDI is deliberately absent. It was defined here as "SysV arg 0
// (receiver for instance methods)" and used to answer what class an
// allocation returned. AllocateObjectABI is {kResultReg RAX,
// kTypeArgumentsReg RDX, kTagsReg R8} -- RDI is not in it, and inside
// GenerateAllocateObjectHelper it is only a scratch register. The class is
// now read from Code.owner via TypeContext.AllocationStubCID.

// x86ArgRegCanon lists Dart's OWN calling-convention integer argument
// registers as canonical indices, parameter 0 first. This is NOT the
// SysV C ABI — Dart declares its own convention (verified via gh api to
// constants_x64.h @3.9.2):
//
//	DartCallingConvention::kCpuRegistersForArgs[] = {RDI, RSI, RDX, RBX, R8, R9}
//
// The previous value used RCX (1) for parameter 3 instead of RBX (3) —
// the SysV C ABI order. On releases that have this register calling
// convention, RCX is DispatchTableNullErrorABI::kClassIdReg, not an argument
// register. killX86ArgRegs was killing RCX
// (losing class-id type info needed for dispatch resolution) and NOT
// killing RBX (leaving stale type info after calls that could propagate
// incorrect types).
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
	//   CALL [RAX + cid_reg*8 + disp32]                (dispatch table call)
	// cid_reg is caller-selected in 2.10/2.12 and fixed to RCX from 2.13.
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
		if inst.Bad {
			continue
		}
		if inst.Inst.Op != x86asm.CALL {
			continue
		}
		mem, ok := inst.Inst.Args[0].(x86asm.Mem)
		if !ok {
			continue
		}
		baseReg := x86.CanonReg(mem.Base)
		idxReg := x86.CanonReg(mem.Index)
		// Dart 2.10/2.12 pass cid_reg as an arbitrary register parameter to
		// EmitDispatchTableCall. From 2.13 onward the SDK fixes it to RCX via
		// DispatchTableNullErrorABI. Accept exactly the register shape valid for
		// this version instead of projecting RCX backwards.
		if baseReg == x86RegRAX && sdk.IsDispatchTableClassIDReg(ctx.DartVersion, sdk.ArchX86, idxReg) && mem.Scale == 8 && mem.Disp%8 == 0 {
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
	blockVisited := make([]bool, len(blocks))
	blockEntry[0] = entryTypes
	blockVisited[0] = true

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
		// class-ID-extract pattern and preserve HeaderTags/CID provenance. Without
		// this, x86_64 kills the header fact and the selector-offset-scan
		// dispatch path never fires, explaining the BLR gap vs ARM64.
		var prevInst *x86.Decoded
		// Flow-sensitive narrowing, the x86 counterpart of the ARM64 rule in
		// intraproc.go: a `CMP reg, #imm` against a class id means that on
		// the edge where the comparison SUCCEEDED, the register holds
		// exactly that CID scalar. It is step 3 of the chain that turns a header
		// load into a resolved dispatch -- header load gives HeaderTags, the
		// SHR extract turns it into UnknownClassID, the compare narrows to an
		// exact CID, and the dispatch call consumes it. Keeping header tags and
		// class-ID scalars as distinct lattice states is what lets this chain
		// survive without overloading Bottom as "unknown CID".
		var cmpReg, cmpImm int
		var hasCmp bool
		for _, inst := range blk.insts {
			if inst.Bad {
				hasCmp = false
				transferInstructionX86(&state, inst, nil, ctx, result, lca, stackTypes)
				prevInst = nil
				continue
			}
			if r, imm, ok := isX86CmpRegImm(inst); ok {
				cmpReg, cmpImm, hasCmp = r, imm, true
			} else if hasCmp && !x86PreservesCompareFlags(inst.Inst.Op) {
				hasCmp = false
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
			branchPC := blk.insts[len(blk.insts)-1].VA
			if isClassID(state[cmpReg].Kind) {
				ctx.recordNarrowMetric(branchPC, narrowMetricHit)
			} else {
				ctx.recordNarrowMetric(branchPC, narrowMetricNoType)
			}
		}
		for succIdx, succ := range blk.successors {
			var newEntry [31]TypeLattice
			narrowedState := state
			if succIdx == eqSucc && isClassID(state[cmpReg].Kind) {
				narrowedState[cmpReg] = ExactClassID(cmpImm)
			}
			if !blockVisited[succ] {
				newEntry = narrowedState
			} else {
				for r := 0; r < 31; r++ {
					newEntry[r] = joinType(blockEntry[succ][r], narrowedState[r], lca)
				}
			}

			firstVisit := !blockVisited[succ]
			changed := firstVisit || !typesEqual(newEntry, blockEntry[succ])
			newStackEntry, stackChanged := mergeStackFacts(blockStackEntry[succ], stackTypes, firstVisit, lca)
			if stackChanged {
				blockStackEntry[succ] = newStackEntry
				changed = true
			}

			if changed {
				blockEntry[succ] = newEntry
				blockVisited[succ] = true
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
				result.ExitTypes[r] = joinType(result.ExitTypes[r], blockExit[i][r], lca)
			}
		}
	}

	result.ParamTypes = entryTypes
	return result
}

// x86PreservesCompareFlags is intentionally small. Any operation not proven
// flag-transparent invalidates a prior CMP before JE/JNE narrowing. This makes
// CMP; TEST; JE correct and is safer than trying to maintain an incomplete
// model of every x86 EFLAGS writer.
func x86PreservesCompareFlags(op x86asm.Op) bool {
	if x86.IsCondJump(op) || op == x86asm.JMP || op == x86asm.RET {
		return true
	}
	switch op {
	case x86asm.MOV, x86asm.MOVZX, x86asm.MOVSX, x86asm.MOVSXD,
		x86asm.LEA, x86asm.NOP, x86asm.PUSH, x86asm.POP, x86asm.XCHG:
		return true
	}
	return false
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
	addrToIdx := make(map[uint64]int, len(insts))
	for i, d := range insts {
		addrToIdx[d.VA] = i
	}

	leaders := map[int]bool{0: true}
	for i, d := range insts {
		if d.Bad || x86.IsSemanticBarrier(d.Inst) {
			if i+1 < len(insts) {
				leaders[i+1] = true
			}
			continue
		}
		isBranch := false
		switch d.Inst.Op {
		case x86asm.RET:
			isBranch = true
		case x86asm.JMP:
			isBranch = true
			if t, ok := x86.RelTarget(d.Inst, d.VA, d.Len); ok {
				if idx, ok2 := addrToIdx[t]; ok2 {
					leaders[idx] = true
				}
			}
		default:
			if x86.IsCondJump(d.Inst.Op) {
				isBranch = true
				if t, ok := x86.RelTarget(d.Inst, d.VA, d.Len); ok {
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
		if last.Bad || x86.IsSemanticBarrier(last.Inst) {
			// A failed decode or architectural trap is not an instruction we can
			// safely execute through.
			continue
		}
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
			// The next block in instruction order is the real fallthrough. Do
			// not reconstruct it with VA+Len: near MaxUint64 that arithmetic can
			// wrap even though the block order itself is already known.
			if bi+1 < len(blocks) {
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
// while preserving header/CID provenance, mirroring ARM64's prevRaw UBFX fix.
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
//
// Only the RBP (stack) case existed originally. Object stores are recorded for
// field-access xrefs, but their observed value class is deliberately not promoted
// into a whole-program field type: a scanned store is not an exhaustive value set.
//
// PP/THR/SP bases address the pool, the Thread and the stack, none of
// which are Dart objects with fields; the same exclusions ARM64's STUR
// handler applies.
func handleX86Store(tc *transferCtxX86) bool {
	ins := tc.inst.Inst
	if ins.Op == x86asm.MOV && len(ins.Args) >= 2 {
		if mem, ok := ins.Args[0].(x86asm.Mem); ok {
			baseIdx := x86.CanonReg(mem.Base)
			if baseIdx == sdk.X86FrameReg {
				if mem.Index == 0 {
					if srcReg, srcOK := ins.Args[1].(x86asm.Reg); srcOK {
						srcIdx := x86.CanonReg(srcReg)
						if srcIdx >= 0 && srcIdx < 31 {
							tc.stackTypes[int(mem.Disp)] = tc.state[srcIdx]
						}
					}
				}
				return true
			}
			// Not the frame, not a reserved register: an object field.
			if baseIdx >= 0 && baseIdx < 31 &&
				baseIdx != sdk.X86PP && baseIdx != sdk.X86THR && baseIdx != sdk.X86SPReg && mem.Index == 0 &&
				isObjectClass(tc.state[baseIdx].Kind) {
				recordFieldAccess(tc.result, tc.ctx, tc.state[baseIdx].ClassID, int32(mem.Disp), true, tc.inst.VA)
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
					if baseIdx == sdk.X86FrameReg {
						if mem.Index != 0 {
							tc.state[dstIdx] = Top()
							return true
						}
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
			// PP load: MOV reg, [R15+disp] → runtime-object fact or named stub.
			if baseIdx == sdk.X86PP {
				if _, static := x86.StaticBaseDisp(mem, sdk.X86PP); !static {
					tc.state[dstIdx] = Top()
					return true
				}
				tc.ctx.hitMetric(metricPPLoad, tc.inst.VA, &tc.ctx.PPLoads)
				poolIdx, poolIdxOK := disasm.X64PoolIndex(mem.Disp)
				if !poolIdxOK {
					// Same rule as disasm's provenance tracker: the load
					// executed, so the destination's old type is gone.
					// Returning without touching state[dstIdx] left the
					// PREVIOUS type in place, and an exact object-class fact surviving a
					// load it did not survive is authoritative downstream
					// -- it picks dispatch targets.
					tc.state[dstIdx] = Top()
					return true
				}
				lat, hit := ResolvePoolEntry(tc.ctx, poolIdx, int(mem.Disp))
				tc.state[dstIdx] = lat
				if hit {
					tc.ctx.hitMetric(metricPPHit, tc.inst.VA, &tc.ctx.PPHits)
				}
				return true
			}
			// THR load: MOV reg, [R14+disp] → KnownStub.
			if baseIdx == sdk.X86THR {
				if _, static := x86.StaticBaseDisp(mem, sdk.X86THR); !static {
					tc.state[dstIdx] = Top()
					return true
				}
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
			if mem.Index == 0 && baseIdx >= 0 && baseIdx < 31 {
				if lat, ok := ResolveClosureField(tc.ctx, tc.state[baseIdx], int(mem.Disp)); ok {
					tc.state[dstIdx] = lat
					return true
				}
			}
			// Class-id load, Dart <= 2.18 form: MOVZX reg, word [obj + 1].
			//
			// Assembler::LoadClassId emits a 16-bit zero-extending load
			// there, because kClassIdTagPos is 16 and kClassIdTagSize is
			// 16, so the class id occupies the high half-word of the tags
			// word and can be read whole:
			//
			//	movzxw(result, FieldAddress(object, tags_offset + 16 / 8))
			//
			// FieldAddress subtracts the heap-object tag, so tags_offset 0
			// becomes displacement +1. From 2.19.0 the field is 20 bits at
			// position 12 and no longer half-word aligned, so the SDK
			// switched to movl + shrl -- the form the 32-bit path handles.
			//
			// Missing this shape left the class-id register Top on every
			// dispatch call: 83415 of 83415 sites on the 2.18.0 x64
			// sample, against 83417 Bottom on 2.19.0. Bottom is what makes
			// the selector-offset scan possible, so x86_64 dispatch
			// resolution was dead on every version up to 2.18.
			hwDisp, hasHalfWord := tc.ctx.HalfWordClassIDDisp()
			if mem.Index == 0 && hasHalfWord && ins.Op == x86asm.MOVZX && mem.Disp == hwDisp && baseIdx >= 0 && baseIdx < 31 &&
				baseIdx != sdk.X86PP && baseIdx != sdk.X86THR {
				if cid, exact := exactObjectClassID(tc.state[baseIdx]); exact {
					tc.state[dstIdx] = ExactClassID(cid)
				} else {
					tc.state[dstIdx] = UnknownClassID()
				}
				tc.ctx.hitMetric(metricHeader, tc.inst.VA, &tc.ctx.HeaderHits)
				return true
			}
			// Field type lookup — MOV reg, [reg+offset] where base has an object-class fact.
			if mem.Index == 0 && baseIdx >= 0 && baseIdx < 31 && isObjectClass(tc.state[baseIdx].Kind) {
				// Displacement -1 is the object header (FieldAddress
				// subtracts the heap tag), i.e. a class-ID extraction, not
				// a field. Matching 0 as well was too broad; ARM64 checks
				// only -1.
				if mem.Disp == -1 {
					if cid, exact := exactObjectClassID(tc.state[baseIdx]); exact {
						tc.state[dstIdx] = ExactHeaderTags(cid)
					} else {
						tc.state[dstIdx] = UnknownHeaderTags()
					}
					tc.ctx.hitMetric(metricHeader, tc.inst.VA, &tc.ctx.HeaderHits)
					return true
				}
				// ARM64 has recorded field accesses since the file
				// existed; x86_64 never called recordFieldAccess at all,
				// which is why field_accessor_xref.jsonl was absent from
				// an x86_64 run rather than merely empty.
				recordFieldAccess(tc.result, tc.ctx, tc.state[baseIdx].ClassID, int32(mem.Disp), false, tc.inst.VA)
				// Only the declared static field bound is authoritative here;
				// observed instances and scanned stores are not exhaustive value sets.
				// The resolver is shared with ARM64 so this rule has one definition.
				if fieldType, ok2 := tc.ctx.FieldValueType(tc.state[baseIdx].ClassID, int32(mem.Disp), tc.inst.VA); ok2 {
					tc.state[dstIdx] = fieldType
					return true
				}
				// An unknown field types NOTHING, so this deliberately
				// falls through. It used to end in
				// an exact receiver-class copy, effectively claiming
				// a field's value has the same class as the object holding
				// it. True for a linked-list `next`, false for nearly
				// everything else, and exact runtime class identity is authoritative
				// downstream: it selects dispatch targets. ARM64 has no
				// such fallback and never did. It also incremented
				// HeaderHits, so the counter meant to measure header loads
				// was partly measuring this guess.
			}
			// Header load with an UNKNOWN receiver type. Preserve the semantic
			// fact as UnknownHeaderTags rather than collapsing it to Top; an exact
			// SDK class-ID extraction can then produce UnknownClassID, which keeps
			// selector-only dispatch possible without pretending the CID is known.
			if mem.Index == 0 && mem.Disp == -1 && baseIdx >= 0 && baseIdx < 31 {
				tc.state[dstIdx] = UnknownHeaderTags()
				tc.ctx.hitMetric(metricHeader, tc.inst.VA, &tc.ctx.HeaderHits)
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

// handleX86LEA treats LEA as address arithmetic only. The exact Dart x64
// dispatch lowering loads the table with MOV from THR and uses folded addressing
// in CALL; LEA [THR+disp] does not dereference Thread and therefore cannot prove
// a dispatch-table base or callee slot.
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
		tc.state[dstIdx] = Top()
		return true
	}
	return false
}

// handleX86Bitwise handles class ID bitfield extraction from headers.
//
// SHR/AND reg, imm is the 2.19+ form of LoadClassId (movl + shrl). If the
// source has exact header tags, preserve the exact CID -- the same rule as
// ARM64's UBFX. Unknown header tags still yield a proven class-ID scalar whose
// numeric value is unknown, which is what the selector-offset dispatch path
// consumes. These dedicated states replace the historical use of Bottom as a
// reachable "unknown header/CID" signal.
func handleX86Bitwise(tc *transferCtxX86) bool {
	ins := tc.inst.Inst
	if ins.Op == x86asm.SHR && len(ins.Args) >= 2 {
		dstReg, dstOK := ins.Args[0].(x86asm.Reg)
		if !dstOK {
			return false
		}
		dstIdx := x86.CanonReg(dstReg)
		if dstIdx < 0 || dstIdx >= 31 {
			return false
		}
		// Only the exact LoadClassId lowering may preserve the class-id
		// abstraction through SHR.  Modern x64 Dart emits:
		//
		//   movl result, FieldAddress(object, tags_offset)
		//   shrl result, kClassIdTagPos
		//
		// A generic SHR (or AND) is merely integer arithmetic.  Preserving a
		// object/header fact through arbitrary bitwise operations turns an
		// object/type fact into a confidently wrong dispatch receiver.  Require
		// both the SDK-defined shift and the immediately preceding header load.
		shift, shiftOK := ins.Args[1].(x86asm.Imm)
		if !shiftOK || int(shift) != tc.ctx.ClassIDTagPos || !x86PrevLoadsHeaderInto(tc.prevInst, dstIdx) {
			tc.state[dstIdx] = Top()
			return true
		}
		if tc.state[dstIdx].Kind == LatticeExactHeaderTags {
			tc.state[dstIdx] = ExactClassID(tc.state[dstIdx].ClassID)
			tc.ctx.hitMetric(metricUBFX, tc.inst.VA, &tc.ctx.UBFXHits)
			return true
		}
		if tc.state[dstIdx].Kind == LatticeUnknownHeaderTags {
			tc.state[dstIdx] = UnknownClassID()
			tc.ctx.hitMetric(metricUBFX, tc.inst.VA, &tc.ctx.UBFXHits)
			return true
		}
		tc.state[dstIdx] = Top()
		return true
	}
	return false
}

func x86PrevLoadsHeaderInto(prev *x86.Decoded, dstIdx int) bool {
	if prev == nil || prev.Bad || prev.Inst.Op != x86asm.MOV || len(prev.Inst.Args) < 2 {
		return false
	}
	dst, ok := prev.Inst.Args[0].(x86asm.Reg)
	if !ok || x86.CanonReg(dst) != dstIdx {
		return false
	}
	mem, ok := prev.Inst.Args[1].(x86asm.Mem)
	if !ok {
		return false
	}
	return mem.Index == 0 && mem.Disp == -1 && x86.CanonReg(mem.Base) >= 0
}

// handleX86Call handles dispatch calls, allocation stubs, and direct calls.
func handleX86Call(tc *transferCtxX86) bool {
	ins := tc.inst.Inst
	if ins.Op == x86asm.CALL && len(ins.Args) >= 1 {
		// Apply architectural implicit writes even though CALL has a dedicated
		// semantic handler and therefore bypasses the generic write-set path.
		// In particular every CALL updates RSP.
		for _, dst := range x86.DstRegsOfInst(ins) {
			if dst >= 0 && dst < len(tc.state) {
				tc.state[dst] = Top()
			}
		}
		callTarget, hasDirectTarget := x86.RelTarget(ins, tc.inst.VA, tc.inst.Len)
		if _, ok := ins.Args[0].(x86asm.Rel); !ok {
			hasDirectTarget = false
		}
		if hasDirectTarget {
			if tc.result.BLCallSiteTypes == nil {
				tc.result.BLCallSiteTypes = make(map[uint64][31]TypeLattice)
			}
			tc.result.BLCallSiteTypes[tc.inst.VA] = *tc.state
		}

		// CALL [mem] — indirect call (dispatch table or object field).
		if mem, ok := ins.Args[0].(x86asm.Mem); ok {
			idxReg := x86.CanonReg(mem.Index)
			baseReg := x86.CanonReg(mem.Base)
			isDispatchCID := sdk.IsDispatchTableClassIDReg(tc.ctx.DartVersion, sdk.ArchX86, idxReg) && mem.Scale == 8 && mem.Disp%8 == 0
			if isDispatchCID {
				tc.ctx.hitMetric(metricX86DispatchShape, tc.inst.VA, &tc.ctx.X86DispatchShape)
				tableKnown := baseReg >= 0 && baseReg < 31 &&
					tc.state[baseReg].Kind == LatticeKnownDispatchIndex
				classKnown := idxReg >= 0 && idxReg < len(tc.state) && tc.state[idxReg].Kind == LatticeExactClassID
				switch {
				case tableKnown && classKnown:
					tc.ctx.recordX86DispatchMetric(tc.inst.VA, x86DispatchMetricResolved)
				case !classKnown:
					if idxReg < 0 || idxReg >= len(tc.state) {
						tc.ctx.recordX86DispatchMetric(tc.inst.VA, x86DispatchMetricNoClassOther)
						break
					}
					switch tc.state[idxReg].Kind {
					case LatticeTop:
						tc.ctx.recordX86DispatchMetric(tc.inst.VA, x86DispatchMetricNoClassTop)
					case LatticeUnknownClassID:
						tc.ctx.recordX86DispatchMetric(tc.inst.VA, x86DispatchMetricNoClassUnknownCID)
					default:
						tc.ctx.recordX86DispatchMetric(tc.inst.VA, x86DispatchMetricNoClassOther)
					}
				default:
					tc.ctx.recordX86DispatchMetric(tc.inst.VA, x86DispatchMetricNoTable)
				}
			}
			if baseReg >= 0 && baseReg < 31 && tc.state[baseReg].Kind == LatticeKnownDispatchIndex {
				if isDispatchCID && tc.state[idxReg].Kind == LatticeExactClassID {
					slot := int(tc.state[idxReg].ClassID) + int(mem.Disp/8)
					resolveX86Dispatch(tc.state, idxReg, slot, tc.inst, tc.ctx, tc.result)
				} else if isDispatchCID {
					resolveX86DispatchSelectorOffset(tc.state, tc.inst, tc.ctx, tc.result)
				}
			}
			killDartCallClobbered(tc.state, tc.ctx.DartVersion, false)
			return true
		}
		// CALL rel32 — direct call (allocation stub or regular function).
		if _, ok := ins.Args[0].(x86asm.Rel); ok {
			tc.ctx.recordBLReturnMetric(tc.inst.VA, blReturnMetricNone)
			if !hasDirectTarget {
				killDartCallClobbered(tc.state, tc.ctx.DartVersion, false)
				return true
			}
			// A call to a per-class allocation stub returns an instance of
			// that class, exactly, from Code.owner. This replaces a rule that
			// copied RDI's class into RAX whenever the callee's name started
			// with "Allocate" -- RDI is not in AllocateObjectABI at all
			// ({RAX, RDX, R8}), it is a scratch register inside the stub, and
			// the class never travels in a caller register: the per-class stub
			// materialises the tags word itself.
			if cid, ok := tc.ctx.AllocationStubCID[callTarget]; ok {
				tc.ctx.hitMetric(metricAllocStub, tc.inst.VA, &tc.ctx.AllocStubHits)
				killDartCallClobbered(tc.state, tc.ctx.DartVersion, false)
				if allocABI, abiOK := sdk.AllocateObjectRegs(tc.ctx.DartVersion, sdk.ArchX86); abiOK {
					tc.state[allocABI.ResultReg] = ExactClass(cid)
				}
				return true
			}
			if calleeAllExit, hasFull := tc.ctx.CalleeAllExitTypes[callTarget]; hasFull {
				// The full exit array can know nothing about RAX even when snapshot
				// metadata provides a concrete return type. Keep that stronger seed.
				ret := calleeAllExit[x86RegRAX]
				if ret.Kind == LatticeTop || ret.Kind == LatticeBottom {
					if seeded, ok := tc.ctx.CalleeExitTypes[callTarget]; ok && seeded.Kind != LatticeTop && seeded.Kind != LatticeBottom {
						ret = seeded
					}
				}
				if ret.Kind == LatticeTop || ret.Kind == LatticeBottom {
					ret = Top()
				} else if isObjectClass(ret.Kind) {
					tc.ctx.recordBLReturnMetric(tc.inst.VA, blReturnMetricObject)
				} else {
					tc.ctx.recordBLReturnMetric(tc.inst.VA, blReturnMetricNonObject)
				}
				killDartCallClobbered(tc.state, tc.ctx.DartVersion, false)
				tc.state[x86RegRAX] = ret
			} else if calleeExit, hasExit := tc.ctx.CalleeExitTypes[callTarget]; hasExit {
				if calleeExit.Kind == LatticeTop || calleeExit.Kind == LatticeBottom {
					calleeExit = Top()
				} else if isObjectClass(calleeExit.Kind) {
					tc.ctx.recordBLReturnMetric(tc.inst.VA, blReturnMetricObject)
				} else {
					tc.ctx.recordBLReturnMetric(tc.inst.VA, blReturnMetricNonObject)
				}
				killDartCallClobbered(tc.state, tc.ctx.DartVersion, false)
				tc.state[x86RegRAX] = calleeExit
			} else {
				killDartCallClobbered(tc.state, tc.ctx.DartVersion, false)
			}
			return true
		}
		// CALL reg — indirect call through register.
		if reg, ok := ins.Args[0].(x86asm.Reg); ok {
			regIdx := x86.CanonReg(reg)
			if regIdx >= 0 && regIdx < 31 && tc.state[regIdx].Kind == LatticeKnownStub {
				// No allocation case here. An indirect call through a THR
				// stub slot reaches the GENERIC AllocateObject stub, which
				// allocates whatever the tags word says -- there is no
				// per-class Code to read an owner from, and the caller does
				// not hold the class in a register. The rule that used to sit
				// here copied RDI's class into RAX, which the ABI does not
				// support; see AllocationStubCID.
				appendKnownStubResolution(tc.state[regIdx], tc.inst.VA, regIdx, tc.ctx, tc.result)
			}
		}
		killDartCallClobbered(tc.state, tc.ctx.DartVersion, false)
		return true
	}
	return false
}

// handleX86Decompress handles compressed-pointer decompression.
func handleX86Decompress(tc *transferCtxX86) bool {
	ins := tc.inst.Inst
	if ins.Op == x86asm.ADD && len(ins.Args) >= 2 && tc.ctx.THRFields != nil {
		if mem, memOK := ins.Args[1].(x86asm.Mem); memOK &&
			mem.Index == 0 && x86.CanonReg(mem.Base) == sdk.X86THR {
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
	clearFieldAccessAtPC(result, inst.VA)
	if inst.Bad || x86.IsSemanticBarrier(inst.Inst) {
		for i := range state {
			state[i] = Top()
		}
		for k := range stackTypes {
			delete(stackTypes, k)
		}
		return
	}

	tc := &transferCtxX86{
		state:      state,
		inst:       inst,
		prevInst:   prevInst,
		ctx:        ctx,
		result:     result,
		lca:        lca,
		stackTypes: stackTypes,
	}

	if handleArgsDescReceiverX86(tc) {
		return
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
	classReg int,
	slot int,
	inst x86.Decoded,
	ctx *TypeContext,
	result *IntraResult,
) {
	res := BlrResolution{
		PC:         inst.VA,
		SlotIndex:  slot,
		Confidence: ResolutionUnknown,
		Derivation: DerivationDispatchTable,
	}
	if name, ok := ctx.ResolveDispatchTarget(slot); ok {
		res.TargetName = name
		res.Resolved = true
		res.Confidence = ResolutionStaticInferred
		ctx.hitMetric(metricDispatch, inst.VA, &ctx.DispatchHits)
	}
	recordBLRResolution(result, res)
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
		Confidence: ResolutionStaticInferred,
		Derivation: DerivationDispatchTable,
	}
	applySelectorCandidates(&res, ctx.selectorCandidates(selectorImm))
	if res.Polymorphic {
		res.Confidence = ResolutionPolymorphic
	}
	if res.Resolved {
		ctx.hitMetric(metricDispatch, inst.VA, &ctx.DispatchHits)
	}
	recordBLRResolution(result, res)
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
