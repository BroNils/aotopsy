package typetrack

import (
	"sort"
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

// BlrResolution is one indirect call site the analysis said something about.
//
// A site is one of three things, and they are NOT the same claim:
//
//   - monomorphic: exactly one callee is known. TargetName holds it,
//     TargetNames is empty, Polymorphic is false.
//   - polymorphic: the receiver class is unknown but the selector is, so the
//     callee is one of N implementations of that selector. TargetNames holds
//     up to maxPolymorphicNames of them, Candidates the true count, and
//     TargetName is EMPTY -- there is no single callee to name.
//   - unresolved: Resolved is false.
//
// TargetName used to carry a " | "-joined string for the polymorphic case.
// Consumers treat it as a callee name: render.ReachableSet added it to the
// call graph, so a 43-way virtual call became one graph node literally named
// "detach | get:first | paint | ...".
type BlrResolution struct {
	PC          uint64   // instruction address
	Reg         int      // BLR register number (0-30)
	SlotIndex   int      // dispatch table slot (if resolved)
	TargetName  string   // the single resolved callee, monomorphic sites only
	TargetNames []string // candidate callees, polymorphic sites only (capped)
	Resolved    bool     // true if we said anything about this site

	// Polymorphic marks a site whose callee is one of TargetNames.
	// Candidates is how many distinct names the scan found, which can exceed
	// len(TargetNames) -- see maxPolymorphicNames.
	Polymorphic bool
	Candidates  int
}

// maxPolymorphicNames bounds how many callee names a polymorphic resolution
// lists. A selector-offset scan across every class in the dispatch table can
// match hundreds of implementations; listing them all produced a single
// multi-kilobyte field in call_edges.jsonl.
const maxPolymorphicNames = 8

// cappedCandidates returns at most maxPolymorphicNames names.
func cappedCandidates(targets []string) []string {
	if len(targets) <= maxPolymorphicNames {
		return targets
	}
	return targets[:maxPolymorphicNames]
}

// selectorCandidates returns the distinct callee names reachable through a
// dispatch-table call whose class ID is unknown but whose selector immediate
// is known.
//
// The SDK emits (flow_graph_compiler_arm64.cc, EmitDispatchTableCall):
//
//	const intptr_t offset = selector_offset - DispatchTable::kOriginElement;
//	__ AddImmediate(LR, cid_reg, offset);
//	__ Call(Address(DISPATCH_TABLE_REG, LR, UXTX, Scaled));
//
// so the runtime index off DISPATCH_TABLE_REG is `cid + imm`, where imm is the
// signed immediate passed here. DispatchBySlot is keyed by that same
// register-relative index (absolute entry.Index - kOriginElement), therefore:
//
//	cid = key - imm = (entry.Index - kOriginElement) - imm
//
// The earlier formula, `entry.Index - imm + kOriginElement`, had the origin
// term on the wrong side and was off by 2*kOriginElement (8192 on ARM64), so
// every implied class ID -- and thus the RTA filter built on it -- was wrong.
func (ctx *TypeContext) selectorCandidates(imm int) []string {
	seen := map[string]bool{}
	var targets []string
	// The RTA filter is only meaningful once enough instantiated classes have
	// been observed; below that it would silently drop real targets.
	rtaEnabled := ctx.RTAApplied()
	for key, entry := range ctx.DispatchBySlot {
		if entry.Kind != cluster.DispatchCode {
			continue
		}
		impliedCID := key - imm
		if impliedCID < 0 {
			continue
		}
		if rtaEnabled && !ctx.InstantiatedClasses[impliedCID] {
			continue
		}
		if name, ok := ctx.DispatchCodeIndexToName[entry.ClusterIndex]; ok && name != "" {
			if !seen[name] {
				seen[name] = true
				targets = append(targets, name)
			}
		}
	}
	// DispatchBySlot is a map: sort so the same binary yields the same
	// candidate list (and the same call_edges.jsonl) on every run.
	sort.Strings(targets)
	return targets
}

// RTAApplied reports whether the selector-offset scan filters candidates by
// the set of instantiated classes. Exposed so the report can state it: a
// filter that silently does not run looks exactly like one that finds nothing
// to remove.
func (ctx *TypeContext) RTAApplied() bool {
	return len(ctx.InstantiatedClasses) >= rtaMinInstantiatedClasses
}

// rtaMinInstantiatedClasses is the number of observed instantiated classes
// below which the RTA filter is not applied. A previous value of 9999
// disabled the filter on every sample in the corpus while the comment next
// to it claimed the threshold was 100.
// Measured on the 3.12 x86_64 sample (2962 polymorphic sites): with the
// filter off the scan yields 636904 candidate callees, with it on 174943 --
// a 72.5% reduction, average fan-out 215 -> 59. It never turns a polymorphic
// site monomorphic, but it is doing substantial work, so the threshold is
// worth keeping honest.
const rtaMinInstantiatedClasses = 100

// applySelectorCandidates fills res from a selector-offset scan: one name
// means a real (monomorphic) resolution, more means a candidate set.
func applySelectorCandidates(res *BlrResolution, targets []string) {
	if len(targets) == 0 {
		return
	}
	res.Candidates = len(targets)
	res.Resolved = true
	res.SlotIndex = -1
	if len(targets) == 1 {
		res.TargetName = targets[0]
		return
	}
	res.Polymorphic = true
	res.TargetNames = cappedCandidates(targets)
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

	// FieldAccesses lists every instance-field read/write this function
	// performs through a receiver whose class was resolved. It is what makes
	// a real field cross-reference possible: (class, offset) -> the functions
	// that touch it.
	FieldAccesses []FieldAccess
}

// FieldAccess is one instance-field read or write with a known receiver class.
type FieldAccess struct {
	ClassID    int    // receiver's class ID
	ByteOffset int32  // raw instruction displacement (tagged-pointer relative)
	IsStore    bool   // true for a write, false for a read
	PC         uint64 // instruction address
}

// recordFieldAccess appends one access, de-duplicated by PC.
func recordFieldAccess(result *IntraResult, classID int, byteOffset int32, isStore bool, pc uint64) {
	if result == nil || classID < 0 {
		return
	}
	for i := range result.FieldAccesses {
		if result.FieldAccesses[i].PC == pc {
			return
		}
	}
	result.FieldAccesses = append(result.FieldAccesses, FieldAccess{
		ClassID:    classID,
		ByteOffset: byteOffset,
		IsStore:    isStore,
		PC:         pc,
	})
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

	// Pre-scan: find dispatch table call patterns and record selector offsets.
	// Three patterns exist depending on Dart version:
	//
	// 3.x (Dart 2.16+): ADD/SUB X30, X0, #imm → LDR X30, [X21, X30, LSL #3] → BLR X30
	//   SDK: AddImmediate(LR, cid_reg, offset) — LR = X30 as temp
	//
	// 2.x pattern A: ADD/SUB X0, X0, #imm → LDR X30, [X21, X0, LSL #3] → BLR X30
	//   SDK: AddImmediate(cid_reg, cid_reg, offset) — cid_reg = X0, in-place
	//
	// 2.x pattern B: LDURH Wn, [Xobj, #1] → SUB Xn, Xn, #imm → LDR X30, [X21, Xn, LSL #3] → BLR X30
	//   Class ID extracted via 16-bit load, then SUB in-place on any register,
	//   then LDR uses that register as index.
	//
	// The imm gives the selector offset (in slot units, relative to kOriginElement).
	for i := 0; i < len(insts)-2; i++ {
		raw := insts[i].Raw
		var selectorOffset int
		var slotReg int // register used as dispatch table index
		var found bool

		// Pattern 3.x: ADD/SUB X30, X0, #imm (rd=30, rn=0)
		if rd, rn, imm, ok := isADD64Immediate(raw); ok && rd == 30 && rn == 0 {
			selectorOffset = imm
			slotReg = 30
			found = true
		} else if rd, rn, imm, ok := isSUB64Immediate(raw); ok && rd == 30 && rn == 0 {
			selectorOffset = -imm
			slotReg = 30
			found = true
		}
		// Pattern 2.x A: ADD/SUB X0, X0, #imm (rd=0, rn=0)
		if !found {
			if rd, rn, imm, ok := isADD64Immediate(raw); ok && rd == 0 && rn == 0 {
				selectorOffset = imm
				slotReg = 0
				found = true
			} else if rd, rn, imm, ok := isSUB64Immediate(raw); ok && rd == 0 && rn == 0 {
				selectorOffset = -imm
				slotReg = 0
				found = true
			}
		}
		// Pattern 2.x B: ADD/SUB Xn, Xn, #imm (rd==rn, any register)
		// This catches the case where LDURH loads class ID into Wn,
		// then SUB Xn, Xn, #imm computes the slot in-place.
		if !found {
			if rd, rn, imm, ok := isADD64Immediate(raw); ok && rd == rn && rd < 31 {
				selectorOffset = imm
				slotReg = rd
				found = true
			} else if rd, rn, imm, ok := isSUB64Immediate(raw); ok && rd == rn && rd < 31 {
				selectorOffset = -imm
				slotReg = rd
				found = true
			}
		}
		// Pattern D: MOV X30, Xn (register-register move). The SDK emits this
		// instead of an ADD when `selector_offset - kOriginElement == 0`, so
		// the immediate is ZERO and the runtime index is the class ID itself.
		//
		// (This previously recorded kOriginElement as the "selector offset",
		// mixing two different quantities in the same map: every other
		// pattern stores the raw ADD/SUB immediate. The consumer subtracts
		// that immediate from the slot key, so the mismatch shifted every
		// implied class ID by kOriginElement.)
		// Pattern: MOV X30, Xn → ... → LDR X30, [X21, X30, LSL #3] → BLR X30
		if !found {
			if rd, ok := isMOVOrr(raw); ok && rd == 30 {
				for j := i + 1; j < len(insts)-1 && j <= i+4; j++ {
					ldrRaw := insts[j].Raw
					if base, rm2, rt, ok := isLDRRegExtended(ldrRaw); ok && base == 21 && rt == 30 && rm2 == 30 {
						if blrReg, ok := isBLR(insts[j+1].Raw); ok && blrReg == 30 {
							selectorOffset = 0
							slotReg = 30
							found = true
							ctx.SelectorOffsets[insts[j+1].Addr] = selectorOffset
							break
						}
					}
				}
			}
		}
		if !found {
			continue
		}
		// Check next instruction: LDR X30, [X21, XslotReg, LSL #3]
		if i+1 < len(insts) {
			ldrRaw := insts[i+1].Raw
			if base, rm, rt, ok := isLDRRegExtended(ldrRaw); ok && base == 21 && rt == 30 && rm == slotReg {
				// Check instruction after: BLR X30
				if i+2 < len(insts) {
					if blrReg, ok := isBLR(insts[i+2].Raw); ok && blrReg == 30 {
						ctx.SelectorOffsets[insts[i+2].Addr] = selectorOffset
					}
				}
			}
		}
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

		var prevRaw uint32
		// Type narrowing: track CMP/SUBS that compare a class ID with an
		// immediate. Which SUCCESSOR that licenses depends on the branch --
		// see equalitySuccessor.
		var cmpReg int  // register being compared
		var cmpImm int  // immediate being compared against
		var hasCmp bool // whether we saw a CMP/SUBS in this block
		for _, inst := range blk.insts {
			// Detect CMP/SUBS Wd, Wn, #imm (CMP is SUBS WZR, Wn, #imm)
			if _, rn, imm, ok := isSUBS32Immediate(inst.Raw); ok {
				cmpReg = rn
				cmpImm = imm
				hasCmp = true
			}
			transferInstruction(&state, inst, prevRaw, ctx, result, lca, stackTypes)
			prevRaw = inst.Raw
		}

		oldExit := blockExit[idx]
		blockExit[idx] = state
		// PHASE A: save per-block stack exit state.
		blockStackExit[idx] = stackTypes

		// Propagate to successors (meet).
		//
		// eqSucc is the successor index on which the compared register
		// definitely EQUALS cmpImm, or -1 when the terminating branch
		// licenses no such conclusion. Only that successor may be narrowed.
		eqSucc := -1
		if hasCmp && cmpReg < 31 && len(blk.insts) > 0 {
			eqSucc = equalitySuccessor(blk.insts[len(blk.insts)-1].Raw, len(blk.successors))
		}
		for succIdx, succ := range blk.successors {
			var newEntry [31]TypeLattice

			if succIdx == eqSucc {
				// The compared register holds a class ID (Bottom, from a
				// header load) or an already-known class. On this edge the
				// comparison succeeded, so it is exactly cmpImm.
				narrowed := state
				if state[cmpReg].Kind == LatticeBottom || state[cmpReg].Kind == LatticeKnownClass {
					narrowed[cmpReg] = KnownClass(cmpImm)
					ctx.NarrowHits++
				}
				if isFirstVisit := allTop(blockEntry[succ]) && succ != 0; isFirstVisit {
					newEntry = narrowed
				} else {
					for r := 0; r < 31; r++ {
						newEntry[r] = meetType(blockEntry[succ][r], narrowed[r], lca)
					}
				}
			} else {
				// Every other edge, including the "not equal" one: the
				// lattice cannot express "not N", so nothing is learned.
				if isFirstVisit := allTop(blockEntry[succ]) && succ != 0; isFirstVisit {
					newEntry = state
				} else {
					for r := 0; r < 31; r++ {
						newEntry[r] = meetType(blockEntry[succ][r], state[r], lca)
					}
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

// equalitySuccessor reports which successor edge of a block ending in `last`
// proves that a preceding `CMP reg, #imm` compared EQUAL, or -1 when no edge
// does. numSuccs is the block's successor count.
//
// Successors are built target-first, fall-through-second (see buildBlocks),
// so index 0 is the taken edge and index 1 the not-taken one -- but only when
// both were resolvable, hence the numSuccs == 2 requirement. With one
// successor the single entry may be either, and guessing is how this went
// wrong before.
//
// This check did not exist. Narrowing was applied to successor 0 after ANY
// conditional branch, which is right for B.EQ and wrong for everything else:
// after B.NE, reaching the target proves the register is NOT the immediate,
// and after B.LS/B.CS/B.HI/B.GE/B.LT/B.GT the test is a range, not an
// equality.
//
// Measured on the 3.x ARM64 sample, the cost of that was small: narrowings
// actually applied went 4148 -> 3983, so 165 (4%) had no grounds, and no
// output changed at all -- call_edges.jsonl is byte-identical either way.
// The disassembly-level distribution of CMP-then-branch is much worse than
// that (1408 B.EQ against 1207 B.NE and ~1900 range branches), but most of
// those compare ordinary integers, where the register is Top and no
// narrowing fires whatever the branch says. Rate over the WRONG population.
//
// B.NE is not merely excluded, it is inverted usefully: reaching its
// FALL-THROUGH proves equality, so that edge is narrowed instead.
//
// Known remaining limit: this does not verify that the CMP is what set the
// flags the branch reads. Another flag-setting instruction between the two
// would invalidate it. That is a smaller and separate hazard from the branch
// condition, which is what the measurement above sized.
func equalitySuccessor(last uint32, numSuccs int) int {
	if numSuccs != 2 {
		return -1
	}
	// Only B.cond reads the flags a CMP set. CBZ/CBNZ and TBZ/TBNZ test a
	// register or a single bit directly, so a preceding CMP says nothing
	// about which way they go.
	if last&0xFF000010 != 0x54000000 {
		return -1
	}
	switch last & 0xF {
	case 0: // EQ: the taken edge is the equal one.
		return 0
	case 1: // NE: the taken edge proves inequality; the fall-through proves equality.
		return 1
	}
	return -1
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
			if bi, ok2 := addrToBlock[fallThroughAddr]; ok2 {
				blk.successors = append(blk.successors, bi)
			}
			continue
		}
		// BL/BLR: fall-through to next block.
		if _, ok := isBL(lastInst.Raw, lastInst.Addr); ok {
			if bi, ok2 := addrToBlock[fallThroughAddr]; ok2 {
				blk.successors = append(blk.successors, bi)
			}
			continue
		}
		if _, ok := isBLR(lastInst.Raw); ok {
			if bi, ok2 := addrToBlock[fallThroughAddr]; ok2 {
				blk.successors = append(blk.successors, bi)
			}
			continue
		}
		// Default: fall-through.
		if bi, ok2 := addrToBlock[fallThroughAddr]; ok2 {
			blk.successors = append(blk.successors, bi)
		}
	}

	return blocks
}

// transferInstruction updates the register type state based on one instruction.
// On BLR instructions, it attempts to resolve the dispatch target.
// stackTypes tracks stack slot types for frame pointer (X29) loads/stores.
// prevRaw is the raw encoding of the previous instruction (0 if none),
// used to detect header-load → UBFX patterns for class ID extraction.
func transferInstruction(
	state *[31]TypeLattice,
	inst disasm.Inst,
	prevRaw uint32,
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
			if state[base].Kind == LatticeKnownClass {
				recordFieldAccess(result, state[base].ClassID, int32(imm9), true, inst.Addr)
			}
			if state[base].Kind == LatticeKnownClass && state[rt].Kind == LatticeKnownClass {
				key := state[base].ClassID*100000 + imm9
				stackTypes[key+0x20000] = state[rt]
				// P1.3: Record field store for whole-program field-store → field-load tracking.
				recordFieldStore(ctx, state[base].ClassID, int32(imm9), state[rt].ClassID)
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
			if state[base].Kind == LatticeKnownClass {
				recordFieldAccess(result, state[base].ClassID, int32(imm9), true, inst.Addr)
			}
			if state[base].Kind == LatticeKnownClass && state[rt].Kind == LatticeKnownClass {
				key := state[base].ClassID*100000 + imm9
				stackTypes[key+0x20000] = state[rt]
				// P1.3: Record field store for whole-program tracking.
				recordFieldStore(ctx, state[base].ClassID, int32(imm9), state[rt].ClassID)
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
		poolIdx, poolIdxOK := disasm.ARM64PoolIndex(byteOff)
		if !poolIdxOK {
			return
		}
		// SUPER FEATURE 3: Check if PP entry is UnlinkedCall with target_name.
		if ctx.PoolUnlinkedCallNames != nil {
			if name, ok3 := ctx.PoolUnlinkedCallNames[poolIdx]; ok3 && name != "" {
				// UnlinkedCall loaded into IC_DATA_REG — track as KnownStub
				// with target_name. This enables IC-based BLR resolution.
				state[rt] = KnownStub("UnlinkedCall:"+name, byteOff)
				return
			}
		}
		// Removed: an "ICData:<name>" KnownStub path keyed on PP index.
		// ICData is never present in an AOT snapshot (see cluster.ICDataInfo),
		// so the lookup could never hit; measured effect was 0 additional BLR
		// resolutions on every sample. It was also semantically wrong -- the
		// name it propagated came from the ICData object's *owner*, not from
		// CallSiteData.target_name.
		if classID, ok2 := ctx.PoolClassByIndex[poolIdx]; ok2 && classID >= 0 {
			state[rt] = KnownClass(classID)
			ctx.PPHits++
			// Populate InstantiatedClasses: a Class object in the pool
			// means instances of this class exist (const instances are
			// serialized in the snapshot, and the Class object itself
			// is proof the class is instantiated).
			if ctx.InstantiatedClasses != nil {
				ctx.InstantiatedClasses[classID] = true
			}
		} else if ctx.PoolCodeNames != nil {
			if name, ok3 := ctx.PoolCodeNames[poolIdx]; ok3 && name != "" {
				state[rt] = KnownStub("PPCode:"+name, byteOff)
				ctx.PPHits++
				return
			}
		}
		if ctx.PoolClosureClass != nil {
			// Closure consumer: a PP load of a Closure object can still give
			// us a KnownClass via ClosureData.parent_function → Function.owner
			// → Class → ClassID (precomputed in PoolClosureClass). This lets
			// a subsequent BLR through that register resolve via the dispatch
			// table instead of being Top.
			if classID, ok3 := ctx.PoolClosureClass[poolIdx]; ok3 && classID >= 0 {
				state[rt] = KnownClass(classID)
				ctx.PPHits++
				return
			}
			state[rt] = Top()
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
		} else if state[rn].Kind == LatticeBottom {
			// P1.2: ADD on Bottom (class ID from header load with unknown
			// receiver). The class is unknown but the selector immediate is
			// not: per flow_graph_compiler_arm64.cc EmitDispatchTableCall,
			// this immediate is selector_offset - kOriginElement.
			state[rd] = SelectorDispatch(imm)
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
		} else if state[rn].Kind == LatticeBottom {
			// P1.2: SUB on Bottom -- same as the ADD case with a negative
			// immediate (the SDK emits SUB when selector_offset <
			// kOriginElement).
			state[rd] = SelectorDispatch(-imm)
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
				state[rt] = KnownClass(state[base].ClassID)
				ctx.HeaderHits++
				return
			}
			recordFieldAccess(result, state[base].ClassID, int32(imm9), false, inst.Addr)
			if classID, ok2 := ctx.FieldValueClass(state[base].ClassID, int32(imm9)); ok2 {
				state[rt] = KnownClass(classID)
				return
			}
		}
		// PP-loaded Code entry_point: LDUR Xt, [Xn, #7]
		if imm9 == 7 && base < 31 && state[base].Kind == LatticeKnownStub {
			sn := state[base].StubName
			if strings.HasPrefix(sn, "PPCode:") {
				state[rt] = KnownStub(sn, imm9)
				return
			}
		}
		// P1.2: Header load with unknown receiver type.
		// If imm9 == -1, this is a tag load. Set Bottom() instead of Top()
		// so UBFX can detect it as a class ID extraction and the dispatch
		// slot computation can use selector offset scan.
		if imm9 == -1 && base < 31 {
			state[rt] = Bottom()
			ctx.HeaderHits++
			return
		}
		// Unknown field or receiver type.
		state[rt] = Top()
		return
	}

	// 5-ldurh. LDURH Wt, [Xn, #imm9] — 16-bit load (Dart 2.x class ID extraction).
	// In Dart 2.x: kClassIdTagPos=16, kClassIdTagSize=16.
	// LoadClassId: LoadFromOffset(result, object, 2-1, kUnsignedTwoBytes)
	// = LDURH Wt, [Xobj, #1] — loads 2-byte class ID from tags at offset 2.
	// If imm9 == 1, this is a class ID load → set Bottom().
	if base, rt, imm9, ok := isLDURH(raw); ok {
		if rt >= 31 {
			return
		}
		// Stack loads via LDURH (unlikely but handle for safety)
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
		// Class ID load: LDURH Wt, [Xobj, #1].
		//
		// This is the Dart 2.x form of class-id extraction: kClassIdTagPos is
		// 16 there, so the id is a 16-bit field at header offset 2, reached as
		// #1 off the tagged pointer. Dart 3.x moved it to bits [12,32) and
		// uses LDUR + UBFX instead.
		//
		// When the receiver's class is known, the extracted id IS that class,
		// and saying so is what lets the following ADD/SUB compute a dispatch
		// slot -- exactly what the 3.x UBFX handler does with a KnownClass
		// operand. Returning Bottom unconditionally, as this did, throws away
		// a class the analysis had already established.
		//
		// Measured honestly: on the 2.12 sample this branch sees 160806
		// class-id loads and ZERO of them currently have a KnownClass base,
		// so the fix changes no output yet. The blocker is upstream and
		// SDK-confirmed: DartCallingConvention::kCpuRegistersForArgs does not
		// exist before ~2.16 (absent from constants_arm64.h at tag 2.12.0,
		// present at 3.9.2 as {R1,R2,R3,R5,R6,R7}), so 2.x passes the
		// receiver on the STACK. Seeding entry[X1] = KnownClass(owner) types
		// nothing there, and no receiver class ever reaches this load.
		// Seeding 2.x receivers from the frame is the next step.
		if imm9 == 1 && base < 31 {
			if state[base].Kind == LatticeKnownClass {
				state[rt] = KnownClass(state[base].ClassID)
			} else {
				// Class unknown, but the value IS a class id: Bottom keeps
				// the SelectorDispatch path (ADD/SUB on Bottom) alive.
				state[rt] = Bottom()
			}
			ctx.HeaderHits++
			return
		}
		// Regular 16-bit field load
		if base < 31 && state[base].Kind == LatticeKnownClass {
			if classID, ok2 := ctx.FieldValueClass(state[base].ClassID, int32(imm9)); ok2 {
				state[rt] = KnownClass(classID)
				return
			}
		}
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
			if classID, ok2 := ctx.FieldValueClass(state[base].ClassID, int32(imm9)); ok2 {
				state[rt] = KnownClass(classID)
				return
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
				if classID, ok2 := ctx.FieldValueClass(state[baseReg].ClassID, int32(byteOff)); ok2 {
					state[rt] = KnownClass(classID)
					return
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
				if classID, ok2 := ctx.FieldValueClass(state[baseReg].ClassID, int32(byteOff)); ok2 {
					state[rt] = KnownClass(classID)
					return
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
	//     If Xn is Bottom (header load with unknown receiver), preserve Bottom
	//     — the UBFX is extracting class ID from tags, and the result is a
	//     class ID value (not an object pointer).
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
		// P1.1: If previous instruction was LDUR Xt, [Xn, #-1] (header load)
		// and current state[rn] is Bottom, this UBFX extracts class ID.
		// Preserve Bottom — the result is a class ID, not an object.
		if rn < 31 && state[rn].Kind == LatticeBottom {
			// Check if prevRaw was a header load (LDUR Xt, [Xn, #-1])
			if _, rt, ok2 := isLDUR64(prevRaw); ok2 && rt == rn {
				imm9 := int(int32(prevRaw>>12) & 0x1FF)
				if imm9 > 256 {
					imm9 -= 512
				}
				if imm9 == -1 {
					state[rd] = Bottom()
					ctx.UBFXHits++
					return
				}
			}
			// Also check LDUR32 (compressed pointers)
			if _, rt, _, ok2 := isLDUR32(prevRaw); ok2 && rt == rn {
				state[rd] = Bottom()
				ctx.UBFXHits++
				return
			}
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
			} else if strings.HasPrefix(sn, "PPCode:") {
				funcName := sn[len("PPCode:"):]
				res := BlrResolution{
					PC:         inst.Addr,
					Reg:        rn,
					TargetName: funcName,
					Resolved:   true,
				}
				result.BLRResolutions = append(result.BLRResolutions, res)
			} else if sn != "" && !strings.HasPrefix(sn, "Allocate") && !strings.HasPrefix(sn, "allocate") {
				res := BlrResolution{
					PC:         inst.Addr,
					Reg:        rn,
					TargetName: sn,
					Resolved:   true,
				}
				result.BLRResolutions = append(result.BLRResolutions, res)
			}
			// Removed: the matching "ICData:" consumer for the KnownStub
			// producer deleted above. Dead once the producer is gone.
		}
		// Check if this is an allocation call via KnownStub.
		isAllocation := false
		if rn < 31 && state[rn].Kind == LatticeKnownStub {
			sn := state[rn].StubName
			if strings.HasPrefix(sn, "Allocate") || strings.HasPrefix(sn, "allocate") {
				isAllocation = true
			}
		}
		// Also detect allocation via THR stub offset match (more robust than name check).
		if !isAllocation && rn < 31 && state[rn].Kind == LatticeKnownStub {
			off := state[rn].StubOff
			if ctx.AllocStubOffsets != nil {
				if name, found := ctx.AllocStubOffsets[int64(off)]; found {
					if strings.Contains(strings.ToLower(name), "allocate") {
						isAllocation = true
					}
				}
			}
		}
		if isAllocation {
			// Record allocation site + populate InstantiatedClasses.
			// X0 holds the class ID (from PP load or MOVZ).
			if state[0].Kind == LatticeKnownClass {
				recordAllocationSite(ctx, inst.Addr, state[0].ClassID)
			}
			// Also check X0 for Bottom (class ID from header load + UBFX).
			// In some allocation patterns, X0 is loaded from PP as a Class object
			// (KnownClass), but in others it's loaded as a raw class ID (Bottom).
			// We can't determine the exact class from Bottom, but we CAN check
			// if X0 was loaded from PP with a known pool index that maps to a class.
			// This is handled by the PP load handler above which sets KnownClass.
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
		// P1.2: class unknown, selector immediate known -- scan the dispatch
		// table at that selector across all classes.
		if t.SelectorOnly {
			ctx.DispatchHits++
			res.SlotIndex = -1
			imm := t.SelectorImm
			// The pre-scan's per-BLR record is authoritative when present:
			// it saw the actual ADD/SUB + LDR + BLR triple.
			if fromPreScan, ok := ctx.SelectorOffsets[inst.Addr]; ok {
				imm = fromPreScan
			}
			applySelectorCandidates(&res, ctx.selectorCandidates(imm))
			result.BLRResolutions = append(result.BLRResolutions, res)
			return
		}

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
			// P5 CHA: if direct lookup failed, try subclass dispatch slots.
			// The receiver might be a subclass that overrides the method,
			// while the superclass slot is null/stub.
			if !res.Resolved && len(ctx.Subclasses) > 0 {
				// Recover the class ID from the slot: slot = cid + selector - KOrigin
				// We don't know selector, but we can scan subclasses at the
				// same slot offset relative to their own class IDs.
				// This is a heuristic: try shifting the slot by subclass delta.
				for parentCID, subs := range ctx.Subclasses {
					parentSlot := parentCID - ctx.KOriginElement
					if parentSlot != t.DispatchIndex {
						continue
					}
					for _, subCID := range subs {
						subSlot := subCID - ctx.KOriginElement
						if name, ok := ctx.ResolveDispatchTarget(subSlot); ok {
							res.TargetName = name
							res.Resolved = true
							break
						}
					}
					if res.Resolved {
						break
					}
				}
			}
		}
	case LatticeKnownClass:
		// We know the receiver class but not the selector offset.
		// P4: Reverse dispatch scan — scan this class's dispatch slots for
		// non-null targets. If exactly one slot has a non-null Code entry,
		// that is the call target (monomorphic call). If multiple, we cannot
		// pick one, so leave unresolved.
		//
		// P5 CHA: the Subclasses map and ResolveDispatchCHA are available
		// for future use — when a selector offset IS known (via a preceding
		// ADD/SUB that we can recover), CHA can enumerate all subclass
		// dispatch targets for polymorphic call resolution. Currently the
		// reverse scan above handles the monomorphic case; CHA would
		// extend this to polymorphic calls.
		if ctx.DispatchBySlot != nil {
			candidates := 0
			var candidateName string
			var allCandidates []string
			// Dispatch slots for class cid start at cid - KOriginElement.
			baseSlot := t.ClassID - ctx.KOriginElement
			for offset := 0; offset < 128; offset++ {
				slot := baseSlot + offset
				entry, ok := ctx.DispatchBySlot[slot]
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
				res.SlotIndex = -1
				res.Candidates = 1
			} else if candidates > 1 {
				// P5 CHA: multiple dispatch targets. If they all name the
				// same function it is still monomorphic; otherwise it is a
				// candidate set, recorded as such.
				uniqueNames := map[string]bool{}
				var unique []string
				for _, n := range allCandidates {
					if !uniqueNames[n] {
						uniqueNames[n] = true
						unique = append(unique, n)
					}
				}
				sort.Strings(unique)
				applySelectorCandidates(&res, unique)
			}
		}
	case LatticeTop, LatticeBottom:
		// No usable type for the call register -- fall back to the selector
		// immediate the pre-scan recorded for this exact BLR.
		//
		// Bottom must be handled here too, and it is the COMMON case on Dart
		// 2.x. The sequence there is
		//
		//	LDURH W2, [X0,#1]        ; class id (kClassIdTagPos=16)
		//	MOV   X0, X2
		//	SUB   X0, X0, #imm       ; in-place, per 2.x EmitDispatchTableCall
		//	LDR   X30, [X21,X0,LSL #3]
		//	BLR   X30
		//
		// The LDR from the dispatch-table register sets X30 to Bottom
		// ("a dispatch entry, slot unknown"), so the register is Bottom, not
		// Top, and this fallback never ran: 3738 dispatch-table call sites in
		// the 2.12 sample, 129 resolved. Bottom here is strictly MORE
		// evidence than Top -- it says the value came from the dispatch table
		// -- so refusing to use the selector was backwards.
		if selectorImm, ok := ctx.SelectorOffsets[inst.Addr]; ok {
			// Scan every class's slot at this selector immediate; see
			// selectorCandidates for the index arithmetic and its SDK source.
			applySelectorCandidates(&res, ctx.selectorCandidates(selectorImm))
		}
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
//
// TODO(BUG-HUNT): the mask 0xFFE00C00 does NOT cover the option (bits 23-22)
// and S (bit 12) fields of the LDR (register) encoding. This is an
// intentional trade-off: the subsequent dispatch-detection checks constrain
// the result enough to limit false positives, and tightening the mask to
// also verify option==011 (LSL) and S==0 could break the existing dispatch
// table detection. Verifying option/S here is left as future work.
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

// isLDURH detects LDURH Wt, [Xn, #imm9] (16-bit unscaled load).
// Used in Dart 2.x for class ID extraction:
//
//	LDURH Wt, [Xobj, #1] = load 2 bytes at obj+1+1 = obj+2 = class ID field
//
// (kClassIdTagPos=16, kClassIdTagSize=16 in 2.x; vs 12/20 in 3.x)
// Encoding: 01 111 000 01 0 imm9 00 Rn Rt (size=01, V=0, opc=01)
// Base: 0x78400000, Mask: 0xFFE00C00
func isLDURH(raw uint32) (base, rt int, imm9 int, ok bool) {
	if raw&0xFFE00C00 != 0x78400000 {
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
	_ = rt                 // rt is always valid (0-30 are real registers, 31 is WZR which we don't track but still valid)
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
	// shift==0: no shift; shift==1: LSL #12. shift==2,3 are RESERVED in
	// the ADD (immediate) encoding -- treat them as unknown (immValue=0)
	// rather than silently applying the unshifted value, which would
	// misinterpret a reserved encoding as a real immediate.
	if shift == 1 {
		immValue = imm12 << 12
	} else if shift == 0 {
		immValue = imm12
	} else {
		// Reserved shift (2 or 3): leave immValue at its zero value.
		immValue = 0
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
	// shift==0: no shift; shift==1: LSL #12. shift==2,3 are RESERVED in
	// the SUB (immediate) encoding -- treat them as unknown (immValue=0)
	// rather than silently applying the unshifted value.
	if shift == 1 {
		immValue = imm12 << 12
	} else if shift == 0 {
		immValue = imm12
	} else {
		// Reserved shift (2 or 3): leave immValue at its zero value.
		immValue = 0
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
	// ORR Xd, XZR, Xm: 0xAA000000 with Rn=31.
	// Mask 0xFF200000 covers sf+opcode+Rm+fixed bits, NOT Rd (bits 0-4) so
	// any destination register matches. The previous mask 0xFF20001F
	// included Rd, so only Rd==0 (MOV X0) ever matched.
	if raw&0xFF200000 == 0xAA000000 {
		// Rn field is bits 5-9. For MOV, Rn = XZR = 31.
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

// recordFieldStore records a field store for whole-program field-store → field-load tracking.
//
// Unanimity is required, matching InstanceFieldTypes' rule: if two stores
// to the same (receiverCID, byteOffset) pair record different value classes,
// the entry is dropped (set to -1 sentinel) rather than keeping the first
// one. A wrong concrete type is worse than no type, because callers treat
// KnownClass as authoritative (see InstanceFieldTypes' doc comment).
func recordFieldStore(ctx *TypeContext, receiverCID int, byteOffset int32, valueCID int) {
	if ctx.FieldStoreTypes == nil {
		return
	}
	lookupOff := byteOffset + 1
	m, ok := ctx.FieldStoreTypes[receiverCID]
	if !ok {
		m = make(map[int32]int)
		ctx.FieldStoreTypes[receiverCID] = m
	}
	existing, exists := m[lookupOff]
	if !exists {
		m[lookupOff] = valueCID
		return
	}
	// Already recorded: check for conflict.
	if existing != valueCID && existing != -1 {
		// Conflict: drop the entry. -1 sentinel means "conflicting, do not use".
		m[lookupOff] = -1
	}
}

// recordAllocationSite records an allocation site for allocation site tracking.
func recordAllocationSite(ctx *TypeContext, callPC uint64, classID int) {
	if ctx.AllocationSites == nil {
		return
	}
	ctx.AllocationSites[callPC] = classID
	if ctx.InstantiatedClasses != nil {
		ctx.InstantiatedClasses[classID] = true
	}
}

// isSUBS32Immediate detects SUBS Wd, Wn, #imm (32-bit, sets flags).
// CMP Wn, #imm is an alias for SUBS WZR, Wn, #imm (Wd = W31 = WZR).
// Encoding: sf=0 | 1 | 1 | 100010 | sh | imm12 | Rn | Rd
// Mask: 0xFF000000 (top 8 bits), Value: 0x71000000 (32-bit SUBS immediate)
// Returns dest, source, and immediate value (with shift applied).
func isSUBS32Immediate(raw uint32) (rd, rn int, immValue int, ok bool) {
	if raw&0xFF000000 != 0x71000000 {
		return 0, 0, 0, false
	}
	rd = int(raw & 0x1F)
	rn = int((raw >> 5) & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	shift := int((raw >> 22) & 0x3)
	if shift == 1 {
		immValue = imm12 << 12
	} else if shift == 0 {
		immValue = imm12
	} else {
		immValue = 0 // reserved
	}
	return rd, rn, immValue, true
}
