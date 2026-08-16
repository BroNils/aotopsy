package typetrack

import (
	"sort"

	"aotopsy/internal/arch"
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

	// Pattern 2.x C: MOV Xn, #imm → ADD Xd, Xm, Xn → LDR X30, [X21, Xd, LSL #3] → BLR X30
	// The 2.x compiler sometimes loads the selector offset into a register
	// via MOVZ, then uses register-register ADD instead of ADD with immediate.
	// This pattern is NOT caught by the ADD/SUB #imm scan above.
	for i := 0; i < len(insts)-3; i++ {
		// Look for MOVZ Xn, #imm16
		movReg, movImm, movOK := isMOVZ64(insts[i].Raw)
		if !movOK || movReg >= 31 {
			continue
		}
		// Next: ADD Xd, Xm, Xn (register-register, rm == movReg)
		if i+1 >= len(insts) {
			continue
		}
		addRd, _, addRm, addOK := isADD64Register(insts[i+1].Raw)
		if !addOK || addRm != movReg || addRd >= 31 {
			continue
		}
		// Next: LDR X30, [X21, Xd, LSL #3]
		if i+2 >= len(insts) {
			continue
		}
		base, rm, rt, ldrOK := isLDRRegExtended(insts[i+2].Raw)
		if !ldrOK || base != 21 || rt != 30 || rm != addRd {
			continue
		}
		// Next: BLR X30
		if i+3 >= len(insts) {
			continue
		}
		if blrReg, ok := isBLR(insts[i+3].Raw); ok && blrReg == 30 {
			ctx.SelectorOffsets[insts[i+3].Addr] = movImm
		}
	}

	// Pattern 2.x D: LDURH Wn, [Xm,#1] → ... → LDR X30, [X21, Xp, LSL #3] → BLR X30
	// When selector_offset == kOriginElement, the ADD/SUB is a no-op (offset=0)
	// and the compiler omits it entirely. The class ID from LDURH goes directly
	// into the dispatch table LDR without any arithmetic. selectorOffset = 0.
	// There may be intervening instructions (PP loads, STP pushes, MOV) between
	// the LDURH and the LDR. The MOV bridges the register: LDURH writes Wn,
	// MOV Xp, Xn copies it, LDR uses Xp.
	for i := 0; i < len(insts)-2; i++ {
		// Look for LDURH Wn, [Xm,#1] (class ID extraction, 2.x style)
		_, ldurhRt, ldurhImm9, ldurhOK := isLDURH(insts[i].Raw)
		if !ldurhOK || ldurhImm9 != 1 || ldurhRt >= 31 {
			continue
		}
		// Track which register holds the class ID. LDURH writes to ldurhRt,
		// but a MOV Xp, Xn may bridge it to a different register before the LDR.
		classIdReg := ldurhRt
		// Scan forward up to 5 instructions for MOV bridge then LDR.
		for j := i + 1; j < len(insts)-1 && j <= i+5; j++ {
			jraw := insts[j].Raw
			// Check for MOV Xp, Xn (ORR Xd, XZR, Xm) that bridges the class ID.
			if movRd, movOK := isMOVOrr(jraw); movOK && movRd < 31 {
				movRm := int((jraw >> 16) & 0x1F)
				if movRm == classIdReg {
					classIdReg = movRd
					continue
				}
			}
			// Check for LDR X30, [X21, XclassIdReg, LSL #3]
			base, rm, rt, ldrOK := isLDRRegExtended(jraw)
			if !ldrOK || base != 21 || rt != 30 || rm != classIdReg {
				continue
			}
			// Next: BLR X30
			if j+1 < len(insts) {
				if blrReg, ok := isBLR(insts[j+1].Raw); ok && blrReg == 30 {
					ctx.SelectorOffsets[insts[j+1].Addr] = 0
				}
			}
			break
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
		return arch.SuccUnknown
	}
	// Only B.cond reads the flags a CMP set. CBZ/CBNZ and TBZ/TBNZ test a
	// register or a single bit directly, so a preceding CMP says nothing
	// about which way they go.
	if last&0xFF000010 != 0x54000000 {
		return arch.SuccUnknown
	}
	// Same successor convention as arch.X86EqualitySuccessor. The two
	// functions are deliberately NOT merged -- one decodes a raw 32-bit
	// B.cond word, the other switches on an x86asm.Op, and a single
	// function taking both would be a union of unrelated inputs. Only the
	// convention is shared, because that is the part that can be got
	// backwards without anything failing loudly.
	switch last & 0xF {
	case 0: // EQ: the taken edge is the equal one.
		return arch.SuccEqual
	case 1: // NE: the taken edge proves inequality; the fall-through proves equality.
		return arch.SuccNotEqual
	}
	return arch.SuccUnknown
}

// buildBlocks constructs basic blocks from an instruction list.
//
// NOT merged with buildBlocksX86 despite sharing the same algorithm
// (leader detection → partition → successor edges). The two differ in:
//   - Instruction type: disasm.Inst (fixed 4-byte, .Raw uint32) vs
//     X86DecodedInst (variable-length, .Inst x86asm.Inst)
//   - Branch classification: ARM64 raw-encoding pattern matching
//     (isBL/isBLR/isB/isCondBranch) vs x86 opcode switch
//     (x86asm.RET/JMP/IsX86CondJump)
//   - Partition approach: incremental (iterate, check leader map) vs
//     sorted-index (sort leader indices, slice between them)
//
// A generic version would need type parameters for instruction + block
// types plus a branch-classifier callback — more abstraction overhead
// than the ~30 lines of shared partition logic it would save.
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
	tc := transferCtx{
		state:      state,
		inst:       inst,
		prevRaw:    prevRaw,
		ctx:        ctx,
		result:     result,
		lca:        lca,
		stackTypes: stackTypes,
	}

	// Handlers run in the same order as the original if-chain.
	// Stack stores don't kill source registers, so they return false to
	// let subsequent handlers run (except STR [X29] which returns true).
	if handleStackStore(&tc) {
		return
	}
	if handleStackLoad(&tc) {
		return
	}
	if handleTHRLoad(&tc) {
		return
	}
	if handlePPLoad(&tc) {
		return
	}
	if handleDispatchTableLoad(&tc) {
		return
	}
	if handleDispatchArith(&tc) {
		return
	}
	if handleFieldLoad(&tc) {
		return
	}
	if handleUBFX(&tc) {
		return
	}
	if handleMOV(&tc) {
		return
	}
	if handleBLR(&tc) {
		return
	}
	if handleBL(&tc) {
		return
	}

	// 9. Default: if this instruction defines a register, kill its type.
	if rd := dstRegOfInst(inst.Raw); rd >= 0 && rd < 31 {
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
		if t.SelectorOnly {
			ctx.BLRAtKnownDispatchSel++
		} else {
			ctx.BLRAtKnownDispatch++
		}
	case LatticeKnownClass:
		ctx.BLRAtKnownClass++
	case LatticeKnownStub:
		ctx.BLRAtStub++
	case LatticeTop:
		ctx.BLRAtTop++
	case LatticeBottom:
		ctx.BLRAtBottom++
	default:
		ctx.BLRAtOther++
	}
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
		baseSlot := t.ClassID - ctx.KOriginElement
		candidates, candidateName, allCandidates := scanDispatchSlots(ctx, baseSlot)
		if candidates == 1 {
			res.SlotIndex = -1
		}
		applyDispatchCandidates(&res, candidates, candidateName, allCandidates)
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
