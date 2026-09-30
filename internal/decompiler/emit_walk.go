package decompiler

import (
	"fmt"
	"sort"
	"strings"

	"aotopsy/internal/sdk"
)

func identifyLoopHeaders(fir *FuncIR, idom []int) map[int]bool {
	headers := make(map[int]bool)
	for i := range fir.Blocks {
		blk := &fir.Blocks[i]
		for _, s := range blk.Succs {
			if s.BlockID < 0 || s.BlockID >= len(fir.Blocks) {
				continue
			}
			// A back edge is an edge into a block that DOMINATES its own
			// source: every path from the entry to i already passed through
			// s.BlockID, so following this edge re-enters it. See dom.go for
			// why the previous address-order test (target.StartVA <=
			// blk.StartVA) was not this, and what it swept in.
			if dominates(idom, s.BlockID, i) {
				headers[s.BlockID] = true
			}
		}
	}
	return headers
}

// emitOrphanBlocks emits every block the structured walk left out, in
// address order, after the main body.
//
// Two different things end up here, and they are not the same size:
//
//   - Blocks genuinely unreachable from the entry in the lifted CFG.
//     Measured over 1200 functions per sample: 2.0% of ARM64 blocks (5%
//     of functions) against 7.4% of x86_64 blocks (68% of functions),
//     most of them following an unconditional jump nothing else targets.
//   - Blocks that ARE reachable but that the walk declined to emit
//     because a path hit maxDepth or maxVisitCount. These are the larger
//     group. The walk left a `goto block_N;` behind, and dropUnusedLabels
//     then rewrote it to a comment because block_N was never emitted.
//
// Either way the instructions were in the binary and absent from the
// decompilation, with no output saying so -- the only trace was a CFG
// coverage number nothing printed. For a tool whose job is to show what a
// stripped binary contains, silently dropping code is the worst failure
// mode available, and unreachable code is frequently the exact thing an
// analyst is hunting for.
//
// Each orphan is walked with the ordinary emitBlock, so its own reachable
// successors come with it and the shared step budget still applies.
func (e *emitter) emitOrphanBlocks(indent int) {
	orphans := make([]int, 0)
	for i := range e.fir.Blocks {
		if e.visits[i] != 0 || len(e.fir.Blocks[i].Instrs) == 0 {
			continue
		}
		// Handler blocks never increment visits -- emitBlock returns
		// early for them because they were already emitted inside their
		// catch clause. They are in the output; re-emitting them here
		// would duplicate every catch body.
		if e.handlerBlocks != nil && e.handlerBlocks[i] {
			continue
		}
		// Blocks extracted to a `_block_N()` helper also never increment
		// visits in this emitter, but appendHelperFunctions emits their
		// body. Emitting them here too would print each one twice.
		if e.omittedSet != nil && e.omittedSet[i] {
			continue
		}
		orphans = append(orphans, i)
	}
	if len(orphans) == 0 {
		return
	}
	sort.Slice(orphans, func(a, b int) bool {
		return e.fir.Blocks[orphans[a]].StartVA < e.fir.Blocks[orphans[b]].StartVA
	})
	emitted := 0
	for _, id := range orphans {
		// An earlier orphan's walk may already have covered this one.
		if e.visits[id] != 0 {
			continue
		}
		if emitted == 0 {
			e.emit(indent, "// --- code omitted by the structured walk, shown verbatim ---")
		}
		emitted++
		if e.orphanBlocks == nil {
			e.orphanBlocks = make(map[int]bool)
		}
		e.orphanBlocks[id] = true
		e.emit(indent, "// orphan block %d @ 0x%x", id, e.fir.Blocks[id].StartVA)
		// A genuinely unreached block has no path state from the main walk. Do
		// not let it inherit a temporary, comparison, receiver class, or entry
		// argument merely because it is emitted afterwards. Keep only VM-pinned
		// register meanings and let the block/fixpoint establish everything else.
		savedState := e.state
		e.state = seedPinnedState(e.fir)
		e.state.Pool = e.pool
		e.state.AttachSpillSink(e.spillSeq)
		e.emitBlock(id, indent, 0)
		e.state = savedState
	}
	if emitted > 0 {
		e.stats.OrphanBlocks += emitted
	}
}

// emitBlock is the recursive CFG walker: flutterdec's emit_block, ported
// with the same depth-limit/visit-count/cycle-detection anti-explosion
// guards (simplified to a single flat visit budget rather than the Rust
// version's 3-tier 14/24/48 budget-by-block-shape scheme).
func (e *emitter) emitBlock(id, indent, depth int) {
	e.steps++
	if e.steps > maxStepsPerEmitter() {
		if !e.budgetHit {
			e.budgetHit = true
			e.emit(indent, "// analysis budget exceeded, remaining control flow omitted")
			e.stats.UnresolvedCF++
		}
		return
	}
	// Skip handler blocks at their natural CFG position — they were already
	// emitted inside the catch clause. This avoids showing the same code twice.
	if e.handlerBlocks != nil && e.handlerBlocks[id] {
		return
	}
	if depth >= maxDepth || e.active[id] || e.visits[id] >= maxVisitCount || id < 0 || id >= len(e.fir.Blocks) {
		e.emitOmittedPath(id, indent)
		return
	}

	// Fase 7 TASK 2: loop header while(true) wrapping is handled in
	// emitSuccessor, not here, to ensure the wrapper is emitted at the
	// point where the loop is entered (not where the header block is
	// first reached during CFG walk).

	e.active[id] = true
	e.visits[id]++
	prevBlock := e.currentBlock
	e.currentBlock = id
	defer delete(e.active, id)
	defer func() { e.currentBlock = prevBlock }()

	// Real try/catch structuring.
	//
	// The brace pair is opened and closed inside THIS invocation, so it is
	// balanced by construction no matter how the recursion below unfolds --
	// which is what makes this safe in an emitter that walks control flow
	// rather than address order, re-emits blocks, and omits paths. Nesting is
	// guarded by curTryRegion so a region does not re-open inside itself.
	if ri, ok := e.blockTryRegion[id]; ok && e.curTryRegion != ri+1 {
		r := e.fir.TryRegions[ri]
		// Structure the region ONCE per function. The CFG walk reaches a region
		// from many recursion paths, and opening a real try on each produced 162
		// try blocks for a single 32-block region in _Timer._runTimers (416
		// across a 900-function sweep, for 27 regions). Later entries get a
		// marker instead: the structure is stated once where it reads best, and
		// subsequent protected code is still identified.
		if e.tryOpened == nil {
			e.tryOpened = make(map[int]bool)
		}
		if e.tryOpened[ri] {
			// Once per BLOCK, not per visit: the walk re-emits blocks, and an
			// undeduplicated marker reached 9194 lines for 27 regions.
			if e.tryMarked == nil {
				e.tryMarked = make(map[int]bool)
			}
			if !e.tryMarked[id] {
				e.tryMarked[id] = true
				e.emit(indent, "// [still in try #%d -> %s at 0x%x]", r.TryIndex, r.CatchClause(), r.HandlerVA)
			}
			e.emitBlockBody(id, indent, depth)
			return
		}
		e.tryOpened[ri] = true
		e.emit(indent, "try {")
		prevRegion := e.curTryRegion
		e.curTryRegion = ri + 1 // +1 so zero means "no region"
		e.emitBlockBody(id, indent+1, depth)
		e.curTryRegion = prevRegion
		e.emit(indent, "} %s {", r.CatchClause())
		// Emit the handler's own code in the catch body. The handler block
		// is recorded in handlerBlocks so it is not repeated at its natural
		// CFG position below.
		if hid, ok := e.fir.BlockByVA(r.HandlerVA); ok {
			e.emitBlock(hid, indent+1, depth+1)
			// Mark AFTER emitting so the guard in emitBlock doesn't suppress
			// the catch-side emission. The natural-position walk will then
			// skip it.
			if e.handlerBlocks != nil {
				e.handlerBlocks[hid] = true
			}
		} else {
			e.emit(indent+1, "// handler at 0x%x (block not recovered)", r.HandlerVA)
		}
		e.emit(indent, "}")
		return
	}

	e.emitBlockBody(id, indent, depth)
}

// emitBlockBody emits one block's instructions and follows its fallthrough
// successor. Split out of emitBlock so the try/catch wrapper there can emit the
// same body at a deeper indent without re-running emitBlock's recursion guards
// (which have already fired for this block).
func (e *emitter) emitBlockBody(id, indent, depth int) {
	blk := &e.fir.Blocks[id]
	// A3: Emit a label for every block, then drop the unreferenced ones in a
	// post-pass (dropUnusedLabels). Deciding here from Preds alone was wrong:
	// a single-predecessor block still gets `goto block_N;` when it was
	// already visited, and the label it needed was never emitted -- a
	// dangling goto.
	e.emit(indent, "block_%d:;", id)
	if e.emittedAnywhere != nil {
		e.emittedAnywhere[id] = true
	}
	e.annotateInlineFrames(blk.StartVA, indent)
	// Reaching-definition fixpoint: fill live-in registers the recursive walk
	// left unknown but a value-flow fixpoint proves consistent (see ssa.go).
	e.seedFromFixpoint(id)
	for i, ins := range blk.Instrs {
		isLast := i == len(blk.Instrs)-1
		// RegClass invariant: drop the tracked class of any register this
		// instruction overwrites BEFORE lifting it, so a stale type can never
		// survive a redefinition (see LiftState.RegClass).
		e.state.clearWrittenRegClasses(ins)
		switch ins.Op {
		case OpCall:
			e.emitCall(ins, indent)
		case OpLoadPool:
			e.emitLoadPool(ins)
		case OpReturn:
			// P3-feasible-3: Emit bare "return;" if the return register
			// holds a void-call result or is empty/uninitialized.
			retVal := ""
			if full, ok := e.state.Regs[canonReg(e.fir.ReturnReg)]; ok {
				retVal = readRegView(e.fir.ReturnReg, full)
			}
			if retVal = e.returnValue(retVal); retVal == "" {
				e.emit(indent, "return;")
			} else {
				e.emit(indent, "return %s;", retVal)
			}
		case OpBranch:
			if isLast {
				e.emitBranch(blk, ins, indent, depth)
			} else {
				// A3: Non-last branch — emit real if/else when possible.
				// If the taken successor has only this block as predecessor,
				// inline its body. Otherwise fall back to goto.
				cond, ok := e.buildCondition(ins)
				if !ok {
					cond = "/* cond */"
				}
				if sdk.IsStackOverflowCond(cond) || sdk.IsWriteBarrierCond(cond) {
					continue
				}
				var takenID = -1
				var fallID = -1
				for _, s := range blk.Succs {
					if s.Cond == "T" {
						takenID = s.BlockID
					} else if s.Cond == "F" || s.Cond == "" {
						fallID = s.BlockID
					}
				}
				// Check if taken successor can be inlined (only 1 pred = this block, not yet visited)
				canInlineTaken := takenID >= 0 && takenID < len(e.fir.Blocks) &&
					len(e.fir.Blocks[takenID].Preds) == 1 && e.visits[takenID] == 0
				canInlineFall := fallID >= 0 && fallID < len(e.fir.Blocks) &&
					len(e.fir.Blocks[fallID].Preds) == 1 && e.visits[fallID] == 0

				if canInlineTaken && canInlineFall {
					// Both branches can be inlined — emit real if/else
					e.emit(indent, "if (%s) {", cond)
					e.emitBlockBody(takenID, indent+1, depth+1)
					e.visits[takenID]++
					e.emit(indent, "} else {")
					e.emitBlockBody(fallID, indent+1, depth+1)
					e.visits[fallID]++
					e.emit(indent, "}")
				} else if canInlineTaken {
					// Only taken branch can be inlined
					e.emit(indent, "if (%s) {", cond)
					e.emitBlockBody(takenID, indent+1, depth+1)
					e.visits[takenID]++
					e.emit(indent, "}")
					if fallID >= 0 {
						e.emit(indent, "goto block_%d;", fallID)
					}
				} else if takenID >= 0 {
					// Fall back to goto
					e.emit(indent, "if (%s) { goto block_%d; }", cond, takenID)
				} else {
					e.emit(indent, "// non-last branch (cond=%s %s)", ins.CondKind, ins.CondOp)
				}
				e.stats.NonLastBranch++
			}
		case OpJump:
			if isLast {
				e.emitJump(blk, ins, indent, depth)
			} else {
				// Non-last jump: emit a real goto. Targets are block IDs --
				// the VA must be mapped through BlockByVA first. Emitting
				// `goto block_<hex VA>;` (as this did) named a label that
				// never exists, since labels are `block_<block ID>`.
				if va, okVA := parseHexVA(ins.Target); okVA {
					if bid, okB := e.fir.BlockByVA(va); okB {
						e.emit(indent, "goto block_%d;", bid)
					} else {
						e.emit(indent, "// non-last jump to %s (no block at that VA)", ins.Target)
					}
				} else if len(blk.Succs) > 0 {
					e.emit(indent, "goto block_%d;", blk.Succs[0].BlockID)
				} else {
					e.emit(indent, "// non-last jump to %s", ins.Target)
				}
				e.stats.NonLastBranch++
			}
		default:
			line, ok := ApplyOther(e.fir, e.state, ins)
			// Declarations first: `line` may read a name that was just spilled.
			e.drainSpills(indent)
			if ok && !sdk.IsWriteBarrierStmt(line) {
				e.emit(indent, "%s", line)
			}
		}
		// Catches the paths that set registers without returning a line of
		// their own (pool loads, call results).
		e.drainSpills(indent)
		// SSA phi: if this instruction redefined a loop-carried (pinned)
		// register, emit its update as an explicit assignment to the induction
		// local and re-pin, so the loop body carries the value across iterations.
		e.updatePinnedPhis(indent)
	}

	// Fallthrough / unconditional-jump successor for blocks whose last
	// instruction wasn't itself a control-flow op (e.g. ends mid-block
	// due to a leader boundary from an incoming branch target).
	if len(blk.Instrs) == 0 || !isControlFlowOp(blk.Instrs[len(blk.Instrs)-1].Op) {
		for _, s := range blk.Succs {
			if s.Cond == "" {
				e.emitSuccessor(s.BlockID, indent, depth)
				return
			}
		}
	}
}

// emitSuccessor dispatches control to a successor block: inline it if the
// recursion budget allows, emit a bare "continue;" if it is a genuine loop
// back-edge (the target is still on the active recursion stack -- same
// convention as emitJump's pre-existing back-edge handling below), or fall
// back to helper-function extraction otherwise. Using "continue;" instead
// of extracting a fresh-state "_block_N()" helper for back-edges is the
// fix for a real bug found comparing decompiled output against known Dart
// source (StringTools.countVowels): loop-carried register state (e.g. the
// loop counter/accumulator) was silently reset to empty because the loop
// body got rendered as a separate helper function with a brand-new
// LiftState instead of continuing inline with the live one. This only
// covers back-edges reached via a conditional branch or fallthrough/jump
// successor dispatch (emitBranch/emitBlock); emitJump had its own
// equivalent special case already.
func (e *emitter) emitSuccessor(id, indent, depth int) {
	if id < 0 || id >= len(e.fir.Blocks) {
		e.emit(indent, "// unresolved branch target")
		e.stats.UnresolvedCF++
		return
	}
	if e.currentBlock >= 0 && id < len(e.fir.Blocks) {
		if e.emittedEdges == nil {
			e.emittedEdges = make(map[uint64]bool)
		}
		key := uint64(uint32(e.currentBlock))<<32 | uint64(uint32(id))
		e.emittedEdges[key] = true
	}
	// A source-level try may only contain blocks whose full extents were proven
	// protected by buildBlockTryIndex. Do not let the recursive CFG walk inline a
	// successor outside the currently open region before the try brace closes.
	if e.curTryRegion != 0 {
		want := e.curTryRegion - 1
		if got, ok := e.blockTryRegion[id]; !ok || got != want {
			e.emit(indent, "goto block_%d;", id)
			return
		}
	}
	if e.active[id] {
		// Back-edge: emit continue; (inside while loop if loop header was emitted)
		e.emit(indent, "continue;")
		return
	}
	// A4: While-loop pattern recovery. If target is a loop header and not
	// yet visited, try to extract the loop condition from the header's
	// branch instruction. Emit `while (cond) { ... }` instead of
	// `while (true) { ... }` when the condition can be recovered.
	isLoopHeader := e.loopHeaders[id]
	if isLoopHeader && e.visits[id] == 0 {
		// SSA phi materialization: declare an induction local for each
		// loop-carried register just before the loop, initialized to its
		// entry value, and pin the register to that local so its header read
		// resolves to a name and its in-loop updates emit explicitly.
		e.declareLoopPhis(id, indent)
		// A4: Try while-loop condition (for-loop is a post-emit pass). A recovered
		// condition that is really a runtime stack-overflow or write-barrier check
		// (a back-edge safepoint the loop detector latched onto) is not a source
		// loop condition -- fall back to while(true) rather than printing the
		// compiler bookkeeping as the loop guard.
		loopCond := e.extractLoopCondition(id)
		if loopCond != "" && (sdk.IsStackOverflowCond(loopCond) || sdk.IsWriteBarrierCond(loopCond)) {
			loopCond = ""
		}
		if loopCond != "" {
			e.emit(indent, "while (%s) {", loopCond)
		} else {
			e.emit(indent, "while (true) {")
		}
		if e.canInline(id, depth) {
			e.emitBlock(id, indent+1, depth+1)
			e.emit(indent, "}")
			return
		}
		e.emitOmittedPath(id, indent+1)
		e.emit(indent, "}")
		return
	}
	// A join point that has already been emitted is referenced, not
	// emitted again.
	//
	// Without this the walk re-INLINES it, and with it the whole subtree
	// below it, once per reaching path up to maxVisitCount. That is
	// combinatorial, and it dominated the output: ten functions out of a
	// thousand produced 45% of all emitted lines, at 45x-83x LINES PER
	// MACHINE INSTRUCTION (_StringBase._createStringFromIterable: 331
	// instructions -> 27,563 lines). Nothing was wrong with any single
	// line; there were simply tens of thousands of them, which for a tool
	// whose job is to make a stripped binary readable is its own kind of
	// failure. The `analysis budget exceeded` backstop never fired
	// (measured budgetHit=0), so none of this was even caught as runaway.
	//
	// Blocks with ONE predecessor are still inlined: that is a tree edge,
	// inlining it is what makes the output read like source rather than
	// like a basic-block dump, and it cannot multiply. Only a real join --
	// two or more predecessors, already emitted once -- becomes a goto.
	// The label is emitted for every block in emitBlockBody and pruned
	// later by dropUnusedLabels, so referencing one is always safe here:
	// visits>0 means the block, and therefore its label, is in the output.
	if e.emittedAnywhere[id] && len(e.fir.Blocks[id].Preds) > 1 {
		e.emit(indent, "goto block_%d;", id)
		return
	}
	if e.canInline(id, depth) {
		e.emitBlock(id, indent, depth+1)
		return
	}
	e.emitOmittedPath(id, indent)
}

func isControlFlowOp(op Op) bool {
	return op == OpBranch || op == OpJump || op == OpReturn
}

func (e *emitter) canInline(id, depth int) bool {
	return depth < maxDepth && !e.active[id] && e.visits[id] < maxVisitCount && id >= 0 && id < len(e.fir.Blocks)
}

func (e *emitter) emitOmittedPath(id, indent int) {
	if id < 0 || id >= len(e.fir.Blocks) {
		e.emit(indent, "// unresolved branch target")
		e.stats.UnresolvedCF++
		return
	}
	if !e.omittedSet[id] && len(e.omitted) >= maxHelpers {
		e.emit(indent, "// unresolved block_%d: helper budget exhausted", id)
		e.stats.UnresolvedCF++
		return
	}
	if !e.omittedSet[id] {
		e.omittedSet[id] = true
		e.omitted = append(e.omitted, id)
		// Capture live register state at extraction point for helper.
		if e.omittedStates == nil {
			e.omittedStates = map[int]*LiftState{}
		}
		e.omittedStates[id] = e.state.Clone()
	}
	e.emit(indent, "return _block_%d();", id)
}

// emitBranch resolves the branch condition against live LiftState and
// emits "if (cond) { <taken> } else { <fallthrough> }" (or a placeholder
// if the condition can't be resolved -- e.g. no preceding cmp was seen).
//
// After both branches complete, MergeJoin keeps a register only when BOTH
// paths prove the same value. A write on just one branch, or two different
// writes, is a phi/disagreement and is dropped to unknown rather than choosing
// one path or resurrecting the pre-branch value. Loop-carried phis are handled
// separately by the bounded SSA pass.
func (e *emitter) emitBranch(blk *Block, ins Instr, indent, depth int) {
	cond, ok := e.buildCondition(ins)
	var takenID, fallID = -1, -1
	for _, s := range blk.Succs {
		switch s.Cond {
		case "T":
			takenID = s.BlockID
		case "F":
			fallID = s.BlockID
		}
	}
	if !ok {
		e.stats.PlaceholderIfs++
		cond = "/* cond */"
	}

	// D1: Stack overflow check elision.
	// In Dart AOT, functions check stack limit at entry or in loops:
	// "cmp SP, THR.stack_limit; b.ls <runtime_stub>".
	// The slow path calls the runtime and exits/retries; the fallthrough
	// is the normal body. Modeling this as 2-way if/else duplicates the entire body.
	// We elide the check and continue directly into the normal function body.
	if sdk.IsStackOverflowCond(cond) {
		normalID := fallID
		if strings.Contains(cond, ">") || strings.Contains(cond, "!=") {
			normalID = takenID
		}
		if normalID < 0 {
			normalID = fallID
			if normalID < 0 {
				normalID = takenID
			}
		}
		if normalID >= 0 {
			e.emitSuccessor(normalID, indent, depth)
			return
		}
	}

	// Generational write-barrier check elision (see isWriteBarrierCond). The
	// ZERO/EQ edge skips the barrier stub -- that is the normal continuation, and
	// the store the check guards was already emitted, so follow it and drop the
	// stub-call path entirely.
	if sdk.IsWriteBarrierCond(cond) {
		normalID := takenID // b(&done, ZERO): the taken (== 0) edge skips the stub
		if normalID < 0 {
			normalID = fallID
		}
		if normalID >= 0 {
			e.emitSuccessor(normalID, indent, depth)
			return
		}
	}

	savedState := e.state

	e.emit(indent, "if (%s) {", cond)
	takenState := e.state.Clone()
	e.state = takenState
	e.emitSuccessor(takenID, indent+1, depth)
	e.emit(indent, "} else {")
	fallState := savedState.Clone()
	e.state = fallState
	e.emitSuccessor(fallID, indent+1, depth)
	// Item 7: Merge branch states instead of restoring pre-branch state.
	e.state = savedState.MergeJoin(takenState, fallState)
	e.emit(indent, "}")
}

// isStackOverflowCond and isWriteBarrierCond/Stmt are now in internal/sdk —
// shared with disasm, typetrack, and signal. The SDK ground-truth comments
// moved with them.

func (e *emitter) buildCondition(ins Instr) (string, bool) {
	switch ins.CondKind {
	case "cmp":
		return rememberedCmpCondition(e.state, ins.CondOp, ins.CondUnsigned)
	case "eqz":
		return e.state.lookupReg(ins.CondReg) + " == 0", true
	case "nez":
		return e.state.lookupReg(ins.CondReg) + " != 0", true
	case "bittest0":
		return fmt.Sprintf("((%s >> %d) & 1) == 0", e.state.lookupReg(ins.CondReg), ins.CondBit), true
	case "bittest1":
		return fmt.Sprintf("((%s >> %d) & 1) != 0", e.state.lookupReg(ins.CondReg), ins.CondBit), true
	}
	return "", false
}

// emitJump resolves an unconditional direct jump to a known block
// (recurse/inline, or record a loop back-edge via "continue;" if the
// target is already on the active recursion stack) or, for an indirect
// jump / unresolved external target, emits a tail-call placeholder.
func (e *emitter) emitJump(blk *Block, ins Instr, indent, depth int) {
	var targetID = -1
	for _, s := range blk.Succs {
		targetID = s.BlockID
	}
	if targetID >= 0 {
		e.emitSuccessor(targetID, indent, depth)
		return
	}
	// P6: Indirect branch (br xN) — jump-table dispatch or tail call.
	// When SwitchCases is populated, emit real `switch` syntax with case
	// targets. Otherwise emit a dispatch comment.
	if ins.Target != "" && !strings.HasPrefix(ins.Target, "0x") {
		if len(e.fir.SwitchCases) > 0 {
			// Case bodies go through emitBlock, like every other
			// recursion site.
			//
			// This called emitBlockBody directly, which bypasses ALL of
			// emitBlock's guards at once: the depth limit, the active-set
			// cycle detection, the visit cap, the id bounds check and the
			// step budget. A jump table whose cases lead back into the
			// dispatch then recursed without any bound. It cost six of the
			// project's 93 corpus samples -- Dart 2.14.0, 2.15.0 and
			// 2.16.0 on ARM64, every variant of each -- which died with
			// `fatal error: out of memory` at depth ~5,400 and an indent
			// of ~10,800 columns. The same three versions on x86_64, and
			// 2.13.0/2.17.6 on ARM64, were unaffected, which is what makes
			// it look like a version quirk rather than what it is.
			//
			// The stated reason for the bypass -- "so the emitter does NOT
			// follow fallthrough into the next case" -- did not hold
			// either: emitBlockBody follows the fallthrough successor at
			// its end just as emitBlock does.
			e.emit(indent, "switch (%s) {", ins.Target)
			for _, sc := range e.fir.SwitchCases {
				e.emit(indent+1, "case %d:", sc.Index)
				if sc.BlockID >= 0 && sc.BlockID < len(e.fir.Blocks) {
					e.emitBlock(sc.BlockID, indent+2, depth+1)
				} else {
					e.emit(indent+2, "// case target block %d not recovered", sc.BlockID)
				}
				e.emit(indent+2, "break;")
			}
			e.emit(indent+1, "default:")
			e.emit(indent+2, "// unreachable")
			e.emit(indent, "}")
			return
		}
		// No jump table for this one, so it is not known to be a switch.
		//
		// Calling every unresolved indirect jump a "switch dispatch" was a
		// mislabel, and a load-bearing one: dart-3.7.0-sampleapp2-x64 has 45 jump
		// tables in the entire binary against 270 of these in 400 functions, so
		// the overwhelming majority are something else -- a tail call through a
		// register, most often. Naming the mechanism (an indirect jump) instead
		// of guessing the construct is what the tool can actually support.
		e.emit(indent, "// indirect jump via %s (target computed at runtime)", ins.Target)
		e.stats.UnresolvedCF++
		return
	}
	if ins.Target != "" {
		if va, ok := parseHexVA(ins.Target); ok {
			name := fmt.Sprintf("sub_%x", va)
			if e.symbols != nil {
				if sym, ok := e.symbols(va); ok && sym != "" {
					name = sym
				}
			}
			name = cleanCalleeName(name)
			// A tail call is a call: bound its arguments by the callee's
			// arity too.
			args := e.callArgExprs(len(e.fir.ArgRegs), va)
			argsText := strings.Join(args, ", ")
			e.emit(indent, "return %s(%s);", name, argsText)
			return
		}
		e.emit(indent, "return tailCall_%s();", sanitizeTailCallName(ins.Target))
		return
	}
	e.emit(indent, "// unresolved jump target")
	e.stats.UnresolvedCF++
}
