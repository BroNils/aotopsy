package decompiler

import (
	"fmt"
	"strings"
)

func identifyLoopHeaders(fir *FuncIR) map[int]bool {
	headers := make(map[int]bool)
	for i := range fir.Blocks {
		blk := &fir.Blocks[i]
		for _, s := range blk.Succs {
			if s.BlockID < 0 || s.BlockID >= len(fir.Blocks) {
				continue
			}
			target := &fir.Blocks[s.BlockID]
			// Back-edge: target address <= current address (backward branch).
			if target.StartVA <= blk.StartVA {
				headers[s.BlockID] = true
			}
		}
	}
	return headers
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
	defer delete(e.active, id)

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
	e.annotateInlineFrames(blk.StartVA, indent)
	// Forward dataflow join: fill live-in registers every already-emitted
	// predecessor agrees on but the taken path left unknown.
	e.seedFromEmittedPreds(id)
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
			retVal := e.state.lookupReg(e.fir.ReturnReg)
			if retVal == "" || retVal == "/* void */" || retVal == "/* pop */" {
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
				if isStackOverflowCond(cond) {
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
			if line, ok := ApplyOther(e.fir, e.state, ins); ok {
				e.emit(indent, "%s", line)
			}
		}
	}

	// Record this block's OUT state (after its own instructions, before any
	// successor recursion) for downstream forward joins.
	e.recordBlockOut(id)

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
	if id < 0 {
		e.emit(indent, "// unresolved branch target")
		e.stats.UnresolvedCF++
		return
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
		// A4: Try while-loop condition (for-loop is a post-emit pass)
		loopCond := e.extractLoopCondition(id)
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
	if e.canInline(id, depth) {
		e.emitBlock(id, indent, depth+1)
		return
	}
	e.emitOmittedPath(id, indent)
}

func isControlFlowOp(op Op) bool {
	return op == OpBranch || op == OpJump || op == OpReturn
}

// isStateIndexValue reports whether a register value looks like a
// SuspendState state index — a small integer loaded from a field or
// pool slot. This is a heuristic: the state index is typically a small
// integer (0, 1, 2, ...) loaded from the SuspendState object.
func isStateIndexValue(val string) bool {
	if val == "" {
		return false
	}
	// State index is typically a small integer literal or a field load
	// from a SuspendState object. Check for common patterns:
	// - "0", "1", "2" (literal state index)
	// - "state" or "stateIndex" (named local)
	// - A value containing "state" (from SuspendState field access)
	if val == "0" || val == "1" || val == "2" || val == "3" {
		return true
	}
	return strings.Contains(strings.ToLower(val), "state")
}

// emitAsyncStateBranch emits an async state machine dispatch as a
// switch statement on the state index, making the state machine
// structure visible. Each branch becomes a case in the switch,
// with the state index value as the case label.
//
// This is the structural collapse that item 9 calls for: instead of
// a bare if/else with a comment, the reader sees a real switch/case
// that maps directly to the async state machine's dispatch table.
func (e *emitter) emitAsyncStateBranch(blk *Block, ins Instr, indent, depth int) {
	var takenID, fallID = -1, -1
	for _, s := range blk.Succs {
		switch s.Cond {
		case "T":
			takenID = s.BlockID
		case "F":
			fallID = s.BlockID
		}
	}
	regVal := e.state.lookupReg(ins.CondReg)
	condKind := ins.CondKind

	savedState := e.state

	// Emit as a switch on the state index.
	// For eqz: "if (state == 0) { ... } else { ... }" becomes
	//   switch (state) { case 0: ... default: ... }
	// For nez: "if (state != 0) { ... } else { ... }" becomes
	//   switch (state) { default: ... case 0: ... }
	e.emit(indent, "// async state machine dispatch")
	e.emit(indent, "switch (%s) {", regVal)

	// Determine which branch is "state == 0" and which is "state != 0".
	// eqz: taken = state==0, fall = state!=0
	// nez: taken = state!=0, fall = state==0
	var zeroID, nonzeroID int
	if condKind == "eqz" {
		zeroID = takenID
		nonzeroID = fallID
	} else {
		zeroID = fallID
		nonzeroID = takenID
	}

	// Case 0: initial entry / first execution
	e.emit(indent+1, "case 0:")
	zeroState := savedState.Clone()
	e.state = zeroState
	e.emitSuccessor(zeroID, indent+2, depth)

	// Default: resumed from await
	e.emit(indent+1, "default:")
	nonzeroState := savedState.Clone()
	e.state = nonzeroState
	e.emitSuccessor(nonzeroID, indent+2, depth)

	// Merge branch states (Item 7 dataflow join).
	e.state = savedState.MergeJoin(zeroState, nonzeroState)
	e.emit(indent, "}")
}

func (e *emitter) canInline(id, depth int) bool {
	return depth < maxDepth && !e.active[id] && e.visits[id] < maxVisitCount && id >= 0 && id < len(e.fir.Blocks)
}

func (e *emitter) emitOmittedPath(id, indent int) {
	if id < 0 {
		e.emit(indent, "// unresolved branch target")
		e.stats.UnresolvedCF++
		return
	}
	if !e.omittedSet[id] && len(e.omitted) < maxHelpers {
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
// Item 7: After both branches complete, merges the two branch states
// via MergeJoin instead of restoring the pre-branch state. This is the
// dataflow join that was missing — the old code lost every register
// write inside either branch, so code after an if/else saw stale
// pre-branch values. MergeJoin keeps branch-specific values for
// registers that only one branch wrote, and conservatively keeps
// the pre-branch value for registers that both branches wrote
// differently (a text-based emitter cannot emit phi nodes).
//
// Item 9: When the function is async and the branch is on a state index
// (eqz/nez on a register loaded from SuspendState), emit it as a
// labeled state-machine case instead of a bare if/else, making the
// async state machine structure visible.
func (e *emitter) emitBranch(blk *Block, ins Instr, indent, depth int) {
	// Item 9: Async state machine dispatch detection.
	if e.fir.IsAsync && (ins.CondKind == "eqz" || ins.CondKind == "nez") {
		regVal := e.state.lookupReg(ins.CondReg)
		if isStateIndexValue(regVal) {
			e.emitAsyncStateBranch(blk, ins, indent, depth)
			return
		}
	}

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
	if isStackOverflowCond(cond) {
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

// isStackOverflowCond reports whether a branch condition is a Dart runtime
// stack-overflow check: `CMP SP, [THR + stack_limit]`.
//
// It requires the SPECIFIC `stack_limit` thread-field token (audit D1), not just
// any THR reference, so an ordinary comparison against some other THR field can
// never be mistaken for the prologue guard and have its branch elided. The stack
// pointer is x15 on ARM64 (verified: `SPREG = R15` in constants_arm64.h) and
// rsp on x86_64.
func isStackOverflowCond(cond string) bool {
	if cond == "" {
		return false
	}
	if !strings.Contains(cond, "stack_limit") {
		return false
	}
	return strings.Contains(cond, "x15") || strings.Contains(cond, "SP") ||
		strings.Contains(cond, "rsp") || strings.Contains(cond, "RSP")
}

func (e *emitter) buildCondition(ins Instr) (string, bool) {
	switch ins.CondKind {
	case "cmp":
		if !e.state.HasCmp || ins.CondOp == "?" {
			return "", false
		}
		return fmt.Sprintf("%s %s %s", e.state.LastCmp[0], ins.CondOp, e.state.LastCmp[1]), true
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
			// Real switch/case recovery: emit switch with ALL case blocks.
			// Use emitBlockBody (not emitSuccessor) for each case so the
			// emitter does NOT follow fallthrough into the next case —
			// each case is emitted independently with its own break.
			e.emit(indent, "switch (%s) {", ins.Target)
			for _, sc := range e.fir.SwitchCases {
				e.emit(indent+1, "case %d:", sc.Index)
				if sc.BlockID >= 0 && sc.BlockID < len(e.fir.Blocks) {
					e.emitBlockBody(sc.BlockID, indent+2, depth+1)
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
		e.emit(indent, "// switch dispatch via %s (indirect branch / jump table)", ins.Target)
		e.emit(indent, "// target = %s;", ins.Target)
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
			args := e.callArgExprs(len(e.fir.ArgRegs))
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

