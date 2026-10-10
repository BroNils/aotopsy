package decompiler

import (
	"fmt"
	"regexp"
	"strings"

	"aotopsy/internal/sdk"
)

func (e *emitter) emitLoadPool(ins Instr) {
	if ins.Target == "" {
		return
	}
	dst := strings.ToLower(ins.Target)
	// x64 loads the CallSiteData with its own pool load into RBX; arm64 uses one
	// LDP (applyPairedPoolLoad).
	if e.fir.ICDataReg == sdk.X86ICDataStr {
		e.noteCallSiteLoad(dst, ins.PoolIndex)
	}
	if e.pool != nil && ins.PoolIndex >= 0 {
		if disp, ok := e.pool(ins.PoolIndex); ok {
			e.state.setReg(dst, dartPoolDisplay(disp))
			return
		}
	}
	if ins.PoolIndex >= 0 {
		e.state.setReg(dst, fmt.Sprintf("pool[%d]", ins.PoolIndex))
		return
	}
	e.state.setReg(dst, "pool[?]")
}

// appendHelperFunctions materializes every block recorded in e.omitted as
// a standalone "dynamic _block_N() { ... }" function using a fresh
// sub-emitter (pool hints/symbols are shared; register state starts
// empty, matching flutterdec's append_helper_functions -- note this
// means a helper's arg-register aliases aren't known, a documented
// completeness gap flutterdec itself also has).
//
// Helper inlining: if a helper's body is small (<= maxInlineHelperLines
// non-empty lines), it is inlined as a comment block at the call site
// instead of emitted as a separate function. This reduces the number of
// opaque `_block_N()` calls in the output.
func (e *emitter) appendHelperFunctions() {
	const maxInlineHelperLines = 5 // helpers with <= 5 non-empty lines are inlined
	seen := map[int]bool{}
	queue := append([]int(nil), e.omitted...)
	inlined := map[int][]string{} // id → inlined body lines
	// maxInlineFanIn bounds duplication: a small helper reached from many
	// emission paths appears as `return _block_N();` at every one of them, so
	// inlining its body at each site multiplies its content (and every raw
	// register token in it) by the fan-in. On a 116-block chunked-JSON state
	// machine this exploded one function to 130k lines / 15k rawReg hits. Above
	// this fan-in the helper is kept as a single function and CALLED instead.
	const maxInlineFanIn = 3
	fanIn := map[int]int{}
	for _, line := range e.lines {
		var fid int
		if _, err := fmt.Sscanf(strings.TrimSpace(line), "return _block_%d();", &fid); err == nil {
			fanIn[fid]++
		}
	}
	for len(queue) > 0 && len(seen) < maxHelpers {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true

		sub := &emitter{fir: e.fir, symbols: e.symbols, pool: e.pool, state: newLiftState(e.fir.NullReg),
			active: make(map[int]bool), visits: make(map[int]int), omittedSet: make(map[int]bool),
			blockTryRegion: e.blockTryRegion,
			tryMarked:      e.tryMarked,
			inlineMarked:   e.inlineMarked,
			tryOpened:      e.tryOpened,
			handlerBlocks:  e.handlerBlocks,
			// Per-FuncIR analyses are valid to share with helper sub-emitters so
			// extracted loops keep both fixpoint live-in seeding and phi
			// materialization; the phi bookkeeping maps are per-emitter, fresh.
			loopHeaders:     e.loopHeaders,
			blockEntryState: e.blockEntryState,
			loopPhis:        e.loopPhis,
			pinnedPhi:       make(map[string]string),
			phiDeclared:     make(map[int]bool),
			// Shared, unlike visits: see emitter.emittedAnywhere.
			emittedAnywhere: e.emittedAnywhere,
			elidedSlowPaths: e.elidedSlowPaths,
			emittedEdges:    e.emittedEdges,
			currentBlock:    -1}
		sub.state.Pool = e.pool
		// Pass live register state from extraction point to helper.
		// This gives the helper knowledge of register aliases (e.g. arg0,
		// THR, PP) that were live when the helper was extracted.
		if e.omittedStates != nil {
			if liveState, ok := e.omittedStates[id]; ok && liveState != nil {
				sub.state = liveState.Clone()
			}
		}
		sub.emitBlock(id, 1, 0)

		// Count non-empty lines (excluding labels and braces).
		nonEmpty := 0
		for _, line := range sub.lines {
			t := strings.TrimSpace(line)
			if t != "" && !strings.HasPrefix(t, "block_") && t != "{" && t != "}" {
				nonEmpty++
			}
		}

		if nonEmpty <= maxInlineHelperLines && fanIn[id] <= maxInlineFanIn {
			// Inline: store body for replacement at call sites.
			inlined[id] = sub.lines
			// Don't emit as separate function.
		} else {
			// Emit as separate function.
			e.lines = append(e.lines, fmt.Sprintf("dynamic _block_%d() {", id))
			e.lines = append(e.lines, sub.lines...)
			e.lines = append(e.lines, "}")
		}

		for _, nid := range sub.omitted {
			if !seen[nid] {
				queue = append(queue, nid)
			}
		}
		// Propagate the sub-emitter's captured live-in states into e's map so
		// nested helpers reached only through this helper are materialized with
		// their real register context. Without this the queued nested blocks
		// fell back to a fresh empty state, leaking every live-in register
		// (e.g. `if (x8 != null)`) as a raw token.
		if sub.omittedStates != nil {
			for nid, st := range sub.omittedStates {
				if _, exists := e.omittedStates[nid]; !exists {
					if e.omittedStates == nil {
						e.omittedStates = map[int]*LiftState{}
					}
					e.omittedStates[nid] = st
				}
			}
		}
		e.stats.UnresolvedCF += sub.stats.UnresolvedCF
		e.stats.PlaceholderIfs += sub.stats.PlaceholderIfs
		e.stats.TotalCalls += sub.stats.TotalCalls
		e.stats.IndirectCalls += sub.stats.IndirectCalls
		e.stats.NonLastBranch += sub.stats.NonLastBranch
		e.stats.OrphanBlocks += sub.stats.OrphanBlocks
	}

	// Replace `return _block_N();` calls with the inlined body where the
	// helper was small enough.
	//
	// This builds a fresh slice in one pass. The previous version mutated
	// e.lines from inside `for i, line := range e.lines`: range captured the
	// original slice, so after the first splice every later index was stale
	// and bodies were inserted at the wrong offsets.
	if len(inlined) > 0 {
		callSite := make(map[string]int, len(inlined))
		for id := range inlined {
			callSite[fmt.Sprintf("return _block_%d();", id)] = id
		}
		out := make([]string, 0, len(e.lines))
		for _, line := range e.lines {
			id, ok := callSite[strings.TrimSpace(line)]
			if !ok {
				out = append(out, line)
				continue
			}
			body := inlined[id]
			callIndent := leadingIndent(line)
			out = append(out, strings.Repeat("  ", callIndent)+fmt.Sprintf("// inlined _block_%d", id))
			bodyIndent := 0
			if len(body) > 0 {
				bodyIndent = leadingIndent(body[0])
			}
			for _, bl := range body {
				indent := callIndent + 1 + leadingIndent(bl) - bodyIndent
				if indent < 0 {
					indent = 0
				}
				out = append(out, strings.Repeat("  ", indent)+strings.TrimSpace(bl))
			}
		}
		e.lines = out
	}
}

// extractLoopCondition tries to recover the loop condition from a loop
// header block's branch instruction. Returns "" if the condition cannot
// be recovered (falls back to `while (true)`).
//
// Pattern: loop header block ends with a conditional branch where:
//   - taken (T) successor is NOT a back-edge (continues into loop body)
//   - fall-through (F) successor exits the loop (not a back-edge)
//
// If the taken branch continues the loop, the condition is used as-is.
// If the taken branch EXITS the loop (taken is back-edge or exit), the
// condition is inverted (negated) so `while (!cond)` becomes `while (cond)`.
//
// Stack overflow checks (CMP SP, THR.stack_limit) are skipped — they are
// not real loop conditions.
func (e *emitter) extractLoopCondition(id int) string {
	if id < 0 || id >= len(e.fir.Blocks) {
		return ""
	}
	blk := &e.fir.Blocks[id]
	if len(blk.Instrs) == 0 {
		return ""
	}
	lastInst := blk.Instrs[len(blk.Instrs)-1]
	if lastInst.Op != OpBranch {
		return ""
	}
	// Build the condition expression
	cond, ok := e.buildCondition(lastInst)
	if !ok || cond == "" || cond == "/* cond */" {
		return ""
	}
	// Skip stack overflow checks — they are not real loop conditions.
	if sdk.IsStackOverflowCond(cond) {
		return ""
	}

	// Determine which successor continues the loop vs exits.
	// If taken (T) continues into loop body (not a back-edge), cond is as-is.
	// If taken (T) exits (back-edge or exit block), invert cond.
	takenID := -1
	for _, s := range blk.Succs {
		if s.Cond == "T" {
			takenID = s.BlockID
		}
	}

	// Check if taken successor is a back-edge (exits loop by branching back).
	// Dominance, not address order: a backward JUMP is not a back EDGE, and
	// treating the two as the same inverted loop conditions on the strength of
	// a stack-overflow slow path. See dom.go.
	takenIsBackEdge := dominates(e.idom, takenID, blk.ID)

	if takenIsBackEdge {
		// Taken = back-edge (exit loop), fall-through = continue.
		// Invert the condition: while(!cond) means "continue while cond is false"
		// → emit while(invert(cond))
		return invertCondition(cond)
	}

	// Taken = continue loop (forward edge). Condition is as-is.
	return cond
}

// invertCondition negates a Dart boolean condition expression.
// Handles simple comparisons by flipping the operator, and wraps
// complex expressions with !(...).
// A single comparison, and nothing else: `<operand> <op> <operand>`. Operands
// may contain parentheses, so `f() == null` flips, but never spaces or
// logical operators, so a compound condition never matches.
//
// The `-` MUST stay last in the right-hand class. Written as `'-()` it is a
// RANGE from `'` (0x27) to `(` (0x28) rather than a literal hyphen, and
// negative literals silently stopped matching: `x != -1` flipped to
// `x == -1` before, and degraded to `!(x != -1)` after. Both are correct
// Dart; one is readable. 41 such comparisons on the 3.12 x86_64 sample.
//
// Note this still cannot match `(a + b) > 10` -- the spaces inside the
// parentheses put it outside the class -- which an earlier version of this
// comment gave as the reason for allowing parentheses. Grouped
// sub-expressions containing operators go to the `!(...)` fallback, as they
// always did.
var singleCmpRe = regexp.MustCompile(`^([A-Za-z0-9_.$\[\]'()]+) (>=|<=|==|!=|>|<) ([A-Za-z0-9_.$\[\]'()-]+)$`)

var cmpFlips = map[string]string{
	"==": "!=",
	"!=": "==",
	"<":  ">=",
	">=": "<",
	">":  "<=",
	"<=": ">",
}

func invertCondition(cond string) string {
	// Flip the operator only when the WHOLE condition is one comparison.
	//
	// The previous version scanned an unordered map for the first operator
	// found anywhere in the string. That made the result depend on Go's map
	// iteration order, and on a compound condition like `a == b || c != d`
	// it flipped a single operator -- which is not the negation of the
	// expression. Anything that is not one bare comparison is wrapped.
	if m := singleCmpRe.FindStringSubmatch(strings.TrimSpace(cond)); m != nil {
		return m[1] + " " + cmpFlips[m[2]] + " " + m[3]
	}
	// Can't flip — wrap with !()
	return "!(" + cond + ")"
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
