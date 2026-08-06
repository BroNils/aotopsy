package decompiler

import (
	"fmt"
	"strings"

	"aotopsy/internal/strutil"
)

// Stats mirrors flutterdec's PseudocodeArtifact per-function counters --
// built-in telemetry on how "good" a given function's decompilation is.
type Stats struct {
	TotalCalls            int `json:"total_calls"`
	IndirectCalls         int `json:"indirect_calls"`
	SemanticDirectCalls   int `json:"semantic_direct_calls"`
	SemanticIndirectCalls int `json:"semantic_indirect_calls"`
	PlaceholderIfs        int `json:"placeholder_ifs"`
	UnresolvedCF          int `json:"unresolved_cf"`
	RawRegisterCalls      int `json:"raw_register_calls"`
	NonLastBranch         int `json:"non_last_branch"`
}

// Artifact is one function's emitted pseudocode plus its stats.
type Artifact struct {
	FunctionName string `json:"function_name"`
	Source       string `json:"source"`
	Stats        Stats  `json:"stats"`
}

const (
	maxDepth      = 20 // Fase 7: increased from 12 to reach loop headers in deep CFGs
	maxVisitCount = 24
	maxHelpers    = 64
	// maxStepsPerEmitter caps total emitBlock invocations for one
	// emitter instance (the main function body, or one helper
	// sub-emitter) -- a hard backstop against combinatorial blowup.
	// maxDepth/maxVisitCount bound any SINGLE recursive path, but a
	// pathological CFG with many blocks each independently reachable
	// via many different paths can still multiply out to an enormous
	// total amount of work across a whole function; found necessary
	// after this exact command crashed the host running unbounded
	// against a real full Flutter framework build (not just a
	// hypothetical -- a genuine incident during this porting session).
	maxStepsPerEmitter = 20000
)

type emitter struct {
	fir         *FuncIR
	symbols     SymbolLookup
	pool        PoolLookup
	lines       []string
	state       *LiftState
	active      map[int]bool
	visits      map[int]int
	omitted     []int
	omittedSet  map[int]bool
	callIdx     int
	steps       int
	budgetHit   bool
	stats       Stats
	loopHeaders map[int]bool // Fase 7 TASK 2: blocks that are loop entry points
}

// EmitPseudocode is the top-level entry point: lifts+walks fir's CFG into
// readable pseudocode text, matching flutterdec's emit_pseudocode /
// FuncEmitter::emit pipeline (signature -> recursive block walk ->
// helper-function materialization -> text-compaction pass -> naming
// pass).
//
// Fase 7 TASK 2: loop structure detection. Before emitting, identifies
// loop headers (blocks that are targets of back-edges) and wraps loop
// bodies in `while (true) { ... break; }` instead of bare `continue;`.
func EmitPseudocode(fir *FuncIR, symbols SymbolLookup, pool PoolLookup) Artifact {
	e := &emitter{
		fir:        fir,
		symbols:    symbols,
		pool:       pool,
		state:      newLiftState(),
		active:     make(map[int]bool),
		visits:     make(map[int]int),
		omittedSet: make(map[int]bool),
	}

	// Fase 7 TASK 2: identify loop headers (blocks targeted by back-edges).
	e.loopHeaders = identifyLoopHeaders(fir)

	// fir.ArgRegIndices (when resolved) is the real declared arity, found by
	// aggregating cross-function call-site evidence -- NOT a positional
	// arg0..argN-1 run necessarily starting at ArgRegs[0]. Falls back to
	// the full ArgRegs set (the old fixed ABI-register display) when
	// unresolved, unchanged from before.
	argRegIdx := fir.ArgRegIndices
	if len(argRegIdx) == 0 {
		argRegIdx = make([]int, len(fir.ArgRegs))
		for i := range fir.ArgRegs {
			argRegIdx[i] = i
		}
	}
	// Real per-parameter type names are only trusted when their count
	// EXACTLY matches the independently-verified arity above (and that
	// arity was itself confidently resolved, not the raw-ArgRegs
	// fallback) -- see FuncIR.ParamTypeNames' doc comment for why this
	// cross-check exists at all.
	trustParamTypes := len(fir.ArgRegIndices) > 0 && len(fir.ParamTypeNames) == len(argRegIdx)

	argList := make([]string, len(argRegIdx))
	for i, ri := range argRegIdx {
		typeName := "dynamic"
		if trustParamTypes && fir.ParamTypeNames[i] != "" && fir.ParamTypeNames[i] != "?" {
			typeName = fir.ParamTypeNames[i]
		}
		argList[i] = fmt.Sprintf("%s arg%d", typeName, i)
		if ri >= 0 && ri < len(fir.ArgRegs) {
			e.state.Regs[fir.ArgRegs[ri]] = fmt.Sprintf("arg%d", i)
		}
	}
	e.lines = append(e.lines, fmt.Sprintf("dynamic %s(%s) {", safeFuncName(fir.Name), strings.Join(argList, ", ")))
	e.state.Regs[fir.ThreadReg] = "THR"
	e.state.Regs[fir.PoolReg] = "PP"

	if entryID, ok := fir.BlockByVA(fir.EntryVA); ok {
		e.emitBlock(entryID, 1, 0)
	}
	e.lines = append(e.lines, "}") // close the main function body

	e.appendHelperFunctions() // appends sibling "_block_N()" top-level functions, if any

	source := strings.Join(e.lines, "\n")
	source = compactLines(source)
	source = applyNamingPass(source, fir)

	return Artifact{FunctionName: fir.Name, Source: source, Stats: e.stats}
}

func safeFuncName(name string) string {
	// P4-5: Use shared strutil.SanitizeIdentifier for consistent
	// identifier sanitization across all packages.
	return strutil.SanitizeIdentifier(name)
}

func indentStr(n int) string { return strings.Repeat("  ", n) }

func (e *emitter) emit(indent int, format string, args ...interface{}) {
	e.lines = append(e.lines, indentStr(indent)+fmt.Sprintf(format, args...))
}

// identifyLoopHeaders finds blocks that are targets of back-edges (loops).
// Fase 7 TASK 2: used to wrap loop bodies in `while (true) { ... }`.
// Uses address-based heuristic: a back-edge is a successor whose StartVA
// is <= the current block's StartVA (backward branch in the code layout).
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
	if e.steps > maxStepsPerEmitter {
		if !e.budgetHit {
			e.budgetHit = true
			e.emit(indent, "// analysis budget exceeded, remaining control flow omitted")
			e.stats.UnresolvedCF++
		}
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

	blk := &e.fir.Blocks[id]
	for i, ins := range blk.Instrs {
		isLast := i == len(blk.Instrs)-1
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
				// Non-last branch: emit a diagnostic comment so the
				// control-flow instruction is not silently dropped.
				e.emit(indent, "// non-last branch (cond=%s %s) — emitted as comment", ins.CondKind, ins.CondOp)
				e.stats.NonLastBranch++
			}
		case OpJump:
			if isLast {
				e.emitJump(blk, ins, indent, depth)
			} else {
				e.emit(indent, "// non-last jump to %s — emitted as comment", ins.Target)
				e.stats.NonLastBranch++
			}
		default:
			if line, ok := ApplyOther(e.fir, e.state, ins); ok {
				e.emit(indent, "%s", line)
			}
		}
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
	// Fase 7 TASK 2: if target is a loop header and not yet visited,
	// emit while (true) { wrapper.
	isLoopHeader := e.loopHeaders[id]
	if isLoopHeader && e.visits[id] == 0 {
		e.emit(indent, "while (true) {")
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
	}
	e.emit(indent, "return _block_%d();", id)
}

// emitBranch resolves the branch condition against live LiftState and
// emits "if (cond) { <taken> } else { <fallthrough> }" (or a placeholder
// if the condition can't be resolved -- e.g. no preceding cmp was seen).
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
	e.emit(indent, "if (%s) {", cond)
	takenState := e.state.Clone()
	savedState := e.state
	e.state = takenState
	e.emitSuccessor(takenID, indent+1, depth)
	e.state = savedState
	e.emit(indent, "} else {")
	fallState := e.state.Clone()
	e.state = fallState
	e.emitSuccessor(fallID, indent+1, depth)
	e.state = savedState
	e.emit(indent, "}")
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
	if ins.Target != "" {
		e.emit(indent, "return tailCall_%s();", sanitizeTailCallName(ins.Target))
		return
	}
	e.emit(indent, "// unresolved jump target")
	e.stats.UnresolvedCF++
}

func sanitizeTailCallName(target string) string {
	return safeFuncName(target)
}

func (e *emitter) emitLoadPool(ins Instr) {
	if ins.Target == "" {
		return
	}
	dst := strings.ToLower(ins.Target)
	if e.pool != nil && ins.PoolIndex >= 0 {
		if disp, ok := e.pool(ins.PoolIndex); ok {
			e.state.Regs[dst] = disp
			return
		}
	}
	if ins.PoolIndex >= 0 {
		e.state.Regs[dst] = fmt.Sprintf("pool[%d]", ins.PoolIndex)
		return
	}
	e.state.Regs[dst] = "pool[?]"
}

// appendHelperFunctions materializes every block recorded in e.omitted as
// a standalone "dynamic _block_N() { ... }" function using a fresh
// sub-emitter (pool hints/symbols are shared; register state starts
// empty, matching flutterdec's append_helper_functions -- note this
// means a helper's arg-register aliases aren't known, a documented
// completeness gap flutterdec itself also has).
func (e *emitter) appendHelperFunctions() {
	seen := map[int]bool{}
	queue := append([]int(nil), e.omitted...)
	for len(queue) > 0 && len(seen) < maxHelpers {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true

		sub := &emitter{fir: e.fir, symbols: e.symbols, pool: e.pool, state: newLiftState(),
			active: make(map[int]bool), visits: make(map[int]int), omittedSet: make(map[int]bool)}
		sub.emitBlock(id, 1, 0)

		e.lines = append(e.lines, fmt.Sprintf("dynamic _block_%d() {", id))
		e.lines = append(e.lines, sub.lines...)
		e.lines = append(e.lines, "}")

		for _, nid := range sub.omitted {
			if !seen[nid] {
				queue = append(queue, nid)
			}
		}
		e.stats.UnresolvedCF += sub.stats.UnresolvedCF
		e.stats.PlaceholderIfs += sub.stats.PlaceholderIfs
		e.stats.TotalCalls += sub.stats.TotalCalls
		e.stats.IndirectCalls += sub.stats.IndirectCalls
		e.stats.NonLastBranch += sub.stats.NonLastBranch
	}
}
