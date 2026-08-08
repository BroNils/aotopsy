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
	TryBlocks             int `json:"try_blocks"`
	CatchHandlers         int `json:"catch_handlers"`
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

	// blockTryRegion maps a block ID to the index in fir.TryRegions whose PC
	// range covers it, for per-block try annotation. See annotateBlockTry.
	blockTryRegion map[int]int
	// tryMarked records which blocks already carry a try marker, so the
	// repeated visits of the CFG walk do not repeat it.
	tryMarked map[int]bool
	// inlineMarked does the same for inlined-frame markers, keyed by VA.
	inlineMarked map[uint64]bool
	// curTryRegion is the try region currently open, stored as index+1 so the
	// zero value means "none". Prevents a region re-opening inside itself.
	curTryRegion int
	// tryOpened records regions already structured with real try/catch, so the
	// many recursion paths into a region do not each emit their own.
	tryOpened map[int]bool
	// handlerBlocks records block IDs that were already emitted inside a
	// catch clause, so they are not repeated at their natural CFG position.
	handlerBlocks map[int]bool
}

// buildBlockTryIndex assigns each block to the try region covering its start.
//
// Regions are block-aligned by SnapTryRegionsToBlocks, so a block is either
// wholly inside a region or wholly outside it; testing StartVA is enough. When
// regions overlap (nested trys that descriptors could not separate) the
// innermost — smallest — one wins, which matches Dart semantics where the
// nearest enclosing handler runs first.
func (e *emitter) buildBlockTryIndex() {
	if len(e.fir.TryRegions) == 0 {
		return
	}
	e.blockTryRegion = make(map[int]int, len(e.fir.Blocks))
	for bi := range e.fir.Blocks {
		va := e.fir.Blocks[bi].StartVA
		best := -1
		var bestSize uint64
		for ri := range e.fir.TryRegions {
			r := &e.fir.TryRegions[ri]
			if va < r.StartVA || va >= r.EndVA {
				continue
			}
			size := r.EndVA - r.StartVA
			if best < 0 || size < bestSize {
				best, bestSize = ri, size
			}
		}
		if best >= 0 {
			e.blockTryRegion[bi] = best
		}
	}
}

// annotateInlineFrames marks a block whose code came from an inlined callee.
//
// Deduplicated per VA for the same reason as the try markers: the CFG walk
// re-emits blocks, and repeating an identical frame line adds nothing.
func (e *emitter) annotateInlineFrames(va uint64, indent int) {
	if len(e.fir.InlineFrames) == 0 {
		return
	}
	frames, ok := e.fir.InlineFrames[va]
	if !ok || len(frames) == 0 {
		return
	}
	if e.inlineMarked == nil {
		e.inlineMarked = make(map[uint64]bool)
	}
	if e.inlineMarked[va] {
		return
	}
	e.inlineMarked[va] = true
	e.emit(indent, "// [inlined: %s]", strings.Join(frames, " -> "))
}

// annotateBlockTry emits a marker for a block that sits inside a try region.
//
// Why a marker and not real `try { … }` syntax: emitBlock is a recursive walk
// that FOLLOWS CONTROL FLOW, not address order. A block can be emitted more
// than once (maxVisitCount), nested inside if/else produced by the traversal,
// or omitted entirely. Opening a brace at a region's first block and closing it
// at the last would therefore produce unbalanced, malformed Dart in the general
// case. Marking each protected block is correct regardless of traversal order
// and repetition, and still tells the reader exactly which code the handler
// covers. Real syntax needs the emitter restructured to emit regions as units.
func (e *emitter) annotateBlockTry(id, indent int) {
	ri, ok := e.blockTryRegion[id]
	if !ok {
		return
	}
	// Once per block, not once per visit. The CFG walk re-emits blocks (up to
	// maxVisitCount) and loop bodies especially: without this, one big
	// loop-heavy function (_Timer._runTimers) produced 9010 identical marker
	// lines, 91% of all markers in a 900-function sweep. The fact being
	// reported -- "this block is inside try N" -- is a property of the block,
	// so stating it once is both sufficient and readable.
	if e.tryMarked == nil {
		e.tryMarked = make(map[int]bool)
	}
	if e.tryMarked[id] {
		return
	}
	e.tryMarked[id] = true
	r := e.fir.TryRegions[ri]
	e.emit(indent, "// [in try #%d -> %s at 0x%x]", r.TryIndex, r.CatchClause(), r.HandlerVA)
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
	// Map blocks to the try region covering them, for per-block annotation.
	e.buildBlockTryIndex()
	// Allocate up front so sub-emitters for helper functions share the same
	// set rather than each starting with a nil map of their own.
	if e.blockTryRegion != nil {
		e.tryMarked = make(map[int]bool, len(e.blockTryRegion))
	}
	if len(fir.InlineFrames) > 0 {
		e.inlineMarked = make(map[uint64]bool, len(fir.InlineFrames))
	}
	if len(fir.TryRegions) > 0 {
		e.tryOpened = make(map[int]bool, len(fir.TryRegions))
		e.handlerBlocks = make(map[int]bool)
	}

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
	// P7: Pre-scan for async stub calls to set IsAsync before the signature
	// is emitted. The signature needs `async` prefix, but IsAsync is set
	// during block walking which happens after the signature. A pre-scan
	// of call targets is the clean solution.
	//
	// Two sources of async detection:
	// 1. Direct BL calls to symbols containing "init_async"/"return_async"
	// 2. THR stub calls (indirect BLR) — detected during walking, but
	//    those set IsAsync AFTER the signature is emitted. To handle both,
	//    we record the signature line index and patch it post-walk.
	if !fir.IsAsync && e.symbols != nil {
		for bi := range fir.Blocks {
			for _, ins := range fir.Blocks[bi].Instrs {
				if ins.Op != OpCall {
					continue
				}
				if va, ok := parseHexVA(ins.Target); ok {
					if name, ok2 := e.symbols(va); ok2 && name != "" {
						// P7: Async detection via call targets.
						// Direct BL to async stubs (rare in AOT — usually inlined).
						if strings.Contains(name, "init_async") || strings.Contains(name, "return_async") ||
							strings.Contains(name, "InitAsync") || strings.Contains(name, "ReturnAsync") {
							fir.IsAsync = true
							break
						}
						// P7: Async detection via SuspendState runtime helpers.
						// Functions that call _SuspendState._await, _SuspendState._resume,
						// or _SuspendState._yieldAsyncStar are async/async* functions.
						if strings.Contains(name, "_SuspendState") &&
							(strings.Contains(name, "_await") ||
								strings.Contains(name, "_resume") ||
								strings.Contains(name, "_yield") ||
								strings.Contains(name, "_handleException") ||
								strings.Contains(name, "_initAsync") ||
								strings.Contains(name, "_returnAsync")) {
							fir.IsAsync = true
							break
						}
						// P7: Async detection via Future method calls.
						// Functions that call Future.delayed, Future.any, etc.
						// are likely async functions. This is a heuristic —
						// sync functions can also call Future methods, but
						// in practice most callers of Future.delayed are async.
						if strings.Contains(name, "Future.delayed") ||
							strings.Contains(name, "Future._asyncComplete") ||
							strings.Contains(name, "Future._thenAwait") {
							fir.IsAsync = true
							break
						}
					}
				}
			}
			if fir.IsAsync {
				break
			}
		}
	}

	// Signature, with the function's declared generic type parameters when
	// recovered: `dynamic foo<T>(...)`. These are type PARAMETERS from
	// FunctionType.type_parameters, not type arguments -- see
	// FuncIR.TypeParamNames.
	sig := safeFuncName(fir.Name)
	if len(fir.TypeParamNames) > 0 {
		sig += "<" + strings.Join(fir.TypeParamNames, ", ") + ">"
	}
	// For a closure, name the function it was declared inside. Without this an
	// anonymous closure is indistinguishable from every other one in its class.
	if fir.EnclosingFunction != "" {
		e.lines = append(e.lines, fmt.Sprintf("// closure declared in: %s", fir.EnclosingFunction))
	}
	asyncPrefix := ""
	if fir.IsAsync {
		asyncPrefix = "async "
	}
	sigLineIdx := len(e.lines) // P7: record signature line index for post-walk patching
	e.lines = append(e.lines, fmt.Sprintf("%sdynamic %s(%s) {", asyncPrefix, sig, strings.Join(argList, ", ")))
	e.state.Regs[fir.ThreadReg] = "THR"
	e.state.Regs[fir.PoolReg] = "PP"

	// P7: Async state machine annotation. Dart compiles async functions
	// into state machines: the function body is split at each await point,
	// and a switch on the SuspendState's state index selects which
	// continuation to run on resume. The if/switch chain the compiler
	// generates is visible in the CFG as branches on a loaded state index.
	// Annotate it so the reader knows the if/else chain is the async
	// state machine dispatch, not application logic.
	if fir.IsAsync {
		e.lines = append(e.lines, "  // async state machine: branches on SuspendState state index")
		e.lines = append(e.lines, "  // await points are marked with `await` below")
	}

	// Exception handlers are reported as a comment block, NOT as synthesised
	// try/catch syntax.
	//
	// The previous version wrapped the whole body in `try { ... } catch (e, st)
	// { <comments>; rethrow; }`. That output was actively wrong in four ways,
	// all reproduced against real binaries:
	//
	//  1. The handler's own basic blocks stay in the CFG and were emitted
	//     INSIDE the try body, so recovered handler code was presented as
	//     normal fall-through control flow. On dart:async's
	//     _RootZone.runUnaryGuarded the call that the source has in its catch
	//     clause (handleUncaughtError) appeared inside the try.
	//  2. `rethrow;` was invented. No handler in the sample corpus rethrows;
	//     the real bodies return values (e.g. `return -1;`).
	//  3. `catch (e, st)` was hardcoded regardless of needs_stacktrace, so a
	//     source-level `catch (e)` was rendered with a stack-trace binding it
	//     does not have.
	//  4. It fired on is_generated handlers too -- compiler-synthesised async
	//     machinery -- putting a try/catch on functions whose source has none.
	//
	// Recovering real try regions needs the handler PC ranges to re-partition
	// the CFG, which this emitter does not do. Until it does, reporting the
	// recovered facts is honest and the syntax was not.
	if len(fir.ExceptionHandlers) > 0 {
		e.stats.TryBlocks += len(fir.TryRegions)
		e.stats.CatchHandlers = len(fir.ExceptionHandlers)

		if len(fir.TryRegions) > 0 {
			// Real PC extents recovered from PcDescriptors' try_index.
			e.lines = append(e.lines, fmt.Sprintf("  // %d try region(s) recovered from PcDescriptors + ExceptionHandlers:",
				len(fir.TryRegions)))
			for _, r := range fir.TryRegions {
				line := fmt.Sprintf("  //   try #%d: PCs in [0x%x, 0x%x) -> %s at 0x%x",
					r.TryIndex, r.StartVA, r.EndVA, r.CatchClause(), r.HandlerVA)
				if r.Handler.HasCatchAll {
					line += " catch_all"
				}
				if r.Handler.OuterTryIndex >= 0 {
					line += fmt.Sprintf(" outer_try=%d", r.Handler.OuterTryIndex)
				}
				if r.Handler.IsGenerated {
					// async/await lowering, not a `try` the programmer wrote.
					line += " compiler_generated"
				}
				if e.symbols != nil {
					if name, ok := e.symbols(r.HandlerVA); ok && name != "" {
						line += " (" + name + ")"
					}
				}
				e.lines = append(e.lines, line)
			}
			// Two ways these ranges under-report, both from descriptor
			// density; see TryRegionEntry's doc. Stated inline so nobody reads
			// the range as the exact source-level try body.
			e.lines = append(e.lines, "  // NOTE ranges are block-aligned LOWER BOUNDS. PcDescriptors only mark call")
			e.lines = append(e.lines, "  // sites, so a raw range can be one instruction; it is widened to whole basic")
			e.lines = append(e.lines, "  // blocks (sound: a block has one entry). A try may therefore cover less than")
			e.lines = append(e.lines, "  // the source's, and nested trys can merge, so region count != try-block count.")
		} else {
			// Handlers exist but no descriptor carried a try_index for this
			// function, so no extent is known.
			e.lines = append(e.lines, fmt.Sprintf("  // %d exception handler(s), no try extents recoverable:",
				len(fir.ExceptionHandlers)))
			for _, h := range fir.ExceptionHandlers {
				desc := fmt.Sprintf("PC+0x%x outer_try=%d catch_all=%v needs_stacktrace=%v",
					h.PCOffset, h.OuterTryIndex, h.HasCatchAll, h.NeedsStacktrace)
				if h.IsGenerated {
					desc += " compiler_generated=true"
				}
				e.lines = append(e.lines, "  //   handler: "+desc)
			}
		}
		e.lines = append(e.lines, "  // Handler code is emitted inside the catch; it is suppressed at its")
		e.lines = append(e.lines, "  // natural CFG position to avoid duplication.")
	}

	if entryID, ok := fir.BlockByVA(fir.EntryVA); ok {
		e.emitBlock(entryID, 1, 0)
	}

	// P7: Post-walk async patch. If IsAsync was set during block walking
	// (by emitIndirectCall detecting a THR stub like suspend_state_init_async),
	// the signature line was already emitted without `async`. Patch it now.
	if fir.IsAsync && sigLineIdx >= 0 && sigLineIdx < len(e.lines) {
		if !strings.HasPrefix(e.lines[sigLineIdx], "async ") {
			e.lines[sigLineIdx] = "async " + e.lines[sigLineIdx]
		}
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
	e.annotateInlineFrames(blk.StartVA, indent)
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
			active: make(map[int]bool), visits: make(map[int]int), omittedSet: make(map[int]bool),
			// Share the block->region index so extracted helper functions
			// annotate their protected blocks too, and share tryMarked so a
			// block is marked once across the whole function's output. Without
			// sharing tryMarked, each helper's fresh emitter re-marked blocks
			// it walked: _Timer._runTimers reported 679 marked blocks inside a
			// 752-byte region, which cannot hold that many.
			blockTryRegion: e.blockTryRegion,
			tryMarked:      e.tryMarked,
			inlineMarked:   e.inlineMarked,
			tryOpened:      e.tryOpened,
			handlerBlocks:  e.handlerBlocks}
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
