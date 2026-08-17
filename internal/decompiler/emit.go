package decompiler

import (
	"fmt"
	"regexp"
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
	// Configurable via --max-steps flag (0 = use default).
	defaultMaxStepsPerEmitter = 20000
)

// maxStepsPerEmitter returns the configured step budget, or the default
// if no override is set. This allows adaptive budgets based on function
// complexity without changing the constant.
var maxStepsPerEmitterOverride int

func maxStepsPerEmitter() int {
	if maxStepsPerEmitterOverride > 0 {
		return maxStepsPerEmitterOverride
	}
	return defaultMaxStepsPerEmitter
}

// SetMaxStepsPerEmitter sets the configurable step budget override.
// 0 means use the default (20000).
func SetMaxStepsPerEmitter(n int) {
	maxStepsPerEmitterOverride = n
}

type emitter struct {
	fir        *FuncIR
	symbols    SymbolLookup
	pool       PoolLookup
	lines      []string
	state      *LiftState
	active     map[int]bool
	visits     map[int]int
	omitted    []int
	omittedSet map[int]bool
	// omittedStates stores register state snapshots at extraction points,
	// so helper sub-emitters can receive live register aliases as parameters.
	omittedStates map[int]*LiftState
	callIdx       int
	steps         int
	budgetHit     bool
	stats         Stats
	loopHeaders   map[int]bool // Fase 7 TASK 2: blocks that are loop entry points
	phiCounter    int          // Item 7: phi temporary counter for dataflow joins

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
	fir.ComputePreds() // A3: compute predecessors for if/else inlining
	e := &emitter{
		fir:        fir,
		symbols:    symbols,
		pool:       pool,
		state:      newLiftState(fir.NullReg),
		active:     make(map[int]bool),
		visits:     make(map[int]int),
		omittedSet: make(map[int]bool),
	}
	// The pool is reachable from the lift layer too: instructions that name
	// a pool slot without loading it (x86_64 compare-against-memory) resolve
	// through operandExpr, not emitLoadPool. See poolOperandExpr.
	e.state.Pool = pool

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
	// effectiveParamTypes holds exactly the types the signature displays:
	// "" wherever the emitter fell back to dynamic. Downstream passes
	// (type annotation, arg renaming) MUST use this rather than the raw
	// ParamTypeNames, or they would leak types through the trust gate that
	// the signature itself refused to show.
	effectiveParamTypes := make([]string, len(argRegIdx))
	for i, ri := range argRegIdx {
		typeName := "dynamic"
		if trustParamTypes && fir.ParamTypeNames[i] != "" && fir.ParamTypeNames[i] != "?" {
			typeName = fir.ParamTypeNames[i]
			effectiveParamTypes[i] = typeName
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
						//
						// This carried the same loose `Contains(name,
						// "init_async")` that was flagged in call.go, and was
						// left untouched when that one was changed -- so the
						// "fix" hardened the path that never fires and left
						// the one that does. Both now share asyncStubRole.
						if isAsyncStubName(name) {
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
						if strings.Contains(name, "Future.delayed") ||
							strings.Contains(name, "Future._asyncComplete") ||
							strings.Contains(name, "Future._thenAwait") {
							fir.IsAsync = true
							break
						}
						// Generator detection: sync* and async*
						if strings.Contains(name, "InitSyncStar") || strings.Contains(name, "_initSyncStar") {
							fir.IsSyncStar = true
						}
						if strings.Contains(name, "YieldAsyncStar") || strings.Contains(name, "_yieldAsyncStar") ||
							strings.Contains(name, "SuspendSyncStarAtStart") || strings.Contains(name, "_suspendSyncStarAtStart") ||
							strings.Contains(name, "SuspendSyncStarAtYield") || strings.Contains(name, "_suspendSyncStarAtYield") {
							if strings.Contains(name, "Async") {
								fir.IsAsyncStar = true
							} else {
								fir.IsSyncStar = true
							}
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
	// Most specific modifier wins. An async* body calls
	// _SuspendState._yieldAsyncStar, which also matches the "_SuspendState +
	// _yield" rule that sets IsAsync -- so testing IsAsync first labelled
	// every async* function `async`. Same for sync*, whose Resume stub use
	// matches the `_resume` rule.
	asyncPrefix := ""
	if fir.IsAsyncStar {
		asyncPrefix = "async* "
	} else if fir.IsSyncStar {
		asyncPrefix = "sync* "
	} else if fir.IsAsync {
		asyncPrefix = "async "
	}
	sigLineIdx := len(e.lines) // P7: record signature line index for post-walk patching
	// A1: Use LocalTypeHints for typed return when available, otherwise
	// infer from function name heuristic.
	returnType := "dynamic"
	if fir.LocalTypeHints != nil {
		if hint, ok := fir.LocalTypeHints["return"]; ok && hint != "" {
			returnType = hint
		}
	}
	if returnType == "dynamic" {
		returnType = inferReturnTypeFromName(fir.Name)
	}
	e.lines = append(e.lines, fmt.Sprintf("%s%s %s(%s) {", asyncPrefix, returnType, sig, strings.Join(argList, ", ")))
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

	// P7: Post-walk modifier patch. IsAsync/IsSyncStar/IsAsyncStar can be set
	// during block walking (emitIndirectCall detecting a THR stub such as
	// suspend_state_init_async), after the signature line was emitted.
	//
	// This is ONE patch, not three: the three separate ones each tested
	// `HasPrefix` against their own modifier, so a line already carrying
	// "async* " did not match "async " and got a second prefix -- producing
	// `async async* dynamic foo()`. The precedence matches the pre-walk
	// selection above (most specific first).
	if sigLineIdx >= 0 && sigLineIdx < len(e.lines) {
		modifier := ""
		switch {
		case fir.IsAsyncStar:
			modifier = "async* "
		case fir.IsSyncStar:
			modifier = "sync* "
		case fir.IsAsync:
			modifier = "async "
		}
		if modifier != "" {
			line := e.lines[sigLineIdx]
			if !strings.HasPrefix(line, "async ") && !strings.HasPrefix(line, "async* ") &&
				!strings.HasPrefix(line, "sync* ") {
				e.lines[sigLineIdx] = modifier + line
			}
		}
	}

	e.lines = append(e.lines, "}") // close the main function body

	e.appendHelperFunctions() // appends sibling "_block_N()" top-level functions, if any

	source := strings.Join(e.lines, "\n")
	source = dropUnusedLabels(source)
	// Structural compaction, dataflow and expression cleanup all run inside
	// compactLines, on the statement/expression trees, to a shared fixed
	// point -- the expression passes used to be four separate regex sweeps
	// over the text here (constant folding, negated comparisons, wrapped
	// member access, outer parens).
	source = compactLines(source)
	// Expression simplification (algebraic identities)
	source = simplifyExpressions(source)
	// Enum reconstruction (detect switch-over-CID patterns)
	source = enumReconstruction(source)
	// Null-safety annotation (detect null-check patterns)
	source = nullSafetyAnnotation(source)
	// A1: Local variable type inference — consolidated pass that combines
	// IR-level hints (from typetrack KnownClass) with heuristic text-based
	// inference from ParamTypeNames. One split + one join instead of two.
	source = localTypeInference(source, effectiveParamTypes, fir.LocalTypeHints)
	// For-loop recovery, guard merging and null-check annotation now run
	// inside compactLines, on the statement tree -- see stmt_loops.go, which
	// records what each of them used to get wrong as a text pass.
	// Arg renaming with type hints (from flutterdec naming.rs). Uses the
	// types the signature actually displayed, so a name never implies a type
	// the trust gate rejected.
	source = applyArgRenaming(source, effectiveParamTypes)
	source = applyNamingPass(source, fir)

	return Artifact{FunctionName: fir.Name, Source: source, Stats: e.stats}
}

// labelDeclRe matches an emitted block label line, gotoRe a reference to one.
var (
	labelDeclRe = regexp.MustCompile(`^\s*block_(\d+):;$`)
	gotoRefRe   = regexp.MustCompile(`goto block_(\d+);`)
)

// dropUnusedLabels reconciles block labels and gotos so the emitted text is
// internally consistent:
//
//   - a `block_N:;` label that no `goto block_N;` refers to is removed (labels
//     are emitted for every block, then pruned here, which avoids having to
//     predict at emit time which blocks get jumped to);
//   - a `goto block_N;` whose target block was never emitted -- it can be
//     unreachable from the walk, or dropped by the step budget -- becomes a
//     comment, rather than naming a label that does not exist.
func dropUnusedLabels(source string) string {
	lines := strings.Split(source, "\n")
	used := map[string]bool{}
	declared := map[string]bool{}
	for _, line := range lines {
		for _, m := range gotoRefRe.FindAllStringSubmatch(line, -1) {
			used[m[1]] = true
		}
		if m := labelDeclRe.FindStringSubmatch(line); m != nil {
			declared[m[1]] = true
		}
	}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if m := labelDeclRe.FindStringSubmatch(line); m != nil {
			if !used[m[1]] {
				continue
			}
			out = append(out, line)
			continue
		}
		line = gotoRefRe.ReplaceAllStringFunc(line, func(g string) string {
			m := gotoRefRe.FindStringSubmatch(g)
			if declared[m[1]] {
				return g
			}
			return "/* goto block_" + m[1] + ": block not emitted */"
		})
		out = append(out, line)
	}
	return strings.Join(out, "\n")
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
