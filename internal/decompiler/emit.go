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
	// A1: Local variable type inference — use LocalTypeHints from typetrack
	// (IR-level) plus heuristic text-based inference from ParamTypeNames.
	source = localTypeInference(source, effectiveParamTypes)
	if fir.LocalTypeHints != nil {
		source = applyLocalTypeHints(source, fir.LocalTypeHints)
	}
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
				// A3: Non-last branch — emit real if/else when possible.
				// If the taken successor has only this block as predecessor,
				// inline its body. Otherwise fall back to goto.
				cond, ok := e.buildCondition(ins)
				if !ok {
					cond = "/* cond */"
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
			handlerBlocks:  e.handlerBlocks}
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

		if nonEmpty <= maxInlineHelperLines {
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
		e.stats.UnresolvedCF += sub.stats.UnresolvedCF
		e.stats.PlaceholderIfs += sub.stats.PlaceholderIfs
		e.stats.TotalCalls += sub.stats.TotalCalls
		e.stats.IndirectCalls += sub.stats.IndirectCalls
		e.stats.NonLastBranch += sub.stats.NonLastBranch
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
	// Pattern: "x15 <= THR.f56" or similar comparisons involving THR
	// and the stack pointer register.
	if strings.Contains(cond, "THR.") && (strings.Contains(cond, "x15") ||
		strings.Contains(cond, "SP") || strings.Contains(cond, "stack_limit")) {
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

	// Check if taken successor is a back-edge (exits loop by branching back)
	takenIsBackEdge := false
	if takenID >= 0 && takenID < len(e.fir.Blocks) {
		target := &e.fir.Blocks[takenID]
		if target.StartVA <= blk.StartVA {
			takenIsBackEdge = true
		}
	}

	if takenIsBackEdge {
		// Taken = back-edge (exit loop), fall-through = continue.
		// Invert the condition: while(!cond) means "continue while cond is false"
		// → emit while(invert(cond))
		return invertCondition(cond)
	}

	// Taken = continue loop (forward edge). Condition is as-is.
	// But verify taken is NOT a back-edge.
	if takenID >= 0 && takenID < len(e.fir.Blocks) {
		target := &e.fir.Blocks[takenID]
		if target.StartVA <= blk.StartVA {
			return "" // do-while pattern
		}
	}

	return cond
}

// invertCondition negates a Dart boolean condition expression.
// Handles simple comparisons by flipping the operator, and wraps
// complex expressions with !(...).
// A single comparison, and nothing else: `<operand> <op> <operand>`. Operands
// may contain parentheses (for grouped sub-expressions like `(a + b) > 10`)
// but may not contain spaces or logical operators, so a compound condition
// never matches.
var singleCmpRe = regexp.MustCompile(`^([A-Za-z0-9_.$\[\]'()]+) (>=|<=|==|!=|>|<) ([A-Za-z0-9_.$\[\]'-()]+)$`)

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

// extractIterVarFromCond extracts the iterator variable name from a condition
// like "local_8 < 10" or "local_m8 != arg0".
func extractIterVarFromCond(cond string) string {
	// Look for local_NN or local_mNN at the start of the condition
	for _, op := range []string{" < ", " <= ", " != ", " > ", " >= ", " == "} {
		idx := strings.Index(cond, op)
		if idx > 0 {
			left := strings.TrimSpace(cond[:idx])
			if strings.HasPrefix(left, "local_") {
				return left
			}
		}
	}
	return ""
}

// inferReturnTypeFromName infers a Dart function's return type from its name
// using Dart naming conventions. Returns "dynamic" when unknown.
//
// Conventions:
//   - "get:foo" → dynamic (getter, type depends on field — can't infer from name alone)
//   - "set:foo" → void (setter)
//   - "is_foo" / "isFoo" → bool (type check / predicate)
//   - "toFoo" / "to_Foo" → dynamic (conversion, type depends)
//   - "operator ==" → bool
//   - "operator <" → bool
//   - "operator +" → same as receiver (dynamic)
//   - "hashCode" → int
//   - "toString" → String
//   - "noSuchMethod" → dynamic
//   - "runtimeType" → Type
//   - "length" → int
//   - "isEmpty" → bool
//   - "isNotEmpty" → bool
//   - "contains" → bool
//   - "startsWith" → bool
//   - "endsWith" → bool
//   - "indexOf" → int
//   - "lastIndexOf" → int
//   - "compareTo" → int
//   - "forEach" → void
//   - "add" → void (List.add)
//   - "remove" → bool (List.remove) or void (Set.remove)
//   - "clear" → void
//   - "sort" → void
//   - "map" → Iterable
//   - "where" → Iterable
//   - "filter" → Iterable
//   - "fold" → dynamic
//   - "reduce" → dynamic
//   - "any" → bool
//   - "every" → bool
//   - "firstWhere" → dynamic
//   - "lastWhere" → dynamic
//   - "singleWhere" → dynamic
//   - "elementAt" → dynamic
//   - "getRange" → Iterable
//   - "sublist" → List
//   - "join" → String
//   - "toString" → String
//   - "hashCode" → int
func inferReturnTypeFromName(name string) string {
	// Strip library/class prefix for pattern matching
	short := name
	if idx := strings.LastIndex(short, "."); idx >= 0 {
		short = short[idx+1:]
	}
	// Strip @NNNNNN suffix (library hash)
	if idx := strings.Index(short, "@"); idx >= 0 {
		short = short[:idx]
	}
	// Strip _NNNN suffix (function hash)
	if idx := strings.LastIndex(short, "_"); idx >= 0 {
		suffix := short[idx+1:]
		if isAllDigits(suffix) && len(suffix) >= 4 {
			short = short[:idx]
		}
	}

	// Check specific method names
	switch short {
	case "set", "set:":
		return "void"
	case "toString", "toStringDeep", "toStringShallow":
		return "String"
	case "hashCode", "length", "offset", "index", "count", "size",
		"numberOfArguments", "parameterCount", "arity",
		"microsecondsSinceEpoch", "millisecondsSinceEpoch":
		return "int"
	case "isEmpty", "isNotEmpty", "isFinite", "isInfinite", "isNaN",
		"isEven", "isOdd", "isLowerCase", "isUpperCase",
		"contains", "startsWith", "endsWith", "matches",
		"any", "every", "equals", "isEqual",
		"hasNext", "hasMore", "isRegistered", "isAttached",
		"isMounted", "isCurrent", "isDisposed", "isListening":
		return "bool"
	case "forEach", "add", "clear", "sort", "removeWhere",
		"retainWhere", "insertAll", "setAll", "fillRange",
		"setRange", "writeTo", "writeAsString":
		return "void"
	case "map", "where", "filter", "expand", "skip", "take",
		"getRange", "followedBy", "distinct", "reversed":
		return "Iterable"
	case "sublist", "toList":
		return "List"
	case "join":
		return "String"
	case "runtimeType":
		return "Type"
	case "first", "last", "single":
		return "dynamic" // element type, can't infer from name
	case "firstWhere", "lastWhere", "singleWhere",
		"elementAt", "fold", "reduce", "min", "max":
		return "dynamic"
	case "indexOf", "lastIndexOf", "compareTo":
		return "int"
	case "keys":
		return "Iterable"
	case "values":
		return "Iterable"
	case "entries":
		return "Iterable"
	case "putIfAbsent":
		return "dynamic"
	case "containsKey", "containsValue":
		return "bool"
	}

	// Check prefixes
	if strings.HasPrefix(short, "get:") {
		return "dynamic" // getter — type depends on field
	}
	if strings.HasPrefix(short, "set:") {
		return "void"
	}
	if strings.HasPrefix(short, "is") && len(short) > 2 && short[2] >= 'A' && short[2] <= 'Z' {
		return "bool"
	}
	if strings.HasPrefix(short, "has") && len(short) > 3 && short[3] >= 'A' && short[3] <= 'Z' {
		return "bool"
	}
	if strings.HasPrefix(short, "can") && len(short) > 3 && short[3] >= 'A' && short[3] <= 'Z' {
		return "bool"
	}
	if strings.HasPrefix(short, "to") && len(short) > 2 && short[2] >= 'A' && short[2] <= 'Z' {
		// toList, toSet, toMap, etc.
		suffix := short[2:]
		switch suffix {
		case "String":
			return "String"
		case "List":
			return "List"
		case "Set":
			return "Set"
		case "Map":
			return "Map"
		case "Int":
			return "int"
		case "Double":
			return "double"
		case "Bool":
			return "bool"
		}
		return "dynamic"
	}
	if strings.HasPrefix(short, "as") && len(short) > 2 && short[2] >= 'A' && short[2] <= 'Z' {
		// asString, asInt, etc.
		suffix := short[2:]
		switch suffix {
		case "String":
			return "String"
		case "Int":
			return "int"
		case "Double":
			return "double"
		case "Bool":
			return "bool"
		case "List":
			return "List"
		case "Map":
			return "Map"
		case "Set":
			return "Set"
		}
		return "dynamic"
	}
	if strings.HasPrefix(short, "operator ") {
		op := strings.TrimSpace(strings.TrimPrefix(short, "operator "))
		switch op {
		case "==", "!=", "<", "<=", ">", ">=":
			return "bool"
		case "[]", "[]=":
			return "dynamic"
		case "~/", "%":
			return "int"
		case "&&", "||":
			return "bool"
		case "unary-":
			return "dynamic" // same type as receiver
		case "~":
			return "int"
		}
		return "dynamic"
	}

	return "dynamic"
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
