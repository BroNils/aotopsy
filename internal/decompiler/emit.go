package decompiler

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"aotopsy/internal/decompiler/compare"
	"aotopsy/internal/decompiler/stmt"
	"aotopsy/internal/sdk"
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
	// OrphanBlocks counts blocks emitted only because the entry walk
	// never reached them -- see emitOrphanBlocks.
	OrphanBlocks int `json:"orphan_blocks,omitempty"`
}

// Artifact is one function's emitted pseudocode plus its stats.
type Artifact struct {
	FunctionName  string       `json:"function_name"`
	Source        string       `json:"source"`
	Stats         Stats        `json:"stats"`
	VisitedBlocks map[int]bool `json:"visited_blocks,omitempty"`
	// EmittedEdges is the CFG edge set the emitter actually followed or
	// represented. It is internal verification evidence, not a serialized output
	// contract; VerifyCFG uses it to compare targets instead of merely comparing
	// the number of `if` tokens in the rendered text.
	EmittedEdges []CFGEdge `json:"-"`
}

type CFGEdge struct {
	From int
	To   int
}

const (
	maxDepth = 20 // Fase 7: increased from 12 to reach loop headers in deep CFGs
	// Re-emission cap. Lowered from 24: coverage is set by each block's FIRST
	// emission (unaffected here), so anything above this only DUPLICATES already-
	// emitted code. On dense 100+ block state machines (chunked-JSON parser) the
	// old cap re-inlined blocks up to ~42x, inflating both line count and the
	// raw-register census by the same factor. At 4, average CFG coverage is
	// unchanged (verified 87.9% on dart-3.9.2-gt-arm64, identical to 24) while
	// emitted lines and duplicated raw-register leaks drop ~60-68%.
	maxVisitCount = 4
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
	// blockEntryState is the per-block register state computed by the pre-emission
	// reaching-definition fixpoint (computeEntryStates). seedFromFixpoint fills a
	// block's unknown live-ins from it. Supersedes the already-emitted-predecessor
	// forward join.
	blockEntryState []*LiftState
	// loopPhis maps a loop-header block id to its loop-carried registers and each
	// one's clean entry-initial value (computeLoopPhis). At the loop's entry the
	// emitter declares an induction local `phi_bH_<reg>` initialized to that value
	// and pins the register to it; the register's in-loop redefinitions are then
	// emitted as explicit `phi_bH_<reg> = <update>;` statements instead of leaking
	// the raw register token at the header read.
	loopPhis map[int]map[string]string
	// pinnedPhi maps a currently-pinned canonical register to its phi induction
	// local name. While pinned, a redefinition of the register emits an update to
	// the local and re-pins, rather than forwarding the raw value expression.
	pinnedPhi map[string]string
	// phiDeclared guards against re-declaring a header's induction locals if the
	// loop-entry path is reached more than once.
	phiDeclared map[int]bool
	callIdx     int
	steps       int
	budgetHit   bool
	stats       Stats
	loopHeaders map[int]bool // Fase 7 TASK 2: blocks that are loop entry points
	// idom is the dominator tree, computed once per function. Every question
	// of the form "is this edge a back edge?" goes through it -- see dom.go
	// for why block addresses cannot answer that.
	idom []int

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

	// emittedAnywhere records every block already written out by this
	// emitter OR by any helper sub-emitter, and is SHARED with them.
	//
	// visits is deliberately not shared: it drives canInline's recursion
	// budget, which is per-emitter. This map answers a different question
	// -- "is this block's text already somewhere in the output?" -- and
	// that question is global, because a `goto block_N;` refers to a label
	// wherever it was emitted. Without it every helper re-walked its whole
	// subtree from a fresh visit map and re-emitted join blocks the main
	// body had already shown.
	emittedAnywhere map[int]bool
	// emittedEdges is shared with helper sub-emitters, like emittedAnywhere.
	// Key packs source/target block ids into one uint64.
	emittedEdges map[uint64]bool
	currentBlock int
	// orphanBlocks records predecessorless/unreached blocks emitted after the
	// main structured walk. Their labels are semantic control-flow boundaries for
	// the compactor even when no goto references them; pruning those labels would
	// let dead-code elimination delete the orphan body after an earlier return.
	orphanBlocks map[int]bool

	// spillSeq numbers the `_tN` temporaries setReg materializes for
	// expressions too large to keep inlining. Shared with helper sub-emitters
	// for the same reason emittedAnywhere is: the names land in one source
	// file and must not collide.
	spillSeq *int
}

// drainSpills writes out any temporary declarations the last instruction
// produced. Called before the statement that reads them, so the declaration
// always precedes the use.
func (e *emitter) drainSpills(indent int) {
	for _, line := range e.state.TakeSpills() {
		e.emit(indent, "%s", line)
	}
}

// buildBlockTryIndex assigns a block to a try region only when the recovered
// region proves the WHOLE block is protected. PcDescriptor ranges are sparse
// evidence at exact PCs; they are not permission to widen a region to a block.
// A region that starts/ends mid-block is therefore left unstructured rather
// than fabricating a source-level try around unprotected instructions.
//
// Block ends are known exactly only when there is a following basic-block start.
// The final block has no instruction-width metadata in FuncIR (x86 is variable
// width), so it is intentionally not wrapped unless future IR carries an exact
// exclusive end. Under-claiming here is honest; over-claiming changes semantics.
func (e *emitter) buildBlockTryIndex() {
	if len(e.fir.TryRegions) == 0 {
		return
	}
	e.blockTryRegion = make(map[int]int, len(e.fir.Blocks))
	type blockExtent struct {
		id         int
		start, end uint64
	}
	extents := make([]blockExtent, 0, len(e.fir.Blocks))
	for bi := range e.fir.Blocks {
		if len(e.fir.Blocks[bi].Instrs) == 0 {
			continue
		}
		extents = append(extents, blockExtent{id: bi, start: e.fir.Blocks[bi].StartVA})
	}
	sort.Slice(extents, func(i, j int) bool { return extents[i].start < extents[j].start })
	for i := 0; i+1 < len(extents); i++ {
		extents[i].end = extents[i+1].start
	}
	for _, b := range extents {
		if b.end == 0 || b.end <= b.start {
			continue
		}
		best := -1
		var bestSize uint64
		for ri := range e.fir.TryRegions {
			r := &e.fir.TryRegions[ri]
			if b.start < r.StartVA || b.end > r.EndVA {
				continue
			}
			size := r.EndVA - r.StartVA
			if best < 0 || size < bestSize {
				best, bestSize = ri, size
			}
		}
		if best >= 0 {
			e.blockTryRegion[b.id] = best
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
	fir.ComputePreds()         // A3: compute predecessors for if/else inlining
	annotateDispatchCalls(fir) // mark DispatchTable calls and recover their selector
	e := &emitter{
		fir:         fir,
		symbols:     symbols,
		pool:        pool,
		state:       newLiftState(fir.NullReg),
		active:      make(map[int]bool),
		visits:      make(map[int]int),
		omittedSet:  make(map[int]bool),
		pinnedPhi:   make(map[string]string),
		phiDeclared: make(map[int]bool),

		emittedAnywhere: make(map[int]bool),
		emittedEdges:    make(map[uint64]bool),
		currentBlock:    -1,
		spillSeq:        new(int),
	}
	// One sequence per function, shared with every clone and helper
	// sub-emitter, so two spilled temporaries can never take the same name.
	e.state.AttachSpillSink(e.spillSeq)
	// The pool is reachable from the lift layer too: instructions that name
	// a pool slot without loading it (x86_64 compare-against-memory) resolve
	// through operandExpr, not emitLoadPool. See poolOperandExpr.
	e.state.Pool = pool

	// Seed the receiver register with the receiver's class so field-load chains
	// starting from `this` are typed (this.a -> a's type -> a.b resolves). The
	// clear-before-write invariant drops it as soon as the register is reused,
	// so it never goes stale.
	if fir.ReceiverClassID > 0 && len(fir.ArgRegs) > 0 {
		e.state.setRegClass(fir.ArgRegs[0], fir.ReceiverClassID)
	}

	// Fase 7 TASK 2: identify loop headers (blocks targeted by back-edges).
	e.idom = dominators(fir)
	e.loopHeaders = identifyLoopHeaders(fir, e.idom)
	// Pre-emission reaching-definition fixpoint: correct value state at each
	// block entry regardless of the recursive walk's path (ssa.go). The same
	// fixpoint's exit states drive loop-carried phi detection.
	entryStates, exitStates, fixpointConverged := runFixpoint(fir, pool)
	if fixpointConverged {
		e.blockEntryState = entryStates
		e.loopPhis = computeLoopPhis(fir, exitStates)
	}
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
	// fir.StackMaps is deliberately NOT consumed here. The emitter has no
	// sound use for it: naming the object slots is a no-op because localName
	// is deterministic and lift.go already assigns the same name on demand,
	// and the only non-trivial use anyone attempted -- killing "dead"
	// registers -- misread the bitmap three different ways. The stack maps
	// are emitted as data instead, in stack_maps.jsonl.

	// fir.ArgRegIndices (when resolved) is the real declared arity, found by
	// aggregating cross-function call-site evidence -- NOT a positional
	// arg0..argN-1 run necessarily starting at ArgRegs[0].
	// When cross-site evidence is empty, we deduce arity from intraprocedural
	// liveness (LiveInArgIndices) rather than blindly declaring 8 fake arguments (D2).
	argRegIdx := fir.ArgRegIndices
	if len(argRegIdx) == 0 {
		argRegIdx = LiveInArgIndices(fir)
	}
	// Real per-parameter type names are only trusted when their count EXACTLY
	// matches arity that was CONFIDENTLY resolved from cross-call-site evidence
	// (fir.ArgRegIndices) -- NOT the intraprocedural-liveness heuristic
	// (LiveInArgIndices) that fills argRegIdx when cross-site evidence is
	// empty. Trusting types on a heuristic arity (audit C1) leaks confident-wrong
	// parameter types; the liveness count is good enough to stop declaring 8 fake
	// args, but not to vouch for per-parameter TYPES. Gate stays on ArgRegIndices.
	trustParamTypes := len(fir.ArgRegIndices) > 0 && len(fir.ParamTypeNames) == len(argRegIdx)

	argList := make([]string, len(argRegIdx))
	// effectiveParamTypes holds exactly the types the signature displays:
	// "" wherever the emitter fell back to dynamic. Downstream passes
	// (type annotation, arg renaming) MUST use this rather than the raw
	// ParamTypeNames, or they would leak types through the trust gate that
	// the signature itself refused to show.
	effectiveParamTypes := make([]string, len(argRegIdx))
	// Item 11: NamedParamNames — use recovered named parameter names
	// instead of generic "argN" when available and count matches.
	//
	// The slice is aligned to argument position (positional slots are ""),
	// so indexing it by i is correct; the length check is what rejects it
	// when the FunctionType's parameter count disagrees with the arity
	// observed at call sites, which would make the alignment meaningless.
	trustNamedParams := len(fir.NamedParamNames) > 0 && len(fir.NamedParamNames) == len(argRegIdx)
	for i, ri := range argRegIdx {
		typeName := "dynamic"
		if trustParamTypes && fir.ParamTypeNames[i] != "" && fir.ParamTypeNames[i] != "?" {
			typeName = fir.ParamTypeNames[i]
			effectiveParamTypes[i] = typeName
		}
		// Item 11: Use named parameter name when available.
		paramName := fmt.Sprintf("arg%d", i)
		if trustNamedParams && fir.NamedParamNames[i] != "" && fir.NamedParamNames[i] != "?" {
			paramName = fir.NamedParamNames[i]
		}
		argList[i] = fmt.Sprintf("%s %s", typeName, paramName)
		if ri >= 0 && ri < len(fir.ArgRegs) {
			e.state.setReg(fir.ArgRegs[ri], paramName)
		}
	}
	// FPU argument registers are deliberately not seeded. Dart's register CC
	// chooses GPR vs FPU from per-parameter Representation; a bank index alone
	// does not identify the corresponding source parameter, and `fpargN` would be
	// an undeclared pseudo-parameter in otherwise-Dart output. See ssa.go.
	// Type-testing stubs are entered with the TypeTestABI registers already
	// holding their operands; see seedTypeTestABI.
	seedTypeTestABI(fir, e.state)
	// Pre-scan direct suspendable-function stub calls before emitting the
	// signature. The shared SDK classifier distinguishes async, async*, and
	// sync*; the block walk repeats the same classification for indirect THR
	// calls discovered later.
	//
	// Direct calls can therefore select the right modifier up front; indirect
	// calls still use the post-walk signature patch below.
	if e.symbols != nil {
		for bi := range fir.Blocks {
			for _, ins := range fir.Blocks[bi].Instrs {
				if ins.Op != OpCall {
					continue
				}
				if va, ok := parseHexVA(ins.Target); ok {
					if name, ok2 := e.symbols(va); ok2 && name != "" {
						markSuspendableStubRole(fir, sdk.ClassifyStubRole(name))
					}
				}
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
	// Most specific modifier wins. async* intentionally also sets IsAsync for
	// shared state-machine handling, while sync* remains a distinct non-async
	// generator kind.
	modifier := ""
	if fir.IsAsyncStar {
		modifier = "async*"
	} else if fir.IsSyncStar {
		modifier = "sync*"
	} else if fir.IsAsync {
		modifier = "async"
	}
	sigLineIdx := len(e.lines) // P7: record signature line index for post-walk patching
	// A declared return type is emitted only when enrichment recovered an exact
	// serialized AbstractType. Function names do not constrain return types in
	// Dart (an application is free to declare `int clear()` or `String isReady()`),
	// so unresolved metadata must stay dynamic rather than being guessed from a
	// familiar SDK method spelling.
	returnType := "dynamic"
	if fir.ReturnType != "" && fir.ReturnType != "?" {
		returnType = fir.ReturnType
	}
	baseSignature := fmt.Sprintf("%s %s(%s)", returnType, sig, strings.Join(argList, ", "))
	modifierSuffix := ""
	if modifier != "" {
		modifierSuffix = " " + modifier
	}
	e.lines = append(e.lines, baseSignature+modifierSuffix+" {")
	if !fixpointConverged {
		e.lines = append(e.lines, "  // reaching-definition fixpoint did not converge; SSA enrichment disabled")
		e.stats.UnresolvedCF++
	}
	e.state.setReg(fir.ThreadReg, sdk.SymTHR)
	e.state.setReg(fir.PoolReg, sdk.SymPP)
	// SPREG and the versioned ARM64 heap/GC pinned registers have fixed VM
	// meanings. Seeding them by name keeps stack addresses, pointer
	// decompression, and write-barrier math from leaking raw register tokens.
	if fir.StackReg != "" {
		e.state.setReg(fir.StackReg, sdk.SymSP)
	}
	if fir.HeapBitsReg != "" {
		e.state.setReg(fir.HeapBitsReg, sdk.SymHeapBits)
	}
	if fir.HeapBaseReg != "" {
		e.state.setReg(fir.HeapBaseReg, sdk.SymHeapBase)
	}
	if fir.BarrierMaskReg != "" {
		e.state.setReg(fir.BarrierMaskReg, sdk.SymBarrierMask)
	}

	// Async/async* is a source-level modifier recovered from suspendable runtime
	// calls/metadata. Do not claim a numeric state-index dispatcher here:
	// SuspendState stores a resume PC in supported AOT releases (2.18+), and
	// ordinary application comparisons inside an async function are still just
	// ordinary branches. Await sites are annotated only where the call lowering
	// itself proves them.
	if fir.IsAsync {
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
	// Anything the walk above could not reach is still code in the
	// binary, so it is shown rather than dropped.
	e.emitOrphanBlocks(1)

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
			modifier = "async*"
		case fir.IsSyncStar:
			modifier = "sync*"
		case fir.IsAsync:
			modifier = "async"
		}
		if modifier != "" {
			e.lines[sigLineIdx] = baseSignature + " " + modifier + " {"
		}
	}

	e.lines = append(e.lines, "}") // close the main function body

	e.appendHelperFunctions() // appends sibling "_block_N()" top-level functions, if any

	source := strings.Join(e.lines, "\n")
	source = dropUnusedLabels(source, e.orphanBlocks)
	// Structural compaction, dataflow and expression cleanup all run inside
	// compactLines, on the statement/expression trees, to a shared fixed
	// point -- the expression passes used to be four separate regex sweeps
	// over the text here (constant folding, negated comparisons, wrapped
	// member access, outer parens).
	source = compactLines(source)
	// Hoist long, repeated string literals to function-local consts. The
	// control-flow walk re-emits blocks, so a compiler-generated character table
	// can appear dozens of times in one function; naming it once is a large, safe
	// size reduction (constants have no CSE-invariance hazard).
	source = hoistStringLiterals(source)
	// Expression simplification (algebraic identities)
	source = simplifyExpressions(source)
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
	// Item 17: IdentStats-based re-classification pass from flutterdec.
	// Renames generic temps (t0, t1) to semantic names (result, flag,
	// counter, accumulator) based on usage patterns.
	source = compare.ApplyIdentReclassification(source)

	visited := make(map[int]bool, len(e.visits))
	for id, count := range e.visits {
		if count > 0 {
			visited[id] = true
		}
	}
	emittedEdges := make([]CFGEdge, 0, len(e.emittedEdges))
	for key := range e.emittedEdges {
		emittedEdges = append(emittedEdges, CFGEdge{From: int(uint32(key >> 32)), To: int(uint32(key))})
	}
	sort.Slice(emittedEdges, func(i, j int) bool {
		if emittedEdges[i].From != emittedEdges[j].From {
			return emittedEdges[i].From < emittedEdges[j].From
		}
		return emittedEdges[i].To < emittedEdges[j].To
	})

	return Artifact{
		FunctionName:  fir.Name,
		Source:        source,
		Stats:         e.stats,
		VisitedBlocks: visited,
		EmittedEdges:  emittedEdges,
	}
}

// gotoRefRe matches a `goto block_N;` reference.
var gotoRefRe = regexp.MustCompile(`goto block_(\d+);`)

// dropUnusedLabels reconciles block labels and gotos so the emitted text is
// internally consistent:
//
//   - a `block_N:;` label that no `goto block_N;` refers to is removed (labels
//     are emitted for every block, then pruned here, which avoids having to
//     predict at emit time which blocks get jumped to);
//   - a `goto block_N;` whose target block was never emitted -- it can be
//     unreachable from the walk, or dropped by the step budget -- becomes a
//     comment, rather than naming a label that does not exist.
func dropUnusedLabels(source string, preserve map[int]bool) string {
	lines := strings.Split(source, "\n")
	used := map[string]bool{}
	declared := map[string]bool{}
	for _, line := range lines {
		for _, m := range gotoRefRe.FindAllStringSubmatch(line, -1) {
			used[m[1]] = true
		}
		if m := stmt.LabelDeclRe.FindStringSubmatch(line); m != nil {
			declared[m[1]] = true
		}
	}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if m := stmt.LabelDeclRe.FindStringSubmatch(line); m != nil {
			id, _ := strconv.Atoi(m[1])
			if !used[m[1]] && !preserve[id] {
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

// returnValue picks the value a `return` statement should show, or ""
// when there is genuinely nothing to return.
//
// A function returning a double leaves it in V0 (ARM64) / XMM0 (x86_64),
// not in the integer return register. Reading only the integer one
// printed a bare `return;` for every such function and silently dropped
// the value it returned. FpuReturnReg is what says where to look, and it
// was populated by both lifters and read by nothing.
//
// The FP register is consulted only as a fallback, so an integer return
// is never overridden by a value left in V0 by earlier arithmetic. And
// lookupReg echoes the register name back when it has no tracked value,
// so that case is rejected explicitly -- otherwise this would trade a
// missing return for `return v0;`, which is a leak, not a fix.
func (e *emitter) returnValue(intVal string) string {
	if e.fir.ReturnType == "void" {
		return ""
	}
	if usableReturnValue(intVal) {
		return intVal
	}
	if e.fir.FpuReturnReg != "" {
		full, tracked := e.state.Regs[canonReg(e.fir.FpuReturnReg)]
		if !tracked {
			return ""
		}
		fp := readRegView(e.fir.FpuReturnReg, full)
		// ARM64 V0 is both the first FPU argument register and the FPU return
		// register. An untouched entry seed therefore proves only "argument 0
		// arrived in V0", not that this function returns it. Prefer a missing
		// value to a fabricated `return fparg0;`; a real operation/copy will
		// replace the seed with a computed expression before RET.
		if fp == "fparg0" && len(e.fir.FpuArgRegs) > 0 && canonReg(e.fir.FpuArgRegs[0]) == canonReg(e.fir.FpuReturnReg) {
			return ""
		}
		if usableReturnValue(fp) && fp != e.fir.FpuReturnReg {
			return fp
		}
	}
	return ""
}

func usableReturnValue(v string) bool {
	return v != "" && v != "/* void */" && v != "/* pop */"
}

// emit appends one indented output line -- or several, when the formatted
// text contains newlines.
//
// A lifter is allowed to return more than one statement for a single
// instruction: ARM64 `stp` is two stores, and returns them joined by a
// newline. Prefixing the indent once left every continuation line hard
// against column 0, in the middle of otherwise correctly nested output.
// Indenting per line fixes it here, at the one place indentation is
// applied, rather than requiring every current and future multi-statement
// lifter to remember.
func (e *emitter) emit(indent int, format string, args ...interface{}) {
	text := fmt.Sprintf(format, args...)
	pad := indentStr(indent)
	if !strings.Contains(text, "\n") {
		e.lines = append(e.lines, pad+text)
		return
	}
	for _, l := range strings.Split(text, "\n") {
		e.lines = append(e.lines, pad+l)
	}
}

// identifyLoopHeaders finds blocks that are targets of back-edges (loops).
// Fase 7 TASK 2: used to wrap loop bodies in `while (true) { ... }`.
// Uses address-based heuristic: a back-edge is a successor whose StartVA
// is <= the current block's StartVA (backward branch in the code layout).
