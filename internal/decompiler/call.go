package decompiler

import (
	"fmt"
	"strconv"
	"strings"

	"aotopsy/internal/sdk"
)

// namedIndirectTarget maps well-known ABI registers to a readable alias,
// mirroring flutterdec's named_indirect_target (dispatchTarget for the
// link/return-address register a Dart dispatch-table call often reuses,
// cachedTarget for a second common slot, else a numbered generic name).
func namedIndirectTarget(reg string, fir *FuncIR) string {
	reg = strings.ToLower(reg)
	switch reg {
	case fir.LinkReg:
		return "dispatchTarget"
	case fir.ArgRegAt(2):
		return "cachedTarget"
	}
	return "indirectTarget_" + sanitizeTailCallName(reg)
}

// ArgRegAt returns the i'th calling-convention argument register name,
// or "" if out of range.
func (f *FuncIR) ArgRegAt(i int) string {
	if i < 0 || i >= len(f.ArgRegs) {
		return ""
	}
	return f.ArgRegs[i]
}

// callArgExprs collects the first few argument-register expressions'
// CURRENT symbolic values, for both display and selector-hint sniffing.
//
// calleeVA is the target of a direct call, or 0 when the target is not a known
// address. When the callee's arity is known the argument list is cut to it,
// which is the only truthful bound available: everything else here is a
// heuristic over whatever the registers happen to hold.
func (e *emitter) callArgExprs(n int, calleeVA uint64) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		reg := e.fir.ArgRegAt(i)
		if reg == "" {
			break
		}
		out = append(out, e.state.lookupReg(reg))
	}
	// There used to be a truncation here by e.fir.ArgRegIndices -- the arity of
	// the function being DECOMPILED, applied to a call it makes. Those are two
	// unrelated numbers. It was removed rather than corrected: resolving the
	// callee's own arity from ArgRegMasks and truncating by that was built and
	// measured, and changed the emitted source of 2400 functions across six
	// samples by zero bytes, so it was machinery with no effect to keep.
	//
	// An indirect call is a switchable/dynamic call, and those pass their
	// arguments on the STACK. The register at sdk.ICDataArgRegIndex holds the
	// UnlinkedCall/MegamorphicCache the call sequence just loaded, so it is
	// provably not an argument -- and arguments being positional, nothing above
	// it is either. See sdk.ICDataArgRegIndex for the SDK sequence and for why
	// this hurt x86_64 far more than ARM64.
	if calleeVA == 0 && len(out) > sdk.ICDataArgRegIndex {
		out = out[:sdk.ICDataArgRegIndex]
	}
	// D2: Truncate trailing unassigned argument registers (where lookupReg(reg) == reg or argN)
	for len(out) > 0 {
		lastIdx := len(out) - 1
		reg := e.fir.ArgRegAt(lastIdx)
		defaultArg := fmt.Sprintf("arg%d", lastIdx)
		if out[lastIdx] == reg || out[lastIdx] == defaultArg || out[lastIdx] == "" {
			out = out[:lastIdx]
		} else {
			break
		}
	}
	return out
}

// sniffSelectorHint looks for a quoted string literal among the given
// expressions and returns its content as a candidate Dart selector name
// -- a best-effort stand-in for flutterdec's much richer
// selector_context_expr/selector_hint_from_expr pool-object traversal,
// which aotopsy does not have live-memory access to reconstruct here
// (this operates on static pool-string values only).
func sniffSelectorHint(exprs []string) string {
	for _, ex := range exprs {
		if len(ex) >= 2 && strings.HasPrefix(ex, `"`) && strings.HasSuffix(ex, `"`) {
			return ex[1 : len(ex)-1]
		}
	}
	return ""
}

// emitCall resolves and emits one call instruction, matching
// flutterdec's emit_call resolution-priority chain: direct-VA symbol
// name decoding, else indirect-target naming + selector/intent fallback
// chain, else a generic dynamicCall(...).
func (e *emitter) emitCall(ins Instr, indent int) {
	e.stats.TotalCalls++
	e.callIdx++
	tmpName := fmt.Sprintf("t%d", e.callIdx)

	// Resolve the target first: the callee's identity is what bounds the
	// argument list.
	calleeVA, isDirect := parseHexVA(ins.Target)
	if !isDirect {
		calleeVA = 0
	}
	args := e.callArgExprs(len(e.fir.ArgRegs), calleeVA)
	selectorHint := sniffSelectorHint(args)
	argsText := strings.Join(args, ", ")

	// A call overwrites the return register with a result of unknown class;
	// drop any stale tracked type. emitDirectCall re-establishes it only when the
	// callee is an allocation stub (`new <Class>`).
	e.state.clearRegClass(e.fir.ReturnReg)

	var bound bool
	if ins.IsDispatchCall {
		// A DispatchTable call dispatches on `selector_offset + receiver cid`.
		// The cid is a runtime value, so there is no single callee to name --
		// but the selector offset is right there in the instruction, it is
		// stable, and two sites sharing one call the same selector. Saying
		// that beats `dynamicCall(indirectTarget__rax_8_rcx_0x200a8_, ...)`,
		// which named the addressing mode.
		if ins.DispatchSelector == dispatchSelectorUnknown {
			e.emit(indent, "final %s = dispatchCall([%s]);", tmpName, argsText)
		} else {
			e.emit(indent, "final %s = dispatchCall(selector: %d, [%s]);",
				tmpName, ins.DispatchSelector, argsText)
		}
		e.stats.IndirectCalls++
		bound = true
	} else if isDirect {
		bound = e.emitDirectCall(tmpName, calleeVA, argsText, selectorHint, indent)
	} else {
		bound = e.emitIndirectCall(tmpName, ins.Target, argsText, selectorHint, indent)
	}
	// The call clobbers the return register. If it bound a result temp, the
	// return register now holds that temp's value, so make reads of it render as
	// the temp (this is the single largest source of raw-register leakage: every
	// call result used afterwards was rendering as the bare return register).
	// Otherwise the register holds an untracked/void result -- drop any stale
	// value so it is not read as a prior expression.
	if bound {
		e.bindReturnReg(tmpName)
	} else {
		e.clobberReturnReg()
	}
}

// bindReturnReg makes subsequent reads of the return register render as name
// (a just-declared temp), with the ARM64 w/x alias kept in sync.
func (e *emitter) bindReturnReg(name string) {
	rr := e.fir.ReturnReg
	if rr == "" {
		return
	}
	// setReg keys by canonical physical register, so the ARM64 w/x (and
	// x86 sub-register) views are updated by this single write.
	e.state.setReg(rr, name)
}

// clobberReturnReg drops any tracked value for the return register (a void or
// untracked call result must not be read as a stale prior expression).
func (e *emitter) clobberReturnReg() {
	rr := e.fir.ReturnReg
	if rr == "" {
		return
	}
	delete(e.state.Regs, canonReg(rr))
}

func parseHexVA(target string) (uint64, bool) {
	if !strings.HasPrefix(target, "0x") {
		return 0, false
	}
	v, err := strconv.ParseUint(target[2:], 16, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// knownVoidSelectors is a set of Dart method names that are known to return
// void. Calls to these should not be assigned to a temp variable.
// (P3-feasible-3 / E-018)
//
// M-2 (oracle-audit): "add" and "remove" were removed because they are
// NOT universally void — Set.add returns bool, List.remove returns bool,
// Set.remove returns bool. Since the decompiler can't distinguish List.add
// (void) from Set.add (bool) by selector name alone, it's safer to not
// mark them as void and keep the temp assignment.
//
// Additional removals (bug-fix): "apply", "close", "cancel", "start",
// "stop", "resume", "pause", "reset" were removed because they are NOT
// universally void:
//   - Function.apply returns dynamic (dart:core)
//   - IOSink.close returns Future, File.close returns Future
//   - Timer.cancel returns void, but StreamSubscription.cancel returns Future
//   - Stopwatch.start/stop return void, but many start/stop methods return Future
//   - StreamSubscription.resume/pause return void, but Isolate.resume/pause
//     return Future/void depending on overload
//   - List.reset doesn't exist, but many custom reset methods return values
//
// Keeping these as void would silently drop return values in decompiled output.
var knownVoidSelectors = map[string]bool{
	"setState":          true,
	"print":             true,
	"notifyListeners":   true,
	"addListener":       true,
	"removeListener":    true,
	"clear":             true,
	"dispose":           true,
	"markNeedsBuild":    true,
	"requestLayout":     true,
	"markNeedsLayout":   true,
	"scheduleMicrotask": true,
	"complete":          true,
	"completeError":     true,
	"insert":            true,
	"forEach":           true,
	"sort":              true,
	"shuffle":           true,
	"clearCache":        true,
	"notifyClients":     true,
	"performRebuild":    true,
	"performLayout":     true,
	"assemble":          true,
	"reassemble":        true,
	"visitChildren":     true,
	"visitAncestors":    true,
	"visitDescendants":  true,
}

// isVoidCall returns true if the call target is a known void function/method.
func isVoidCall(name, selectorHint string) bool {
	if knownVoidSelectors[name] {
		return true
	}
	if selectorHint != "" && knownVoidSelectors[selectorHint] {
		return true
	}
	return false
}

// emitDirectCall emits the call and returns true when it bound the result into
// `tmpName` (a `final tmpName = …` form), so the caller can make the return
// register read as `tmpName` afterwards instead of the raw register.
func (e *emitter) emitDirectCall(tmpName string, va uint64, argsText, selectorHint string, indent int) bool {
	name := fmt.Sprintf("sub_%x", va)
	if e.symbols != nil {
		if sym, ok := e.symbols(va); ok && sym != "" {
			name = sym
		}
	}
	name = cleanCalleeName(name)
	// If this call allocates a `new <Class>`, the return register now holds a
	// fresh instance of that class -- record it so subsequent field accesses on
	// the object resolve to real field names (audit-driven P2 / value typing).
	if cid := e.fir.AllocatedClassID(name); cid > 0 {
		e.state.setRegClass(e.fir.ReturnReg, cid)
	}
	// P7: Async/await detection. Calls to suspend_state_init_async_ep or
	// suspend_state_await_ep indicate this is an async function. Mark it
	// so the signature gets `async`. Await calls are rendered as `await`
	// rather than a regular call.
	//
	// Name matching lives in asyncStubRole (asyncstub.go), shared with the
	// pre-pass in emit.go so the two cannot drift apart.
	switch sdk.ClassifyStubRole(name) {
	case sdk.StubRoleAsyncInit:
		e.fir.IsAsync = true
		e.emit(indent, "// async function entry (InitAsync stub)")
		return false
	case sdk.StubRoleAsyncAwait:
		e.fir.IsAsync = true
		if argsText != "" {
			e.emit(indent, "final %s = await %s;", tmpName, argsText)
		} else {
			e.emit(indent, "final %s = await;", tmpName)
		}
		return true
	case sdk.StubRoleAsyncReturn:
		e.fir.IsAsync = true
		if argsText != "" {
			e.emit(indent, "return %s;", argsText)
		} else {
			e.emit(indent, "return %s;", tmpName)
		}
		return false
	}
	intent := resolveCallIntent(name, selectorHint)
	// P3-feasible-3: Skip temp assignment for known void calls.
	if isVoidCall(name, selectorHint) {
		if intent != "" {
			e.stats.SemanticDirectCalls++
			e.emit(indent, "%s(%s); // %s", name, argsText, intent)
			return false
		}
		e.emit(indent, "%s(%s);", name, argsText)
		return false
	}
	if intent != "" {
		e.stats.SemanticDirectCalls++
		e.emit(indent, "final %s = %s(%s); // %s", tmpName, name, argsText, intent)
		return true
	}
	e.emit(indent, "final %s = %s(%s);", tmpName, name, argsText)
	return true
}

// emitIndirectCall emits the indirect call and returns true when it bound the
// result into `tmpName` (see emitDirectCall).
func (e *emitter) emitIndirectCall(tmpName, targetText, argsText, selectorHint string, indent int) bool {
	e.stats.IndirectCalls++

	// A structural signal, checked before anything else: the target
	// register was JUST stored into a Thread field (see lift.go's
	// applyStore) -- Dart AOT's native/FFI-leaf-call bookkeeping idiom
	// (Thread::vm_tag_offset(), recording what's about to run for the
	// profiler). No other call convention stores the call target itself
	// into Thread state right before dispatching it, so this is a
	// confirmed call kind, not a guess -- takes priority over
	// selector-hint sniffing.
	if e.state.Regs[canonReg(targetText)] == ffiCallTargetSentinel {
		e.stats.SemanticIndirectCalls++
		// Emit typed FFI call with argument count for signature inference.
		// In a full implementation, this would resolve the FFI signature
		// from FfiTrampolineData (callback_target → Function → signature).
		// For now, we emit ffi_call with the args and a comment indicating
		// this is a native FFI call with N arguments.
		argCount := countArgs(argsText)
		e.emit(indent, "final %s = %s%s); // FFI native call (%d args, Thread vm_tag bookkeeping)", tmpName, FFICallMarker, argsText, argCount)
		return true
	}

	// A second structural signal, same priority as the FFI check above:
	// the target register was just loaded from a KNOWN Thread-cached stub
	// entry-point offset (see lift.go's ldr/mov THR-stub-offset check) --
	// Dart AOT's fast path for calling a small set of extremely hot
	// runtime stubs (WriteBarrier, AllocateObject, StackOverflow checks,
	// etc.) without going through the object pool. Verified on a real
	// sample: the resolved offset for
	// call_native_through_safepoint_entry_point_ matched the single most
	// frequent THR-relative ldr+blr pattern found in an FFI-heavy
	// function, cross-checked against dart-lang/sdk's generated
	// runtime_offsets_extracted.h (ground truth, not a guess).
	if v, ok := e.state.Regs[canonReg(targetText)]; ok && strings.HasPrefix(v, thrStubSentinelPrefix) {
		stubName := strings.TrimPrefix(v, thrStubSentinelPrefix)
		// P7: Detect async/await stubs loaded from THR. Same classifier as
		// emitDirectCall -- this is the path that actually sees the
		// snake_case Thread-table spellings.
		switch sdk.ClassifyStubRole(stubName) {
		case sdk.StubRoleAsyncInit:
			e.fir.IsAsync = true
			e.emit(indent, "// async function entry (InitAsync stub)")
			return false
		case sdk.StubRoleAsyncAwait:
			e.fir.IsAsync = true
			if argsText != "" {
				e.emit(indent, "final %s = await %s;", tmpName, argsText)
			} else {
				e.emit(indent, "final %s = await;", tmpName)
			}
			return true
		case sdk.StubRoleAsyncReturn:
			e.fir.IsAsync = true
			if argsText != "" {
				e.emit(indent, "return %s;", argsText)
			} else {
				e.emit(indent, "return %s;", tmpName)
			}
			return false
		}
		e.stats.SemanticIndirectCalls++
		e.emit(indent, "final %s = %s(%s); // Dart AOT runtime stub call (Thread cached entry point)", tmpName, stubName, argsText)
		return true
	}

	// x86_64-specific variant of the same check: unlike ARM64 (BLR always
	// takes a register, so the THR-cached load is always a separate prior
	// "ldr"), x86_64's CALL can address memory directly
	// ("call [r14+0x240]") -- confirmed on a real sample
	// (StringTools.countVowels, compare_sample x86_64/Dart 3.9.2): the
	// stack-overflow-check prologue calls THR-cached
	// stack_overflow_shared_without_fpu_regs_entry_point_ this way, which
	// the register-mediated check above cannot see since no register ever
	// holds the loaded value. Checked structurally on targetText itself,
	// not via e.state.Regs.
	if e.fir.ThreadStubOffsets != nil {
		if memOp := parseOperand(targetText); memOp.isMem && memOp.hasDisp && strings.ToLower(memOp.memBase) == e.fir.ThreadReg {
			if stubName, ok := e.fir.ThreadStubOffsets[memOp.memDisp]; ok {
				e.stats.SemanticIndirectCalls++
				e.emit(indent, "final %s = %s(%s); // Dart AOT runtime stub call (Thread cached entry point)", tmpName, stubName, argsText)
				return true
			}
		}
	}

	named := namedIndirectTarget(targetText, e.fir)

	// P3-feasible-3: Skip temp assignment for known void calls (indirect).
	if isVoidCall("", selectorHint) {
		intent := resolveCallIntent("", selectorHint)
		if intent != "" {
			e.stats.SemanticIndirectCalls++
			e.emit(indent, "%s(%s); // %s, indirect via: %s", sanitizeCallName(selectorHint), argsText, intent, named)
			return false
		}
		if selectorHint != "" {
			if fallback := fallbackCallNameFromSelector(selectorHint); fallback != "" {
				e.emit(indent, "%s(%s); // indirect via: %s", fallback, argsText, named)
				return false
			}
		}
	}

	intent := resolveCallIntent("", selectorHint)
	if intent != "" {
		e.stats.SemanticIndirectCalls++
		e.emit(indent, "final %s = %s(%s); // %s, indirect via: %s", tmpName, sanitizeCallName(selectorHint), argsText, intent, named)
		return true
	}
	if selectorHint != "" {
		if fallback := fallbackCallNameFromSelector(selectorHint); fallback != "" {
			e.emit(indent, "final %s = %s(%s); // indirect via: %s", tmpName, fallback, argsText, named)
			return true
		}
	}
	e.stats.RawRegisterCalls++
	e.emit(indent, "final %s = dynamicCall(%s, [%s]);", tmpName, named, argsText)
	return true
}

// countArgs counts the number of comma-separated arguments in an args string.
// Handles nested parentheses and brackets.
func countArgs(argsText string) int {
	if strings.TrimSpace(argsText) == "" {
		return 0
	}
	depth := 0
	count := 1
	for _, c := range argsText {
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				count++
			}
		}
	}
	return count
}

func sanitizeCallName(s string) string {
	if s == "" {
		return "call"
	}
	return safeFuncName(s)
}

// CallTargetsOf extracts every resolved direct-call target VA from a
// FuncIR's blocks -- used by --from-main's reachability walk to
// discover callees without re-running EmitPseudocode's full
// text-emission pipeline just to find call sites.
func CallTargetsOf(fir *FuncIR) []uint64 {
	var out []uint64
	for _, blk := range fir.Blocks {
		for _, ins := range blk.Instrs {
			if ins.Op != OpCall || ins.Target == "" {
				continue
			}
			if va, err := strconv.ParseUint(strings.TrimPrefix(ins.Target, "0x"), 16, 64); err == nil {
				out = append(out, va)
			}
		}
	}
	return out
}
