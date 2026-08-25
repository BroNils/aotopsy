package decompiler

import (
	"fmt"
	"regexp"
	"strings"
)

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
			e.state.setReg(dst, disp)
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
