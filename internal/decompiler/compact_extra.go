package decompiler

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// This file ports additional readability passes from flutterdec's
// compaction.rs, expr_cleanup.rs, and naming.rs that were not in the
// original 5-pass compactLines.

// --- Compaction passes (from compaction.rs) ---

// NOTE: retryLoopSynthesis was removed. It searched for
//   var retry = false; while (retry) { ...body...; retry = true; }
// and unwrapped the body, but (a) this emitter never generates that pattern
// (it emits `while (true) { ... break; }`, handled by unwrapDeadWhileTrue),
// so the pass never fired, and (b) the logic was wrong: `while (false)` runs
// zero times, but unwrapping makes the body run once -- a semantic reversal.
// The pattern was ported from flutterdec's Rust emitter which produced it;
// it does not apply here.

// collapseIfElseReturn detects:
//   if (cond) { return X; } else { return Y; }
// and collapses to just the if-else without redundant nesting.
// Also detects:
//   if (cond) { return X; } return X;
// and collapses to just "return X;" (both paths return same value).
func collapseIfElseReturn(lines []string) ([]string, bool) {
	var out []string
	changed := false
	for i := 0; i < len(lines); i++ {
		t := trimmed(lines[i])
		if !strings.HasPrefix(t, "if (") || !strings.HasSuffix(t, ") {") {
			out = append(out, lines[i])
			continue
		}
		end := findBlockEnd(lines, i)
		if end < 0 {
			out = append(out, lines[i])
			continue
		}
		// Check if then-block has a single return
		thenRet := singleTopLevelReturn(lines, i+1, end)
		if thenRet == "" {
			out = append(out, lines[i])
			continue
		}
		// Check what follows
		next := end + 1
		for next < len(lines) && trimmed(lines[next]) == "" {
			next++
		}
		if next >= len(lines) {
			out = append(out, lines[i])
			continue
		}
		nextT := trimmed(lines[next])
		// Pattern: if (cond) { return X; } return X; → return X;
		if nextT == thenRet && leadingIndent(lines[next]) == leadingIndent(lines[i]) {
			indent := leadingIndent(lines[i])
			out = append(out, strings.Repeat("  ", indent)+thenRet)
			i = next
			changed = true
			continue
		}
		// Pattern: if (cond) { return X; } else { return Y; } → keep but simplify
		if nextT == "else {" {
			elseEnd := findBlockEnd(lines, next)
			if elseEnd > 0 {
				elseRet := singleTopLevelReturn(lines, next+1, elseEnd)
				if elseRet != "" {
					indent := leadingIndent(lines[i])
					cond := extractIfCondition(t)
					out = append(out, strings.Repeat("  ", indent)+"if ("+cond+") {")
					out = append(out, strings.Repeat("  ", indent+1)+thenRet)
					out = append(out, strings.Repeat("  ", indent)+"} else {")
					out = append(out, strings.Repeat("  ", indent+1)+elseRet)
					out = append(out, strings.Repeat("  ", indent)+"}")
					i = elseEnd
					changed = true
					continue
				}
			}
		}
		out = append(out, lines[i])
	}
	return out, changed
}

// mergeIfChainContinue detects consecutive:
//   if (c1) { continue; }
//   if (c2) { continue; }
// and merges to:
//   if (c1 || c2) { continue; }
// Ported from flutterdec's if-chain-with-continue pattern.
func mergeIfChainContinue(lines []string) ([]string, bool) {
	var out []string
	changed := false
	for i := 0; i < len(lines); i++ {
		t := trimmed(lines[i])
		if !strings.HasPrefix(t, "if (") || !strings.HasSuffix(t, ") {") {
			out = append(out, lines[i])
			continue
		}
		end := findBlockEnd(lines, i)
		if end < 0 {
			out = append(out, lines[i])
			continue
		}
		// Check if body is single "continue;"
		if !singleTopLevelStmtIs(lines, i+1, end, "continue;") {
			out = append(out, lines[i])
			continue
		}
		cond := extractIfCondition(t)
		if cond == "" {
			out = append(out, lines[i])
			continue
		}
		// Collect consecutive if-continue blocks at same indent
		indent := leadingIndent(lines[i])
		conds := []string{cond}
		lastEnd := end
		for {
			next := lastEnd + 1
			for next < len(lines) && trimmed(lines[next]) == "" {
				next++
			}
			if next >= len(lines) || leadingIndent(lines[next]) != indent {
				break
			}
			nt := trimmed(lines[next])
			if !strings.HasPrefix(nt, "if (") || !strings.HasSuffix(nt, ") {") {
				break
			}
			ne := findBlockEnd(lines, next)
			if ne < 0 || !singleTopLevelStmtIs(lines, next+1, ne, "continue;") {
				break
			}
			nc := extractIfCondition(nt)
			if nc == "" {
				break
			}
			conds = append(conds, nc)
			lastEnd = ne
		}
		if len(conds) < 2 {
			out = append(out, lines[i])
			continue
		}
		// Emit merged: if (c1 || c2 || ...) { continue; }
		mergedCond := strings.Join(conds, " || ")
		out = append(out, strings.Repeat("  ", indent)+"if ("+mergedCond+") {")
		out = append(out, strings.Repeat("  ", indent+1)+"continue;")
		out = append(out, strings.Repeat("  ", indent)+"}")
		i = lastEnd
		changed = true
	}
	return out, changed
}

// --- Expression cleanup passes (from expr_cleanup.rs) ---

// rewriteNegatedComparisons rewrites !(a > b) → a <= b, !(a < b) → a >= b, etc.
// Ported from flutterdec's rewrite_negated_comparisons.
func rewriteNegatedComparisons(source string) string {
	// Only rewrite outside string literals — simple approach: skip lines
	// that are purely string content (start with a quote)
	lines := strings.Split(source, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, `"`) {
			continue
		}
		lines[i] = rewriteNegatedComparisonsLine(line)
	}
	return strings.Join(lines, "\n")
}

func rewriteNegatedComparisonsLine(line string) string {
	// !(a > b) → a <= b
	re := regexp.MustCompile(`!\(([^"]*?)\s*(>=|<=|>|<|==|!=)\s*([^"]*?)\)`)
	for {
		m := re.FindStringSubmatchIndex(line)
		if m == nil {
			break
		}
		lhs := line[m[2]:m[3]]
		op := line[m[4]:m[5]]
		rhs := line[m[6]:m[7]]
		var newOp string
		switch op {
		case ">":
			newOp = "<="
		case "<":
			newOp = ">="
		case ">=":
			newOp = "<"
		case "<=":
			newOp = ">"
		case "==":
			newOp = "!="
		case "!=":
			newOp = "=="
		default:
			return line
		}
		line = line[:m[0]] + lhs + " " + newOp + " " + rhs + line[m[1]:]
	}
	return line
}

// simplifyWrappedMemberAccess rewrites (expr).field → expr.field
// and ((expr)).field → (expr).field
// Ported from flutterdec's simplify_wrapped_member_access.
func simplifyWrappedMemberAccess(source string) string {
	lines := strings.Split(source, "\n")
	for i, line := range lines {
		// Skip string literals
		if strings.TrimSpace(strings.TrimSpace(line)) == "" || strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		lines[i] = simplifyWrappedMemberAccessLine(line)
	}
	return strings.Join(lines, "\n")
}

func simplifyWrappedMemberAccessLine(line string) string {
	// (expr).field → expr.field — but only for simple expressions (no spaces in expr)
	re := regexp.MustCompile(`\((\w+)\)\.(\w+)`)
	for {
		m := re.FindStringSubmatchIndex(line)
		if m == nil {
			break
		}
		line = line[:m[0]] + line[m[2]:m[3]] + "." + line[m[4]:m[5]] + line[m[1]:]
	}
	return line
}

// stripOuterParens removes redundant outer parentheses from expressions
// like ((expr)) → (expr), but only when safe.
func stripOuterParens(source string) string {
	lines := strings.Split(source, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") {
			continue
		}
		lines[i] = stripOuterParensLine(line)
	}
	return strings.Join(lines, "\n")
}

func stripOuterParensLine(line string) string {
	// Only strip if the entire line (after indentation) is ((...))
	indent := leadingIndent(line)
	rest := strings.TrimPrefix(line, strings.Repeat("  ", indent))
	if len(rest) >= 4 && rest[0] == '(' && rest[1] == '(' && rest[len(rest)-1] == ')' && rest[len(rest)-2] == ')' {
		// Check balanced parens
		inner := rest[1 : len(rest)-1]
		depth := 0
		balanced := true
		for _, c := range inner {
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
				if depth < 0 {
					balanced = false
					break
				}
			}
		}
		if balanced && depth == 0 {
			return strings.Repeat("  ", indent) + inner
		}
	}
	return line
}

// --- Naming passes (from naming.rs) ---

// applyArgRenaming renames arg0..arg7 to more meaningful names based on
// usage patterns. Ported from flutterdec's apply_name_and_type_hints.
// This is a lightweight version: it renames based on parameter type names
// when available (passed via FuncIR.ParamTypeNames).
func applyArgRenaming(source string, paramTypes []string) string {
	if len(paramTypes) == 0 {
		return source
	}
	lines := strings.Split(source, "\n")
	for i := range lines {
		// Skip the signature line (first non-empty, non-comment line)
		// — arg renaming should only apply to the function body, not
		// the signature which already shows param types.
		t := strings.TrimSpace(lines[i])
		if strings.HasPrefix(t, "dynamic ") || strings.HasPrefix(t, "async dynamic ") {
			continue
		}
		for argIdx, typeName := range paramTypes {
			if argIdx > 7 || typeName == "" {
				continue
			}
			oldName := "arg" + string(rune('0'+argIdx))
			// Don't rename if type is dynamic or unknown
			if typeName == "dynamic" || typeName == "Object" || typeName == "" {
				continue
			}
			// Generate a semantic name from the type
			newName := semanticArgName(typeName, argIdx)
			if newName != "" && newName != oldName {
				lines[i] = replaceIdent(lines[i], oldName, newName)
			}
		}
	}
	return strings.Join(lines, "\n")
}

func semanticArgName(typeName string, idx int) string {
	// Strip library prefix and generic params
	typeName = strings.TrimSpace(typeName)
	if i := strings.Index(typeName, "<"); i >= 0 {
		typeName = typeName[:i]
	}
	if i := strings.Index(typeName, "@"); i >= 0 {
		typeName = typeName[:i]
	}
	// Map common types to argument names
	switch strings.ToLower(typeName) {
	case "string":
		return "str"
	case "int", "integer":
		return "n"
	case "double":
		return "d"
	case "bool", "boolean":
		return "flag"
	case "list":
		return "items"
	case "map":
		return "entries"
	case "set":
		return "values"
	case "future":
		return "future"
	case "stream":
		return "stream"
	case "function":
		return "callback"
	case "widget":
		return "widget"
	case "buildelement", "element":
		return "element"
	case "renderobject":
		return "renderObj"
	case "context":
		return "context"
	case "duration":
		return "duration"
	case "key":
		return "key"
	case "stringbuffer":
		return "buffer"
	}
	// For other types, use first letter lowercase
	if len(typeName) > 0 && typeName[0] >= 'A' && typeName[0] <= 'Z' {
		return strings.ToLower(typeName[:1])
	}
	return ""
}

// replaceIdent replaces whole-word identifiers, not substrings.
func replaceIdent(line, old, new string) string {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(old) + `\b`)
	return re.ReplaceAllString(line, new)
}

// --- Helper functions ---

func singleTopLevelReturn(lines []string, start, end int) string {
	indent := leadingIndent(lines[start-1]) + 1
	var found string
	for i := start; i < end; i++ {
		t := trimmed(lines[i])
		if t == "" || strings.HasPrefix(t, "//") {
			continue
		}
		if leadingIndent(lines[i]) == indent {
			if strings.HasPrefix(t, "return ") {
				if found != "" {
					return "" // multiple returns
				}
				found = t
			} else if !strings.HasPrefix(t, "}") {
				// Non-return statement at top level
				return ""
			}
		}
	}
	return found
}

func singleTopLevelStmtIs(lines []string, start, end int, stmt string) bool {
	indent := leadingIndent(lines[start-1]) + 1
	for i := start; i < end; i++ {
		t := trimmed(lines[i])
		if t == "" || strings.HasPrefix(t, "//") {
			continue
		}
		if leadingIndent(lines[i]) == indent {
			return t == stmt
		}
	}
	return false
}

func extractIfCondition(line string) string {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "if (") || !strings.HasSuffix(t, ") {") {
		return ""
	}
	return t[4 : len(t)-3]
}

// --- Constant folding passes ---

// constantFold evaluates simple constant expressions in text:
//   (1 << 3) → 8
//   (1 << 12) → 4096
//   (2 * 4) → 8
//   (1 + 2) → 3
// Only folds expressions that are entirely numeric (no variables).
func constantFold(source string) string {
	lines := strings.Split(source, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		lines[i] = constantFoldLine(line)
	}
	return strings.Join(lines, "\n")
}

func constantFoldLine(line string) string {
	// Fold (N << M) → N * 2^M
	re := regexp.MustCompile(`\((\d+)\s*<<\s*(\d+)\)`)
	for {
		m := re.FindStringSubmatchIndex(line)
		if m == nil {
			break
		}
		n, _ := strconv.Atoi(line[m[2]:m[3]])
		shift, _ := strconv.Atoi(line[m[4]:m[5]])
		result := n << shift
		line = line[:m[0]] + strconv.Itoa(result) + line[m[1]:]
	}
	// Fold (N + M) → result
	re2 := regexp.MustCompile(`\((\d+)\s*\+\s*(\d+)\)`)
	for {
		m := re2.FindStringSubmatchIndex(line)
		if m == nil {
			break
		}
		a, _ := strconv.Atoi(line[m[2]:m[3]])
		b, _ := strconv.Atoi(line[m[4]:m[5]])
		line = line[:m[0]] + strconv.Itoa(a+b) + line[m[1]:]
	}
	// Fold (N * M) → result
	re3 := regexp.MustCompile(`\((\d+)\s*\*\s*(\d+)\)`)
	for {
		m := re3.FindStringSubmatchIndex(line)
		if m == nil {
			break
		}
		a, _ := strconv.Atoi(line[m[2]:m[3]])
		b, _ := strconv.Atoi(line[m[4]:m[5]])
		line = line[:m[0]] + strconv.Itoa(a*b) + line[m[1]:]
	}
	return line
}

// --- Dead-store elimination ---

// deadStoreElimination removes assignments where the variable is immediately
// reassigned without being read:
//   x = 5;\n  x = 10;  →  x = 10;
// Only applies to simple variable assignments (no field accesses).
func deadStoreElimination(lines []string) ([]string, bool) {
	var out []string
	changed := false
	for i := 0; i < len(lines); i++ {
		t := trimmed(lines[i])
		// Check if this is a simple assignment: "var = expr;"
		m := regexp.MustCompile(`^(\w+)\s*=\s*(.+);$`).FindStringSubmatch(t)
		if m == nil {
			out = append(out, lines[i])
			continue
		}
		varName := m[1]
		// Check if next non-empty line at same indent reassigns the same var
		j := i + 1
		for j < len(lines) && trimmed(lines[j]) == "" {
			j++
		}
		if j >= len(lines) {
			out = append(out, lines[i])
			continue
		}
		nextT := trimmed(lines[j])
		nextM := regexp.MustCompile(`^(\w+)\s*=\s*(.+);$`).FindStringSubmatch(nextT)
		if nextM != nil && nextM[1] == varName && leadingIndent(lines[i]) == leadingIndent(lines[j]) {
			// Check that varName is not read between i and j (there's nothing between)
			// Since j is the very next non-empty line, nothing is between
			changed = true
			continue // skip the dead store
		}
		out = append(out, lines[i])
	}
	return out, changed
}

// --- Copy propagation ---

// copyPropagation replaces uses of a copy variable with its source:
//   t1 = arg0;\n  t2 = t1 + 1;  →  t2 = arg0 + 1;
// Only propagates simple copies (t1 = var) where t1 is not reassigned.
//
// Scope-aware: a copy declared at indent N is only valid at indent >= N (the
// same block or a nested one). A copy inside an `if` block is NOT propagated
// to lines outside that block where the temp may be undefined. A temp that is
// reassigned (appears as `tN = ...` more than once, or as `final tN = ...`) is
// excluded entirely since its value changes.
func copyPropagation(lines []string) ([]string, bool) {
	// First pass: count assignments per temp to detect reassignment.
	assignCount := map[string]int{}
	declaredFinal := map[string]bool{}
	reAssign := regexp.MustCompile(`^(?:final\s+)?(t\d+)\s*=`)
	for _, line := range lines {
		t := trimmed(line)
		if m := reAssign.FindStringSubmatch(t); m != nil {
			assignCount[m[1]]++
			if strings.HasPrefix(t, "final ") {
				declaredFinal[m[1]] = true
			}
		}
	}

	// Build copy map: var → (source, declaring indent). Only simple
	// "var = ident;" lines with exactly one assignment (no reassignment).
	type copyEntry struct {
		source string
		indent int
	}
	copies := map[string]copyEntry{}
	simpleCopy := regexp.MustCompile(`^(t\d+)\s*=\s*(\w+);$`)
	for _, line := range lines {
		t := trimmed(line)
		m := simpleCopy.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		temp := m[1]
		// Skip if reassigned or declared final (different semantics).
		if assignCount[temp] != 1 || declaredFinal[temp] {
			continue
		}
		if _, exists := copies[temp]; !exists {
			copies[temp] = copyEntry{source: m[2], indent: leadingIndent(line)}
		}
	}
	if len(copies) == 0 {
		return lines, false
	}
	changed := false
	out := make([]string, len(lines))
	for i, line := range lines {
		newLine := line
		lineIndent := leadingIndent(line)
		t := trimmed(newLine)
		for copy, entry := range copies {
			// Only propagate to lines at the same or deeper indent (same
			// block or nested). A copy declared inside `if` must not leak
			// to a less-indented (outer) line.
			if lineIndent < entry.indent {
				continue
			}
			re := regexp.MustCompile(`\b` + regexp.QuoteMeta(copy) + `\b`)
			if re.MatchString(newLine) {
				// Don't replace in the declaration line itself
				if strings.HasPrefix(t, copy+" = ") {
					continue
				}
				newLine = re.ReplaceAllString(newLine, entry.source)
				changed = true
			}
		}
		out[i] = newLine
	}
	return out, changed
}

// --- Common Subexpression Elimination (CSE) ---

// commonSubexpressionElimination detects repeated complex expressions
// and replaces them with references to a previously-computed temporary.
// This is a text-rewriting pass: it scans for "final tN = <expr>;" lines,
// then replaces subsequent occurrences of <expr> with tN.
func commonSubexpressionElimination(lines []string) ([]string, bool) {
	// Build map: expression → temp variable name
	// Only track expressions that are "complex enough" (contain an operator
	// and are at least 8 chars) to avoid replacing simple variable references.
	exprToTemp := map[string]string{}
	var reAssign = regexp.MustCompile(`^final (t\d+) = (.+);$`)

	// Count all assignments per temp (final or not) to detect reassignment.
	// A temp that is reassigned cannot be safely used as a CSE target, since
	// a later use of the expression would resolve to the reassigned value.
	anyAssign := regexp.MustCompile(`^(?:final\s+)?(t\d+)\s*=`)
	assignCount := map[string]int{}
	for _, line := range lines {
		t := trimmed(line)
		if m := anyAssign.FindStringSubmatch(t); m != nil {
			assignCount[m[1]]++
		}
	}

	// First pass: collect all temp = expr assignments
	for _, line := range lines {
		t := trimmed(line)
		m := reAssign.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		temp := m[1]
		expr := m[2]
		// Skip temps that are reassigned elsewhere (value is not stable).
		if assignCount[temp] > 1 {
			continue
		}
		// Only track complex expressions (contain operator, not just a var)
		if len(expr) < 8 {
			continue
		}
		if !strings.ContainsAny(expr, "+-*/&|^><%") {
			continue
		}
		// Skip if expression contains function calls (too complex for CSE)
		if strings.Contains(expr, "(") && strings.Contains(expr, ")") {
			continue
		}
		// If this expression is already mapped to a different temp, keep the first
		if _, exists := exprToTemp[expr]; !exists {
			exprToTemp[expr] = temp
		}
	}

	if len(exprToTemp) == 0 {
		return lines, false
	}

	// Second pass: replace occurrences of expressions with temp references.
	// Track which temps have been declared so far: only replace with a temp
	// AFTER its declaration line (a use before the declaration would reference
	// an undefined temp).
	changed := false
	out := make([]string, len(lines))
	declared := map[string]bool{}
	for i, line := range lines {
		newLine := line
		t := trimmed(line)
		// Record declaration before skipping (so subsequent lines can use it).
		if m := reAssign.FindStringSubmatch(t); m != nil {
			declared[m[1]] = true
			out[i] = line
			continue
		}
		for expr, temp := range exprToTemp {
			// Only replace with a temp that has already been declared.
			if !declared[temp] {
				continue
			}
			// Only replace if the expression appears as a standalone token
			// (not as a substring of a larger expression)
			if strings.Contains(newLine, expr) {
				// Check word boundaries — the expression should be a complete token
				newLine = replaceExactSubstring(newLine, expr, temp)
				if newLine != line {
					changed = true
				}
			}
		}
		out[i] = newLine
	}
	return out, changed
}

// replaceExactSubstring replaces old with new in s, but only when old
// appears as a complete token (not part of a larger identifier).
func replaceExactSubstring(s, old, new string) string {
	idx := 0
	for {
		pos := strings.Index(s[idx:], old)
		if pos < 0 {
			break
		}
		absPos := idx + pos
		// Check character before
		if absPos > 0 {
			c := s[absPos-1]
			if isIdentChar(c) || c == '.' {
				idx = absPos + len(old)
				continue
			}
		}
		// Check character after
		afterPos := absPos + len(old)
		if afterPos < len(s) {
			c := s[afterPos]
			if isIdentChar(c) || c == '.' {
				idx = afterPos
				continue
			}
		}
		// Replace
		s = s[:absPos] + new + s[afterPos:]
		idx = absPos + len(new)
	}
	return s
}

// --- Expression Simplification (lightweight SSA-style) ---

// simplifyExpressions applies algebraic simplification rules to expressions
// in the decompiled output. This is a text-rewriting pass that handles
// common patterns without requiring a full SSA AST.
type exprRule struct {
	pattern *regexp.Regexp
	replace string
}

var exprSimplificationRules = []exprRule{
	// a * 1 → a
	{regexp.MustCompile(`([^()\s]+) \* 1\b`), "$1"},
	// 1 * a → a
	{regexp.MustCompile(`\b1 \* ([^()\s]+)`), "$1"},
	// a * 0 → 0
	{regexp.MustCompile(`([^()\s]+) \* 0\b`), "0"},
	// 0 * a → 0
	{regexp.MustCompile(`\b0 \* ([^()\s]+)`), "0"},
	// a + 0 → a
	{regexp.MustCompile(`([^()\s]+) \+ 0\b`), "$1"},
	// 0 + a → a
	{regexp.MustCompile(`\b0 \+ ([^()\s]+)`), "$1"},
	// a - 0 → a
	{regexp.MustCompile(`([^()\s]+) - 0\b`), "$1"},
	// a >> 0 → a
	{regexp.MustCompile(`([^()\s]+) >> 0\b`), "$1"},
	// a << 0 → a
	{regexp.MustCompile(`([^()\s]+) << 0\b`), "$1"},
	// a | 0 → a
	{regexp.MustCompile(`([^()\s]+) \| 0\b`), "$1"},
	// a & 0xFFFFFFFF → a (mask with all 1s)
	{regexp.MustCompile(`([^()\s]+) & 0xFFFFFFFF\b`), "$1"},
	// (a | 0) → a
	{regexp.MustCompile(`\(([^()]+) \| 0\)`), "$1"},
	// double negation: !!a → a (bool context)
	{regexp.MustCompile(`!!([^()\s]+)`), "$1"},
}

// simplifyExpressions applies arithmetic simplification rules to the source.
// It protects string-literal contents from replacement: rules like `a * 1 → a`
// would otherwise corrupt a literal `"x * 1"` into `"x"`. The source is split
// into code and string-literal segments; rules apply only to code segments.
func simplifyExpressions(source string) string {
	lines := strings.Split(source, "\n")
	for i, line := range lines {
		lines[i] = simplifyLineProtectingStrings(line)
	}
	return strings.Join(lines, "\n")
}

// simplifyLineProtectingStrings applies the simplification rules to the
// non-string-literal portions of a single line. String literals (single- or
// double-quoted) are preserved verbatim. Comment-only lines are skipped.
func simplifyLineProtectingStrings(line string) string {
	t := strings.TrimSpace(line)
	if strings.HasPrefix(t, "//") {
		return line
	}
	// Tokenize into string-literal and non-literal segments.
	var out strings.Builder
	i := 0
	for i < len(line) {
		c := line[i]
		if c == '"' || c == '\'' {
			// Copy the string literal verbatim (including quotes and content).
			quote := c
			out.WriteByte(c)
			i++
			for i < len(line) {
				out.WriteByte(line[i])
				if line[i] == '\\' && i+1 < len(line) {
					// Escaped char: copy next byte too.
					i++
					out.WriteByte(line[i])
					i++
					continue
				}
				if line[i] == quote {
					i++
					break
				}
				i++
			}
			continue
		}
		// Collect a non-literal segment up to the next quote.
		start := i
		for i < len(line) && line[i] != '"' && line[i] != '\'' {
			i++
		}
		seg := line[start:i]
		for _, rule := range exprSimplificationRules {
			seg = rule.pattern.ReplaceAllString(seg, rule.replace)
		}
		out.WriteString(seg)
	}
	return out.String()
}

// --- Enum Reconstruction ---

// enumReconstruction detects switch-over-CID patterns and annotates them
// as potential enum dispatches. This is a heuristic text-based pass that
// looks for chains of "if (x == N) { return 'Name'; }" patterns that
// suggest enum-to-string mapping.
func enumReconstruction(source string) string {
	lines := strings.Split(source, "\n")
	var out []string
	var enumCases []string
	inEnumChain := false

	for i := 0; i < len(lines); i++ {
		t := trimmed(lines[i])

		// Detect "if (x == N) { return 'Name'; }" pattern
		m := regexp.MustCompile(`^if \((\w+) == (\d+)\) \{ return '([^']+)'; \}$`).FindStringSubmatch(t)
		if m != nil {
			if !inEnumChain {
				inEnumChain = true
				enumCases = nil
			}
			enumCases = append(enumCases, fmt.Sprintf("  // %s = %s → '%s'", m[1], m[2], m[3]))
			out = append(out, lines[i])
			continue
		}

		// If we were in an enum chain and hit a non-matching line
		if inEnumChain && len(enumCases) >= 3 {
			// Emit enum annotation before the current line
			out = append(out, fmt.Sprintf("// enum reconstruction: %d cases detected", len(enumCases)))
			for _, c := range enumCases {
				out = append(out, c)
			}
			inEnumChain = false
			enumCases = nil
		} else if inEnumChain {
			inEnumChain = false
			enumCases = nil
		}

		out = append(out, lines[i])
	}

	// Handle trailing enum chain
	if inEnumChain && len(enumCases) >= 3 {
		out = append(out, fmt.Sprintf("// enum reconstruction: %d cases detected", len(enumCases)))
		for _, c := range enumCases {
			out = append(out, c)
		}
	}

	return strings.Join(out, "\n")
}

// --- Null-safety Annotation ---

// nullSafetyAnnotation detects null-check patterns and annotates variables
// with nullability info. This is a heuristic pass that looks for:
// 1. "if (x == null)" → x is nullable
// 2. "x!" → x is being null-asserted
// 3. "x?.field" → x is nullable, safe access
func nullSafetyAnnotation(source string) string {
	lines := strings.Split(source, "\n")
	var out []string
	nullableVars := map[string]bool{}

	for _, line := range lines {
		t := trimmed(line)

		// Detect "if (x == null)" → mark x as nullable
		m := regexp.MustCompile(`if \((\w+) == null\)`).FindStringSubmatch(t)
		if m != nil {
			nullableVars[m[1]] = true
		}

		// Detect "x != null" checks
		m2 := regexp.MustCompile(`(\w+) != null`).FindStringSubmatch(t)
		if m2 != nil {
			nullableVars[m2[1]] = true
		}

		out = append(out, line)
	}

	// If any nullable vars were found, emit annotation at the top
	if len(nullableVars) > 0 {
		var vars []string
		for v := range nullableVars {
			vars = append(vars, v)
		}
		sort.Strings(vars)
		annotation := "// null-safety: nullable variables: " + strings.Join(vars, ", ")
		// Insert after the first line (signature)
		if len(out) > 0 {
			rest := make([]string, len(out)-1)
			copy(rest, out[1:])
			out = append([]string{out[0], annotation}, rest...)
		}
	}

	return strings.Join(out, "\n")
}

// --- Local Variable Type Inference (heuristic) ---

// localTypeInference annotates local variables with inferred types based on
// usage patterns. This is a heuristic text-based pass.
func localTypeInference(source string, paramTypes []string) string {
	if len(paramTypes) == 0 {
		return source
	}
	lines := strings.Split(source, "\n")
	var out []string
	varTypes := map[string]string{}

	argTypes := map[string]string{}
	for i, t := range paramTypes {
		if t != "" {
			argTypes[fmt.Sprintf("arg%d", i)] = t
		}
	}

	for _, line := range lines {
		t := trimmed(line)
		m := regexp.MustCompile(`^(local_\w+) = (arg\d+);`).FindStringSubmatch(t)
		if m != nil {
			if typ, ok := argTypes[m[2]]; ok {
				varTypes[m[1]] = typ
			}
		}
		m2 := regexp.MustCompile(`^final (t\d+) = (.+);`).FindStringSubmatch(t)
		if m2 != nil {
			val := m2[1]
			expr := m2[2]
			switch {
			case regexp.MustCompile(`^-?\d+$`).MatchString(expr):
				varTypes[val] = "int"
			case regexp.MustCompile(`^-?\d+\.\d+$`).MatchString(expr):
				varTypes[val] = "double"
			case regexp.MustCompile(`^'[^']*'$`).MatchString(expr):
				varTypes[val] = "String"
			case expr == "true" || expr == "false":
				varTypes[val] = "bool"
			}
		}
		out = append(out, line)
	}

	if len(varTypes) > 0 {
		var annotations []string
		for v, t := range varTypes {
			annotations = append(annotations, fmt.Sprintf("%s: %s", v, t))
		}
		sort.Strings(annotations)
		annotation := "// local types: " + strings.Join(annotations, ", ")
		if len(out) > 0 {
			rest := make([]string, len(out)-1)
			copy(rest, out[1:])
			out = append([]string{out[0], annotation}, rest...)
		}
	}

	return strings.Join(out, "\n")
}

// applyLocalTypeHints annotates local variable declarations with inferred
// types from LocalTypeHints (populated from typetrack KnownClass → class name
// and ParamTypeNames). This is the IR-level type inference consumer.
// It scans for "local_NN = arg0;" patterns and annotates with the arg's type.
func applyLocalTypeHints(source string, hints map[string]string) string {
	if len(hints) == 0 {
		return source
	}
	lines := strings.Split(source, "\n")
	var out []string
	for _, line := range lines {
		t := trimmed(line)
		// Annotate "local_NN = argN;" with type from hints
		m := regexp.MustCompile(`^(local_\w+) = (arg\d+);`).FindStringSubmatch(t)
		if m != nil {
			if typeName, ok := hints[m[2]]; ok && typeName != "" {
				// Insert type annotation comment before the line
				indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
				out = append(out, indent+"// "+m[1]+": "+typeName)
			}
		}
		// Annotate "final tN = <expr>;" with type from hints if tN is in hints
		m2 := regexp.MustCompile(`^final (t\d+) =`).FindStringSubmatch(t)
		if m2 != nil {
			if typeName, ok := hints[m2[1]]; ok && typeName != "" {
				indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
				out = append(out, indent+"// "+m2[1]+": "+typeName)
			}
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// A6: nullCheckHoisting detects `if (x == null) { return; }` or
// `if (x == null) { return null; }` at the start of a function body
// and annotates it as a null-check guard. This makes the intent clear
// in the decompiled output.
func nullCheckHoisting(source string) string {
	lines := strings.Split(source, "\n")
	// Look for null-check patterns in the first 20 lines (function entry)
	for i := 0; i < len(lines) && i < 20; i++ {
		t := strings.TrimSpace(lines[i])
		// Pattern: if (argN == null) { return; }
		// or: if (argN == null) { return null; }
		if strings.Contains(t, "== null") && strings.Contains(t, "if (") {
			// Check if next line is return
			if i+1 < len(lines) {
				next := strings.TrimSpace(lines[i+1])
				if strings.HasPrefix(next, "return") {
					indent := lines[i][:len(lines[i])-len(strings.TrimLeft(lines[i], " "))]
					// Insert annotation before the null check
					lines[i] = indent + "// null-check guard" + "\n" + lines[i]
					break
				}
			}
		}
	}
	return strings.Join(lines, "\n")
}

// A7: rangeGuardMerging merges consecutive range checks:
//   if (x < 0) { return; }
//   if (x >= len) { return; }
// →
//   if (x < 0 || x >= len) { return; }
//
// Also merges:
//   if (x < 0) { throw ...; }
//   if (x >= len) { throw ...; }
// →
//   if (x < 0 || x >= len) { throw ...; }
func rangeGuardMerging(source string) string {
	lines := strings.Split(source, "\n")
	var out []string
	i := 0
	for i < len(lines) {
		// Pattern (6 lines):
		//   i:   if (x < N) {
		//   i+1:   return;
		//   i+2: }
		//   i+3: if (x >= M) {
		//   i+4:   return;
		//   i+5: }
		if i+5 < len(lines) {
			t1 := strings.TrimSpace(lines[i])
			t2 := strings.TrimSpace(lines[i+1])
			t3 := strings.TrimSpace(lines[i+2])
			t4 := strings.TrimSpace(lines[i+3])
			t5 := strings.TrimSpace(lines[i+4])
			t6 := strings.TrimSpace(lines[i+5])
			if isRangeCheck(t1) && t2 == "return;" && t3 == "}" &&
				isRangeCheck(t4) && t5 == "return;" && t6 == "}" {
				cond1 := extractIfCond(t1)
				cond2 := extractIfCond(t4)
				if cond1 != "" && cond2 != "" {
					indent := lines[i][:len(lines[i])-len(strings.TrimLeft(lines[i], " "))]
					out = append(out, indent+"if ("+cond1+" || "+cond2+") {")
					out = append(out, indent+"  return;")
					out = append(out, indent+"}")
					i += 6 // skip all 6 lines
					continue
				}
			}
		}
		out = append(out, lines[i])
		i++
	}
	return strings.Join(out, "\n")
}

// isRangeCheck returns true if the line is `if (x < N) {` or `if (x >= M) {`
// or `if (x > N) {` or `if (x <= M) {`.
func isRangeCheck(line string) bool {
	if !strings.HasPrefix(line, "if (") {
		return false
	}
	return strings.Contains(line, " < ") || strings.Contains(line, " <= ") ||
		strings.Contains(line, " > ") || strings.Contains(line, " >= ")
}

// extractIfCond extracts the condition from `if (cond) {`
func extractIfCond(line string) string {
	idx := strings.Index(line, "if (")
	if idx < 0 {
		return ""
	}
	rest := line[idx+4:]
	idx2 := strings.Index(rest, ") {")
	if idx2 < 0 {
		return ""
	}
	return rest[:idx2]
}

// A5: forLoopRecovery is a post-emit text pass that detects while-loop
// patterns that can be rewritten as for-loops.
//
// Pattern in emitted text:
//   local_8 = 0;               ← init (line before while)
//   while (local_8 < 10) {     ← loop header with condition
//     ...
//     local_8 = local_8 + 1;   ← increment (inside loop body)
//   }
//
// Rewrites to:
//   for (local_8 = 0; local_8 < 10; local_8 = local_8 + 1) {
//     ...
//   }
//
// The init and increment lines are removed from their original positions
// and merged into the for-header.
func forLoopRecovery(source string) string {
	lines := strings.Split(source, "\n")
	var out []string
	i := 0
	for i < len(lines) {
		line := lines[i]
		t := strings.TrimSpace(line)

		// Look for "while (local_NN <op> expr) {"
		if strings.HasPrefix(t, "while (") && strings.Contains(t, "local_") {
			condStart := strings.Index(t, "while (") + 7
			condEnd := strings.LastIndex(t, ") {")
			if condEnd > condStart {
				cond := t[condStart:condEnd]
				iterVar := extractIterVarFromCond(cond)
				if iterVar != "" {
					// Search backwards in out for init: "iterVar = value;"
					initLine := -1
					initText := ""
					for j := len(out) - 1; j >= 0 && j >= len(out)-10; j-- {
						jt := strings.TrimSpace(out[j])
						if strings.HasPrefix(jt, iterVar+" = ") && strings.HasSuffix(jt, ";") {
							// Make sure it's not an increment (iterVar = iterVar + N)
							if !strings.Contains(jt, iterVar+" + ") {
								initLine = j
								initText = strings.TrimSuffix(jt, ";")
								break
							}
						}
					}
					// Search forward in lines for increment: "iterVar = iterVar + 1;"
					incrLine := -1
					incrText := ""
					depth := 1
					for j := i + 1; j < len(lines) && depth > 0; j++ {
						jt := strings.TrimSpace(lines[j])
						depth += strings.Count(jt, "{") - strings.Count(jt, "}")
						if strings.HasPrefix(jt, iterVar+" = "+iterVar+" + 1;") {
							incrLine = j
							incrText = strings.TrimSuffix(jt, ";")
							break
						}
						if depth <= 0 {
							break
						}
					}

					if initLine >= 0 && incrLine >= 0 {
						// Rewrite: remove init from out, replace while with for,
						// remove increment from lines
						indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
						// Remove init line from out
						out = append(out[:initLine], out[initLine+1:]...)
						// Emit for-header
						out = append(out, indent+fmt.Sprintf("for (%s; %s; %s) {", initText, cond, incrText))
						// Copy body lines, skipping the increment line
						depth := 1
						for j := i + 1; j < len(lines) && depth > 0; j++ {
							jt := strings.TrimSpace(lines[j])
							depth += strings.Count(jt, "{") - strings.Count(jt, "}")
							if j == incrLine {
								continue // skip increment
							}
							out = append(out, lines[j])
						}
						i = incrLine + 1
						// Skip past closing brace
						for i < len(lines) {
							jt := strings.TrimSpace(lines[i])
							if jt == "}" {
								out = append(out, lines[i])
								i++
								break
							}
							i++
						}
						continue
					}
				}
			}
		}
		out = append(out, line)
		i++
	}
	return strings.Join(out, "\n")
}
