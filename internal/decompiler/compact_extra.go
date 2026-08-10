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

// retryLoopSynthesis detects the Dart AOT retry-loop pattern:
//   var retry = false;
//   while (retry) { ...body...; retry = true; }
// and unwraps it (the loop runs at most once after the first iteration).
// Ported from flutterdec's retry_decl_var + while_var pattern.
func retryLoopSynthesis(lines []string) ([]string, bool) {
	var out []string
	changed := false
	for i := 0; i < len(lines); i++ {
		t := trimmed(lines[i])
		// Look for "final var retry = false;" or "bool retry = false;"
		if !strings.Contains(t, "= false;") || !strings.Contains(t, "retry") {
			out = append(out, lines[i])
			continue
		}
		// Extract variable name
		m := regexp.MustCompile(`(?:final\s+)?(?:bool\s+)?(\w+)\s*=\s*false;`).FindStringSubmatch(t)
		if m == nil {
			out = append(out, lines[i])
			continue
		}
		varName := m[1]
		// Next non-empty line should be "while (varName) {"
		j := i + 1
		for j < len(lines) && trimmed(lines[j]) == "" {
			j++
		}
		if j >= len(lines) || trimmed(lines[j]) != "while ("+varName+") {" {
			out = append(out, lines[i])
			continue
		}
		end := findBlockEnd(lines, j)
		if end < 0 {
			out = append(out, lines[i])
			continue
		}
		// Check no "continue;" in body and body terminates
		body := lines[j+1 : end]
		if containsTopLevelContinue(body, leadingIndent(lines[j])+1) {
			out = append(out, lines[i])
			continue
		}
		// Unwrap: skip the declaration and while wrapper, dedent body
		out = append(out, dedentBlock(body)...)
		i = end
		changed = true
	}
	return out, changed
}

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
				break
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
func copyPropagation(lines []string) ([]string, bool) {
	// Build copy map: var → source for simple "var = ident;" lines
	copies := map[string]string{}
	for _, line := range lines {
		t := trimmed(line)
		m := regexp.MustCompile(`^(t\d+)\s*=\s*(\w+);$`).FindStringSubmatch(t)
		if m != nil {
			copies[m[1]] = m[2]
		}
	}
	if len(copies) == 0 {
		return lines, false
	}
	changed := false
	out := make([]string, len(lines))
	for i, line := range lines {
		newLine := line
		for copy, source := range copies {
			re := regexp.MustCompile(`\b` + regexp.QuoteMeta(copy) + `\b`)
			if re.MatchString(newLine) {
				// Don't replace in the declaration line itself
				t := trimmed(newLine)
				if strings.HasPrefix(t, copy+" = ") {
					continue
				}
				newLine = re.ReplaceAllString(newLine, source)
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

	// First pass: collect all temp = expr assignments
	for _, line := range lines {
		t := trimmed(line)
		m := reAssign.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		temp := m[1]
		expr := m[2]
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

	// Second pass: replace occurrences of expressions with temp references
	changed := false
	out := make([]string, len(lines))
	for i, line := range lines {
		newLine := line
		t := trimmed(line)
		// Don't modify the declaration line itself
		if reAssign.MatchString(t) {
			out[i] = line
			continue
		}
		for expr, temp := range exprToTemp {
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

func simplifyExpressions(source string) string {
	for _, rule := range exprSimplificationRules {
		source = rule.pattern.ReplaceAllString(source, rule.replace)
	}
	return source
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
