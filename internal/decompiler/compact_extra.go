package decompiler

import (
	"regexp"
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
