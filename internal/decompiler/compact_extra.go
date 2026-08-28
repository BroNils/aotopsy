package decompiler

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"aotopsy/internal/decompiler/stmt"
)

// Pre-compiled regexes for the text-based annotation passes. These were
// previously compiled inside loops (regex.MustCompile called per line),
// which is both slow and a Go anti-pattern. Each regex is compiled once
// at package init and reused across all calls.
var (
	// nullSafetyAnnotation
	nullCheckRe    = regexp.MustCompile(`if \((\w+) == null\)`)
	notNullCheckRe = regexp.MustCompile(`(\w+) != null`)
	// localTypeInference / applyLocalTypeHints
	localAssignArgRe = regexp.MustCompile(`^(local_\w+) = (arg\d+);`)
	finalAssignRe    = regexp.MustCompile(`^final (t\d+) = (.+);`)
	intLitRe         = regexp.MustCompile(`^-?\d+$`)
	doubleLitRe      = regexp.MustCompile(`^-?\d+\.\d+$`)
	stringLitRe      = regexp.MustCompile(`^'[^']*'$`)
	// applyLocalTypeHints: "final tN = ..."
	finalPrefixRe = regexp.MustCompile(`^final (t\d+) =`)
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

// --- Expression cleanup passes (from expr_cleanup.rs) ---

// --- Naming passes (from naming.rs) ---

// applyArgRenaming renames arg0..arg7 to more meaningful names based on
// usage patterns. Ported from flutterdec's apply_name_and_type_hints.
// This is a lightweight version: it renames based on parameter type names
// when available (passed via FuncIR.ParamTypeNames).
func applyArgRenaming(source string, paramTypes []string) string {
	if len(paramTypes) == 0 {
		return source
	}
	// Build the rename map first, so collisions can be resolved BEFORE any
	// text is rewritten. Two params of the same type (`String arg0, String
	// arg1`) both map to "str"; renaming them independently merged two
	// distinct variables into one. Colliding names get their index appended.
	renames := make(map[string]string, len(paramTypes))
	for argIdx, typeName := range paramTypes {
		if argIdx > 7 || typeName == "" {
			continue
		}
		if typeName == "dynamic" || typeName == "Object" {
			continue
		}
		oldName := fmt.Sprintf("arg%d", argIdx)
		base := semanticArgName(typeName, argIdx)
		if base == "" {
			continue
		}
		// The parameter index is always kept as a suffix: it makes the name
		// collision-free (two String params would both be "str" otherwise,
		// silently merging two distinct variables) and keeps the mapping
		// back to argN -- and to the argument register -- readable.
		newName := fmt.Sprintf("%s%d", base, argIdx)
		if newName == oldName {
			continue
		}
		renames[oldName] = newName
	}
	if len(renames) == 0 {
		return source
	}
	// Rename EVERYWHERE, including the signature. Skipping the signature
	// left the parameter declared as `arg0` while the body referred to the
	// new name -- an undeclared identifier in the emitted pseudocode.
	lines := strings.Split(source, "\n")
	for i := range lines {
		for oldName, newName := range renames {
			lines[i] = stmt.ReplaceIdent(lines[i], oldName, newName)
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
	// a * 0 → 0, and 0 * a → 0. Dropping `a` would drop its side effects,
	// so the operand class `[^()\s]` excludes parentheses -- a call cannot
	// match, by construction, and no extra guard is needed. (An earlier
	// comment here presented that as a caveat still to handle; it was
	// already handled by the class itself.)
	//
	// What remains outside the guard is a bare field load, `a.b * 0`. In
	// this emitter a `.` with no parentheses is a field read, not a getter
	// call -- calls always render with an argument list -- so there is no
	// side effect to lose.
	{regexp.MustCompile(`([^()\s]+) \* 0\b`), "0"},
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
	// NOTE: `a & 0xFFFFFFFF → a` was removed. Dart ints are 64-bit, so that
	// mask is a real truncation to the low 32 bits (emitted for uint32 field
	// loads and hash mixing), not an identity. Dropping it changed the
	// meaning of the expression.
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

// enumReconstruction was REMOVED, for the same reason and on the same evidence
// as retryLoopSynthesis above: this emitter does not generate the shape it
// looked for.
//
// It matched chains of `if (x == N) { return 'Name'; }` and, on three or more,
// inserted a `// enum reconstruction: N cases detected` comment. Measured over
// 371773 lines of real output from 700 functions of the 3.12.2 arm64 sample:
// that marker appears ZERO times, and the marker is its only effect -- with no
// match it rebuilds the input line for line. So it was inert, not merely rare.
//
// The two passes beside it were measured the same way and KEPT, because they
// do fire: nullSafetyAnnotation 3 times over those lines, localTypeInference
// 43 (as `// local_m8: List` comments -- proven by diffing the output with the
// call disabled, after a grep for typed declarations wrongly suggested zero).

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
		m := nullCheckRe.FindStringSubmatch(t)
		if m != nil {
			nullableVars[m[1]] = true
		}

		// Detect "x != null" checks
		m2 := notNullCheckRe.FindStringSubmatch(t)
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
// usage patterns. When IR-level hints are available (from typetrack
// KnownClass), they take priority over heuristic inference from ParamTypeNames.
// This consolidates the former localTypeInference + applyLocalTypeHints pair
// into a single pass that does one strings.Split + one strings.Join instead
// of two.
func localTypeInference(source string, paramTypes []string, irHints map[string]string) string {
	if len(paramTypes) == 0 && len(irHints) == 0 {
		return source
	}
	lines := strings.Split(source, "\n")
	var out []string
	varTypes := map[string]string{}

	// Heuristic: arg types from ParamTypeNames.
	argTypes := map[string]string{}
	for i, t := range paramTypes {
		if t != "" {
			argTypes[fmt.Sprintf("arg%d", i)] = t
		}
	}

	for _, line := range lines {
		t := trimmed(line)

		// IR-level hints take priority: annotate "local_NN = argN;" and
		// "final tN = ..." with the hint type.
		if len(irHints) > 0 {
			if m := localAssignArgRe.FindStringSubmatch(t); m != nil {
				if typeName, ok := irHints[m[2]]; ok && typeName != "" {
					indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
					out = append(out, indent+"// "+m[1]+": "+typeName)
				}
			}
			if m := finalPrefixRe.FindStringSubmatch(t); m != nil {
				if typeName, ok := irHints[m[1]]; ok && typeName != "" {
					indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
					out = append(out, indent+"// "+m[1]+": "+typeName)
				}
			}
		}

		// Heuristic inference (lower priority than IR hints).
		if m := localAssignArgRe.FindStringSubmatch(t); m != nil {
			if typ, ok := argTypes[m[2]]; ok {
				varTypes[m[1]] = typ
			}
		}
		if m2 := finalAssignRe.FindStringSubmatch(t); m2 != nil {
			val := m2[1]
			expr := m2[2]
			switch {
			case intLitRe.MatchString(expr):
				varTypes[val] = "int"
			case doubleLitRe.MatchString(expr):
				varTypes[val] = "double"
			case stringLitRe.MatchString(expr):
				varTypes[val] = "String"
			case expr == "true" || expr == "false":
				varTypes[val] = "bool"
			}
		}

		out = append(out, line)
	}

	// Emit heuristic type annotation at the top (IR hints are inline).
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

// applyLocalTypeHints is retained for backward compatibility with tests.
// It delegates to localTypeInference with irHints set and no paramTypes.
func applyLocalTypeHints(source string, hints map[string]string) string {
	return localTypeInference(source, nil, hints)
}
