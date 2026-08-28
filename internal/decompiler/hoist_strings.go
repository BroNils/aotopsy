package decompiler

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"aotopsy/internal/decompiler/stmt"
)

// dartStringLiteralRe matches a double-quoted Dart string literal, honoring
// backslash escapes. The emitter only ever produces double-quoted strings.
var dartStringLiteralRe = regexp.MustCompile(`"(?:\\.|[^"\\])*"`)

// funcSignatureRe recognizes a top-level function signature line (indent 0,
// opens a brace). The emitter's artifact is one such function plus any appended
// `_block_N()` helper functions, all at column 0.
var funcSignatureRe = regexp.MustCompile(`^[A-Za-z_][\w<>, ?]*\s+[\w$]+\([^)]*\)[^{]*\{\s*$`)

// hoistStringLiteralThreshold is the minimum literal length (including quotes)
// worth hoisting. Short strings gain nothing from a named const; the payoff is
// the big compiler-generated tables (e.g. the 256-entry JSON character-class
// string) that the control-flow walk re-emits dozens of times per function.
const hoistStringLiteralThreshold = 40

// hoistStringLiterals replaces long string literals that occur more than once
// within a function with a single function-local `const`. A 256-char character
// table inlined 40 times becomes one `const _str0 = "...";` plus 40 short
// references -- a large, safe size reduction: string literals are compile-time
// constants, so there is never an operand-invariance or dominance concern (the
// CSE pass's usual hazards). Scope is function-local, so concatenating many
// decompiled functions into one file cannot collide on the generated names.
func hoistStringLiterals(source string) string {
	lines := strings.Split(source, "\n")
	var out []string
	i := 0
	for i < len(lines) {
		line := lines[i]
		if !funcSignatureRe.MatchString(line) {
			out = append(out, line)
			i++
			continue
		}
		// Find the function body span [i+1, end) by brace matching, ignoring
		// braces inside string literals.
		depth := 1
		j := i + 1
		for j < len(lines) && depth > 0 {
			depth += stmt.BraceDelta(lines[j])
			if depth == 0 {
				break
			}
			j++
		}
		// Body is lines (i, j): signature at i, closing brace at j.
		body := lines[i+1 : j]
		hoisted, decls := hoistInBody(body)
		out = append(out, line)
		if len(decls) > 0 {
			out = append(out, decls...)
			out = append(out, hoisted...)
		} else {
			out = append(out, body...)
		}
		if j < len(lines) {
			out = append(out, lines[j]) // closing brace
		}
		i = j + 1
	}
	return strings.Join(out, "\n")
}

// hoistInBody finds repeated long literals in one function body, returns the
// body with them replaced by generated names and the const declarations to
// insert (indented one level under the signature).
func hoistInBody(body []string) (rewritten []string, decls []string) {
	counts := map[string]int{}
	for _, l := range body {
		for _, lit := range dartStringLiteralRe.FindAllString(l, -1) {
			if len(lit) >= hoistStringLiteralThreshold {
				counts[lit]++
			}
		}
	}
	// Deterministic assignment order: first appearance in the body.
	name := map[string]string{}
	var order []string
	n := 0
	for _, l := range body {
		for _, lit := range dartStringLiteralRe.FindAllString(l, -1) {
			if counts[lit] < 2 || len(lit) < hoistStringLiteralThreshold {
				continue
			}
			if _, ok := name[lit]; !ok {
				name[lit] = fmt.Sprintf("_str%d", n)
				n++
				order = append(order, lit)
			}
		}
	}
	if len(order) == 0 {
		return body, nil
	}
	// Replace longest literal first so a shorter literal that is a substring of
	// a longer one cannot corrupt it; iterate a stable slice (never the map) so
	// the output stays deterministic (golden/determinism gate).
	repl := make([]string, len(order))
	copy(repl, order)
	sort.SliceStable(repl, func(a, b int) bool { return len(repl[a]) > len(repl[b]) })
	rewritten = make([]string, len(body))
	for idx, l := range body {
		for _, lit := range repl {
			l = strings.ReplaceAll(l, lit, name[lit])
		}
		rewritten[idx] = l
	}
	for _, lit := range order {
		decls = append(decls, fmt.Sprintf("  const %s = %s;", name[lit], lit))
	}
	return rewritten, decls
}
