package decompiler

import "strings"

// compactLines runs a subset of flutterdec's compact_lines readability
// pass to a fixed point (iterated, brace-counted text rewriting over
// []string lines -- no AST, matching the ported architecture exactly).
// This implements the highest-value passes from the Rust original:
// dead-code-after-terminator removal, empty-else removal, redundant
// guarded-return collapsing, duplicate-return collapsing, and
// while(true){...break;}-with-no-continue unwrapping. The full ~20-pass
// Rust pipeline (retry-loop synthesis, range-guard merging, null-check
// hoisting, etc.) is a documented, not-yet-ported subset -- see
// knowledge/SESSION_HANDOFF_2026-07-17_AOTOPSY_UNIVERSAL_RE_PLATFORM.md
// for the full catalog if extending this further.
func compactLines(source string) string {
	lines := strings.Split(source, "\n")
	for pass := 0; pass < 16; pass++ {
		var changed bool
		lines, changed = compactOnePass(lines)
		if !changed {
			break
		}
	}
	return strings.Join(lines, "\n")
}

func compactOnePass(lines []string) ([]string, bool) {
	lines, c1 := removeDeadCodeAfterTerminator(lines)
	lines, c2 := removeEmptyElse(lines)
	lines, c3 := collapseRedundantGuardedReturn(lines)
	lines, c4 := collapseDuplicateReturns(lines)
	lines, c5 := unwrapDeadWhileTrue(lines)
	lines, c7 := collapseIfElseReturn(lines)
	lines, c8 := mergeIfChainContinue(lines)
	lines, c9 := deadStoreElimination(lines)
	lines, c10 := copyPropagation(lines)
	lines, c11 := commonSubexpressionElimination(lines)
	return lines, c1 || c2 || c3 || c4 || c5 || c7 || c8 || c9 || c10 || c11
}

func leadingIndent(line string) int {
	n := 0
	for n < len(line) && line[n] == ' ' {
		n++
	}
	return n / 2
}

func trimmed(line string) string {
	return strings.TrimSpace(line)
}

// isTerminatorStmt reports whether a trimmed line is a statement that
// unconditionally exits its enclosing block (return/continue/break).
func isTerminatorStmt(t string) bool {
	return strings.HasPrefix(t, "return ") || t == "return;" ||
		t == "continue;" || t == "break;"
}

// removeDeadCodeAfterTerminator drops any line at the SAME indent level
// immediately following a terminator statement, up to the next
// close-brace at a lower indent -- mirrors flutterdec's dead-code-after-
// terminal-statement cleanup.
func removeDeadCodeAfterTerminator(lines []string) ([]string, bool) {
	var out []string
	changed := false
	skipIndent := -1
	for _, line := range lines {
		t := trimmed(line)
		ind := leadingIndent(line)
		if skipIndent >= 0 {
			switch {
			case t == "}" && ind < skipIndent:
				skipIndent = -1
			case ind == skipIndent && t != "":
				changed = true
				continue
			case ind < skipIndent:
				skipIndent = -1
			}
		}
		out = append(out, line)
		if isTerminatorStmt(t) {
			skipIndent = ind
		}
	}
	return out, changed
}

// removeEmptyElse deletes an "} else {" / "}" pair with nothing between
// them. The "} else {" line's leading "}" closes the if-block, so we
// must emit a replacement "}" to keep the if-block properly closed.
func removeEmptyElse(lines []string) ([]string, bool) {
	var out []string
	changed := false
	for i := 0; i < len(lines); i++ {
		if trimmed(lines[i]) == "} else {" && i+1 < len(lines) && trimmed(lines[i+1]) == "}" {
			// Emit a replacement "}" to close the if-block (the "}" in
			// "} else {" was the if-block's closing brace).
			indent := leadingIndent(lines[i])
			out = append(out, strings.Repeat("  ", indent)+"}")
			i++
			changed = true
			continue
		}
		out = append(out, lines[i])
	}
	return out, changed
}

// collapseRedundantGuardedReturn finds "if (cond) { return X; }" (no
// else) IMMEDIATELY followed by a bare "return X;" at the same indent,
// and drops the guard (the condition can't change the outcome).
func collapseRedundantGuardedReturn(lines []string) ([]string, bool) {
	var out []string
	changed := false
	for i := 0; i < len(lines); i++ {
		if i+3 < len(lines) &&
			strings.HasPrefix(trimmed(lines[i]), "if (") && strings.HasSuffix(trimmed(lines[i]), ") {") &&
			strings.HasPrefix(trimmed(lines[i+1]), "return ") &&
			trimmed(lines[i+2]) == "}" {
			guardedReturn := trimmed(lines[i+1])
			next := trimmed(lines[i+3])
			if next == guardedReturn && leadingIndent(lines[i]) == leadingIndent(lines[i+3]) {
				changed = true
				i += 2 // skip the whole "if {...}" guard, keep the outer return
				continue
			}
		}
		out = append(out, lines[i])
	}
	return out, changed
}

// collapseDuplicateReturns removes an immediately-repeated identical
// "return X;" line.
func collapseDuplicateReturns(lines []string) ([]string, bool) {
	var out []string
	changed := false
	for i := 0; i < len(lines); i++ {
		t := trimmed(lines[i])
		if strings.HasPrefix(t, "return ") && i+1 < len(lines) && trimmed(lines[i+1]) == t &&
			leadingIndent(lines[i]) == leadingIndent(lines[i+1]) {
			changed = true
			continue
		}
		out = append(out, lines[i])
	}
	return out, changed
}

// unwrapDeadWhileTrue removes a "while (true) { ... }" wrapper whose
// body has no "continue;" and whose last top-level statement already
// terminates (return/break) -- the loop only ever runs once. Mirrors
// flutterdec's while(true) simplification (the retry-loop-synthesis
// half of that same pass is not ported here, see the package doc).
func unwrapDeadWhileTrue(lines []string) ([]string, bool) {
	var out []string
	changed := false
	for i := 0; i < len(lines); i++ {
		if trimmed(lines[i]) == "while (true) {" {
			end := findBlockEnd(lines, i)
			if end > i {
				body := lines[i+1 : end]
				if !containsTopLevelContinue(body, leadingIndent(lines[i])+1) && bodyTerminates(body, leadingIndent(lines[i])+1) {
					out = append(out, dedentBlock(body)...)
					i = end
					changed = true
					continue
				}
			}
		}
		out = append(out, lines[i])
	}
	return out, changed
}

// bodyTerminates reports whether the last top-level statement in body (at the
// given indent) ends in a control-transfer keyword (return/break/continue/
// throw/rethrow). A `while (true) { }` whose body does not terminate is an
// infinite loop and must NOT be unwrapped into a single pass.
func bodyTerminates(body []string, indent int) bool {
	// Find the last non-empty, non-comment top-level line.
	last := ""
	for i := len(body) - 1; i >= 0; i-- {
		t := trimmed(body[i])
		if t == "" || strings.HasPrefix(t, "//") {
			continue
		}
		if leadingIndent(body[i]) != indent {
			continue
		}
		last = t
		break
	}
	if last == "" {
		return false
	}
	for _, kw := range []string{"return", "break", "continue", "throw", "rethrow"} {
		if last == kw || strings.HasPrefix(last, kw+" ") || strings.HasPrefix(last, kw+";") {
			return true
		}
	}
	return false
}

// findBlockEnd returns the index of the line closing the brace opened at
// lines[start] (which must end in "{"), by counting braces -- pure
// brace-counting over text, matching flutterdec's find_block_end.
func findBlockEnd(lines []string, start int) int {
	depth := 0
	for i := start; i < len(lines); i++ {
		depth += strings.Count(lines[i], "{")
		depth -= strings.Count(lines[i], "}")
		if depth == 0 && i > start {
			return i
		}
	}
	return -1
}

// containsTopLevelContinue checks if the body has any "continue;" at or
// deeper than the expected indent level. Fase 7: changed from exact
// indent match to >= indent match, because continue; inside nested
// if/else blocks (deeper indent) is still a valid loop continuation.
func containsTopLevelContinue(body []string, indent int) bool {
	for _, l := range body {
		if leadingIndent(l) >= indent && trimmed(l) == "continue;" {
			return true
		}
	}
	return false
}

func dedentBlock(body []string) []string {
	out := make([]string, 0, len(body))
	for _, l := range body {
		out = append(out, dedentOnce(l))
	}
	return out
}

func dedentOnce(line string) string {
	return strings.TrimPrefix(line, "  ")
}
