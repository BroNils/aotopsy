package stmt

import (
	"regexp"
	"strings"
)

// Loop and guard reshaping on the statement tree.

// guardTerminators are the bodies a guard may have for two adjacent guards to
// be merged. Each leaves the enclosing block, so `if (a) { X } if (b) { X }`
// and `if (a || b) { X }` do the same thing -- `||` stops evaluating exactly
// where the original stopped, since b was only reached when a was false.
func isMergeableGuardBody(body []Stmt) (string, bool) {
	var found string
	for _, s := range body {
		if !isCode(s) {
			continue
		}
		l := asLine(s)
		if l == nil || found != "" || !l.isTerminator() {
			return "", false
		}
		found = l.Text
	}
	return found, found != ""
}

// mergeGuardsStmt merges consecutive single-clause guards whose bodies are the
// SAME terminator statement:
//
//	if (a) { continue; } if (b) { continue; }  ->  if (a || b) { continue; }
//	if (x < 0) { return; } if (x >= n) { return; } -> if (x < 0 || x >= n) { return; }
//
// The bodies must be identical text. Two guards that return DIFFERENT values
// are not interchangeable and are left alone.
//
// This replaces two separate text passes. The `continue` one located an if's
// body as "the lines up to the matching brace", which for an if-with-else is
// the THEN branch alone, so an if-with-else looked mergeable and its else
// branch was deleted -- measured, `if (a) { continue; } else { important(); }`
// lost important() entirely. The `return` one (rangeGuardMerging) matched a
// fixed six-line window and so only ever fired on `return;` with no value,
// despite its doc comment claiming it also merged `throw` guards.
func mergeGuardsStmt(body []Stmt) ([]Stmt, bool) {
	guard := func(s Stmt) (*Construct, string, bool) {
		c := asConstruct(s)
		if c == nil || !c.isIf() || len(c.Clauses) != 1 || c.cond() == "" {
			return nil, "", false
		}
		text, ok := isMergeableGuardBody(c.body())
		if !ok {
			return nil, "", false
		}
		return c, text, true
	}
	for i := range body {
		first, action, ok := guard(body[i])
		if !ok {
			continue
		}
		conds := []string{first.cond()}
		j := i + 1
		for j < len(body) {
			if !isCode(body[j]) {
				break
			}
			c, act, ok := guard(body[j])
			if !ok || act != action {
				break
			}
			conds = append(conds, c.cond())
			j++
		}
		if len(conds) < 2 {
			continue
		}
		merged := &Construct{
			Ind:    first.Ind,
			Closer: "}",
			Clauses: []Clause{{
				Header: "if (" + strings.Join(conds, " || ") + ") {",
				Body:   []Stmt{&Line{Ind: first.Ind + 1, Text: action}},
			}},
		}
		out := append([]Stmt{}, body[:i]...)
		out = append(out, merged)
		out = append(out, body[j:]...)
		return out, true
	}
	return body, false
}

// simpleAssignToRe matches `name = <anything>;` and captures the target.
var simpleAssignToRe = regexp.MustCompile(`^([A-Za-z_]\w*)\s*=\s*.+;$`)

// assignTarget returns the variable a line assigns to, or "".
func assignTarget(l *Line) string {
	if l == nil {
		return ""
	}
	m := simpleAssignToRe.FindStringSubmatch(l.Text)
	if m == nil {
		return ""
	}
	return m[1]
}

// forLoopRecoveryStmt rewrites a counted while-loop into a for-loop:
//
//	v = 0;
//	while (v < n) { ...; v = v + 1; }
//	->
//	for (v = 0; v < n; v = v + 1) { ...; }
//
// Three preconditions, each of which the text version got wrong. All three
// were measured on it:
//
//   - The increment must be the loop body's LAST TOP-LEVEL statement. The
//     text version took the first `v = v + 1;` anywhere in the body at any
//     depth, so `while (v < 10) { if (c) { v = v + 1; } }` became
//     `for (v = 0; v < 10; v = v + 1) { if (c) { } }` -- a conditional
//     increment made unconditional, and an if left empty.
//
//   - The init must be the loop's IMMEDIATELY PRECEDING SIBLING. The text
//     version scanned back up to ten lines with no regard for blocks, so
//     `if (p) { v = 0; } while (v < 10) {...}` hoisted the init out of the
//     conditional and left `if (p) { }` behind.
//
//   - The body must contain no `continue;` of this loop's own. `continue` in
//     a for runs the increment; in a while it skips it. The text version
//     rewrote `while (v < 10) { if (c) { continue; } v = v + 1; }` -- an
//     infinite loop when c holds -- into a for-loop that terminates. A
//     decompiler that repairs the program is not describing the binary.
func forLoopRecoveryStmt(body []Stmt) ([]Stmt, bool) {
	for i, s := range body {
		c := asConstruct(s)
		if c == nil || len(c.Clauses) != 1 || !strings.HasPrefix(c.Clauses[0].Header, "while (") {
			continue
		}
		cond := c.cond()
		if cond == "" || cond == "true" {
			continue
		}
		iter := ExtractIterVarFromCond(cond)
		if iter == "" {
			continue
		}
		inner := c.body()
		last := asLine(lastCode(inner))
		if assignTarget(last) != iter || !strings.HasPrefix(last.Text, iter+" = "+iter+" ") {
			continue
		}
		if containsContinueForThisLoop(inner) {
			continue
		}
		// The init is the previous sibling, and must not itself be an
		// increment of the same variable.
		prevIdx := prevCodeIndex(body, i)
		if prevIdx < 0 {
			continue
		}
		initLine := asLine(body[prevIdx])
		if assignTarget(initLine) != iter || strings.HasPrefix(initLine.Text, iter+" = "+iter+" ") {
			continue
		}
		init := strings.TrimSuffix(initLine.Text, ";")
		incr := strings.TrimSuffix(last.Text, ";")

		// Drop the increment from the body, keeping any trailing comments.
		newInner := make([]Stmt, 0, len(inner))
		for _, st := range inner {
			if st == Stmt(last) {
				continue
			}
			newInner = append(newInner, st)
		}
		loop := &Construct{
			Ind:     c.Ind,
			Closer:  c.Closer,
			Clauses: []Clause{{Header: "for (" + init + "; " + cond + "; " + incr + ") {", Body: newInner}},
		}
		out := append([]Stmt{}, body[:prevIdx]...)
		out = append(out, body[prevIdx+1:i]...)
		out = append(out, loop)
		out = append(out, body[i+1:]...)
		return out, true
	}
	return body, false
}

// prevCodeIndex returns the index of the last statement-carrying sibling
// before i, or -1.
func prevCodeIndex(body []Stmt, i int) int {
	for j := i - 1; j >= 0; j-- {
		if isCode(body[j]) {
			return j
		}
	}
	return -1
}

// There is deliberately no null-check-hoisting pass here.
//
// The text version annotated `if (x == null) { return; }` at a function's
// entry with a `// null-check guard` comment. It never fired, for a reason
// that only became visible once NULL_REG was decoded: before that, the
// condition read `x == x22` and the string "== null" appeared nowhere in the
// output at all.
//
// With `null` now rendered, the 2.12 sample has 14814 `== null` conditions --
// and still zero functions where one is a TOP-LEVEL guard among the first
// statements of the body. Measured across both ARM64 samples: 1892 functions,
// 0 hits. The emitter always emits a prologue first and puts guards inside
// branch structure, so an "entry precondition" in the source is never an
// entry-level statement here.
//
// Relaxing it to any depth would annotate all 14814, which is noise rather
// than information. So the pass has no shape that earns its place, and
// carrying it would be carrying code that cannot fire.
