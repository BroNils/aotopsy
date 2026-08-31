package stmt

import "strings"

// Structural readability passes, working on the statement tree from stmt.go.
//
// Each of these previously re-derived nesting for itself by counting braces
// and dividing leading spaces by two. Two of them could emit unbalanced
// braces as a result -- see collapseIfElseReturnStmt and mergeGuardsStmt,
// where the specific defect is recorded. A Construct knows its own
// clauses and its own extent, so "the else branch" is a field rather than
// something to be re-discovered, and dropping a clause by accident is not
// expressible.

// compactTree runs the structural passes to a fixed point.
func CompactTree(stmts []Stmt) ([]Stmt, bool) {
	anyChanged := false
	for pass := 0; pass < 16; pass++ {
		changed := false
		for _, fn := range []func([]Stmt) ([]Stmt, bool){
			removeDeadCodeAfterTerminatorStmt,
			removeSelfAssignStmt,
			removeEmptyElseStmt,
			collapseElseIfStmt,
			collapseRedundantGuardedReturnStmt,
			collapseDuplicateReturnsStmt,
			unwrapDeadWhileTrueStmt,
			collapseIfElseReturnStmt,
			mergeGuardsStmt,
			forLoopRecoveryStmt,
			deadStoreEliminationStmt,
		} {
			var c bool
			stmts, c = mapBodies(stmts, fn)
			changed = changed || c
		}
		anyChanged = anyChanged || changed
		if !changed {
			break
		}
	}
	return stmts, anyChanged
}

// removeDeadCodeAfterTerminatorStmt drops the statements that follow an
// unconditional return/continue/break in the same block.
//
// The text version approximated "same block" with "same indent, until a
// close-brace at a lower indent", which made it depend on the very
// indentation the other passes were rewriting. Siblings in a body are exactly
// the statements that follow in the same block, so no such rule is needed --
// with one exception the indent rule got for free and this one must state:
// a LABEL can be jumped to, so it ends the dead region. A switch body is a
// flat list of `case N:` labels and statements, and `break;` is a terminator,
// so without this every switch collapsed to its first case. That is a
// regression this pass caused when it first moved to the tree; it showed up
// on the compare_sample sweep as a 45-line switch losing cases 1 through 3
// and its default.
func removeDeadCodeAfterTerminatorStmt(body []Stmt) ([]Stmt, bool) {
	for i, s := range body {
		l := asLine(s)
		if l == nil || !l.isTerminator() {
			continue
		}
		rest := body[i+1:]
		kept := make([]Stmt, 0, len(rest))
		dropped := false
		for j, r := range rest {
			if rl := asLine(r); rl != nil && rl.isLabel() {
				kept = append(kept, rest[j:]...) // reachable again
				break
			}
			// Keep comments -- they annotate the terminator, and dropping
			// them loses the emitter's own notes about omitted control flow.
			if isCode(r) {
				dropped = true
				continue
			}
			kept = append(kept, r)
		}
		if !dropped {
			continue
		}
		return append(append([]Stmt{}, body[:i+1]...), kept...), true
	}
	return body, false
}

// collapseElseIfStmt rewrites an else branch whose whole body is one `if`
// into an `else if` clause on the outer construct:
//
//	} else {          ->   } else if (c) {
//	  if (c) {               ...
//	    ...
//	  }
//	}
//
// The emitter nests instead of chaining, which costs a level of indentation
// per alternative and buries long chains: 14357 of these on the 3.x ARM64
// sample and 30993 on the x86_64 one.
//
// Only fires when the else body is EXACTLY one if-construct and nothing
// else, so no statement or comment can be lost. The inner construct's own
// else/else-if clauses come along, and its closing brace is dropped because
// the outer one now closes the whole chain.
func collapseElseIfStmt(body []Stmt) ([]Stmt, bool) {
	changed := false
	for _, s := range body {
		c := asConstruct(s)
		if c == nil || len(c.Clauses) == 0 {
			continue
		}
		last := len(c.Clauses) - 1
		if c.Clauses[last].Header != "} else {" {
			continue
		}
		inner := onlyConstruct(c.Clauses[last].Body)
		if inner == nil || !inner.isIf() {
			continue
		}
		// The inner clauses move up one nesting level.
		for i := range inner.Clauses {
			for _, st := range inner.Clauses[i].Body {
				st.shift(-1)
			}
		}
		merged := make([]Clause, 0, last+len(inner.Clauses))
		merged = append(merged, c.Clauses[:last]...)
		merged = append(merged, Clause{
			Header: "} else " + inner.Clauses[0].Header,
			Body:   inner.Clauses[0].Body,
		})
		merged = append(merged, inner.Clauses[1:]...)
		c.Clauses = merged
		changed = true
	}
	return body, changed
}

// onlyConstruct returns the body's single statement when it is a Construct
// and nothing else carries code, else nil.
func onlyConstruct(body []Stmt) *Construct {
	var found *Construct
	for _, s := range body {
		if !isCode(s) {
			return nil // a comment or blank would be lost by merging
		}
		c := asConstruct(s)
		if c == nil || found != nil {
			return nil
		}
		found = c
	}
	return found
}

// removeEmptyElseStmt drops an else clause with no statements in it.
func removeEmptyElseStmt(body []Stmt) ([]Stmt, bool) {
	changed := false
	for _, s := range body {
		c := asConstruct(s)
		if c == nil || len(c.Clauses) < 2 {
			continue
		}
		last := len(c.Clauses) - 1
		if c.Clauses[last].Header != "} else {" {
			continue
		}
		if len(c.Clauses[last].Body) != 0 {
			continue
		}
		c.Clauses = c.Clauses[:last]
		changed = true
	}
	return body, changed
}

// singleReturn returns the body's only statement when it is a `return ...;`,
// else "".
func singleReturn(body []Stmt) string {
	var found string
	for _, s := range body {
		if !isCode(s) {
			continue
		}
		l := asLine(s)
		if l == nil || found != "" || !strings.HasPrefix(l.Text, "return") {
			return ""
		}
		found = l.Text
	}
	return found
}

// collapseRedundantGuardedReturnStmt drops `if (c) { return X; }` when the
// very next statement is the same `return X;` -- the guard cannot change the
// outcome.
func collapseRedundantGuardedReturnStmt(body []Stmt) ([]Stmt, bool) {
	for i := 0; i+1 < len(body); i++ {
		c := asConstruct(body[i])
		if c == nil || !c.isIf() || len(c.Clauses) != 1 {
			continue
		}
		ret := singleReturn(c.body())
		if ret == "" {
			continue
		}
		next := asLine(body[i+1])
		if next == nil || next.Text != ret {
			continue
		}
		return append(append([]Stmt{}, body[:i]...), body[i+1:]...), true
	}
	return body, false
}

// collapseDuplicateReturnsStmt removes an immediately repeated `return X;`.
func collapseDuplicateReturnsStmt(body []Stmt) ([]Stmt, bool) {
	for i := 0; i+1 < len(body); i++ {
		a, b := asLine(body[i]), asLine(body[i+1])
		if a == nil || b == nil || a.Text != b.Text || !strings.HasPrefix(a.Text, "return") {
			continue
		}
		return append(append([]Stmt{}, body[:i]...), body[i+1:]...), true
	}
	return body, false
}

// containsContinue reports whether the body has a `continue;` that belongs to
// THIS loop -- one not swallowed by a nested loop.
//
// The text version tested `indent >= loop indent`, which is every continue in
// the body including those inside a nested `while`, where the keyword targets
// the inner loop and says nothing about the outer one. That direction is
// conservative -- it declined to unwrap loops it safely could have -- so this
// is a coverage gain, not a correctness fix. The tree lets the nested loop
// actually be skipped.
func containsContinueForThisLoop(body []Stmt) bool {
	for _, s := range body {
		switch n := s.(type) {
		case *Line:
			if n.Text == "continue;" {
				return true
			}
		case *Construct:
			if isLoopHeader(n.Clauses[0].Header) {
				continue // a `continue;` in there belongs to the inner loop
			}
			for i := range n.Clauses {
				if containsContinueForThisLoop(n.Clauses[i].Body) {
					return true
				}
			}
		}
	}
	return false
}

func isLoopHeader(header string) bool {
	return strings.HasPrefix(header, "while (") ||
		strings.HasPrefix(header, "for (") ||
		header == "do {"
}

// bodyTerminatesStmt reports whether the body's last statement transfers
// control out of the block.
func bodyTerminatesStmt(body []Stmt) bool {
	last := lastCode(body)
	if last == nil {
		return false
	}
	l := asLine(last)
	if l == nil {
		return false
	}
	for _, kw := range []string{"return", "break", "continue", "throw", "rethrow"} {
		if l.Text == kw || strings.HasPrefix(l.Text, kw+" ") || strings.HasPrefix(l.Text, kw+";") {
			return true
		}
	}
	return false
}

// unwrapDeadWhileTrueStmt removes a `while (true) { ... }` whose body cannot
// loop: it has no `continue;` of its own and always terminates.
func unwrapDeadWhileTrueStmt(body []Stmt) ([]Stmt, bool) {
	for i, s := range body {
		c := asConstruct(s)
		if c == nil || !c.isWhileTrue() {
			continue
		}
		inner := c.body()
		if containsContinueForThisLoop(inner) || !bodyTerminatesStmt(inner) {
			continue
		}
		for _, n := range inner {
			n.shift(-1)
		}
		out := append([]Stmt{}, body[:i]...)
		out = append(out, inner...)
		out = append(out, body[i+1:]...)
		return out, true
	}
	return body, false
}

// collapseIfElseReturnStmt collapses an if whose branches both return the
// same value:
//
//	if (c) { return X; } else { return X; }  ->  return X;
//	if (c) { return X; } return X;           ->  return X;
//
// The text version could only ever do the second of these. Its else handling
// looked for a line reading `else {`, which this emitter never writes -- it
// writes `} else {` -- so that half was unreachable. And because its
// brace-counting treated `} else {` as net zero, "the if's block" ran to the
// END of the whole if-else, making the then-branch look like it held both
// branches' statements. A clause is a field here, so both shapes are decided
// by asking rather than by counting.
func collapseIfElseReturnStmt(body []Stmt) ([]Stmt, bool) {
	for i, s := range body {
		c := asConstruct(s)
		if c == nil || !c.isIf() {
			continue
		}
		thenRet := singleReturn(c.Clauses[0].Body)
		if thenRet == "" {
			continue
		}
		ind := c.Ind
		// Both branches return the same value.
		if len(c.Clauses) == 2 && c.Clauses[1].Header == "} else {" {
			if singleReturn(c.Clauses[1].Body) != thenRet {
				continue
			}
			out := append([]Stmt{}, body[:i]...)
			out = append(out, &Line{Ind: ind, Text: thenRet})
			out = append(out, body[i+1:]...)
			return out, true
		}
		// A guard followed by the same return.
		if len(c.Clauses) != 1 {
			continue
		}
		var next *Line
		for _, r := range body[i+1:] {
			if isCode(r) {
				next = asLine(r)
				break
			}
		}
		if next == nil || next.Text != thenRet {
			continue
		}
		out := append([]Stmt{}, body[:i]...)
		out = append(out, &Line{Ind: ind, Text: thenRet})
		out = append(out, body[i+1:]...)
		return out, true
	}
	return body, false
}

// deadStoreEliminationStmt removes an assignment whose variable is reassigned
// by the very next statement without being read in between, provided the
// dropped right-hand side cannot do anything but compute a value.
//
// "The next statement" is a sibling here. The text version used the next
// LINE, which meant a store immediately followed by a nested block's first
// line was compared against a statement in a different scope.
func deadStoreEliminationStmt(body []Stmt) ([]Stmt, bool) {
	for i := 0; i+1 < len(body); i++ {
		a, b := asLine(body[i]), asLine(body[i+1])
		if a == nil || b == nil {
			continue
		}
		lhsA, rhsA, ok := splitSimpleAssign(a.Text)
		if !ok || HasSideEffect(rhsA) {
			continue
		}
		lhsB, rhsB, ok := splitSimpleAssign(b.Text)
		if !ok || lhsB != lhsA {
			continue
		}
		if ReferencesIdent(rhsB, lhsA) {
			continue
		}
		return append(append([]Stmt{}, body[:i]...), body[i+1:]...), true
	}
	return body, false
}

// splitSimpleAssign splits `name = expr;` into its parts. It rejects
// declarations, compound assignments and comparisons.
func splitSimpleAssign(text string) (lhs, rhs string, ok bool) {
	m := SimpleAssignRe.FindStringSubmatch(text)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// removeSelfAssignStmt removes redundant self-assignments like `x = x;`.
func removeSelfAssignStmt(body []Stmt) ([]Stmt, bool) {
	for i, s := range body {
		l := asLine(s)
		if l == nil {
			continue
		}
		lhs, rhs, ok := splitSimpleAssign(l.Text)
		if ok && lhs == rhs {
			return append(append([]Stmt{}, body[:i]...), body[i+1:]...), true
		}
	}
	return body, false
}
