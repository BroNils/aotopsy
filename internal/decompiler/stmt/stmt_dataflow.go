package stmt

import (
	"regexp"
	"strings"
)

// Copy propagation and CSE on the statement tree.
//
// Both passes need two things the text versions could only approximate:
// document order (is this use after that definition?) and SCOPE (is this
// definition even visible here?).
//
// Order they got right, because line index is document order. Scope they did
// not: both used "same or deeper indentation" as a proxy, which two sibling
// blocks satisfy equally. `if (a) { t1 = x; } if (b) { use(t1); }` has both
// bodies at the same indent, so a temp defined in the first branch was
// propagated into the second -- where it is not defined at all, and where the
// first branch may never have run. CSE had the same hole with `final tN`.
//
// On the tree, scope is the recursion: a definition made while walking a body
// is visible to the rest of that body and to bodies nested inside it, and it
// disappears when the walk leaves. Nothing has to be approximated.

var (
	// simpleCopyRe matches `tN = ident;`.
	simpleCopyRe = regexp.MustCompile(`^(t\d+)\s*=\s*(\w+);$`)
	// tempAssignRe matches any assignment to a temp, final or not.
	tempAssignRe = regexp.MustCompile(`^(?:final\s+)?(t\d+)\s*=`)
	// cseDeclRe matches a CSE-eligible declaration `final tN = expr;`.
	cseDeclRe = regexp.MustCompile(`^final (t\d+) = (.+);$`)
	// identRe matches a bare identifier.
	identRe = regexp.MustCompile(`[A-Za-z_]\w*`)
)

// exprOperands returns the identifiers an expression reads, or ok=false when
// the expression is beyond what these passes can reason about -- member or
// index access, where aliasing and side effects are invisible.
func exprOperands(expr string) (ids []string, ok bool) {
	if strings.Contains(expr, ".") || strings.Contains(expr, "[") {
		return nil, false
	}
	for _, id := range identRe.FindAllString(expr, -1) {
		switch id {
		case "true", "false", "null", "this":
			continue
		}
		ids = append(ids, id)
	}
	return ids, true
}

// operandsUnchangedBetween reports whether none of ids is assigned in the
// half-open document range (after, upTo].
func operandsUnchangedBetween(ids []string, assigns map[string][]int, after, upTo int) bool {
	for _, id := range ids {
		for _, at := range assigns[id] {
			if at > after && at <= upTo {
				return false
			}
		}
	}
	return true
}

// lineRef is one leaf line together with its document-order position.
type lineRef struct {
	line *Line
	idx  int
}

// flattenLines returns every Line in document order. Construct headers and
// closers are not Lines, so they are reported separately by flattenTexts.
func flattenLines(stmts []Stmt) []lineRef {
	var out []lineRef
	var walk func([]Stmt)
	walk = func(body []Stmt) {
		for _, s := range body {
			switch n := s.(type) {
			case *Line:
				out = append(out, lineRef{line: n, idx: len(out)})
			case *Construct:
				for i := range n.Clauses {
					walk(n.Clauses[i].Body)
				}
			}
		}
	}
	walk(stmts)
	return out
}

// copyPropagationStmt replaces uses of a copy temp with its source:
//
//	t1 = arg0;  t2 = t1 + 1;  ->  t2 = arg0 + 1;
//
// A copy is propagated only when the temp is assigned exactly once, is not
// `final`, and its SOURCE is stable: assigned at most once in the whole
// function, with that definition textually before the copy. Otherwise the
// temp holds an older value than the name would suggest.
func CopyPropagationStmt(stmts []Stmt) bool {
	flat := flattenLines(stmts)
	if len(flat) == 0 {
		return false
	}
	pos := make(map[*Line]int, len(flat))
	texts := make([]string, len(flat))
	for _, r := range flat {
		pos[r.line] = r.idx
		texts[r.idx] = r.line.Text
	}

	assignCount := map[string]int{}
	declaredFinal := map[string]bool{}
	for _, t := range texts {
		if m := tempAssignRe.FindStringSubmatch(t); m != nil {
			assignCount[m[1]]++
			if strings.HasPrefix(t, "final ") {
				declaredFinal[m[1]] = true
			}
		}
	}
	srcAssign := map[string]int{}
	lastSrcAssign := map[string]int{}
	for i, t := range texts {
		if m := AnyAssignRe.FindStringSubmatch(t); m != nil {
			srcAssign[m[1]]++
			lastSrcAssign[m[1]] = i
		}
	}

	eligible := func(l *Line) (temp, src string, ok bool) {
		m := simpleCopyRe.FindStringSubmatch(l.Text)
		if m == nil {
			return "", "", false
		}
		temp, src = m[1], m[2]
		if assignCount[temp] != 1 || declaredFinal[temp] {
			return "", "", false
		}
		if srcAssign[src] > 1 {
			return "", "", false
		}
		if srcAssign[src] == 1 && lastSrcAssign[src] > pos[l] {
			return "", "", false
		}
		return temp, src, true
	}

	changed := false
	apply := func(env map[string]string, text string) string {
		for temp, src := range env {
			if re := identBoundaryRe(temp); re.MatchString(text) {
				text = re.ReplaceAllString(text, src)
				changed = true
			}
		}
		return text
	}

	var walk func(body []Stmt, env map[string]string)
	walk = func(body []Stmt, env map[string]string) {
		local := make(map[string]string, len(env))
		for k, v := range env {
			local[k] = v
		}
		for _, s := range body {
			switch n := s.(type) {
			case *Line:
				// Control can arrive at a label from elsewhere, where none of
				// these copies were made. Everything learned so far stops
				// being known here.
				if n.isLabel() {
					local = map[string]string{}
					continue
				}
				if temp, src, ok := eligible(n); ok {
					// Resolve through an existing copy so a chain collapses
					// to its ultimate source in one pass.
					if via, ok2 := local[src]; ok2 {
						src = via
					}
					local[temp] = src
					continue
				}
				n.Text = apply(local, n.Text)
			case *Construct:
				for i := range n.Clauses {
					n.Clauses[i].Header = apply(local, n.Clauses[i].Header)
					walk(n.Clauses[i].Body, local)
				}
				n.Closer = apply(local, n.Closer)
			}
		}
	}
	walk(stmts, map[string]string{})
	return changed
}

// identBoundaryRe builds a whole-word matcher for an identifier.
func identBoundaryRe(id string) *regexp.Regexp {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(id) + `\b`)
}

// commonSubexpressionEliminationStmt replaces a repeated expression with the
// temp that already holds it:
//
//	final t1 = a + b;  ...  use(a + b);  ->  use(t1);
//
// Guarded on three counts: the temp must be assigned exactly once, the
// expression must be call-free and operand-transparent (no member or index
// access, where aliasing is invisible), and nothing the expression reads may
// have been written between the definition and the reuse.
func CommonSubexpressionEliminationStmt(stmts []Stmt) bool {
	flat := flattenLines(stmts)
	if len(flat) == 0 {
		return false
	}
	pos := make(map[*Line]int, len(flat))
	texts := make([]string, len(flat))
	for _, r := range flat {
		pos[r.line] = r.idx
		texts[r.idx] = r.line.Text
	}

	assignCount := map[string]int{}
	for _, t := range texts {
		if m := tempAssignRe.FindStringSubmatch(t); m != nil {
			assignCount[m[1]]++
		}
	}
	assigns := map[string][]int{}
	for i, t := range texts {
		if m := AnyAssignRe.FindStringSubmatch(t); m != nil {
			assigns[m[1]] = append(assigns[m[1]], i)
		}
	}

	type cseEntry struct {
		temp string
		at   int
		ids  []string
	}

	eligible := func(l *Line) (expr string, e cseEntry, ok bool) {
		m := cseDeclRe.FindStringSubmatch(l.Text)
		if m == nil {
			return "", e, false
		}
		temp, expr := m[1], m[2]
		if assignCount[temp] > 1 || len(expr) < 8 {
			return "", e, false
		}
		if !strings.ContainsAny(expr, "+-*/&|^><%") {
			return "", e, false
		}
		if strings.Contains(expr, "(") && strings.Contains(expr, ")") {
			return "", e, false
		}
		ids, okOperands := exprOperands(expr)
		if !okOperands {
			return "", e, false
		}
		return expr, cseEntry{temp: temp, at: pos[l], ids: ids}, true
	}

	changed := false
	apply := func(env map[string]cseEntry, text string, at int) string {
		for expr, e := range env {
			if !strings.Contains(text, expr) {
				continue
			}
			if !operandsUnchangedBetween(e.ids, assigns, e.at, at) {
				continue
			}
			if got := ReplaceExactSubstring(text, expr, e.temp); got != text {
				text = got
				changed = true
			}
		}
		return text
	}

	var walk func(body []Stmt, env map[string]cseEntry)
	walk = func(body []Stmt, env map[string]cseEntry) {
		local := make(map[string]cseEntry, len(env))
		for k, v := range env {
			local[k] = v
		}
		for _, s := range body {
			switch n := s.(type) {
			case *Line:
				// A jump to this label skips every declaration above it, so
				// no temp is known to hold its expression here.
				if n.isLabel() {
					local = map[string]cseEntry{}
					continue
				}
				if expr, e, ok := eligible(n); ok {
					if _, exists := local[expr]; !exists {
						local[expr] = e
					}
					continue
				}
				n.Text = apply(local, n.Text, pos[n])
			case *Construct:
				// A construct header is evaluated at the position of the
				// first line inside it, which is the tightest bound
				// available for the operand-mutation check.
				at := constructPos(n, pos)
				for i := range n.Clauses {
					n.Clauses[i].Header = apply(local, n.Clauses[i].Header, at)
					walk(n.Clauses[i].Body, local)
				}
			}
		}
	}
	walk(stmts, map[string]cseEntry{})
	return changed
}

// constructPos returns the document position of a construct, taken from its
// first contained line. Falls back to 0 when it contains none, which makes
// the operand-mutation check maximally conservative rather than optimistic.
func constructPos(c *Construct, pos map[*Line]int) int {
	for i := range c.Clauses {
		for _, s := range c.Clauses[i].Body {
			switch n := s.(type) {
			case *Line:
				return pos[n]
			case *Construct:
				if p := constructPos(n, pos); p != 0 {
					return p
				}
			}
		}
	}
	return 0
}
