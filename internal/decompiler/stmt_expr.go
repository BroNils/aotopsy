package decompiler

import (
	"regexp"
	"strconv"
	"strings"
)

// Expression-level cleanup, driven off the statement tree and the expression
// tree instead of line regexes.
//
// The regex versions had to guess where an expression started and ended, and
// each guess was a separate hazard: the constant folder matched `(1 + 2)`
// inside `foo(1 + 2)` and turned the call into `foo3`, and the negation
// rewriter matched across `||` and applied De Morgan to one conjunct, turning
// `!(a == b || c == d)` into `a != b || c == d`. Both were fixed by narrowing
// the patterns, which is a way of saying the patterns could not tell an
// expression from its surroundings.
//
// Here the statement tree says which text IS an expression, and the
// expression parser either understands that text completely or refuses it. A
// pass that refuses leaves the text byte-for-byte alone.

var (
	// assignExprRe splits `[final ]LHS = RHS;` at the top-level `=`.
	assignExprRe = regexp.MustCompile(`^((?:final\s+)?[A-Za-z_][\w.]*(?:\[[^\]]*\])?\s*=\s*)(.+);$`)
	// returnExprRe splits `return RHS;`.
	returnExprRe = regexp.MustCompile(`^(return\s+)(.+);$`)
)

// rewriteExprs applies fn to every expression slot in the tree, replacing the
// slot when fn returns a different expression. Slots whose text the
// expression parser cannot model are skipped untouched.
func rewriteExprs(stmts []Stmt, fn func(Expr) Expr) bool {
	changed := false
	rewrite := func(src string) (string, bool) {
		out := rewriteExprText(src, fn)
		return out, out != src
	}
	var walk func([]Stmt)
	walk = func(body []Stmt) {
		for _, s := range body {
			switch n := s.(type) {
			case *Line:
				for _, re := range []*regexp.Regexp{assignExprRe, returnExprRe} {
					m := re.FindStringSubmatch(n.Text)
					if m == nil {
						continue
					}
					if got, ch := rewrite(m[2]); ch {
						n.Text = m[1] + got + ";"
						changed = true
					}
					break
				}
			case *Construct:
				for i := range n.Clauses {
					h := n.Clauses[i].Header
					cond := headerCond(h)
					if cond == "" || cond == "true" {
						walk(n.Clauses[i].Body)
						continue
					}
					// Only rewrite conditions of constructs whose header is
					// a single expression. A `for (init; cond; step)` header
					// holds three, and headerCond would hand back all of it.
					if strings.HasPrefix(h, "for (") || strings.Contains(cond, ";") {
						walk(n.Clauses[i].Body)
						continue
					}
					if got, ch := rewrite(cond); ch {
						open := strings.Index(h, "(")
						n.Clauses[i].Header = h[:open+1] + got + ") {"
						changed = true
					}
					walk(n.Clauses[i].Body)
				}
			}
		}
	}
	walk(stmts)
	return changed
}

// rewriteExprText applies fn to an expression AND to every expression nested
// inside the parts the expression tree keeps opaque: call arguments, index
// subscripts, and parenthesised groups that carry a suffix.
//
// Those parts have to be reached explicitly. `(PP + (11 << 12)).f504` parses
// as a single Atom -- a parenthesised group with a `.f504` suffix binds
// tighter than any operator, so the tree deliberately does not decompose it
// -- and without this the inner `11 << 12` never reached the constant folder.
// The regex version folded it, by virtue of not knowing what an expression
// was; losing that would have been a real regression, measured as
// `(PP + 45056)` turning back into `(PP + (11 << 12))` on the compare_sample
// sweep.
func rewriteExprText(src string, fn func(Expr) Expr) string {
	if tree, ok := parseExpr(src); ok {
		if b, isAtom := tree.(*Atom); !isAtom || b.Text != src {
			return printExpr(fn(descendAtoms(tree, fn)))
		}
	}
	// The whole expression is one opaque atom: descend into its bracket
	// groups instead.
	return rewriteBrackets(src, fn)
}

// descendAtoms rewrites the inside of every Atom in a tree.
//
// An atom can still contain expressions -- `(PP + (11 << 12)).f416` is one
// atom, because the `.f416` suffix binds tighter than any operator -- and
// when such an atom is an OPERAND rather than the whole slot, rewriteExprText
// takes the tree path and would otherwise never look inside it. That left 28
// unfolded `11 << 12` in the compare_sample sweep where the regex version had
// none.
//
// Termination: each descent works on the strict inside of a bracket, so the
// text being processed shrinks at every level.
func descendAtoms(e Expr, fn func(Expr) Expr) Expr {
	switch n := e.(type) {
	case *Atom:
		if got := rewriteBrackets(n.Text, fn); got != n.Text {
			return &Atom{Text: got, P: n.P}
		}
		return n
	case *Unary:
		return &Unary{Op: n.Op, X: descendAtoms(n.X, fn)}
	case *Binary:
		return &Binary{Op: n.Op, L: descendAtoms(n.L, fn), R: descendAtoms(n.R, fn)}
	case *Paren:
		return &Paren{X: descendAtoms(n.X, fn)}
	}
	return e
}

// rewriteBrackets rewrites each top-level comma-separated expression inside
// every bracket group of s, recursively.
func rewriteBrackets(s string, fn func(Expr) Expr) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		switch c := s[i]; c {
		case '"', '\'':
			end := skipStringLiteral(s, i)
			out.WriteString(s[i : end+1])
			i = end + 1
		case '(', '[':
			end, ok := matchBracket(s, i)
			if !ok {
				out.WriteString(s[i:])
				return out.String()
			}
			out.WriteByte(c)
			inner := s[i+1 : end]
			for j, part := range splitArgList(inner) {
				if j > 0 {
					out.WriteString(", ")
				}
				out.WriteString(rewriteExprText(strings.TrimSpace(part), fn))
			}
			out.WriteByte(s[end])
			i = end + 1
		default:
			out.WriteByte(c)
			i++
		}
	}
	return out.String()
}

// splitArgList splits an argument list on commas that are not inside a nested bracket
// or a string literal. An empty input yields no parts, so `f()` stays `f()`.
func splitArgList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\'':
			i = skipStringLiteral(s, i)
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, s[start:])
}

// negatedComparison maps a comparison to its negation. Only these six can be
// negated by flipping the operator: negating anything else is not a per-node
// rewrite.
var negatedComparison = map[string]string{
	">": "<=", "<": ">=", ">=": "<", "<=": ">", "==": "!=", "!=": "==",
}

// rewriteNegatedComparisonsExpr rewrites `!(a > b)` to `a <= b`.
//
// The regex version needed a hand-tuned operand charset to avoid spanning
// `&&`/`||`, because `!(a == b || c == d)` is NOT `a != b || c == d` -- De
// Morgan flips the connective too, and applying it to one conjunct inverts
// the meaning. Here the operand of `!` is a parsed node, so a comparison is
// distinguishable from a compound expression by its type, and only the
// comparison is rewritten.
func rewriteNegatedComparisonsExpr(e Expr) Expr {
	switch n := e.(type) {
	case *Unary:
		x := rewriteNegatedComparisonsExpr(n.X)
		if n.Op == "!" {
			if b, ok := x.(*Binary); ok {
				if flipped, ok2 := negatedComparison[b.Op]; ok2 {
					return &Binary{Op: flipped, L: b.L, R: b.R}
				}
			}
		}
		return &Unary{Op: n.Op, X: x}
	case *Binary:
		return &Binary{Op: n.Op, L: rewriteNegatedComparisonsExpr(n.L), R: rewriteNegatedComparisonsExpr(n.R)}
	case *Paren:
		return &Paren{X: rewriteNegatedComparisonsExpr(n.X)}
	}
	return e
}

// intLiteral parses an atom as an integer literal, decimal or hex.
func intLiteral(e Expr) (int64, bool) {
	a, ok := e.(*Atom)
	if !ok {
		return 0, false
	}
	t := a.Text
	if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
		v, err := strconv.ParseInt(t[2:], 16, 64)
		return v, err == nil
	}
	v, err := strconv.ParseInt(t, 10, 64)
	return v, err == nil
}

// constantFoldExpr evaluates integer-only subexpressions.
//
// Only operators that are exact on Dart's 64-bit integers are folded. `/` is
// excluded: in Dart it produces a double even for integer operands, so
// folding it would change both the value and the type. Shifts are folded only
// for a count in [0, 63); the SDK's own behaviour outside that range is not
// something to reproduce from memory.
func constantFoldExpr(e Expr) Expr {
	switch n := e.(type) {
	case *Binary:
		l, r := constantFoldExpr(n.L), constantFoldExpr(n.R)
		a, aok := intLiteral(l)
		b, bok := intLiteral(r)
		if aok && bok {
			if v, ok := foldInt(n.Op, a, b); ok {
				return &Atom{Text: strconv.FormatInt(v, 10), P: precSelector}
			}
		}
		return &Binary{Op: n.Op, L: l, R: r}
	case *Unary:
		x := constantFoldExpr(n.X)
		if n.Op == "-" {
			if v, ok := intLiteral(x); ok {
				return &Atom{Text: strconv.FormatInt(-v, 10), P: precSelector}
			}
		}
		return &Unary{Op: n.Op, X: x}
	case *Paren:
		return &Paren{X: constantFoldExpr(n.X)}
	}
	return e
}

func foldInt(op string, a, b int64) (int64, bool) {
	switch op {
	case "+":
		return a + b, true
	case "-":
		return a - b, true
	case "*":
		return a * b, true
	case "&":
		return a & b, true
	case "|":
		return a | b, true
	case "^":
		return a ^ b, true
	case "<<":
		if b < 0 || b >= 63 {
			return 0, false
		}
		return a << uint(b), true
	case ">>":
		if b < 0 || b >= 63 {
			return 0, false
		}
		return a >> uint(b), true
	case "%", "~/":
		if b == 0 {
			return 0, false // a runtime error, not a constant
		}
		if op == "%" {
			return a % b, true
		}
		return a / b, true
	}
	return 0, false
}

// cleanExprs runs the expression passes over a tree to a fixed point.
// Parenthesis normalisation is not a separate pass: printExpr emits the
// minimum parentheses Dart's grammar allows, so it happens whenever any slot
// is rewritten.
func cleanExprs(stmts []Stmt) bool {
	any := false
	for i := 0; i < 8; i++ {
		changed := rewriteExprs(stmts, func(e Expr) Expr {
			return constantFoldExpr(rewriteNegatedComparisonsExpr(e))
		})
		any = any || changed
		if !changed {
			break
		}
	}
	return any
}
