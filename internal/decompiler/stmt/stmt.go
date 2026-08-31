package stmt

import (
	"regexp"
	"strings"
)

// This file gives the readability passes a real statement tree to work on.
//
// The passes used to be brace-counting text rewrites over []string: each one
// re-derived nesting for itself with strings.Count(line, "{") and
// len(indent)/2 arithmetic. That is where their bugs lived. Counting braces
// with strings.Count also counts braces inside string literals, so a single
// emitted `"{"` desynchronised every structural pass downstream of it.
//
// The input here is not arbitrary Dart -- it is this package's OWN emitter
// output, which is line-oriented, two-space indented, and one statement per
// line. So the tree is recovered exactly rather than approximately, and the
// parser is total: anything it cannot model is preserved verbatim rather than
// dropped or guessed at. parseStmts/printStmts round-trip byte-for-byte
// (asserted by TestStmtRoundTripIsExact on real sample output), which is what
// makes it safe to run a pass and keep the result.

// Stmt is one node of the statement tree.
type Stmt interface {
	// render appends this node's lines to out.
	render(out *[]string)
	// indentOf reports the node's nesting level, or -1 when unknown
	// (Verbatim, whose original whitespace is preserved as-is).
	indentOf() int
	// shift changes the node's nesting level by delta, recursively.
	shift(delta int)
}

// Line is a leaf: one statement, comment, or label.
type Line struct {
	Ind  int
	Text string // trimmed
}

func (l *Line) render(out *[]string) { *out = append(*out, IndentStr(l.Ind)+l.Text) }
func (l *Line) indentOf() int        { return l.Ind }
func (l *Line) shift(delta int) {
	if l.Ind += delta; l.Ind < 0 {
		l.Ind = 0
	}
}

// Verbatim preserves a line the parser chose not to model -- one whose
// leading whitespace is not a whole number of two-space levels, or a blank
// line. Its bytes are reproduced exactly and no pass rewrites it.
type Verbatim struct{ Raw string }

func (v *Verbatim) render(out *[]string) { *out = append(*out, v.Raw) }
func (v *Verbatim) indentOf() int        { return -1 }
func (v *Verbatim) shift(int)            {}

// Clause is one header-plus-body section of a Construct: the `if (c) {` part,
// an `} else if (d) {` part, an `} else {` part, a `} catch (e) {` part.
// Header is trimmed and includes its trailing brace.
type Clause struct {
	Header string
	Body   []Stmt
}

// Construct is any braced construct -- if/else chains, loops, try/catch,
// switch. One node type covers them all because the passes care about the
// same three things in every case: the header text, the exact body, and where
// the construct ends. Kind-specific questions are asked through the helpers
// below (isIf, cond, isWhileTrue, ...) rather than through separate types.
type Construct struct {
	Ind     int
	Clauses []Clause
	Closer  string // trimmed closing line, normally "}"
	// Unterminated marks a construct whose closing brace is missing from the
	// input (truncated output). Rendering must not invent one, or round-trip
	// would silently add a line.
	Unterminated bool
}

func (c *Construct) render(out *[]string) {
	for _, cl := range c.Clauses {
		*out = append(*out, IndentStr(c.Ind)+cl.Header)
		for _, s := range cl.Body {
			s.render(out)
		}
	}
	if !c.Unterminated {
		*out = append(*out, IndentStr(c.Ind)+c.Closer)
	}
}

func (c *Construct) indentOf() int { return c.Ind }

func (c *Construct) shift(delta int) {
	if c.Ind += delta; c.Ind < 0 {
		c.Ind = 0
	}
	for i := range c.Clauses {
		for _, s := range c.Clauses[i].Body {
			s.shift(delta)
		}
	}
}

// printStmts renders a tree back to lines.
func PrintStmts(stmts []Stmt) []string {
	out := make([]string, 0, len(stmts)*2)
	for _, s := range stmts {
		s.render(&out)
	}
	return out
}

// braceDelta returns the net brace balance of a line, ignoring braces inside
// string literals and after a line comment.
//
// The old passes used strings.Count(line, "{") - strings.Count(line, "}"),
// which counts braces in emitted string literals and in `// ...` comments.
// One such line shifted every structural decision after it.
func BraceDelta(text string) int {
	d := 0
	for i := 0; i < len(text); i++ {
		switch c := text[i]; c {
		case '\'', '"':
			i = skipStringLiteral(text, i)
		case '/':
			if i+1 < len(text) && text[i+1] == '/' {
				return d // rest of line is a comment
			}
		case '{':
			d++
		case '}':
			d--
		}
	}
	return d
}

// skipStringLiteral returns the index of the closing quote of the literal
// opening at text[start], or len(text)-1 when the literal is unterminated.
func skipStringLiteral(text string, start int) int {
	q := text[start]
	for i := start + 1; i < len(text); i++ {
		switch text[i] {
		case '\\':
			i++ // skip the escaped character
		case q:
			return i
		}
	}
	return len(text) - 1
}

// splitIndent reports a line's nesting level and trimmed text. ok is false
// when the leading whitespace is not a whole number of two-space levels, or
// the line is blank -- such lines become Verbatim.
func SplitIndent(line string) (ind int, text string, ok bool) {
	n := 0
	for n < len(line) && line[n] == ' ' {
		n++
	}
	if n%2 != 0 || n == len(line) {
		return 0, "", false
	}
	if strings.ContainsAny(line[:n], "\t") {
		return 0, "", false
	}
	return n / 2, line[n:], true
}

// parseStmts recovers the statement tree from emitter output.
//
// Structure comes from brace balance, not from indentation, so a construct
// whose body a pass has already re-indented still parses. Indentation is only
// recorded, never trusted for nesting.
func ParseStmts(lines []string) []Stmt {
	p := &stmtParser{lines: lines}
	return p.parseBody(0)
}

type stmtParser struct {
	lines []string
	i     int
}

// parseBody consumes lines until the brace depth would drop below zero
// relative to where it started, i.e. until the enclosing construct's closer.
// The closer itself is left unconsumed for the caller.
func (p *stmtParser) parseBody(depth int) []Stmt {
	var out []Stmt
	for p.i < len(p.lines) {
		line := p.lines[p.i]
		ind, text, ok := SplitIndent(line)
		if !ok {
			out = append(out, &Verbatim{Raw: line})
			p.i++
			continue
		}
		d := BraceDelta(text)
		// A line that closes more than it opens ends this body -- and so does
		// a continuation clause, which has a leading `}` but nets to zero
		// because it reopens (`} else if (b) {`). Testing only d < 0 swallowed
		// those as ordinary statements, flattening every else-if chain into a
		// single clause.
		if d < 0 || strings.HasPrefix(text, "}") {
			return out
		}
		if d == 0 {
			out = append(out, &Line{Ind: ind, Text: text})
			p.i++
			continue
		}
		// d > 0: opens a construct.
		out = append(out, p.parseConstruct(ind, depth))
	}
	return out
}

// parseConstruct consumes a construct starting at the current line, including
// every `} else {` / `} catch {` continuation clause and the final closer.
func (p *stmtParser) parseConstruct(ind, depth int) Stmt {
	c := &Construct{Ind: ind}
	for {
		_, header, _ := SplitIndent(p.lines[p.i])
		p.i++
		body := p.parseBody(depth + 1)
		c.Clauses = append(c.Clauses, Clause{Header: header, Body: body})
		if p.i >= len(p.lines) {
			// Truncated output: record the missing closer rather than
			// inventing one, so printing reproduces the input exactly.
			c.Closer, c.Unterminated = "}", true
			return c
		}
		_, text, ok := SplitIndent(p.lines[p.i])
		if !ok {
			c.Closer, c.Unterminated = "}", true
			return c
		}
		// A continuation clause both closes and reopens: net balance 0 with a
		// leading `}` (e.g. `} else {`, `} catch (e) {`).
		if BraceDelta(text) == 0 && strings.HasPrefix(text, "}") {
			continue
		}
		c.Closer = text
		p.i++
		return c
	}
}

// --- Construct helpers: the questions the passes actually ask. ---

// isIf reports whether the construct's first clause is an `if`.
func (c *Construct) isIf() bool { return strings.HasPrefix(c.Clauses[0].Header, "if (") }

// hasElse reports whether the construct has a plain trailing `} else {`.
func (c *Construct) hasElse() bool {
	n := len(c.Clauses)
	return n > 1 && c.Clauses[n-1].Header == "} else {"
}

// cond returns the condition text of an `if (...) {` or `while (...) {`
// header, or "" when the header is not of that shape.
func headerCond(header string) string {
	open := strings.Index(header, "(")
	if open < 0 || !strings.HasSuffix(header, ") {") {
		return ""
	}
	return strings.TrimSpace(header[open+1 : len(header)-3])
}

func (c *Construct) cond() string { return headerCond(c.Clauses[0].Header) }

// isWhileTrue reports whether this is a bare `while (true) {` construct.
func (c *Construct) isWhileTrue() bool {
	return len(c.Clauses) == 1 && c.Clauses[0].Header == "while (true) {"
}

// body returns the single clause's body, for constructs with exactly one.
func (c *Construct) body() []Stmt { return c.Clauses[0].Body }

// isTerminator reports whether a leaf line unconditionally leaves its block.
func (l *Line) isTerminator() bool { return IsTerminatorStmt(l.Text) }

// isLabel reports whether a leaf line is a branch TARGET rather than a
// statement: a switch `case N:`/`default:`, or an emitted `block_N:;` goto
// label.
//
// Control can arrive at a label without executing anything before it, so a
// label ends any reasoning that depends on straight-line flow -- code after
// one is not dead just because a `break;` precedes it, and a value defined
// before one is not necessarily defined at it.
func (l *Line) isLabel() bool {
	t := l.Text
	if t == "default:" || strings.HasPrefix(t, "case ") && strings.HasSuffix(t, ":") {
		return true
	}
	return LabelDeclRe.MatchString(t)
}

// asLine returns the node as a *Line, or nil.
func asLine(s Stmt) *Line {
	l, _ := s.(*Line)
	return l
}

// asConstruct returns the node as a *Construct, or nil.
func asConstruct(s Stmt) *Construct {
	c, _ := s.(*Construct)
	return c
}

// isCode reports whether a node carries a statement, as opposed to a comment
// or a blank/verbatim line. Passes that reason about control flow must skip
// the latter rather than treat them as statements.
func isCode(s Stmt) bool {
	switch n := s.(type) {
	case *Verbatim:
		return false
	case *Line:
		return n.Text != "" && !strings.HasPrefix(n.Text, "//")
	}
	return true
}

// lastCode returns the last statement-carrying node in a body, or nil.
func lastCode(body []Stmt) Stmt {
	for i := len(body) - 1; i >= 0; i-- {
		if isCode(body[i]) {
			return body[i]
		}
	}
	return nil
}

// walkConstructs calls fn for every Construct in the tree, innermost first,
// so a pass may rewrite a body without invalidating an outer traversal.
func walkConstructs(stmts []Stmt, fn func(*Construct)) {
	for _, s := range stmts {
		c := asConstruct(s)
		if c == nil {
			continue
		}
		for i := range c.Clauses {
			walkConstructs(c.Clauses[i].Body, fn)
		}
		fn(c)
	}
}

// mapBodies rewrites every statement list in the tree, innermost first, using
// fn. It reports whether any body changed. This is the driver for passes that
// work on a flat sequence of sibling statements.
func mapBodies(stmts []Stmt, fn func([]Stmt) ([]Stmt, bool)) ([]Stmt, bool) {
	changed := false
	for _, s := range stmts {
		c := asConstruct(s)
		if c == nil {
			continue
		}
		for i := range c.Clauses {
			b, ch := mapBodies(c.Clauses[i].Body, fn)
			c.Clauses[i].Body = b
			changed = changed || ch
		}
	}
	out, ch := fn(stmts)
	return out, changed || ch
}

// IsTerminatorStmt reports whether a trimmed line is a statement that
// unconditionally exits its enclosing block (return/continue/break).
func IsTerminatorStmt(t string) bool {
	return strings.HasPrefix(t, "return ") || t == "return;" ||
		t == "continue;" || t == "break;"
}

// IndentStr returns n levels of two-space indentation.
func IndentStr(n int) string { return strings.Repeat("  ", n) }

// LabelDeclRe matches an emitted block label line `block_N:;`.
var LabelDeclRe = regexp.MustCompile(`^\s*block_(\d+):;$`)
