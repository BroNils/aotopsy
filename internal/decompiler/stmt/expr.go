package stmt

import (
	"strings"
)

// An expression tree for the emitter's own expression sublanguage, so the
// cleanup passes stop being regex rewrites over text.
//
// Precedence and associativity are taken verbatim from the Dart SDK's scanner
// (pkg/_fe_analyzer_shared/lib/src/scanner/token.dart at tag 3.9.2), not from
// memory -- getting either wrong means dropping a parenthesis that was load
// bearing, which silently changes what the pseudocode says the binary does.
//
// The parser is deliberately partial and SAYS SO: parseExpr returns ok=false
// for anything outside the shapes below, and every caller leaves such text
// untouched. A pass that cannot understand an expression must not edit it.

// Dart operator precedence, from the SDK scanner's *_PRECEDENCE constants.
const (
	precNone           = 0
	precAssignment     = 1
	precConditional    = 3
	precIfNull         = 4
	precLogicalOr      = 5
	precLogicalAnd     = 6
	precEquality       = 7
	precRelational     = 8
	precBitwiseOr      = 9
	precBitwiseXor     = 10
	precBitwiseAnd     = 11
	precShift          = 12
	precAdditive       = 13
	precMultiplicative = 14
	precPrefix         = 15
	precSelector       = 17
)

// binaryPrec maps each binary operator this package emits to its Dart
// precedence. Operators absent from this table are not parsed at all.
var binaryPrec = map[string]int{
	"??": precIfNull,
	"||": precLogicalOr,
	"&&": precLogicalAnd,
	"==": precEquality, "!=": precEquality,
	"<": precRelational, ">": precRelational, "<=": precRelational, ">=": precRelational,
	"|":  precBitwiseOr,
	"^":  precBitwiseXor,
	"&":  precBitwiseAnd,
	"<<": precShift, ">>": precShift, ">>>": precShift,
	"+": precAdditive, "-": precAdditive,
	"*": precMultiplicative, "/": precMultiplicative, "%": precMultiplicative, "~/": precMultiplicative,
}

// mathematicallyAssociative lists the operators for which a op (b op c) and
// (a op b) op c denote the same value, so the printer may drop parentheses on
// the RIGHT operand of a same-precedence nesting.
//
// The SDK's own TokenType.isAssociativeOperator set is AMPERSAND,
// AMPERSAND_AMPERSAND, BAR, BAR_BAR, CARET, PLUS, STAR. This list is that set
// MINUS `+` and `*`, deliberately.
//
// `+` and `*` are associative on integers but not on doubles: IEEE-754
// addition and multiplication round at every step, so (a + b) + c and
// a + (b + c) can differ. The pseudocode does not carry static types, so
// there is no way to know which case an expression is -- and the SDK flag
// gives no licence here, since nothing in the compiler uses it to
// reassociate; the only reference is a test asserting the flag's own value.
// Reassociating them would be a silent numeric change to satisfy a cosmetic
// pass, so they keep their parentheses.
//
// Also absent, and absent from the SDK set too: `-`, `/`, `%`, `~/`, `<<`,
// `>>`. `a - (b - c)` is not `a - b - c` for any operand type.
var mathematicallyAssociative = map[string]bool{
	"&": true, "&&": true, "|": true, "||": true, "^": true,
}

// nonAssociative lists operators Dart's grammar forbids chaining without
// parentheses: `a == b == c` and `a < b < c` are syntax errors. The printer
// must never produce them.
var nonAssociative = map[string]bool{
	"==": true, "!=": true, "<": true, ">": true, "<=": true, ">=": true,
}

// Expr is one node of an expression tree.
type Expr interface{ prec() int }

// Atom is anything opaque: an identifier, a literal, a call, an index, a
// member chain, a cast -- text the passes do not decompose. It carries the
// precedence of whatever it is so the printer parenthesises it correctly.
type Atom struct {
	Text string
	P    int
}

func (a *Atom) prec() int { return a.P }

// Unary is a prefix operator application: `-x`, `!x`, `~x`.
type Unary struct {
	Op string
	X  Expr
}

func (u *Unary) prec() int { return precPrefix }

// Binary is an infix operator application.
type Binary struct {
	Op   string
	L, R Expr
}

func (b *Binary) prec() int { return binaryPrec[b.Op] }

// Paren marks parentheses the source had that the printer could not prove
// redundant. It is only produced for subexpressions the parser did not
// decompose.
type Paren struct{ X Expr }

func (p *Paren) prec() int { return precSelector }

// --- Printing ---

// printExpr renders an expression with the minimum parentheses that preserve
// its meaning under Dart's grammar.
func printExpr(e Expr) string {
	switch n := e.(type) {
	case *Atom:
		return n.Text
	case *Paren:
		return "(" + printExpr(n.X) + ")"
	case *Unary:
		return n.Op + wrapIf(n.X, n.X.prec() < precPrefix)
	case *Binary:
		p := n.prec()
		lp, rp := n.L.prec(), n.R.prec()
		// A non-associative operator cannot have an operand of its own
		// precedence on EITHER side: the SDK grammar is
		// `equalityExpression: relationalExpression (equalityOperator
		// relationalExpression)?` (Dart.g at 3.9.2), and the `?` means at
		// most one. `a == b == c` and `a < b < c` are syntax errors, so both
		// sides keep their parentheses.
		if nonAssociative[n.Op] {
			return wrapIf(n.L, lp <= p || keepForClarity(n.Op, n.L)) + " " + n.Op + " " +
				wrapIf(n.R, rp <= p || keepForClarity(n.Op, n.R))
		}
		// Otherwise the left operand may omit parentheses at equal
		// precedence, since every remaining operator is left-associative.
		left := wrapIf(n.L, lp < p || keepForClarity(n.Op, n.L))
		// The right operand may only omit them when the operator is
		// mathematically associative -- `a - (b - c)` is not `a - b - c`.
		needRight := rp < p || (rp == p && !mathematicallyAssociative[n.Op]) || keepForClarity(n.Op, n.R)
		return left + " " + n.Op + " " + wrapIf(n.R, needRight)
	}
	return ""
}

// comparisonOps and bitwiseOps are the two families whose relative
// precedence Dart INVERTS with respect to C.
var (
	comparisonOps = map[string]bool{"==": true, "!=": true, "<": true, ">": true, "<=": true, ">=": true}
	bitwiseOps    = map[string]bool{"&": true, "|": true, "^": true}
)

// keepForClarity reports whether a parenthesis is redundant to the compiler
// but should be kept for the reader.
//
// Dart binds `&`, `|` and `^` TIGHTER than `==` (BITWISE_AND_PRECEDENCE 11,
// EQUALITY_PRECEDENCE 7), so `w0 & 1 == 0` means `(w0 & 1) == 0`. C, C++,
// Java and JavaScript all bind equality tighter, where the same text means
// `w0 & (1 == 0)` -- the opposite grouping and a different value.
//
// This output is read next to a disassembly by people who read C. Dropping
// the parentheses here is correct Dart that invites a wrong reading of what
// the binary does, so this is the one place minimal parenthesisation is not
// the goal.
func keepForClarity(op string, operand Expr) bool {
	b, ok := operand.(*Binary)
	if !ok {
		return false
	}
	return comparisonOps[op] && bitwiseOps[b.Op]
}

func wrapIf(e Expr, need bool) string {
	if need {
		return "(" + printExpr(e) + ")"
	}
	return printExpr(e)
}

// --- Parsing ---

// parseExpr parses an expression, reporting ok=false when it contains
// anything the tree does not model. Callers must leave the text alone in that
// case rather than guess.
func parseExpr(src string) (Expr, bool) {
	p := &exprParser{s: src}
	p.skipSpace()
	e, ok := p.parseBinary(precNone)
	if !ok {
		return nil, false
	}
	p.skipSpace()
	if p.i != len(p.s) {
		return nil, false // trailing junk: not fully understood
	}
	return e, true
}

type exprParser struct {
	s string
	i int
}

func (p *exprParser) skipSpace() {
	for p.i < len(p.s) && p.s[p.i] == ' ' {
		p.i++
	}
}

// peekOp returns the binary operator at the cursor, longest match first.
func (p *exprParser) peekOp() string {
	rest := p.s[p.i:]
	for _, op := range []string{">>>", "~/", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "??",
		"+", "-", "*", "/", "%", "&", "|", "^", "<", ">"} {
		if strings.HasPrefix(rest, op) {
			// `>` must not be taken out of `>>`, handled by ordering above.
			return op
		}
	}
	return ""
}

func (p *exprParser) parseBinary(minPrec int) (Expr, bool) {
	left, ok := p.parseUnary()
	if !ok {
		return nil, false
	}
	for {
		p.skipSpace()
		op := p.peekOp()
		if op == "" {
			return left, true
		}
		prec, known := binaryPrec[op]
		if !known || prec <= minPrec {
			return left, true
		}
		p.i += len(op)
		p.skipSpace()
		right, ok := p.parseBinary(prec)
		if !ok {
			return nil, false
		}
		left = &Binary{Op: op, L: left, R: right}
	}
}

func (p *exprParser) parseUnary() (Expr, bool) {
	p.skipSpace()
	if p.i >= len(p.s) {
		return nil, false
	}
	switch c := p.s[p.i]; c {
	case '!', '~':
		p.i++
		x, ok := p.parseUnary()
		if !ok {
			return nil, false
		}
		return &Unary{Op: string(c), X: x}, true
	case '-':
		// A leading `-` is negation; `- ` mid-expression was consumed as a
		// binary operator before reaching here.
		p.i++
		x, ok := p.parseUnary()
		if !ok {
			return nil, false
		}
		return &Unary{Op: "-", X: x}, true
	}
	return p.parsePrimary()
}

// parsePrimary consumes a parenthesised group or one opaque atom.
func (p *exprParser) parsePrimary() (Expr, bool) {
	p.skipSpace()
	if p.i >= len(p.s) {
		return nil, false
	}
	if p.s[p.i] == '(' {
		start := p.i
		end, ok := matchParen(p.s, p.i)
		if !ok {
			return nil, false
		}
		inner := p.s[start+1 : end]
		// A cast or call written as `(T)(x)` / `(expr)(args)`, and an indexed
		// or member-accessed group `(expr).f`, are atoms: what follows the
		// group binds tighter than any operator, so the whole thing is opaque.
		if suffix, isSuffixed := suffixAfter(p.s, end+1); isSuffixed {
			p.i = suffix
			return &Atom{Text: p.s[start:suffix], P: precSelector}, true
		}
		sub, subOK := parseExpr(inner)
		p.i = end + 1
		if !subOK {
			return &Paren{X: &Atom{Text: inner, P: precNone}}, true
		}
		return sub, true
	}
	// An opaque atom: identifier, literal, member chain, call, index. It ends
	// at the first top-level operator or separator.
	start := p.i
	for p.i < len(p.s) {
		c := p.s[p.i]
		if c == '(' || c == '[' {
			end, ok := matchBracket(p.s, p.i)
			if !ok {
				return nil, false
			}
			p.i = end + 1
			continue
		}
		if c == '"' || c == '\'' {
			p.i = skipStringLiteral(p.s, p.i) + 1
			continue
		}
		// A member name may BE an operator: Dart spells them `+`, `*`,
		// `unary-`, `[]`, `[]=`, `==`. Everything from a `.` up to the
		// argument list is the NAME, whatever characters it uses, so consume
		// it here rather than letting the operator and bracket branches
		// below tear it apart.
		//
		// Without this, `_StringBase@0150898.+(a, b)` parsed as the atom
		// `_StringBase@0150898.` plus a binary `+` applied to `(a, b)`, and
		// printed back as `_StringBase@0150898. + (a, b)` -- a method call
		// re-rendered as an addition. 1842 sites on the 3.x ARM64 sample
		// once VM-table name resolution started producing these names.
		if c == '.' {
			p.i++ // the dot
			for p.i < len(p.s) {
				n := p.s[p.i]
			if IsIdentChar(n) || isOperatorStart(n) {
					p.i++
					continue
				}
				// `[]` and `[]=` are index-operator names when they directly
				// follow the dot; a `[` any later opens a real subscript.
				if n == '[' && p.i > 0 && p.s[p.i-1] == '.' {
					p.i++
					for p.i < len(p.s) && (p.s[p.i] == ']' || isOperatorStart(p.s[p.i])) {
						p.i++
					}
					continue
				}
				break
			}
			continue
		}
		if c == ' ' || isOperatorStart(c) {
			break
		}
		p.i++
	}
	if p.i == start {
		return nil, false
	}
	return &Atom{Text: p.s[start:p.i], P: precSelector}, true
}

// isOperatorStart reports whether c can begin a binary operator. `.` is
// excluded: it is part of a member chain, which stays inside the atom.
func isOperatorStart(c byte) bool {
	return strings.IndexByte("+-*/%&|^<>=!~?", c) >= 0
}

// suffixAfter reports the end of a call/index/member suffix starting at i,
// and whether there was one.
func suffixAfter(s string, i int) (int, bool) {
	if i >= len(s) {
		return i, false
	}
	switch s[i] {
	case '(', '[':
		end, ok := matchBracket(s, i)
		if !ok {
			return i, false
		}
		// Consume any further chained suffixes.
		if more, ok2 := suffixAfter(s, end+1); ok2 {
			return more, true
		}
		return end + 1, true
	case '.':
		j := i + 1
	for j < len(s) && (IsIdentChar(s[j]) || s[j] == '.') {
			j++
		}
		if j == i+1 {
			return i, false
		}
		if more, ok2 := suffixAfter(s, j); ok2 {
			return more, true
		}
		return j, true
	}
	return i, false
}

// matchParen returns the index of the `)` closing the `(` at start.
func matchParen(s string, start int) (int, bool) { return matchBracket(s, start) }

// matchBracket returns the index of the bracket closing the one at start,
// skipping string literals.
func matchBracket(s string, start int) (int, bool) {
	open := s[start]
	var close byte
	switch open {
	case '(':
		close = ')'
	case '[':
		close = ']'
	default:
		return 0, false
	}
	depth := 0
	for i := start; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\'':
			i = skipStringLiteral(s, i)
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}
