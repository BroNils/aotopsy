package stmt

import (
	"testing"
)

// exprEqual compares two expression trees for equality of MEANING, which is
// what the printer must preserve.
//
// For an operator in mathematicallyAssociative, re-nesting is not a change of
// meaning -- `a & (b & c)` and `(a & b) & c` denote the same value -- so a
// chain of one such operator is compared as a flat operand sequence. For
// every other operator the nesting is the meaning, and shape must match
// exactly.
func exprEqual(a, b Expr) bool {
	if x, ok := a.(*Binary); ok && mathematicallyAssociative[x.Op] {
		y, ok := b.(*Binary)
		if !ok || y.Op != x.Op {
			return false
		}
		xs, ys := flattenChain(x, x.Op), flattenChain(y, y.Op)
		if len(xs) != len(ys) {
			return false
		}
		for i := range xs {
			if !exprEqual(xs[i], ys[i]) {
				return false
			}
		}
		return true
	}
	switch x := a.(type) {
	case *Atom:
		y, ok := b.(*Atom)
		return ok && x.Text == y.Text
	case *Paren:
		y, ok := b.(*Paren)
		return ok && exprEqual(x.X, y.X)
	case *Unary:
		y, ok := b.(*Unary)
		return ok && x.Op == y.Op && exprEqual(x.X, y.X)
	case *Binary:
		y, ok := b.(*Binary)
		return ok && x.Op == y.Op && exprEqual(x.L, y.L) && exprEqual(x.R, y.R)
	}
	return false
}

// flattenChain collects the operands of a same-operator chain, left to right.
func flattenChain(e Expr, op string) []Expr {
	b, ok := e.(*Binary)
	if !ok || b.Op != op {
		return []Expr{e}
	}
	return append(flattenChain(b.L, op), flattenChain(b.R, op)...)
}

// TestExprPrintPreservesStructure is the safety gate for the expression
// layer. Printing drops parentheses; this asserts that what it drops was
// genuinely redundant, by re-parsing the result and requiring the same tree.
func TestExprPrintPreservesStructure(t *testing.T) {
	corpus := []string{
		"a + b",
		"(a + b)",
		"a + (b + c)",
		"a - (b - c)",
		"(a - b) - c",
		"a * (b + c)",
		"(a * b) + c",
		"a / (b / c)",
		"a % (b % c)",
		"a << (b << c)",
		"a >> (b >> c)",
		"(a >> b) >> c",
		"a & (b & c)",
		"a || (b && c)",
		"(a || b) && c",
		"!(a > b)",
		"((x))",
		"(x).f",
		"a == b",
		"(a == b) == c",
		"a < (b < c)",
		"x & 0xFFFFFFFF",
		"arr[i] + 1",
		"f(a, b) * 2",
		"-x + 1",
		"~x | y",
		"(w0) & 1",
		"local_m24.f15 != (local_m16._tag >> 12)",
		"((THR.f112 >> 30) + 1) < 2",
		"(local_m8 * ((int64)(\"<X>\".f15) >> 1))",
		"(a + b) * (c + d)",
		"a ?? (b ?? c)",
		"(a | b) ^ c",
		"a - b + c",
		"a + b - c",
		"a * b / c",
		"a + (b + c)",
		"a * (b * c)",
	}
	for _, src := range corpus {
		t.Run(src, func(t *testing.T) {
			tree, ok := parseExpr(src)
			if !ok {
				t.Skipf("not parsed (passes leave it alone): %s", src)
			}
			out := printExpr(tree)
			reparsed, ok := parseExpr(out)
			if !ok {
				t.Fatalf("printed form does not re-parse: %q -> %q", src, out)
			}
			if !exprEqual(tree, reparsed) {
				t.Errorf("printing changed the expression's structure:\n  in : %s\n  out: %s", src, out)
			}
			// Printing must be idempotent, or the pass pipeline would never
			// reach a fixed point.
			if again := printExpr(reparsed); again != out {
				t.Errorf("printing is not idempotent: %q -> %q -> %q", src, out, again)
			}
		})
	}
}

// Dart forbids chaining equality and relational operators; the printer must
// never emit `a == b == c`, which does not compile.
func TestExprKeepsNonAssociativeParens(t *testing.T) {
	for _, src := range []string{"(a == b) == c", "(a < b) < c", "(a != b) != c", "(a >= b) >= c"} {
		tree, ok := parseExpr(src)
		if !ok {
			t.Fatalf("could not parse %q", src)
		}
		if got := printExpr(tree); got != src {
			t.Errorf("non-associative operator lost its parentheses: %q -> %q", src, got)
		}
	}
}

// Operators that are left-associative but not mathematically associative must
// keep the parentheses on their right operand.
func TestExprKeepsNonCommutingRightParens(t *testing.T) {
	for _, src := range []string{"a - (b - c)", "a / (b / c)", "a % (b % c)", "a << (b << c)", "a >> (b >> c)"} {
		tree, ok := parseExpr(src)
		if !ok {
			t.Fatalf("could not parse %q", src)
		}
		if got := printExpr(tree); got != src {
			t.Errorf("%q must keep its right-hand parentheses, got %q", src, got)
		}
	}
}

// Only operators that are associative for EVERY Dart operand type may drop
// them. `+` and `*` are in the SDK's isAssociativeOperator set but are not
// associative on doubles, so they are excluded -- see mathematicallyAssociative.
func TestExprDropsRedundantParensForAssociativeOps(t *testing.T) {
	cases := map[string]string{
		"a & (b & c)":   "a & b & c",
		"a | (b | c)":   "a | b | c",
		"a ^ (b ^ c)":   "a ^ b ^ c",
		"a || (b || c)": "a || b || c",
		"a && (b && c)": "a && b && c",
		"((x))":         "x",
		"(a + b)":       "a + b",
	}
	for src, want := range cases {
		tree, ok := parseExpr(src)
		if !ok {
			t.Fatalf("could not parse %q", src)
		}
		if got := printExpr(tree); got != want {
			t.Errorf("%q -> %q, want %q", src, got, want)
		}
	}
}

// The parser must refuse what it does not model, so callers leave it alone.
func TestExprRefusesWhatItCannotModel(t *testing.T) {
	for _, src := range []string{
		"a ? b : c", // conditional is not modelled
		"a = b",     // assignment is not an expression here
		"(unclosed",
		"",
	} {
		if _, ok := parseExpr(src); ok {
			t.Errorf("parseExpr(%q) reported success for an unmodelled shape", src)
		}
	}
}

// Dart binds `&` tighter than `==`; C, Java and JavaScript bind `==` tighter.
// The same text means different things in the two families, and this output
// is read alongside a disassembly, so the parentheses stay.
func TestExprKeepsBitwiseVsComparisonParens(t *testing.T) {
	cases := map[string]string{
		"(w0 & 1) == 0":   "(w0 & 1) == 0",
		"((w0) & 1) == 0": "(w0 & 1) == 0",
		"(a | b) != c":    "(a | b) != c",
		"(a ^ b) < c":     "(a ^ b) < c",
		"x == (y & mask)": "x == (y & mask)",
		// A comparison inside a bitwise operand is unambiguous the other way
		// round -- Dart and C agree there -- but the grouping still has to
		// survive, because it is not implied by precedence in either.
		"(a < b) & c": "(a < b) & c",
	}
	for src, want := range cases {
		tree, ok := parseExpr(src)
		if !ok {
			t.Fatalf("could not parse %q", src)
		}
		if got := printExpr(tree); got != want {
			t.Errorf("%q -> %q, want %q", src, got, want)
		}
	}
}

// Dart spells operator methods `+`, `*`, `unary-`, `[]`, `==`, so those
// characters after a `.` are part of the member NAME, not an infix operator.
// Without that, `_StringBase.+(a, b)` parsed as `_StringBase.` plus a binary
// `+` and printed back as `_StringBase. + (a, b)` -- a method call
// re-rendered as an addition. 1842 sites on the 3.x ARM64 sample.
func TestExprKeepsOperatorMethodNamesIntact(t *testing.T) {
	for _, src := range []string{
		"_StringBase@0150898.+(a, b)",
		"_OneByteString@0150898.*(s, n)",
		"Offset.unary-(p)",
		"Alignment.+(x, y)",
		"Map.[]=(m, k, v)",
	} {
		tree, ok := parseExpr(src)
		if !ok {
			t.Errorf("could not parse %q", src)
			continue
		}
		if got := printExpr(tree); got != src {
			t.Errorf("operator method mangled: %q -> %q", src, got)
		}
	}
	// A genuine addition between two member accesses must still parse as one.
	add := "a.field + b.field"
	tree, ok := parseExpr(add)
	if !ok {
		t.Fatalf("could not parse %q", add)
	}
	if _, isBin := tree.(*Binary); !isBin {
		t.Errorf("%q should still be a binary addition, got %T", add, tree)
	}
}
