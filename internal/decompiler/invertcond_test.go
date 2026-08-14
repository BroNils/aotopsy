package decompiler

import "testing"

// A single comparison flips its operator; anything else is wrapped.
//
// The negative-literal cases are the regression this pins. Adding `()` to the
// right-hand character class as `'-()` turned the trailing literal hyphen into
// a RANGE (0x27-0x28), so `x != -1` stopped matching and degraded to
// `!(x != -1)`. Correct Dart either way, which is why no golden caught it.
//
// TestInvertCondition in compact_passes_test.go did exist and did pass: every
// one of its literals is a positive integer (`x == 0`, `x < 10`), so the
// hyphen it depends on is never exercised. A test suite that covers an
// operator but only one sign of its operands is the shape to watch for.
func TestInvertConditionFlipsSingleComparisons(t *testing.T) {
	cases := []struct{ in, want string }{
		{"x > 10", "x <= 10"},
		{"a.b != null", "a.b == null"},
		{"x != -1", "x == -1"},
		{"local_m24 == -16", "local_m24 != -16"},
		{"t1 >= -128", "t1 < -128"},
		{"f() == null", "f() != null"},
		{"(a) < (b)", "(a) >= (b)"},
	}
	for _, c := range cases {
		if got := invertCondition(c.in); got != c.want {
			t.Errorf("invertCondition(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Anything that is not one bare comparison must be wrapped, never partially
// flipped -- flipping one operator inside `a == b || c != d` is not its
// negation.
func TestInvertConditionWrapsCompoundConditions(t *testing.T) {
	for _, in := range []string{
		"a == b || c != d",
		"a == b && c == d",
		"(a + b) > 10",
		"someFlag",
	} {
		want := "!(" + in + ")"
		if got := invertCondition(in); got != want {
			t.Errorf("invertCondition(%q) = %q, want %q", in, got, want)
		}
	}
}

// Double negation is not simplified, but it must at least be stable: the
// operators are a closed set, so every one of them has a flip.
func TestCmpFlipsIsTotal(t *testing.T) {
	for op, flipped := range cmpFlips {
		if back, ok := cmpFlips[flipped]; !ok || back != op {
			t.Errorf("cmpFlips[%q] = %q, which does not flip back (got %q, ok=%v)", op, flipped, back, ok)
		}
	}
}
