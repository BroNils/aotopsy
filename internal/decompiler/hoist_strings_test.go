package decompiler

import (
	"strings"
	"testing"
)

func TestHoistStringLiterals(t *testing.T) {
	long := `"` + strings.Repeat("A", 60) + `"`
	src := "dynamic f() {\n" +
		"  foo(" + long + ");\n" +
		"  bar(" + long + ");\n" +
		"}"
	out := hoistStringLiterals(src)
	// The repeated literal is hoisted to one const and referenced by name.
	if strings.Count(out, long) != 1 {
		t.Errorf("literal should appear once (the const decl), got %d:\n%s", strings.Count(out, long), out)
	}
	if !strings.Contains(out, "const _str0 = "+long+";") {
		t.Errorf("expected const decl, got:\n%s", out)
	}
	if strings.Count(out, "_str0") != 3 { // 1 decl + 2 refs
		t.Errorf("expected 3 _str0 tokens (decl + 2 refs), got %d", strings.Count(out, "_str0"))
	}
}

// A literal appearing only once is left inline (nothing to gain).
func TestHoistStringLiteralsSingleOccurrenceUntouched(t *testing.T) {
	long := `"` + strings.Repeat("B", 60) + `"`
	src := "dynamic f() {\n  foo(" + long + ");\n}"
	if out := hoistStringLiterals(src); out != src {
		t.Errorf("single-occurrence literal must be untouched, got:\n%s", out)
	}
}

// Short repeated strings are not worth hoisting.
func TestHoistStringLiteralsShortUntouched(t *testing.T) {
	src := "dynamic f() {\n  foo(\"hi\");\n  bar(\"hi\");\n}"
	if out := hoistStringLiterals(src); out != src {
		t.Errorf("short literal must be untouched, got:\n%s", out)
	}
}
