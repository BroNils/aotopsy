package decompiler

import (
	"strings"
	"testing"

	"aotopsy/internal/decompiler/stmt"
)

// TestValidateIgnoresComments pins the fix for a gate that was checking prose.
//
// The emitter writes inline-frame markers as comments, and an unnamed
// constructor's name ends in a dot, so `. ` appears in the text. The
// spaced-member-operator rule matched it and reported invalid Dart in 55
// functions of one sample -- all of them valid. Only BraceDelta was
// comment-aware; the syntax rules were not.
func TestValidateIgnoresComments(t *testing.T) {
	src := strings.Join([]string{
		"void f() {",
		"  // [inlined: _AsyncCompleter._AsyncCompleter. -> _Completer._Completer.]",
		"  // final x = 1; is not a declaration when it sits in a comment",
		"  final y = g();",
		"  return y;",
		"}",
	}, "\n")
	if probs := ValidateSource(src); len(probs) > 0 {
		t.Errorf("comments reported as invalid Dart: %v", probs)
	}
}

// TestValidateStillCatchesRealProblems is the other half: making the rules
// comment-aware must not make them blind.
func TestValidateStillCatchesRealProblems(t *testing.T) {
	src := strings.Join([]string{
		"void f() {",
		"  final y = g(); // a trailing comment must not hide the code",
		"  y = 3;",
		"}",
	}, "\n")
	probs := ValidateSource(src)
	found := false
	for _, p := range probs {
		if p.Rule == "assign-to-final" {
			found = true
		}
	}
	if !found {
		t.Errorf("assign-to-final not reported: %v", probs)
	}
}

func TestCodePrefix(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`a = b;`, `a = b;`},
		{`a = b; // trailing`, `a = b; `},
		{`// whole line`, ``},
		{`a = "http://x"; // real comment`, `a = "http://x"; `},
		{`a = 'not // a comment';`, `a = 'not // a comment';`},
		{`a = "escaped \" // still string";`, `a = "escaped \" // still string";`},
	} {
		if got := stmt.CodePrefix(tc.in); got != tc.want {
			t.Errorf("CodePrefix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestBraceDeltaUsesCodePrefix guards the shared scanner: a brace inside a
// comment or a string is not structure.
func TestBraceDeltaUsesCodePrefix(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
	}{
		{`if (x) {`, 1},
		{`} // }`, -1},
		{`// { { {`, 0},
		{`s = "{{{";`, 0},
	} {
		if got := stmt.BraceDelta(tc.in); got != tc.want {
			t.Errorf("BraceDelta(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
