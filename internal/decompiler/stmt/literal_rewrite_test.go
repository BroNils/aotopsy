package stmt

import (
	"reflect"
	"testing"
)

func TestInlineSingleUseTempsIgnoresStringLiteralIdentifiers(t *testing.T) {
	stmts := []Stmt{
		&Line{Text: "final t0 = obj.width;"},
		&Line{Text: `print("t0");`},
	}

	got, changed := InlineSingleUseTempsStmt(stmts)
	if changed {
		t.Fatalf("string-literal text was treated as a temp use: %v", PrintStmts(got))
	}
	want := []string{"final t0 = obj.width;", `print("t0");`}
	if lines := PrintStmts(got); !reflect.DeepEqual(lines, want) {
		t.Fatalf("literal contents changed: got %v want %v", lines, want)
	}
}

func TestCSEPreservesMatchingTextInsideStringLiteral(t *testing.T) {
	stmts := []Stmt{
		&Line{Text: "final t0 = alpha + beta;"},
		&Line{Text: `log("alpha + beta");`},
		&Line{Text: "use(alpha + beta);"},
	}

	if !CommonSubexpressionEliminationStmt(stmts) {
		t.Fatal("expected the real code occurrence to be CSE'd")
	}
	want := []string{
		"final t0 = alpha + beta;",
		`log("alpha + beta");`,
		"use(t0);",
	}
	if got := PrintStmts(stmts); !reflect.DeepEqual(got, want) {
		t.Fatalf("CSE rewrote literal data or missed code occurrence: got %v want %v", got, want)
	}
}

func TestCopyPropagationPreservesStringLiteralIdentifiers(t *testing.T) {
	stmts := []Stmt{
		&Line{Text: "t1 = arg0;"},
		&Line{Text: `print("t1");`},
	}

	if CopyPropagationStmt(stmts) {
		t.Fatalf("copy propagation rewrote literal-only occurrence: %v", PrintStmts(stmts))
	}
	want := []string{"t1 = arg0;", `print("t1");`}
	if got := PrintStmts(stmts); !reflect.DeepEqual(got, want) {
		t.Fatalf("literal contents changed: got %v want %v", got, want)
	}
}

func TestIdiomRewritesIgnorePatternTextInsideStringLiterals(t *testing.T) {
	tests := []struct {
		name string
		line string
		run  func([]Stmt) ([]Stmt, bool)
	}{
		{
			name: "interpolation call text",
			line: `print("_StringBase._interpolate([name])");`,
			run:  StringInterpolationIdiomStmt,
		},
		{
			name: "null-aware ternary text",
			line: `print("(a != null) ? a : b");`,
			run:  NullAwareIdiomStmt,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmts := []Stmt{&Line{Text: tt.line}}
			got, changed := tt.run(stmts)
			if changed {
				t.Fatalf("literal-only pattern triggered rewrite: %v", PrintStmts(got))
			}
			if lines := PrintStmts(got); !reflect.DeepEqual(lines, []string{tt.line}) {
				t.Fatalf("literal contents changed: %v", lines)
			}
		})
	}
}

func TestStringInterpolationEscapesLiteralDollarSegments(t *testing.T) {
	got := formatStringInterpolation(`["price $", value, " / ${literal}"]`)
	want := `"price \$$value / \${literal}"`
	if got != want {
		t.Fatalf("formatStringInterpolation = %q, want %q", got, want)
	}

	alreadyEscaped := formatStringInterpolation(`["price \$", value]`)
	if want := `"price \$$value"`; alreadyEscaped != want {
		t.Fatalf("already-escaped literal dollar was changed: got %q want %q", alreadyEscaped, want)
	}
}

func TestIdentifierHelpersRewriteOnlyInterpolationCode(t *testing.T) {
	line := `print("literal t0 / $t0 / ${t0 + 1} / \$t0");`
	got := ReplaceIdent(line, "t0", "obj.width")
	want := `print("literal t0 / ${obj.width} / ${obj.width + 1} / \$t0");`
	if got != want {
		t.Fatalf("ReplaceIdent = %q, want %q", got, want)
	}
	if !ReferencesIdent(line, "t0") {
		t.Fatal("live interpolation references were hidden from identifier analysis")
	}
	if ReferencesIdent(`print("literal t0 / \$t0");`, "t0") {
		t.Fatal("literal or escaped-dollar text was treated as executable identifier use")
	}
}
