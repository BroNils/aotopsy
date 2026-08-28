package stmt

import (
	"strings"
	"testing"
)

// TestStmtRoundTripIsExact is the safety gate for the whole statement-tree
// layer: if parse+print is not the identity, no pass built on it can be
// trusted, because a "no-op" pass would already be corrupting output.
func TestStmtRoundTripIsExact(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"empty", ""},
		{"flat", "int f() {\n  return 1;\n}"},
		{"if_else", "void f() {\n  if (a > b) {\n    x = 1;\n  } else {\n    x = 2;\n  }\n}"},
		{"else_if_chain", "void f() {\n  if (a) {\n    p();\n  } else if (b) {\n    q();\n  } else {\n    r();\n  }\n}"},
		{"try_catch", "void f() {\n  try {\n    g();\n  } catch (e, st) {\n    h();\n  }\n}"},
		{"nested_loops", "void f() {\n  while (true) {\n    for (var i = 0; i < n; i++) {\n      if (x) {\n        break;\n      }\n    }\n  }\n}"},
		{"switch", "void f() {\n  switch (k) {\n    case 0:\n      a();\n      break;\n    default:\n      b();\n  }\n}"},
		{"blank_lines", "void f() {\n\n  a();\n\n  b();\n}"},
		{"comments", "void f() {\n  // a note with { and } braces\n  a();\n}"},
		{"brace_in_string", "void f() {\n  var s = \"{\";\n  a();\n}"},
		{"brace_in_char", "void f() {\n  var s = '}';\n  if (x) {\n    a();\n  }\n}"},
		{"escaped_quote_in_string", "void f() {\n  var s = \"a\\\"{b\";\n  a();\n}"},
		{"closure_arg_on_one_line", "void f() {\n  run(() { return 1; });\n}"},
		{"label", "void f() {\n  block_3:;\n  goto block_3;\n}"},
		{"odd_indent_preserved", "void f() {\n   weird();\n  ok();\n}"},
		{"tab_indent_preserved", "void f() {\n\tweird();\n}"},
		{"unterminated", "void f() {\n  if (a) {\n    b();"},
		{"trailing_closer_semicolon", "void f() {\n  var g = () {\n    a();\n  };\n}"},
		{"do_while", "void f() {\n  do {\n    a();\n  } while (x);\n}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := strings.Split(tc.src, "\n")
		got := strings.Join(PrintStmts(ParseStmts(lines)), "\n")
			if got != tc.src {
				t.Errorf("round trip changed the source\n--- want ---\n%s\n--- got ---\n%s", tc.src, got)
			}
		})
	}
}

func TestBraceDeltaIgnoresStringsAndComments(t *testing.T) {
	cases := []struct {
		text string
		want int
	}{
		{`if (a) {`, 1},
		{`}`, -1},
		{`} else {`, 0},
		{`var s = "{";`, 0},
		{`var s = '}';`, 0},
		{`var s = "{{{";`, 0},
		{`var s = "\"{";`, 0},
		{`// a { comment }`, 0},
		{`a(); // trailing { brace`, 0},
		{`run(() { return 1; });`, 0},
		{`switch (k) {`, 1},
	}
	for _, tc := range cases {
		if got := BraceDelta(tc.text); got != tc.want {
			t.Errorf("BraceDelta(%q) = %d, want %d", tc.text, got, tc.want)
		}
	}
}

// TestStmtTreeShape checks the parser recovers the structure the passes rely
// on, not just that it round-trips.
func TestStmtTreeShape(t *testing.T) {
	src := "void f() {\n  if (a) {\n    p();\n  } else if (b) {\n    q();\n  } else {\n    r();\n  }\n  z();\n}"
	tree := ParseStmts(strings.Split(src, "\n"))
	if len(tree) != 1 {
		t.Fatalf("top level: got %d nodes, want 1", len(tree))
	}
	fn := asConstruct(tree[0])
	if fn == nil {
		t.Fatal("top node is not a Construct")
	}
	body := fn.body()
	if len(body) != 2 {
		t.Fatalf("function body: got %d nodes, want 2 (the if-chain and z())", len(body))
	}
	ifc := asConstruct(body[0])
	if ifc == nil {
		t.Fatal("first body node is not a Construct")
	}
	if !ifc.isIf() {
		t.Error("isIf() = false for an if-chain")
	}
	if got := len(ifc.Clauses); got != 3 {
		t.Fatalf("if-chain: got %d clauses, want 3", got)
	}
	if !ifc.hasElse() {
		t.Error("hasElse() = false for a chain ending in `} else {`")
	}
	if got := ifc.cond(); got != "a" {
		t.Errorf("cond() = %q, want %q", got, "a")
	}
	if l := asLine(body[1]); l == nil || l.Text != "z();" {
		t.Errorf("second body node = %#v, want the line z();", body[1])
	}
}
