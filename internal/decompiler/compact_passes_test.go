package decompiler

import (
	"strings"
	"testing"
)

// --- countArgs tests ---

func TestCountArgs(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"", 0},
		{"arg0", 1},
		{"arg0, arg1", 2},
		{"arg0, arg1, arg2", 3},
		{"arg0, func(a, b), arg2", 3},     // nested parens
		{"arg0, [a, b], arg2", 3},          // nested brackets
		{"arg0, {a: b}, arg2", 3},          // nested braces
		{"  arg0  ", 1},                    // whitespace
		{"arg0, , arg2", 3},                // empty arg still counts
	}
	for _, tt := range tests {
		got := countArgs(tt.input)
		if got != tt.want {
			t.Errorf("countArgs(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

// --- Expression simplification tests ---

func TestSimplifyExpressions(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"a * 1", "a"},
		{"1 * a", "a"},
		{"a * 0", "0"},
		{"0 * a", "0"},
		{"a + 0", "a"},
		{"0 + a", "a"},
		{"a - 0", "a"},
		{"a >> 0", "a"},
		{"a << 0", "a"},
		{"a | 0", "a"},
		{"(a | 0)", "(a)"}, // regex replaces inner "a | 0" → "a", but parens remain
		{"!!a", "a"},
		// Non-matching patterns should be unchanged
		{"a + b", "a + b"},
		{"a * 2", "a * 2"},
	}
	for _, tt := range tests {
		got := simplifyExpressions(tt.input)
		if got != tt.want {
			t.Errorf("simplifyExpressions(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// --- CSE tests ---

func TestCommonSubexpressionElimination(t *testing.T) {
	lines := []string{
		"final t1 = arg0 + arg1;",
		"final t2 = someFunc(t1);",
		"final t3 = arg0 + arg1;", // declaration — CSE skips this
		"return arg0 + arg1;",     // non-declaration — CSE should replace
	}
	out, changed := commonSubexpressionElimination(lines)
	if !changed {
		t.Error("CSE should have changed lines")
	}
	// The 4th line (return) should have "arg0 + arg1" replaced with "t1"
	if !strings.Contains(out[3], "t1") {
		t.Errorf("CSE should replace 'arg0 + arg1' with 't1' in return line, got: %s", out[3])
	}
}

// --- Enum reconstruction tests ---

func TestEnumReconstruction(t *testing.T) {
	source := `dynamic foo(int x) {
  if (x == 0) { return 'Zero'; }
  if (x == 1) { return 'One'; }
  if (x == 2) { return 'Two'; }
  if (x == 3) { return 'Three'; }
  return 'Unknown';
}`
	result := enumReconstruction(source)
	if !strings.Contains(result, "enum reconstruction") {
		t.Error("enum reconstruction should detect 4-case chain")
	}
}

// --- Null-safety annotation tests ---

func TestNullSafetyAnnotation(t *testing.T) {
	source := `dynamic foo(int x) {
  if (x == null) { return 0; }
  if (x != null) { return x; }
  return null;
}`
	result := nullSafetyAnnotation(source)
	if !strings.Contains(result, "null-safety") {
		t.Error("null-safety annotation should detect null checks")
	}
	if !strings.Contains(result, "x") {
		t.Error("null-safety annotation should list 'x' as nullable")
	}
}

// --- Local type inference tests ---

func TestLocalTypeInference(t *testing.T) {
	source := `dynamic foo(int arg0) {
  local_8 = arg0;
  final t1 = 42;
  final t2 = 'hello';
  final t3 = true;
  return t1;
}`
	result := localTypeInference(source, []string{"int"})
	if !strings.Contains(result, "local types") {
		t.Error("local type inference should emit annotation")
	}
	if !strings.Contains(result, "local_8: int") {
		t.Error("local type inference should infer local_8 as int from arg0")
	}
	if !strings.Contains(result, "t1: int") {
		t.Error("local type inference should infer t1 as int from literal 42")
	}
	if !strings.Contains(result, "t2: String") {
		t.Error("local type inference should infer t2 as String from literal 'hello'")
	}
	if !strings.Contains(result, "t3: bool") {
		t.Error("local type inference should infer t3 as bool from literal true")
	}
}

// --- maxStepsPerEmitter tests ---

func TestSetMaxStepsPerEmitter(t *testing.T) {
	// Save original
	orig := maxStepsPerEmitterOverride
	defer func() { maxStepsPerEmitterOverride = orig }()

	SetMaxStepsPerEmitter(0)
	if maxStepsPerEmitter() != defaultMaxStepsPerEmitter {
		t.Error("maxStepsPerEmitter() should return default when override is 0")
	}

	SetMaxStepsPerEmitter(50000)
	if maxStepsPerEmitter() != 50000 {
		t.Errorf("maxStepsPerEmitter() = %d, want 50000", maxStepsPerEmitter())
	}

	SetMaxStepsPerEmitter(100)
	if maxStepsPerEmitter() != 100 {
		t.Errorf("maxStepsPerEmitter() = %d, want 100", maxStepsPerEmitter())
	}
}
