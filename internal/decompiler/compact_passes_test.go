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
		{"arg0, func(a, b), arg2", 3}, // nested parens
		{"arg0, [a, b], arg2", 3},     // nested brackets
		{"arg0, {a: b}, arg2", 3},     // nested braces
		{"  arg0  ", 1},               // whitespace
		{"arg0, , arg2", 3},           // empty arg still counts
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
	result := localTypeInference(source, []string{"int"}, nil)
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

// --- A3: if/else inlining tests ---

func TestComputePreds(t *testing.T) {
	fir := &FuncIR{
		Blocks: []Block{
			{ID: 0, Succs: []Succ{{BlockID: 1, Cond: "T"}, {BlockID: 2, Cond: "F"}}},
			{ID: 1, Succs: []Succ{{BlockID: 3, Cond: ""}}},
			{ID: 2, Succs: []Succ{{BlockID: 3, Cond: ""}}},
			{ID: 3},
		},
	}
	fir.ComputePreds()
	if len(fir.Blocks[0].Preds) != 0 {
		t.Errorf("block 0 should have 0 preds, got %d", len(fir.Blocks[0].Preds))
	}
	if len(fir.Blocks[1].Preds) != 1 || fir.Blocks[1].Preds[0] != 0 {
		t.Errorf("block 1 should have pred [0], got %v", fir.Blocks[1].Preds)
	}
	if len(fir.Blocks[3].Preds) != 2 {
		t.Errorf("block 3 should have 2 preds, got %d", len(fir.Blocks[3].Preds))
	}
}

// --- A4: while-loop condition extraction tests ---

func TestExtractIterVarFromCond(t *testing.T) {
	tests := []struct {
		cond string
		want string
	}{
		{"local_8 < 10", "local_8"},
		{"local_m8 != arg0", "local_m8"},
		{"local_16 <= arg0", "local_16"},
		{"arg0 < 10", ""}, // not local_
		{"x == null", ""}, // no comparison operator with spaces
		{"", ""},
	}
	for _, tt := range tests {
		got := extractIterVarFromCond(tt.cond)
		if got != tt.want {
			t.Errorf("extractIterVarFromCond(%q) = %q, want %q", tt.cond, got, tt.want)
		}
	}
}

// --- A1: applyLocalTypeHints tests ---

func TestApplyLocalTypeHints(t *testing.T) {
	hints := map[string]string{
		"arg0": "int",
		"arg1": "String",
	}
	source := `dynamic foo(dynamic arg0, dynamic arg1) {
  local_8 = arg0;
  local_m8 = arg1;
  return local_8;
}`
	result := applyLocalTypeHints(source, hints)
	if !strings.Contains(result, "local_8: int") {
		t.Error("applyLocalTypeHints should annotate local_8 as int")
	}
	if !strings.Contains(result, "local_m8: String") {
		t.Error("applyLocalTypeHints should annotate local_m8 as String")
	}
}

// --- A1: inferReturnTypeFromName tests ---

func TestInferReturnTypeFromName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"toString", "String"},
		{"toStringDeep", "String"},
		{"hashCode", "int"},
		{"length", "int"},
		{"isEmpty", "bool"},
		{"isNotEmpty", "bool"},
		{"contains", "bool"},
		{"startsWith", "bool"},
		{"endsWith", "bool"},
		{"forEach", "void"},
		{"add", "void"},
		{"clear", "void"},
		{"sort", "void"},
		{"map", "Iterable"},
		{"where", "Iterable"},
		{"join", "String"},
		{"any", "bool"},
		{"every", "bool"},
		{"indexOf", "int"},
		{"compareTo", "int"},
		{"sublist", "List"},
		{"toList", "List"},
		{"runtimeType", "Type"},
		{"set:foo", "void"},
		{"get:foo", "dynamic"},
		{"isFinite", "bool"},
		{"isEven", "bool"},
		{"hasNext", "bool"},
		{"canFly", "bool"},
		{"toList", "List"},
		{"toSet", "Set"},
		{"toInt", "int"},
		{"toDouble", "double"},
		{"toBool", "bool"},
		{"asString", "String"},
		{"asInt", "int"},
		{"operator ==", "bool"},
		{"operator !=", "bool"},
		{"operator <", "bool"},
		{"operator >=", "bool"},
		{"operator ~/", "int"},
		{"operator ~", "int"},
		{"sub_b0", "dynamic"},
		{"_throwNew@0150898", "dynamic"},
		{"Foo.bar@3099033", "dynamic"},
	}
	for _, tt := range tests {
		got := inferReturnTypeFromName(tt.name)
		if got != tt.want {
			t.Errorf("inferReturnTypeFromName(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// --- A4: invertCondition tests ---

func TestInvertCondition(t *testing.T) {
	tests := []struct {
		cond string
		want string
	}{
		{"x == 0", "x != 0"},
		{"x != 0", "x == 0"},
		{"x < 10", "x >= 10"},
		{"x >= 10", "x < 10"},
		{"x > 10", "x <= 10"},
		{"x <= 10", "x > 10"},
		{"complex expr", "!(complex expr)"},
	}
	for _, tt := range tests {
		got := invertCondition(tt.cond)
		if got != tt.want {
			t.Errorf("invertCondition(%q) = %q, want %q", tt.cond, got, tt.want)
		}
	}
}

// --- Regression tests for the correctness fixes in the readability passes ---

// constantFold must not eat a call's own parentheses: `foo(1 + 2)` was folded
// to `foo3`, silently deleting the call.
// The folder must not consume a CALL's parentheses. The regex version
// matched `(1 + 2)` inside `foo(1 + 2)` and produced `foo3`, silently
// deleting the call. Folding the argument itself is correct and expected --
// the invariant is that the call survives, not that arguments are left alone.
func TestConstantFoldDoesNotEatCallParens(t *testing.T) {
	tests := []struct{ in, want string }{
		{"  final t1 = foo(1 + 2);", "  final t1 = foo(3);"},
		{"  final t2 = bar(2 * 4);", "  final t2 = bar(8);"},
		{"  final t3 = (1 << 12) + 1;", "  final int t3 = 4097;"},
		{"  final t4 = (2 * 4);", "  final int t4 = 8;"},
		{"  final t5 = foo(a + 1);", "  final t5 = foo(a + 1);"},
	}
	for _, tt := range tests {
		src := "void f() {\n" + tt.in + "\n}"
		want := "void f() {\n" + tt.want + "\n}"
		if got := compactLines(src); got != want {
			t.Errorf("constant folding %q gave %q, want %q", tt.in, got, want)
		}
	}
}

// Negating a compound condition is not a per-operator flip: De Morgan flips
// the connective too, so `!(a == b || c == d)` is not `a != b || c == d`.
func TestRewriteNegatedComparisonsSkipsCompound(t *testing.T) {
	compound := "void f() {\n  if (!(a == b || c == d)) {\n    p();\n  }\n}"
	if got := compactLines(compound); got != compound {
		t.Errorf("compound condition must be left alone, got:\n%s", got)
	}
	simple := "void f() {\n  if (!(a > b)) {\n    p();\n  }\n}"
	want := "void f() {\n  if (a <= b) {\n    p();\n  }\n}"
	if got := compactLines(simple); got != want {
		t.Errorf("simple negation gave:\n%s\nwant:\n%s", got, want)
	}
}

// `x & 0xFFFFFFFF` is a 32-bit truncation on 64-bit Dart ints, not identity.
func TestSimplifyExpressionsKeepsMask(t *testing.T) {
	in := "  final t1 = x & 0xFFFFFFFF;"
	if got := simplifyExpressions(in); got != in {
		t.Errorf("mask must be preserved, got %q", got)
	}
}

// A dead store may only be dropped when the value it computes has no effect,
// and when the reassignment does not read the variable.
// Two parameters of the same type must not collapse onto one name.
func TestApplyArgRenamingIsCollisionFree(t *testing.T) {
	src := "dynamic foo(String arg0, String arg1) {\n  return arg0 + arg1;\n}"
	got := applyArgRenaming(src, []string{"String", "String"})
	if strings.Contains(got, "str + str") {
		t.Errorf("two params collapsed onto one name:\n%s", got)
	}
	if strings.Contains(got, "arg0") || strings.Contains(got, "arg1") {
		t.Errorf("signature and body disagree on parameter names:\n%s", got)
	}
}

// invertCondition must be deterministic and must not flip one operator of a
// compound condition.
func TestInvertConditionCompound(t *testing.T) {
	got := invertCondition("a == b || c != d")
	if got != "!(a == b || c != d)" {
		t.Errorf("compound negation = %q", got)
	}
	for i := 0; i < 20; i++ {
		if invertCondition("x <= 10") != "x > 10" {
			t.Fatal("invertCondition is not deterministic")
		}
	}
}
