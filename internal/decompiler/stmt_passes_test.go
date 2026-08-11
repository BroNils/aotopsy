package decompiler

import (
	"strings"
	"testing"
)

// runCompact is the way these passes are actually reached in production.
func runCompact(src string) string { return compactLines(src) }

func assertBalanced(t *testing.T, got string) {
	t.Helper()
	depth := 0
	for _, line := range strings.Split(got, "\n") {
		_, text, ok := splitIndent(line)
		if !ok {
			continue
		}
		depth += braceDelta(text)
		if depth < 0 {
			t.Fatalf("brace depth went negative:\n%s", got)
		}
	}
	if depth != 0 {
		t.Fatalf("unbalanced braces (depth %d):\n%s", depth, got)
	}
}

// An else branch that does more than return must survive intact.
func TestCollapseIfElseReturnKeepsElseBodyIntact(t *testing.T) {
	src := strings.Join([]string{
		"int f() {",
		"  if (a) {",
		"    return 1;",
		"  } else {",
		"    return 1;",
		"    sideEffect();",
		"  }",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if strings.Contains(got, "sideEffect") && !strings.Contains(got, "} else {") {
		t.Errorf("else body survived without its else clause:\n%s", got)
	}
}

func TestCollapseIfElseReturnBothBranchesSame(t *testing.T) {
	src := strings.Join([]string{
		"int f() {",
		"  if (a) {",
		"    return 1;",
		"  } else {",
		"    return 1;",
		"  }",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if strings.Contains(got, "if (") {
		t.Errorf("both branches return the same value, the if should be gone:\n%s", got)
	}
	if !strings.Contains(got, "return 1;") {
		t.Errorf("the return was lost:\n%s", got)
	}
}

// Regression: the text version DELETED the else branch here. Measured on the
// old implementation, this input became `if (a || b) { continue; }` with
// important() gone and the braces still balanced, so nothing downstream could
// notice the loss.
func TestMergeIfContinueLeavesIfWithElseAlone(t *testing.T) {
	src := strings.Join([]string{
		"void f() {",
		"  while (true) {",
		"    if (a) {",
		"      continue;",
		"    } else {",
		"      important();",
		"    }",
		"    if (b) {",
		"      continue;",
		"    }",
		"    rest();",
		"  }",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if !strings.Contains(got, "important();") {
		t.Errorf("the else branch was dropped:\n%s", got)
	}
	if strings.Contains(got, "if (a || b)") {
		t.Errorf("an if with an else branch must not be merged:\n%s", got)
	}
}

func TestMergeIfContinueMergesPlainGuards(t *testing.T) {
	src := strings.Join([]string{
		"void f() {",
		"  while (true) {",
		"    if (a) {",
		"      continue;",
		"    }",
		"    if (b) {",
		"      continue;",
		"    }",
		"    rest();",
		"  }",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if !strings.Contains(got, "if (a || b) {") {
		t.Errorf("consecutive continue-guards should merge:\n%s", got)
	}
}

// `continue;` inside a NESTED loop targets that loop, so it says nothing
// about whether the outer `while (true)` can repeat. The text version matched
// any continue at a deeper indent and so refused to unwrap.
func TestUnwrapDeadWhileTrueIgnoresNestedLoopContinue(t *testing.T) {
	src := strings.Join([]string{
		"void f() {",
		"  while (true) {",
		"    for (var i = 0; i < n; i++) {",
		"      continue;",
		"    }",
		"    return;",
		"  }",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if strings.Contains(got, "while (true)") {
		t.Errorf("the outer loop has no continue of its own and always returns, so it should unwrap:\n%s", got)
	}
	if !strings.Contains(got, "for (var i = 0; i < n; i++) {") {
		t.Errorf("the inner loop was lost:\n%s", got)
	}
}

func TestUnwrapDeadWhileTrueKeepsRealLoop(t *testing.T) {
	src := strings.Join([]string{
		"void f() {",
		"  while (true) {",
		"    if (a) {",
		"      continue;",
		"    }",
		"    return;",
		"  }",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if !strings.Contains(got, "while (true)") {
		t.Errorf("a loop with its own continue must not be unwrapped:\n%s", got)
	}
}

func TestRemoveDeadCodeAfterTerminator(t *testing.T) {
	src := strings.Join([]string{
		"int f() {",
		"  return 1;",
		"  unreachable();",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if strings.Contains(got, "unreachable") {
		t.Errorf("code after a return should be dropped:\n%s", got)
	}
}

// A statement in a DIFFERENT block is not dead just because it follows a
// return textually.
func TestRemoveDeadCodeStopsAtBlockBoundary(t *testing.T) {
	src := strings.Join([]string{
		"int f() {",
		"  if (a) {",
		"    return 1;",
		"  }",
		"  stillReachable();",
		"  return 2;",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if !strings.Contains(got, "stillReachable();") {
		t.Errorf("a statement after the if-block is reachable:\n%s", got)
	}
}

// Regression: a switch body is a flat list of `case N:` labels and
// statements, and `break;` is a terminator. Treating everything after a
// terminator as dead collapsed every switch to its first case -- caught on
// the compare_sample sweep, where a 45-line switch lost cases 1 to 3 and its
// default. Control can be transferred to a label, so a label is reachable.
func TestRemoveDeadCodeStopsAtSwitchCaseLabels(t *testing.T) {
	src := strings.Join([]string{
		"void f() {",
		"  switch (k) {",
		"    case 0:",
		"      a();",
		"      break;",
		"    case 1:",
		"      b();",
		"      break;",
		"    default:",
		"      c();",
		"  }",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	for _, want := range []string{"case 1:", "b();", "default:", "c();"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q was dropped as dead code:\n%s", want, got)
		}
	}
}

// A goto label is reachable for the same reason.
func TestRemoveDeadCodeStopsAtGotoLabels(t *testing.T) {
	src := strings.Join([]string{
		"void f() {",
		"  if (a) {",
		"    goto block_3;",
		"  }",
		"  return;",
		"  block_3:;",
		"  reachableByGoto();",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if !strings.Contains(got, "reachableByGoto();") {
		t.Errorf("code after a goto label is reachable:\n%s", got)
	}
}

// A value defined before a label is not defined when control JUMPS to that
// label, so neither dataflow pass may carry knowledge across one.
func TestDataflowPassesResetAtLabels(t *testing.T) {
	got := runCompact("void f() {\n  t1 = arg0;\n  block_3:;\n  use(t1);\n}")
	if strings.Contains(got, "use(arg0)") {
		t.Errorf("copy propagation crossed a label:\n%s", got)
	}
	cse := runCompact("int f() {\n  final t1 = alpha + beta;\n  block_3:;\n  return alpha + beta;\n}")
	if strings.Contains(cse, "return t1;") {
		t.Errorf("CSE crossed a label:\n%s", cse)
	}
}

func TestRemoveEmptyElse(t *testing.T) {
	src := strings.Join([]string{
		"void f() {",
		"  if (a) {",
		"    p();",
		"  } else {",
		"  }",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if strings.Contains(got, "else") {
		t.Errorf("an empty else should be removed:\n%s", got)
	}
	if !strings.Contains(got, "p();") {
		t.Errorf("the then branch was lost:\n%s", got)
	}
}

func TestCollapseRedundantGuardedReturn(t *testing.T) {
	src := strings.Join([]string{
		"int f() {",
		"  if (a) {",
		"    return 7;",
		"  }",
		"  return 7;",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if strings.Contains(got, "if (") {
		t.Errorf("the guard cannot change the outcome and should go:\n%s", got)
	}
	if strings.Count(got, "return 7;") != 1 {
		t.Errorf("expected exactly one return:\n%s", got)
	}
}

func TestDeadStoreEliminationOnTree(t *testing.T) {
	keep := runCompact("void f() {\n  x = sideEffect();\n  x = 10;\n}")
	if !strings.Contains(keep, "sideEffect()") {
		t.Errorf("a call must not be dropped as a dead store:\n%s", keep)
	}
	read := runCompact("void f() {\n  x = 5;\n  x = x + 1;\n}")
	if !strings.Contains(read, "x = 5;") {
		t.Errorf("a store read by its successor must be kept:\n%s", read)
	}
	drop := runCompact("void f() {\n  x = 5;\n  x = 10;\n}")
	if strings.Contains(drop, "x = 5;") {
		t.Errorf("a genuinely dead store should be dropped:\n%s", drop)
	}
}

// Regression: scope, not indentation. Two sibling blocks sit at the same
// indent but are different scopes -- a temp defined in the first is not
// defined in the second, and the first branch may never have run. Measured on
// the old implementation, this input became `use(arg0)`.
func TestCopyPropagationDoesNotCrossSiblingBlocks(t *testing.T) {
	src := strings.Join([]string{
		"void f() {",
		"  if (a) {",
		"    t1 = arg0;",
		"  }",
		"  if (b) {",
		"    use(t1);",
		"  }",
		"}",
	}, "\n")
	got := runCompact(src)
	if strings.Contains(got, "use(arg0)") {
		t.Errorf("a copy defined in one branch must not propagate into a sibling branch:\n%s", got)
	}
}

func TestCopyPropagationWithinScope(t *testing.T) {
	got := runCompact("void f() {\n  t1 = arg0;\n  use(t1);\n}")
	if !strings.Contains(got, "use(arg0)") {
		t.Errorf("a stable copy should propagate within its own scope:\n%s", got)
	}
}

func TestCopyPropagationRespectsSourceMutationOnTree(t *testing.T) {
	got := runCompact("void f() {\n  t1 = local_5;\n  local_5 = 7;\n  use(t1);\n}")
	if strings.Contains(got, "use(local_5)") {
		t.Errorf("must not propagate past a reassignment of the source:\n%s", got)
	}
}

// Regression, same scope hole as copy propagation: `final t1` declared inside
// a branch is not in scope after the branch ends. Measured on the old
// implementation, this input emitted `return t1;` -- a reference to a
// variable that is not declared on that path.
func TestCSEDoesNotCrossSiblingBlocks(t *testing.T) {
	src := strings.Join([]string{
		"int f() {",
		"  if (a) {",
		"    final t1 = alpha + beta;",
		"    sink(t1);",
		"  }",
		"  return alpha + beta;",
		"}",
	}, "\n")
	got := runCompact(src)
	if strings.Contains(got, "return t1;") {
		t.Errorf("a temp declared inside a branch is not in scope after it:\n%s", got)
	}
}

func TestCSEWithinScope(t *testing.T) {
	got := runCompact("int f() {\n  final t1 = alpha + beta;\n  return alpha + beta;\n}")
	if !strings.Contains(got, "return t1;") {
		t.Errorf("a stable expression should be reused in scope:\n%s", got)
	}
}

func TestCSERespectsOperandMutationOnTree(t *testing.T) {
	got := runCompact("int f() {\n  final t1 = alpha + beta;\n  alpha = 5;\n  return alpha + beta;\n}")
	if strings.Contains(got, "return t1;") {
		t.Errorf("must not reuse t1 after alpha changed:\n%s", got)
	}
}

// A brace inside a string literal must not shift the structure.
//
// The old block finder counted braces with strings.Count, so the `"{"` below
// made it overshoot the loop's closing brace and return the FUNCTION's
// instead. Unwrapping then consumed that brace and dedented everything after
// it, putting the rest of the function at top level. Measured on the old
// implementation, this exact input produced:
//
//	void f() {
//	  log("{");
//	  return;
//	}
//	after();          <- outside the function
func TestStructuralPassesIgnoreBracesInStrings(t *testing.T) {
	src := strings.Join([]string{
		"void f() {",
		"  while (true) {",
		"    log(\"{\");",
		"    return;",
		"  }",
		"  after();",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	// after() is genuinely unreachable once the loop is unwrapped, so it may
	// be dropped -- but it must never end up OUTSIDE the function.
	for _, line := range strings.Split(got, "\n") {
		if strings.TrimSpace(line) == "after();" && !strings.HasPrefix(line, "  ") {
			t.Errorf("a brace in a string literal pushed code out of the function:\n%s", got)
		}
	}
}
