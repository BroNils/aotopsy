package decompiler

import (
	"strings"
	"testing"
)

func TestForLoopRecoveryOnTree(t *testing.T) {
	src := strings.Join([]string{
		"dynamic foo() {",
		"  local_8 = 0;",
		"  while (local_8 < 10) {",
		"    final t1 = doSomething(local_8);",
		"    local_8 = local_8 + 1;",
		"  }",
		"  return null;",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if !strings.Contains(got, "for (local_8 = 0; local_8 < 10; local_8 = local_8 + 1) {") {
		t.Errorf("for header missing:\n%s", got)
	}
	if strings.Contains(got, "while (local_8 < 10)") {
		t.Errorf("the while should have been replaced:\n%s", got)
	}
	if strings.Count(got, "local_8 = local_8 + 1") != 1 {
		t.Errorf("the increment should appear once, in the header:\n%s", got)
	}
}

func TestForLoopRecoveryLeavesWhileTrueAlone(t *testing.T) {
	src := "dynamic foo() {\n  while (true) {\n    final t1 = doSomething();\n  }\n}"
	got := runCompact(src)
	assertBalanced(t, got)
	if strings.Contains(got, "for (") {
		t.Errorf("while (true) has no counter to lift:\n%s", got)
	}
}

// Regression: the increment must be the body's LAST TOP-LEVEL statement.
// The text version took the first `v = v + 1;` at any depth, so this input
// became `for (local_8 = 0; local_8 < 10; local_8 = local_8 + 1) { if (c) { } }`
// -- a conditional increment made unconditional, and an if left empty.
func TestForLoopRecoveryRejectsConditionalIncrement(t *testing.T) {
	src := strings.Join([]string{
		"void f() {",
		"  local_8 = 0;",
		"  while (local_8 < 10) {",
		"    if (c) {",
		"      local_8 = local_8 + 1;",
		"    }",
		"    body();",
		"  }",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if strings.Contains(got, "for (") {
		t.Errorf("an increment inside a conditional must not be lifted:\n%s", got)
	}
	if !strings.Contains(got, "local_8 = local_8 + 1;") {
		t.Errorf("the increment was removed from the body:\n%s", got)
	}
}

// Regression: the init must be the loop's IMMEDIATELY PRECEDING SIBLING. The
// text version scanned back ten lines ignoring blocks, so this input hoisted
// `local_8 = 0;` out of `if (p)` and left the if empty.
func TestForLoopRecoveryRejectsInitInAnotherBlock(t *testing.T) {
	src := strings.Join([]string{
		"void f() {",
		"  if (p) {",
		"    local_8 = 0;",
		"  }",
		"  while (local_8 < 10) {",
		"    local_8 = local_8 + 1;",
		"  }",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if strings.Contains(got, "for (") {
		t.Errorf("an init in a different block must not be lifted:\n%s", got)
	}
	if !strings.Contains(got, "local_8 = 0;") {
		t.Errorf("the init was removed from its block:\n%s", got)
	}
}

// Regression: `continue` runs the increment in a for and skips it in a while.
// The text version rewrote this -- an infinite loop when c holds -- into a
// for-loop that terminates. A decompiler must describe the binary, not repair
// it.
func TestForLoopRecoveryRejectsContinueInBody(t *testing.T) {
	src := strings.Join([]string{
		"void f() {",
		"  local_8 = 0;",
		"  while (local_8 < 10) {",
		"    if (c) {",
		"      continue;",
		"    }",
		"    local_8 = local_8 + 1;",
		"  }",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if strings.Contains(got, "for (") {
		t.Errorf("a body that can continue must keep its while form:\n%s", got)
	}
}

// A continue belonging to a NESTED loop says nothing about this one.
func TestForLoopRecoveryAllowsNestedLoopContinue(t *testing.T) {
	src := strings.Join([]string{
		"void f() {",
		"  local_8 = 0;",
		"  while (local_8 < 10) {",
		"    while (q) {",
		"      continue;",
		"    }",
		"    local_8 = local_8 + 1;",
		"  }",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if !strings.Contains(got, "for (local_8 = 0; local_8 < 10; local_8 = local_8 + 1) {") {
		t.Errorf("the inner loop's continue should not block the rewrite:\n%s", got)
	}
}

func TestMergeGuardsMergesReturns(t *testing.T) {
	src := strings.Join([]string{
		"dynamic foo(int x) {",
		"  if (x < 0) {",
		"    return;",
		"  }",
		"  if (x >= 10) {",
		"    return;",
		"  }",
		"  return x;",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if !strings.Contains(got, "if (x < 0 || x >= 10) {") {
		t.Errorf("consecutive return-guards should merge:\n%s", got)
	}
}

// Guards that return DIFFERENT values are not interchangeable. The text
// version could not express this: it only ever matched a bare `return;`.
func TestMergeGuardsRejectsDifferentReturnValues(t *testing.T) {
	src := strings.Join([]string{
		"int foo(int x) {",
		"  if (x < 0) {",
		"    return 1;",
		"  }",
		"  if (x >= 10) {",
		"    return 2;",
		"  }",
		"  return x;",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if strings.Contains(got, "||") {
		t.Errorf("guards returning different values must not merge:\n%s", got)
	}
}

// Now that guards merge on any terminator, identical `throw` guards merge
// too -- which the old doc comment claimed but the old code never did.
func TestMergeGuardsMergesIdenticalBreaks(t *testing.T) {
	src := strings.Join([]string{
		"void f() {",
		"  while (true) {",
		"    if (a) {",
		"      break;",
		"    }",
		"    if (b) {",
		"      break;",
		"    }",
		"    work();",
		"  }",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if !strings.Contains(got, "if (a || b) {") {
		t.Errorf("identical break-guards should merge:\n%s", got)
	}
}

// A null guard is left exactly as emitted -- see the note in stmt_loops.go
// for why no annotation pass survives here.
func TestNullGuardIsLeftAlone(t *testing.T) {
	src := strings.Join([]string{
		"dynamic foo(dynamic arg0) {",
		"  if (arg0 == null) {",
		"    return;",
		"  }",
		"  final t1 = arg0 + 1;",
		"  return t1;",
		"}",
	}, "\n")
	got := runCompact(src)
	assertBalanced(t, got)
	if got != src {
		t.Errorf("a null guard should pass through unchanged:\n--- want ---\n%s\n--- got ---\n%s", src, got)
	}
}
