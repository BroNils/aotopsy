package stmt

import (
	"strings"
	"testing"
)

func collapseBox(t *testing.T, src string) (string, bool) {
	t.Helper()
	tree := ParseStmts(strings.Split(src, "\n"))
	out, changed := collapseMintBoxDiamondStmt(tree)
	// descend like CompactTree would
	out, c2 := mapBodies(out, collapseMintBoxDiamondStmt)
	return strings.Join(PrintStmts(out), "\n"), changed || c2
}

// Real arm64 (compressed pointers) shape from the 3.9.2 sample.
func TestMintBoxDiamondArm64(t *testing.T) {
	src := "void f() {\n" +
		"  if (local_m16.f11 == local_m8 >> 1) {\n" +
		"    block_3:;\n" +
		"    accumulator.f23 = local_m8 & 0xffffffff;\n" +
		"    return;\n" +
		"  } else {\n" +
		"    AllocateMintWithoutFpuRegs(null, accumulator, local_m16).f7 = local_m16.f11;\n" +
		"    goto block_3;\n" +
		"  }\n" +
		"}"
	got, changed := collapseBox(t, src)
	want := "void f() {\n  block_3:;\n  accumulator.f23 = local_m8 & 0xffffffff;\n  return;\n}"
	if !changed || got != want {
		t.Fatalf("changed=%v\n got:\n%s\nwant:\n%s", changed, got, want)
	}
}

// Real x64 shape: the miss path is wrapped by an "inlined" helper comment.
func TestMintBoxDiamondX64WithInlinedComment(t *testing.T) {
	src := "void f() {\n" +
		"  if (((t40 >> 30) + 1 & 0xffffffffffffffff) < (2 & 0xffffffffffffffff)) {\n" +
		"    block_48:;\n" +
		"    g();\n" +
		"  } else {\n" +
		"    // inlined _block_47\n" +
		"      final t1 = AllocateMintWithoutFpuRegs()..f7 = t40;\n" +
		"      goto block_48;\n" +
		"  }\n" +
		"}"
	got, changed := collapseBox(t, src)
	if !changed || strings.Contains(got, "Allocate") || !strings.Contains(got, "g();") {
		t.Fatalf("changed=%v got:\n%s", changed, got)
	}
}

// A branch that does ANYTHING besides the allocation is a real branch.
func TestMintBoxDiamondLeavesRealBranches(t *testing.T) {
	for name, src := range map[string]string{
		"extra statement":   "void f() {\n  if (c) {\n    block_3:;\n    a();\n  } else {\n    AllocateMintWithoutFpuRegs().f7 = v;\n    log();\n    goto block_3;\n  }\n}",
		"other goto":        "void f() {\n  if (c) {\n    block_3:;\n    a();\n  } else {\n    AllocateMintWithoutFpuRegs().f7 = v;\n    goto block_9;\n  }\n}",
		"call in condition": "void f() {\n  if (probe()) {\n    block_3:;\n    a();\n  } else {\n    goto block_3;\n  }\n}",
		// A bool bit test (`enabled ? "on" : "off"`) is a real branch whose join
		// value differs by path: it must stay visible.
		"bool bit test":   "void f() {\n  if ((((e.f19 & 0xffffffff) >> 4 & 1) != 0) {\n    block_6:;\n    s = \"off\";\n  } else {\n    goto block_6;\n  }\n}",
		"plain condition": "void f() {\n  if (c) {\n    block_3:;\n    a();\n  } else {\n    goto block_3;\n  }\n}",
		"not a mint":      "void f() {\n  if (c) {\n    block_3:;\n    a();\n  } else {\n    AllocateDouble().f7 = v;\n    goto block_3;\n  }\n}",
	} {
		if _, changed := collapseBox(t, src); changed {
			t.Errorf("%s: a real branch was collapsed", name)
		}
	}
}

// `if (c) { L: X } else { goto L }` is X when c has no side effect: both paths
// run X. This is what remains of an array-store Smi/write-barrier check once the
// barrier stub call itself has been elided.
func TestPureGotoDiamondIsCollapsed(t *testing.T) {
	src := "void f() {\n" +
		"  if (((t10 & 0xff) >> 0 & 1) == 0) {\n" +
		"    block_4:;\n" +
		"    g();\n" +
		"  } else {\n" +
		"    goto block_4;\n" +
		"  }\n" +
		"}"
	got, changed := collapseBox(t, src)
	if !changed || got != "void f() {\n  block_4:;\n  g();\n}" {
		t.Fatalf("changed=%v got:\n%s", changed, got)
	}
}
