package stmt

import (
	"strings"
	"testing"
)

func foldInterp(src string) (string, bool) {
	tree := ParseStmts(strings.Split(src, "\n"))
	out, changed := FoldInterpolationArrayStmt(tree)
	return strings.Join(PrintStmts(out), "\n"), changed
}

// Shape of the 3.9.2 arm64 sample (compressed pointers: f15 + 4*i), with the
// real register-leak arguments of the call.
func TestFoldInterpolationArrayCompressed(t *testing.T) {
	src := "dynamic f(dynamic arg0) {\n" +
		"  final t1 = AllocateArray(null, 8, arg0.f7 & 0xffffffff)..f15 = local_m8 & 0xffffffff..f19 = \" v\";\n" +
		"  block_3:;\n" +
		"  t1.f23 = arg0.f11 & 0xffffffff;\n" +
		"  t1.f27 = \")\";\n" +
		"  stack_sp = t1;\n" +
		"  return _StringBase._interpolate(null, t1, local_m16);\n" +
		"}"
	got, changed := foldInterp(src)
	want := "dynamic f(dynamic arg0) {\n  block_3:;\n  return \"$local_m8 v${arg0.f11})\";\n}"
	if !changed || got != want {
		t.Fatalf("changed=%v\n got:\n%s\nwant:\n%s", changed, got, want)
	}
}

// Uncompressed layout: f23 + 8*i, plain (non-cascade) stores.
func TestFoldInterpolationArrayUncompressed(t *testing.T) {
	src := "dynamic f() {\n" +
		"  final t1 = AllocateArray(null, 4, null);\n" +
		"  t1.f23 = \"a=\";\n" +
		"  t1.f31 = x;\n" +
		"  final s = _StringBase._interpolate(t1);\n" +
		"  return s;\n" +
		"}"
	got, changed := foldInterp(src)
	if !changed || !strings.Contains(got, `final s = "a=$x";`) || strings.Contains(got, "AllocateArray") {
		t.Fatalf("changed=%v got:\n%s", changed, got)
	}
}

func TestFoldInterpolationArrayRefusals(t *testing.T) {
	for name, src := range map[string]string{
		"conditional element": "dynamic f() {\n  final t1 = AllocateArray(null, 4, null);\n  t1.f23 = \"a\";\n  if (c) {\n    t1.f31 = x;\n  }\n  return _StringBase._interpolate(t1);\n}",
		"missing index":       "dynamic f() {\n  final t1 = AllocateArray(null, 6, null);\n  t1.f23 = \"a\";\n  t1.f39 = x;\n  return _StringBase._interpolate(t1);\n}",
		"length disagrees":    "dynamic f() {\n  final t1 = AllocateArray(null, 20, null);\n  t1.f23 = \"a\";\n  t1.f31 = x;\n  return _StringBase._interpolate(t1);\n}",
		"local reassigned":    "dynamic f() {\n  final t1 = AllocateArray(null, 4, null);\n  t1.f23 = \"a\";\n  t1.f31 = x;\n  x = 5;\n  return _StringBase._interpolate(t1);\n}",
		"call piece moved":    "dynamic f() {\n  final t1 = AllocateArray(null, 4, null);\n  t1.f23 = \"a\";\n  t1.f31 = compute();\n  g();\n  return _StringBase._interpolate(t1);\n}",
		"field read vs call":  "dynamic f() {\n  final t1 = AllocateArray(null, 4, null);\n  t1.f23 = \"a\";\n  t1.f31 = obj.f11;\n  g();\n  return _StringBase._interpolate(t1);\n}",
		"array escapes":       "dynamic f() {\n  final t1 = AllocateArray(null, 4, null);\n  t1.f23 = \"a\";\n  keep(t1);\n  t1.f31 = x;\n  return _StringBase._interpolate(t1);\n}",
		"array not an arg":    "dynamic f() {\n  final t1 = AllocateArray(null, 2, null);\n  t1.f23 = \"a\";\n  return _StringBase._interpolate(other);\n}",
		"single-arg list use": "dynamic f() {\n  final t1 = AllocateArray(null, 2, null);\n  t1.f23 = \"a\";\n  return use(t1);\n}",
	} {
		if got, changed := foldInterp(src); changed {
			t.Errorf("%s: folded when it must not:\n%s", name, got)
		}
	}
}

// Unrelated statements between the stores and the call are fine when every piece
// is provably unaffected (a literal and a never-reassigned local here), and the
// raw `*((V + N))` store form (array store through a computed address) counts as
// an element store.
func TestFoldInterpolationArraySkipsUnrelatedStatementsAndRawStores(t *testing.T) {
	src := "dynamic f() {\n" +
		"  final t1 = AllocateArray(null, 4, null);\n" +
		"  t1.f23 = \"a\";\n" +
		"  g();\n" +
		"  *((t1 + 31)) = x;\n" +
		"  return _StringBase._interpolate(t1);\n" +
		"}"
	got, changed := foldInterp(src)
	want := "dynamic f() {\n  g();\n  return \"a$x\";\n}"
	if !changed || got != want {
		t.Fatalf("changed=%v\n got:\n%s\nwant:\n%s", changed, got, want)
	}
}

// Real shape (3.9.2 sample): the array is pushed inline with its pieces in a
// cascade and the call shows NO arguments.
func TestFoldInterpolationInlinePushedArray(t *testing.T) {
	src := "dynamic f() {\n" +
		"  block_56:;\n" +
		"  local_m112 = t24;\n" +
		"  stack_sp = AllocateArray()..f15 = (local_m112 & 0xffffffff)..f19 = \"_\"..f23 = (local_m104 & 0xffffffff);\n" +
		"  final t26 = _StringBase._interpolate();\n" +
		"  return t26;\n" +
		"}"
	got, changed := foldInterp(src)
	want := "dynamic f() {\n  block_56:;\n  local_m112 = t24;\n  final t26 = \"${local_m112}_$local_m104\";\n  return t26;\n}"
	if !changed || got != want {
		t.Fatalf("changed=%v\n got:\n%s\nwant:\n%s", changed, got, want)
	}
}

// Real shape: the temp is copied to a frame slot, pieces are stored through either
// name, the array is pushed, and the call overwrites the slot.
func TestFoldInterpolationAliasOverwrittenByCall(t *testing.T) {
	src := "dynamic f() {\n" +
		"  final t27 = AllocateArray();\n" +
		"  local_m16 = t27;\n" +
		"  t27.f15 = \"(elided one frame from \";\n" +
		"  *((local_m16 + 19)) = (_GrowableList.get:single() & 0xffffffff);\n" +
		"  block_111:;\n" +
		"  local_m16.f23 = \")\";\n" +
		"  stack_sp = local_m16;\n" +
		"  local_m16 = _StringBase._interpolate();\n" +
		"  return local_m16;\n" +
		"}"
	got, changed := foldInterp(src)
	want := "dynamic f() {\n  block_111:;\n  local_m16 = \"(elided one frame from ${_GrowableList.get:single()})\";\n  return local_m16;\n}"
	if !changed || got != want {
		t.Fatalf("changed=%v\n got:\n%s\nwant:\n%s", changed, got, want)
	}
}

// The slot is NOT overwritten by the call (`final t = _interpolate()`): it may be
// read later, so the alias copy cannot be dropped and nothing is folded.
func TestFoldInterpolationAliasKeptWhenCallDoesNotOverwriteIt(t *testing.T) {
	src := "dynamic f() {\n" +
		"  final t27 = AllocateArray();\n" +
		"  local_m16 = t27;\n" +
		"  t27.f15 = \"a\";\n" +
		"  stack_sp = local_m16;\n" +
		"  final t = _StringBase._interpolate();\n" +
		"  return local_m16;\n" +
		"}"
	if got, changed := foldInterp(src); changed {
		t.Fatalf("folded although the alias slot stays live:\n%s", got)
	}
}
