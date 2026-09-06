package compare

import (
	"strings"
	"testing"
)

// TestReclassificationNeverMergesTwoTemps pins the guard that was missing.
//
// The collision check only asked whether the semantic name already existed as
// an identifier in the source. It never asked whether another rename in the
// same pass had claimed it, so two temps that classify the same way both got
// renamed to it -- presenting two distinct values as one variable. The corpus
// sweep surfaced it as `final accumulator = ...` followed by
// `accumulator = ...`, but the invalid Dart was only the symptom; the defect
// is the false identity.
func TestReclassificationNeverMergesTwoTemps(t *testing.T) {
	// t1 and t2 are both assigned twice and both used as arguments, so both
	// classify as "accumulator".
	src := strings.Join([]string{
		"void f() {",
		"  final t1 = a();",
		"  t1 = b();",
		"  use(t1);",
		"  final t2 = c();",
		"  t2 = d();",
		"  use(t2);",
		"}",
	}, "\n")

	out := ApplyIdentReclassification(src)

	names := map[string]int{}
	for _, tok := range []string{"accumulator", "counter", "flag", "result"} {
		names[tok] = strings.Count(out, tok+" ")
	}
	// Whatever the classifier decides, no two ORIGINAL temps may end up
	// sharing a name. Check by counting distinct identifiers still present.
	remaining := 0
	for _, id := range []string{"t1", "t2"} {
		if strings.Contains(out, id) {
			remaining++
		}
	}
	renamed := 0
	for _, n := range names {
		if n > 0 {
			renamed++
		}
	}
	if remaining+renamed < 2 {
		t.Errorf("two temps collapsed into fewer than two identifiers:\n%s", out)
	}
	// The specific failure: both temps became the same semantic name.
	for tok, count := range names {
		if count > 0 && !strings.Contains(out, "t1") && !strings.Contains(out, "t2") && count < 2 {
			continue
		}
		if strings.Count(out, "final "+tok+" =") > 1 {
			t.Errorf("%q declared twice:\n%s", tok, out)
		}
	}
}

// TestReclassificationIsDeterministic guards the ordering the collision fix
// depends on: with a guard but no sort, which temp wins would follow Go's map
// iteration order and the same binary would decompile differently per run.
func TestReclassificationIsDeterministic(t *testing.T) {
	src := strings.Join([]string{
		"void f() {",
		"  final t1 = a();",
		"  t1 = b();",
		"  use(t1);",
		"  final t2 = c();",
		"  t2 = d();",
		"  use(t2);",
		"  final t3 = e();",
		"  t3 = g();",
		"  use(t3);",
		"}",
	}, "\n")

	first := ApplyIdentReclassification(src)
	for i := 0; i < 50; i++ {
		if got := ApplyIdentReclassification(src); got != first {
			t.Fatalf("run %d differs:\n--- first ---\n%s\n--- got ---\n%s", i, first, got)
		}
	}
}
