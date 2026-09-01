package cmacro

import (
	"reflect"
	"testing"
)

// The expander is the piece every SDK gate depends on, and its failure
// mode is silent truncation -- a short list reads as a narrower mask or a
// shifted table, not as an error. These cases are the shapes that
// actually appear in the SDK headers.

const sampleHeader = `
// A leading comment mentioning V(NotAnEntry).
#define PROBE_POINT_STUBS_LIST(V)                                              \
  V(AllocationProbePoint)                                                      \
  V(ReturnProbePoint)

/* A block comment with V(AlsoNotAnEntry) in it. */
#define VM_TYPE_TESTING_STUB_CODE_LIST(V)                                      \
  V(DefaultTypeTest)

#define VM_STUB_CODE_LIST(V)                                                   \
  V(GetCStackPointer)                                                          \
  PROBE_POINT_STUBS_LIST(V)                                                    \
  V(JumpToFrame)                                                               \
  VM_TYPE_TESTING_STUB_CODE_LIST(V)

#define CACHED_VM_STUBS_ADDRESSES_LIST(V)                                      \
  V(uword, deoptimize_entry_, StubCode::Deoptimize().EntryPoint(), 0)          \
  V(uword, interpret_call_entry_point_, RuntimeEntry::InterpretCallEntry(), 0)
`

func TestExpandNested(t *testing.T) {
	got, err := Expand(ParseMacros(sampleHeader), "VM_STUB_CODE_LIST")
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	want := []string{
		"GetCStackPointer",
		"AllocationProbePoint", "ReturnProbePoint",
		"JumpToFrame",
		"DefaultTypeTest",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("nested expansion\n got %q\nwant %q", got, want)
	}
}

func TestExpandIgnoresComments(t *testing.T) {
	got, err := Expand(ParseMacros(sampleHeader), "PROBE_POINT_STUBS_LIST")
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if want := []string{"AllocationProbePoint", "ReturnProbePoint"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	for _, n := range got {
		if n == "NotAnEntry" || n == "AlsoNotAnEntry" {
			t.Errorf("comment contents leaked into the list: %q", n)
		}
	}
}

// An entry whose initialiser has its own parentheses must keep all of its
// arguments. Dropping the row here is how a stub table loses entries.
func TestExpandKeepsEntriesWithNestedParens(t *testing.T) {
	rows, err := ExpandRaw(ParseMacros(sampleHeader), "CACHED_VM_STUBS_ADDRESSES_LIST")
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2: %q", len(rows), rows)
	}
	want := []string{"uword", "deoptimize_entry_", "StubCode::Deoptimize().EntryPoint()", "0"}
	if !reflect.DeepEqual(rows[0], want) {
		t.Errorf("row 0\n got %q\nwant %q", rows[0], want)
	}
	names, err := Column(ParseMacros(sampleHeader), "CACHED_VM_STUBS_ADDRESSES_LIST", 1)
	if err != nil {
		t.Fatalf("column: %v", err)
	}
	if want := []string{"deoptimize_entry_", "interpret_call_entry_point_"}; !reflect.DeepEqual(names, want) {
		t.Errorf("column 1 = %q, want %q", names, want)
	}
}

func TestExpandUnknownMacroFails(t *testing.T) {
	if _, err := Expand(ParseMacros(sampleHeader), "NO_SUCH_LIST"); err == nil {
		t.Error("expanding an unknown macro must fail, not return an empty list")
	}
}

func TestSplitTopLevel(t *testing.T) {
	got := SplitTopLevel("Type<A, B>, name, f(a, b), 0")
	want := []string{"Type<A, B>", "name", "f(a, b)", "0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
