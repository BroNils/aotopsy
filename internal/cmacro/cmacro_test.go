package cmacro

import (
	"fmt"
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

func TestNestedMacroFormalSubstitution(t *testing.T) {
	src := `
#define SUB(F) F(A) F(B)
#define LIST(X) SUB(X)
`
	got, err := Expand(ParseMacros(src), "LIST")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"A", "B"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestWhitespaceInvocationAndQuotedParen(t *testing.T) {
	src := `#define LIST(V) V (Name, "x)y")`
	rows, err := ExpandRaw(ParseMacros(src), "LIST")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"Name", `"x)y"`}}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("got %q, want %q", rows, want)
	}
}

func TestMalformedInvocationFailsInsteadOfPartialResult(t *testing.T) {
	src := `#define LIST(V) V(A) V(B`
	if rows, err := ExpandRaw(ParseMacros(src), "LIST"); err == nil {
		t.Fatalf("unterminated invocation returned partial success: %q", rows)
	}
}

func TestMissingNestedMacroFailsInsteadOfTruncatingList(t *testing.T) {
	src := `#define LIST(V) V(A) MISSING(V) V(B)`
	if rows, err := ExpandRaw(ParseMacros(src), "LIST"); err == nil {
		t.Fatalf("missing nested macro returned partial success: %q", rows)
	}
}

func TestFormalSubstitutionIsSimultaneous(t *testing.T) {
	src := `
#define PAIR(A, B) V(A, B)
#define LIST(V) PAIR(B, A)
`
	rows, err := ExpandRaw(ParseMacros(src), "LIST")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"B", "A"}}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("sequential substitution corrupted arguments: got %q, want %q", rows, want)
	}
}

func TestExpansionScannerIgnoresQuotedCallbackText(t *testing.T) {
	src := `#define LIST(V) "V(Fake)" V(Real)`
	got, err := Expand(ParseMacros(src), "LIST")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Real"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("quoted callback leaked into expansion: got %q, want %q", got, want)
	}
}

func TestParseMacrosAcceptsPreprocessorWhitespaceAndPreservesTokenBoundary(t *testing.T) {
	src := "  #  define LIST(V) V(A/**/B)\n"
	got, err := Expand(ParseMacros(src), "LIST")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"A B"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("comment removal merged tokens: got %q, want %q", got, want)
	}
}

func TestExpansionDepthIsBounded(t *testing.T) {
	macros := Macros{}
	for i := 0; i <= maxExpansionDepth+1; i++ {
		name := fmt.Sprintf("M%d", i)
		if i == maxExpansionDepth+1 {
			macros[name] = Macro{Params: []string{"V"}, Body: "V(End)", FunctionLike: true}
			continue
		}
		macros[name] = Macro{Params: []string{"V"}, Body: fmt.Sprintf("M%d(V)", i+1), FunctionLike: true}
	}
	if rows, err := ExpandRaw(macros, "M0"); err == nil {
		t.Fatalf("over-depth expansion succeeded with %d rows", len(rows))
	}
}

func TestZeroParameterFunctionLikeMacroStaysDistinctFromObjectLike(t *testing.T) {
	src := `
#define SUB() V(B)
#define CALLED(V) SUB() V(A)
#define BARE(V) SUB V(A)
`
	macros := ParseMacros(src)
	if !macros["SUB"].FunctionLike {
		t.Fatal("zero-parameter function-like macro lost its invocation form")
	}
	got, err := Expand(macros, "CALLED")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"B", "A"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SUB() expansion = %q, want %q", got, want)
	}
	got, err = Expand(macros, "BARE")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"A"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("bare function-like SUB was expanded: got %q, want %q", got, want)
	}
}

func TestObjectLikeMacroStillExpandsWhenFollowedByParens(t *testing.T) {
	src := `
#define OBJ V(B)
#define LIST(V) OBJ() V(A)
`
	got, err := Expand(ParseMacros(src), "LIST")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"B", "A"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("object-like OBJ() expansion = %q, want %q", got, want)
	}
}

func TestSubstitutionHonorsByteBudgetBeforeAmplification(t *testing.T) {
	// A repeated formal is the dangerous shape: one modest actual argument can
	// be copied hundreds of times before the step/depth limits advance at all.
	if _, err := substituteIdentifiers("X X X X", []string{"X"}, []string{"abcd"}, 12); err == nil {
		t.Fatal("substitution exceeding byte budget succeeded")
	}
	got, err := substituteIdentifiers("X X", []string{"X"}, []string{"ab"}, 5)
	if err != nil {
		t.Fatalf("bounded substitution failed: %v", err)
	}
	if got != "ab ab" {
		t.Fatalf("bounded substitution = %q, want %q", got, "ab ab")
	}
}

func TestColumnRejectsShortRowAndNegativeIndex(t *testing.T) {
	macros := ParseMacros(`#define LIST(V) V(A, B) V(C)`)
	if _, err := Column(macros, "LIST", 1); err == nil {
		t.Fatal("short row was silently skipped")
	}
	if _, err := Column(macros, "LIST", -1); err == nil {
		t.Fatal("negative column index was accepted")
	}
}

func TestSplitTopLevelDoesNotTreatOperatorsAsTemplates(t *testing.T) {
	got := SplitTopLevel(`uword, mask, kOne >> 1, a < b, a<b, next, Type<A, B>, 0`)
	want := []string{"uword", "mask", "kOne >> 1", "a < b", "a<b", "next", "Type<A, B>", "0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
