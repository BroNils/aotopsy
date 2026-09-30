package cmacro

import (
	"fmt"
	"reflect"
	"strings"
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

func mustParseMacros(t *testing.T, src string) Macros {
	t.Helper()
	macros, err := ParseMacros(src)
	if err != nil {
		t.Fatalf("ParseMacros: %v", err)
	}
	return macros
}

func TestExpandNested(t *testing.T) {
	got, err := Expand(mustParseMacros(t, sampleHeader), "VM_STUB_CODE_LIST")
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
	got, err := Expand(mustParseMacros(t, sampleHeader), "PROBE_POINT_STUBS_LIST")
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
	rows, err := ExpandRaw(mustParseMacros(t, sampleHeader), "CACHED_VM_STUBS_ADDRESSES_LIST")
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
	names, err := Column(mustParseMacros(t, sampleHeader), "CACHED_VM_STUBS_ADDRESSES_LIST", 1)
	if err != nil {
		t.Fatalf("column: %v", err)
	}
	if want := []string{"deoptimize_entry_", "interpret_call_entry_point_"}; !reflect.DeepEqual(names, want) {
		t.Errorf("column 1 = %q, want %q", names, want)
	}
}

func TestExpandUnknownMacroFails(t *testing.T) {
	if _, err := Expand(mustParseMacros(t, sampleHeader), "NO_SUCH_LIST"); err == nil {
		t.Error("expanding an unknown macro must fail, not return an empty list")
	}
}

func TestSplitTopLevel(t *testing.T) {
	got, err := SplitTopLevel("Type<A, B>, name, f(a, b), 0")
	if err != nil {
		t.Fatal(err)
	}
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
	got, err := Expand(mustParseMacros(t, src), "LIST")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"A", "B"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestWhitespaceInvocationAndQuotedParen(t *testing.T) {
	src := `#define LIST(V) V (Name, "x)y")`
	rows, err := ExpandRaw(mustParseMacros(t, src), "LIST")
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
	if rows, err := ExpandRaw(mustParseMacros(t, src), "LIST"); err == nil {
		t.Fatalf("unterminated invocation returned partial success: %q", rows)
	}
}

func TestMissingNestedMacroFailsInsteadOfTruncatingList(t *testing.T) {
	src := `#define LIST(V) V(A) MISSING(V) V(B)`
	if rows, err := ExpandRaw(mustParseMacros(t, src), "LIST"); err == nil {
		t.Fatalf("missing nested macro returned partial success: %q", rows)
	}
}

func TestFormalSubstitutionIsSimultaneous(t *testing.T) {
	src := `
#define PAIR(A, B) V(A, B)
#define LIST(V) PAIR(B, A)
`
	rows, err := ExpandRaw(mustParseMacros(t, src), "LIST")
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
	got, err := Expand(mustParseMacros(t, src), "LIST")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Real"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("quoted callback leaked into expansion: got %q, want %q", got, want)
	}
}

func TestParseMacrosAcceptsPreprocessorWhitespaceAndPreservesTokenBoundary(t *testing.T) {
	src := "  #  define LIST(V) V(A/**/B)\n"
	got, err := Expand(mustParseMacros(t, src), "LIST")
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
	macros := mustParseMacros(t, src)
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
	got, err := Expand(mustParseMacros(t, src), "LIST")
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
	macros := mustParseMacros(t, `#define LIST(V) V(A, B) V(C)`)
	if _, err := Column(macros, "LIST", 1); err == nil {
		t.Fatal("short row was silently skipped")
	}
	if _, err := Column(macros, "LIST", -1); err == nil {
		t.Fatal("negative column index was accepted")
	}
}

func TestSplitTopLevelDoesNotTreatOperatorsAsTemplates(t *testing.T) {
	got, err := SplitTopLevel(`uword, mask, kOne >> 1, a < b, a<b, next, Type<A, B>, 0`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"uword", "mask", "kOne >> 1", "a < b", "a<b", "next", "Type<A, B>", "0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParseMacrosRejectsMalformedLexicalInput(t *testing.T) {
	for name, src := range map[string]string{
		"unterminated block comment":  `#define LIST(V) V(A) /*`,
		"unterminated quoted literal": `#define LIST(V) V("A)`,
		"missing define name":         `#define`,
		"malformed undef":             `#undef`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseMacros(src); err == nil {
				t.Fatalf("ParseMacros accepted malformed input %q", src)
			}
		})
	}
}

func TestParseMacrosRejectsOversizedSource(t *testing.T) {
	src := strings.Repeat("x", maxSourceBytes+1)
	if _, err := ParseMacros(src); err == nil {
		t.Fatalf("ParseMacros accepted %d-byte source over %d-byte limit", len(src), maxSourceBytes)
	}
}

func TestConditionalRedefinitionFailsClosed(t *testing.T) {
	src := `
#if defined(A)
#define LIST(V) V(A)
#else
#define LIST(V) V(B)
#endif
`
	macros := mustParseMacros(t, src)
	if _, err := Expand(macros, "LIST"); err == nil {
		t.Fatal("conditional redefinition expanded without preprocessing context")
	}
}

func TestConditionalRedefinitionWithBranchUndefStillFailsClosed(t *testing.T) {
	src := `
#if defined(A)
#define LIST(V) V(A)
#undef LIST
#else
#define LIST(V) V(B)
#undef LIST
#endif
`
	macros := mustParseMacros(t, src)
	if _, err := Expand(macros, "LIST"); err == nil {
		t.Fatal("branch-local #undef incorrectly made conditional definitions unambiguous")
	}
}

func TestUndefStartsNewCatalogDefinitionLifetime(t *testing.T) {
	src := `
#define LIST(V) V(Old)
#undef LIST
#define LIST(V) V(New)
#undef LIST
`
	got, err := Expand(mustParseMacros(t, src), "LIST")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"New"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog expansion = %q, want %q", got, want)
	}
}

func TestUndefWithinSameIncludeGuardStartsNewLifetime(t *testing.T) {
	src := `
#ifndef SAMPLE_HEADER_H_
#define SAMPLE_HEADER_H_
#define LIST(V) V(Old)
#undef LIST
#define LIST(V) V(New)
#endif
`
	got, err := Expand(mustParseMacros(t, src), "LIST")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"New"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog expansion inside include guard = %q, want %q", got, want)
	}
}

func TestParseMacrosRejectsUnbalancedConditionalDirectives(t *testing.T) {
	for _, src := range []string{
		"#if defined(A)\n#define LIST(V) V(A)\n",
		"#else\n#define LIST(V) V(A)\n",
		"#endif\n",
	} {
		if _, err := ParseMacros(src); err == nil {
			t.Fatalf("ParseMacros accepted unbalanced conditional source %q", src)
		}
	}
}

// A different redefinition with no #undef between the two must be ambiguous at
// top level too, not only inside a conditional or an include guard. The
// "reset by #undef" test compared a missing map entry (empty string) with the
// empty top-level context, so it held for every macro that was never undefined
// and the last body silently won.
func TestTopLevelRedefinitionWithoutUndefIsAmbiguous(t *testing.T) {
	src := "#define LIST(V) V(A)\n#define LIST(V) V(B)\n"
	macros := mustParseMacros(t, src)
	if !macros["LIST"].Ambiguous {
		t.Fatal("different top-level redefinition without #undef was not marked ambiguous")
	}
	if got, err := Expand(macros, "LIST"); err == nil {
		t.Fatalf("ambiguous top-level redefinition expanded to %q", got)
	}
}

func TestIdenticalRedefinitionIsNotAmbiguous(t *testing.T) {
	src := "#define LIST(V) V(A)\n#define LIST(V) V(A)\n"
	got, err := Expand(mustParseMacros(t, src), "LIST")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"A"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestUnsupportedFormalParametersFailOnExpansion(t *testing.T) {
	for name, src := range map[string]string{
		"variadic":          `#define LIST(V, ...) V(A)`,
		"duplicate":         `#define LIST(V, V) V(A)`,
		"empty":             `#define LIST(V,, X) V(A)`,
		"malformed formals": `#define LIST(V V(A)`,
	} {
		t.Run(name, func(t *testing.T) {
			macros := mustParseMacros(t, src)
			if _, err := Expand(macros, "LIST"); err == nil {
				t.Fatalf("unsupported formals expanded for %q", src)
			}
		})
	}
}

func TestExpandRawAllCallbacksPreservesExactRowOrder(t *testing.T) {
	src := `
#define OBJECT_STORE_FIELD_LIST(R_, RW, ARW_RELAXED, LAZY_CORE) \
  LAZY_CORE(Class, list_class)                              \
  RW(Type, object_type)                                    \
  ARW_RELAXED(Object, global_object_pool)                  \
  R_(Code, slow_tts_stub)
`
	rows, err := ExpandRawAllCallbacks(mustParseMacros(t, src), "OBJECT_STORE_FIELD_LIST")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"Class", "list_class"},
		{"Type", "object_type"},
		{"Object", "global_object_pool"},
		{"Code", "slow_tts_stub"},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("multi-callback rows\n got %#v\nwant %#v", rows, want)
	}
}

func TestRecursiveMacroCycleFails(t *testing.T) {
	src := `
#define A(V) B(V)
#define B(V) A(V)
`
	if rows, err := ExpandRaw(mustParseMacros(t, src), "A"); err == nil {
		t.Fatalf("recursive cycle returned partial success: %q", rows)
	}
}

func TestEmptyCallbackRowFails(t *testing.T) {
	if rows, err := ExpandRaw(mustParseMacros(t, `#define LIST(V) V(A) V() V(B)`), "LIST"); err == nil {
		t.Fatalf("empty callback row returned partial success: %q", rows)
	}
}

func TestSplitTopLevelRejectsUnbalancedDelimiters(t *testing.T) {
	for _, src := range []string{
		`A, f(x, y`,
		`A, values[0, 1`,
		`A, Init{1, 2`,
		`A, Type<B, C`,
		`A, ]`,
		`A, }`,
	} {
		if got, err := SplitTopLevel(src); err == nil {
			t.Fatalf("SplitTopLevel(%q) = %q without error", src, got)
		}
	}
}

func TestExpansionIsDeterministic(t *testing.T) {
	macros := mustParseMacros(t, sampleHeader)
	want, err := ExpandRaw(macros, "VM_STUB_CODE_LIST")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		got, err := ExpandRaw(macros, "VM_STUB_CODE_LIST")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d changed expansion: got %q want %q", i, got, want)
		}
	}
}
