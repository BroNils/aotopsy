package naming

import "testing"

// The symbol table is a last resort, not a naming path. It may only fill in
// where the snapshot produced nothing, because a name that came from
// `.symtab` proves nothing about whether the snapshot-derived naming works --
// and production builds are stripped, so leaning on it would make the corpus
// numbers measure the linker instead of the analysis.
func TestELFStubNameOnlyFillsAGap(t *testing.T) {
	syms := map[uint64]string{
		0x15b58c: "stub _iso_stub_AwaitStub",
		0x1364f8: "assert type is HitTestTarget",
	}
	if got, want := ElfStubName(syms, 0x15b58c, "sub_2560c"), "stub__iso_stub_AwaitStub"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// An address the table does not describe keeps the placeholder.
	if got, want := ElfStubName(syms, 0xdeadbeef, "sub_dead"), "sub_dead"; got != want {
		t.Errorf("unknown address: got %q, want %q", got, want)
	}
	// A stripped build has no table at all, and that is not an error.
	if got, want := ElfStubName(nil, 0x15b58c, "sub_2560c"), "sub_2560c"; got != want {
		t.Errorf("stripped build: got %q, want %q", got, want)
	}
}

// These names are Dart-side prose rather than identifiers -- "new Duration",
// "assert type is HitTestTarget" -- so a consumer that splits a function name
// on whitespace would see several tokens. The text is kept; only the
// separator changes.
func TestELFStubNameHasNoSpaces(t *testing.T) {
	syms := map[uint64]string{0x10: "assert type is HitTestTarget"}
	got := ElfStubName(syms, 0x10, "sub_10")
	if want := "assert_type_is_HitTestTarget"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A symbol that is present but blank must not replace the placeholder with an
// empty name.
func TestELFStubNameIgnoresBlankSymbols(t *testing.T) {
	syms := map[uint64]string{0x10: "   "}
	if got, want := ElfStubName(syms, 0x10, "sub_10"), "sub_10"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
