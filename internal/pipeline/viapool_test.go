package pipeline

import "testing"

// TestResolveViaPoolDisplay covers the guards that keep a BLR edge from being
// labelled with something that cannot be called.
//
// The display string is all this function gets, so what it can rule out is
// exactly what ResolvePoolDisplay makes visible in the text: a String entry is
// rendered with %q, and an object with no resolvable name is rendered
// "<CidName>". Both must be refused. Accepting either is how the deleted
// symbolic_blr.go came to report "Subtype6TestCache" -- a data object -- as a
// call target.
func TestResolveViaPoolDisplay(t *testing.T) {
	cases := []struct{ via, want string }{
		// Real shapes from the corpus, both architectures' spellings.
		{"PP[123] TypeTestingStub_Iterable", "TypeTestingStub_Iterable"},
		{"pp[4021] SmiAddInlineCache", "SmiAddInlineCache"},
		{"pp[88] AllocateUint64Array", "AllocateUint64Array"},
		{"PP[7] Widget.build", "Widget.build"},

		// A String constant. Nothing can be called through it.
		{`pp[12] "hello world"`, ""},
		{`PP[12] ""`, ""},

		// Placeholders name no target.
		{"PP[9] <Instance_42>", ""},
		{"pp[9] <String>", ""},
		{"pp[9] <vm:311>", ""},

		// A pool slot with no display at all.
		{"PP[9]", ""},
		{"pp[9] ", ""},

		// Not a pool annotation.
		{"THR.AllocateArray_ep", ""},
		{"dispatch_table[17]", ""},
		{"object_field", ""},
		{"", ""},

		// Malformed: no closing bracket.
		{"PP[123 foo", ""},
	}
	for _, c := range cases {
		if got := resolveViaPoolDisplay(c.via); got != c.want {
			t.Errorf("resolveViaPoolDisplay(%q) = %q, want %q", c.via, got, c.want)
		}
	}
}
