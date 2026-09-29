package compare

import "testing"

func TestR2ExportSkipsEmptySanitizedFlag(t *testing.T) {
	r := NewR2Export()
	r.AddFunction(0x10, "___")
	if len(r.Lines) != 0 {
		t.Fatalf("lines = %q, want none", r.Lines)
	}

	r.AddFunction(0x20, "Foo@1")
	if len(r.Lines) != 1 || r.Lines[0] != "f Foo_at_1 @ 0x20" {
		t.Fatalf("lines = %q", r.Lines)
	}
}
