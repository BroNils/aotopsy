package compare

import (
	"strings"
	"testing"
)

func TestR2ExportSkipsOnlyAbsentFlagAndKeepsIdentity(t *testing.T) {
	r := NewR2Export()
	r.AddFunction(0x10, "   ")
	if len(r.Lines) != 0 {
		t.Fatalf("lines = %q, want none", r.Lines)
	}

	r.AddFunction(0x20, "[]=")
	r.AddFunction(0x30, "Foo@1")
	if len(r.Lines) != 2 {
		t.Fatalf("lines = %q", r.Lines)
	}
	if !strings.Contains(r.Lines[0], " @ 0x20") || !strings.Contains(r.Lines[1], " @ 0x30") {
		t.Fatalf("r2 identities lost their VA binding: %q", r.Lines)
	}
	if r.Lines[0] == r.Lines[1] {
		t.Fatalf("distinct raw names collapsed: %q", r.Lines)
	}
}
