package disasm

import "testing"

// TestNilSymbolLookupIsSafeOnBothArches pins the cross-architecture contract
// for SymbolLookup: it is an ordinary parameter with no documented non-nil
// requirement, and the two entry points must behave the same when it is nil.
//
// They did not. ARM64 guarded its lookup in two places (arm64.go, and
// dataflowarm64.go's touchInstrEffect); x86_64's classifyX86Call called it
// unconditionally, so identical arguments produced a working scan on one
// architecture and a nil-func panic on the other. Both production callers
// happen to pass non-nil, which is why nothing caught it until a probe passed
// nil to both.
func TestNilSymbolLookupIsSafeOnBothArches(t *testing.T) {
	// x86_64: `call rel32` — the instruction whose classification resolves a
	// target name.
	x86Code := []byte{0xe8, 0x00, 0x00, 0x00, 0x00} // call +0
	res := ScanX86FunctionCFG(x86Code, 0x1000, nil, nil, "fn", nil)
	if len(res.Edges) == 0 {
		t.Fatalf("expected a call edge from `call rel32`")
	}
	if res.Edges[0].Kind != "call" {
		t.Errorf("kind = %q, want %q", res.Edges[0].Kind, "call")
	}
	if res.Edges[0].TargetName != "" {
		t.Errorf("TargetName = %q, want empty with a nil lookup", res.Edges[0].TargetName)
	}

	// ARM64: `bl #0` at 0x1000.
	insts := []Inst{{Addr: 0x1000, Raw: 0x94000000, Size: 4, Text: "bl #0"}}
	edges := ExtractCallEdgesCFG("fn", insts, nil, nil)
	if len(edges) == 0 {
		t.Fatalf("expected a call edge from `bl`")
	}
	if edges[0].TargetName != "" {
		t.Errorf("ARM64 TargetName = %q, want empty with a nil lookup", edges[0].TargetName)
	}
}
