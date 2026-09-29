package disasm

import "testing"

func TestARM64BlockEffectPreservesIncomingCodeProvenance(t *testing.T) {
	ldrPoolX16 := uint32(0xF9400000) | (2 << 10) | (27 << 5) | 16 // ldr x16,[x27,#0x10]
	bNext := uint32(0x14000001)                                   // b pc+4
	ldurEntryX17 := uint32(0xF8400000) | (7 << 12) | (16 << 5) | 17
	blrX17 := uint32(0xD63F0000) | (17 << 5)
	insts := []Inst{
		{Addr: 0x3000, Raw: ldrPoolX16, Text: "ldr x16, [x27, #0x10]"},
		{Addr: 0x3004, Raw: bNext, Text: "b #0x3008"},
		{Addr: 0x3008, Raw: ldurEntryX17, Text: "ldur x17, [x16, #7]"},
		{Addr: 0x300c, Raw: bNext, Text: "b #0x3010"},
		{Addr: 0x3010, Raw: blrX17, Text: "blr x17"},
	}

	edges := ExtractCallEdgesCFG("block_transfer", insts, nil, []Annotator{PPAnnotator(map[int]string{0: "CodeTarget"})})
	if len(edges) != 1 || edges[0].Kind != "blr" {
		t.Fatalf("edges = %+v, want one BLR", edges)
	}
	if got, want := edges[0].Via, "PP[0] CodeTarget"; got != want {
		t.Fatalf("cross-block Code entry provenance = %q, want %q", got, want)
	}
}

func TestX86BlockEffectPreservesIncomingMoveProvenance(t *testing.T) {
	// mov rax,[r15+0xf] ; jmp next ; mov rbx,rax ; jmp next ; call rbx ; ret
	code := []byte{
		0x49, 0x8b, 0x47, 0x0f,
		0xeb, 0x00,
		0x48, 0x89, 0xc3,
		0xeb, 0x00,
		0xff, 0xd3,
		0xc3,
	}
	res := ScanX86FunctionCFG(code, 0x4000, nil, map[int]string{0: "CodeTarget"}, "block_transfer", nil)
	if len(res.Edges) != 1 || res.Edges[0].Kind != "call_indirect" {
		t.Fatalf("edges = %+v, want one indirect CALL", res.Edges)
	}
	if got, want := res.Edges[0].Via, "pp[0] CodeTarget"; got != want {
		t.Fatalf("cross-block MOV provenance = %q, want %q", got, want)
	}
}
