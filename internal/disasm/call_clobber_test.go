package disasm

import "testing"

func TestARM64CallClobbersTrackedProvenance(t *testing.T) {
	const thrOff = 0x88
	ldrX5 := uint32(0xF9400000) | (uint32(thrOff/8) << 10) | (26 << 5) | 5
	bl := uint32(0x94000000)
	blrX5 := uint32(0xD63F0000) | (5 << 5)
	insts := []Inst{
		{Addr: 0x1000, Raw: ldrX5, Text: "ldr x5, [x26, #0x88]"},
		{Addr: 0x1004, Raw: bl, Text: "bl #0x1004"},
		{Addr: 0x1008, Raw: blrX5, Text: "blr x5"},
	}

	edges := ExtractCallEdgesCFG("call_clobber", insts, nil, []Annotator{
		THRContextAnnotator(insts, map[int]string{thrOff: "runtime_entry"}),
	})
	if len(edges) != 2 {
		t.Fatalf("edges = %+v, want BL and BLR", edges)
	}
	if got := edges[1].Via; got != "" {
		t.Fatalf("BLR retained provenance across BL: Via=%q", got)
	}
}

func TestX86CallClobbersTrackedProvenance(t *testing.T) {
	// mov r11,[r15+0xf] ; call next ; call r11 ; ret
	code := []byte{
		0x4d, 0x8b, 0x5f, 0x0f,
		0xe8, 0x00, 0x00, 0x00, 0x00,
		0x41, 0xff, 0xd3,
		0xc3,
	}
	res := ScanX86FunctionCFG(code, 0x2000, nil, map[int]string{0: "CodeTarget"}, "call_clobber", nil)
	if len(res.Edges) != 2 {
		t.Fatalf("edges = %+v, want direct and indirect CALL", res.Edges)
	}
	if got := res.Edges[1].Via; got != "" {
		t.Fatalf("indirect CALL retained provenance across CALL: Via=%q", got)
	}
}
