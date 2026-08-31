package disasm

import (
	"testing"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/vmtables"
)

func TestIsBL(t *testing.T) {
	// BL #0x1234 at PC=0x1000:
	// imm26 = 0x1234/4 = 0x48D, encoding: 0x94000000 | 0x48D = 0x9400048D
	raw := uint32(0x9400048D)
	target, ok := arm64.BL(raw, 0x1000)
	if !ok {
		t.Fatal("isBL failed to detect BL")
	}
	want := uint64(0x1000 + 0x48D*4)
	if target != want {
		t.Errorf("isBL target = 0x%x, want 0x%x", target, want)
	}

	// Negative offset: BL #-8 at PC=0x2000.
	// imm26 = -2 (signed), encoded as 0x03FFFFFE
	raw = 0x94000000 | 0x03FFFFFE
	target, ok = arm64.BL(raw, 0x2000)
	if !ok {
		t.Fatal("isBL failed for negative offset")
	}
	want = uint64(0x2000 - 8)
	if target != want {
		t.Errorf("isBL negative = 0x%x, want 0x%x", target, want)
	}

	// Non-BL instruction should not match.
	_, ok = arm64.BL(0xD503201F, 0) // NOP
	if ok {
		t.Error("isBL matched NOP")
	}
}

func TestIsBLR(t *testing.T) {
	// BLR X16: 1101 0110 0011 1111 0000 00 10000 00000 = 0xD63F0200
	raw := uint32(0xD63F0200)
	rn, ok := arm64.BLR(raw)
	if !ok {
		t.Fatal("isBLR failed")
	}
	if rn != 16 {
		t.Errorf("isBLR rn = %d, want 16", rn)
	}

	// BLR X30: 0xD63F03C0
	rn, ok = arm64.BLR(0xD63F03C0)
	if !ok {
		t.Fatal("isBLR X30 failed")
	}
	if rn != 30 {
		t.Errorf("isBLR rn = %d, want 30", rn)
	}

	// Non-BLR.
	_, ok = arm64.BLR(0xD503201F)
	if ok {
		t.Error("isBLR matched NOP")
	}
}

func TestExtractCallEdgesCFG_BL(t *testing.T) {
	// Build instructions: NOP, BL +8, NOP
	insts := []Inst{
		{Addr: 0x1000, Raw: 0xD503201F, Text: "NOP"},
		{Addr: 0x1004, Raw: 0x94000002, Text: "BL .+8"}, // target = 0x1004 + 2*4 = 0x100C
		{Addr: 0x1008, Raw: 0xD503201F, Text: "NOP"},
	}

	symbols := PlaceholderLookup(map[uint64]string{
		0x100C: "target_func",
	})

	edges := ExtractCallEdgesCFG("test_fn", insts, symbols, nil)
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1", len(edges))
	}
	e := edges[0]
	if e.Kind != "bl" {
		t.Errorf("kind = %q", e.Kind)
	}
	if e.TargetPC != 0x100C {
		t.Errorf("target = 0x%x, want 0x100C", e.TargetPC)
	}
	if e.TargetName != "target_func" {
		t.Errorf("name = %q", e.TargetName)
	}
}

func TestExtractCallEdgesCFG_BLR_WithProvenance(t *testing.T) {
	// Simulate: LDR X16, [X26,#0x2e8] (THR.AllocateArray_ep), then BLR X16.
	thrLDR := uint32(0xF9417350) // LDR X16, [X26,#0x2e8]
	blrX16 := uint32(0xD63F0200) // BLR X16

	insts := []Inst{
		{Addr: 0x1000, Raw: thrLDR, Text: "LDR X16, [X26,#744]"},
		{Addr: 0x1004, Raw: blrX16, Text: "BLR X16"},
	}

	thrFields := vmtables.THRFields("3.10.7", true)
	thrAnn := THRContextAnnotator(insts, thrFields)

	edges := ExtractCallEdgesCFG("test_fn", insts, nil, []Annotator{thrAnn})
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1", len(edges))
	}
	e := edges[0]
	if e.Kind != "blr" {
		t.Errorf("kind = %q", e.Kind)
	}
	if e.Reg != "X16" {
		t.Errorf("reg = %q", e.Reg)
	}
	if e.Via == "" {
		t.Error("via is empty, expected THR annotation")
	}
	t.Logf("via = %q", e.Via)
}

func TestInferCallArgRegMaskLocal(t *testing.T) {
	// MOV X1, #10 (imm mov to R1 -> arg pos 0)
	// MOV X2, #20 (imm mov to R2 -> arg pos 1)
	// MOV X4, #0  (imm mov to R4 -> ARGS_DESC_REG, not an arg register -> pos -1)
	// MOV X5, #30 (imm mov to R5 -> arg pos 3)
	// BL target
	movX1 := uint32(0xD2800141) // MOV X1, #10
	movX2 := uint32(0xD2800282) // MOV X2, #20
	movX4 := uint32(0xD2800004) // MOV X4, #0
	movX5 := uint32(0xD28003C5) // MOV X5, #30
	blTarget := uint32(0x94000002)

	insts := []Inst{
		{Addr: 0x1000, Raw: movX1},
		{Addr: 0x1004, Raw: movX2},
		{Addr: 0x1008, Raw: movX4},
		{Addr: 0x100C, Raw: movX5},
		{Addr: 0x1010, Raw: blTarget},
	}

	mask := inferCallArgRegMaskLocal(insts, 4)
	// Expected bits set:
	// pos 0 (R1) -> bit 0 (1)
	// pos 1 (R2) -> bit 1 (2)
	// R4 is ignored -> no bit
	// pos 3 (R5) -> bit 3 (8)
	// Total expected mask = 1 | 2 | 8 = 11 (0b1011)
	wantMask := uint8(0b1011)
	if mask != wantMask {
		t.Errorf("inferCallArgRegMaskLocal mask = 0b%b, want 0b%b", mask, wantMask)
	}
	if gotCount := inferCallArgCountLocal(insts, 4); gotCount != 3 {
		t.Errorf("inferCallArgCountLocal count = %d, want 3", gotCount)
	}
}
