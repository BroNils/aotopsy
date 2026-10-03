package disasm

import (
	"testing"

	archx86 "aotopsy/internal/arch/x86"
	"golang.org/x/arch/x86/x86asm"
)

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

	pool := map[int]string{0: "CodeTarget"}
	edges := ExtractCallEdgesCFG("block_transfer", insts, nil, []Annotator{PPAnnotator(pool)}, pool)
	if len(edges) != 1 || edges[0].Kind != "blr" {
		t.Fatalf("edges = %+v, want one BLR", edges)
	}
	if got, want := edges[0].Via, "PP[0] CodeTarget"; got != want {
		t.Fatalf("cross-block Code entry provenance = %q, want %q", got, want)
	}
}

func TestARM64MovePreservesCallTargetProvenance(t *testing.T) {
	ldrPoolX16 := uint32(0xF9400000) | (2 << 10) | (27 << 5) | 16 // ldr x16,[x27,#0x10]
	movX17X16 := uint32(0xAA1003F1)                               // mov x17,x16
	blrX17 := uint32(0xD63F0000) | (17 << 5)
	insts := []Inst{
		{Addr: 0x3800, Raw: ldrPoolX16, Text: "ldr x16, [x27, #0x10]"},
		{Addr: 0x3804, Raw: movX17X16, Text: "mov x17, x16"},
		{Addr: 0x3808, Raw: blrX17, Text: "blr x17"},
	}

	pool := map[int]string{0: "CodeTarget"}
	edges := ExtractCallEdgesCFG("mov_provenance", insts, nil, []Annotator{PPAnnotator(pool)}, pool)
	if len(edges) != 1 || edges[0].Kind != "blr" {
		t.Fatalf("edges = %+v, want one BLR", edges)
	}
	if got, want := edges[0].Via, "PP[0] CodeTarget"; got != want {
		t.Fatalf("MOV call-target provenance = %q, want %q", got, want)
	}
}

func TestARM64FrameLoadIsNotObjectFieldProvenance(t *testing.T) {
	// ldur x17,[x29,#-8] ; blr x17. The load is from a frame slot, not a
	// heap-object field, so disasm must not fabricate object_field provenance.
	ldurX17 := uint32(0xF8400000) | (0x1F8 << 12) | (29 << 5) | 17
	blrX17 := uint32(0xD63F0000) | (17 << 5)
	insts := []Inst{
		{Addr: 0x3900, Raw: ldurX17, Text: "ldur x17, [x29, #-8]"},
		{Addr: 0x3904, Raw: blrX17, Text: "blr x17"},
	}
	edges := ExtractCallEdgesCFG("frame_load", insts, nil, nil, nil)
	if len(edges) != 1 || edges[0].Via != "" {
		t.Fatalf("frame load produced call provenance: %+v", edges)
	}
}

func TestARM64PPPatternDoesNotInventProvenanceAtJoin(t *testing.T) {
	// The conditional branch can enter the LDR directly, bypassing the ADD
	// that derives X0 from PP. A linear ADD+LDR peephole must therefore not
	// make the join's X16 look like a path-consistent pool load.
	bEqToLdr := uint32(0x54000000 | (2 << 5)) // b.eq 0x1008
	addX0PP := uint32(0x91000000 | (1 << 22) | (4 << 10) | (27 << 5))
	ldrX16X0 := uint32(0xF9400010)
	blrX16 := uint32(0xD63F0200)
	insts := []Inst{
		{Addr: 0x1000, Raw: bEqToLdr, Text: "b.eq 0x1008"},
		{Addr: 0x1004, Raw: addX0PP, Text: "add x0, x27, #0x4000"},
		{Addr: 0x1008, Raw: ldrX16X0, Text: "ldr x16, [x0]"},
		{Addr: 0x100c, Raw: blrX16, Text: "blr x16"},
	}
	ppCtx := PPContextAnnotator(insts, map[int]string{2046: "CodeTarget"})
	edges := ExtractCallEdgesCFG("join", insts, nil, []Annotator{ppCtx}, map[int]string{2046: "CodeTarget"})
	if len(edges) != 1 || edges[0].Kind != "blr" {
		t.Fatalf("edges = %+v, want one BLR", edges)
	}
	if got := edges[0].Via; got != "" {
		t.Fatalf("join bypassing PP ADD produced fake provenance %q", got)
	}
}

func TestARM64LargePoolFallbackReachesIndirectCall(t *testing.T) {
	// SDK fallback for offset 0x01000010 (pool index 0x200000):
	// movz x16,#0x10 ; movk x16,#0x100,lsl#16 ; ldr x16,[x27,x16] ; blr x16.
	movz := uint32(0xD2800000 | (0x10 << 5) | 16)
	movk := uint32(0xF2800000 | (1 << 21) | (0x100 << 5) | 16)
	ldr := uint32(0xF8606800 | (16 << 16) | (27 << 5) | 16)
	blr := uint32(0xD63F0000 | (16 << 5))
	insts := []Inst{
		{Addr: 0x1800, Raw: movz, Text: "movz x16, #0x10"},
		{Addr: 0x1804, Raw: movk, Text: "movk x16, #0x100, lsl #16"},
		{Addr: 0x1808, Raw: ldr, Text: "ldr x16, [x27, x16]"},
		{Addr: 0x180c, Raw: blr, Text: "blr x16"},
	}
	const poolIdx = 0x200000
	ppCtx := PPContextAnnotator(insts, map[int]string{poolIdx: "HugeCodeTarget"})
	if got, want := ppCtx(insts[2]), "PP[2097152] HugeCodeTarget"; got != want {
		t.Fatalf("large-pool annotation = %q, want %q", got, want)
	}
	edges := ExtractCallEdgesCFG("large_pool", insts, nil, []Annotator{ppCtx}, map[int]string{poolIdx: "HugeCodeTarget"})
	if len(edges) != 1 || edges[0].Kind != "blr" || edges[0].Via != "PP[2097152] HugeCodeTarget" {
		t.Fatalf("large-pool call provenance = %+v", edges)
	}
}

func TestARM64PairPoolLoadKeepsDistinctRegisterProvenance(t *testing.T) {
	tests := []struct {
		name       string
		prefix     []Inst
		ldp        Inst
		firstIndex int
	}{
		{
			name: "direct",
			ldp: Inst{Addr: 0x5000,
				Raw:  0xA9400000 | (2 << 15) | (24 << 10) | (27 << 5) | 5,
				Text: "ldp x5, x24, [x27, #0x10]"},
			firstIndex: 0,
		},
		{
			name: "add-derived",
			prefix: []Inst{{
				Addr: 0x5100,
				Raw:  0x91000000 | (1 << 22) | (4 << 10) | (27 << 5) | 16,
				Text: "add x16, x27, #0x4000",
			}},
			ldp: Inst{Addr: 0x5104,
				Raw:  0xA9400000 | (24 << 10) | (16 << 5) | 5,
				Text: "ldp x5, x24, [x16]"},
			firstIndex: 2046,
		},
		{
			name: "movz-movk-add-derived",
			prefix: []Inst{
				{Addr: 0x5200, Raw: 0xD2800000 | (0x10 << 5) | 16, Text: "movz x16, #0x10"},
				{Addr: 0x5204, Raw: 0xF2800000 | (1 << 21) | (0x100 << 5) | 16, Text: "movk x16, #0x100, lsl #16"},
				{Addr: 0x5208, Raw: 0x8B000000 | (27 << 16) | (16 << 5) | 16, Text: "add x16, x16, x27"},
			},
			ldp: Inst{Addr: 0x520c,
				Raw:  0xA9400000 | (24 << 10) | (16 << 5) | 5,
				Text: "ldp x5, x24, [x16]"},
			firstIndex: 0x200000,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pool := map[int]string{
				tc.firstIndex:     "ICData",
				tc.firstIndex + 1: "CodeTarget",
			}
			insts := append([]Inst(nil), tc.prefix...)
			insts = append(insts, tc.ldp, Inst{
				Addr: tc.ldp.Addr + 4,
				Raw:  uint32(0xD63F0000 | (24 << 5)),
				Text: "blr x24",
			})

			loads := ExtractARM64PoolLoads(insts, pool)
			if len(loads) != 2 {
				t.Fatalf("pool loads = %+v, want two LDP destinations", loads)
			}
			if loads[0].Reg != 5 || loads[0].PoolIndex != tc.firstIndex ||
				loads[1].Reg != 24 || loads[1].PoolIndex != tc.firstIndex+1 {
				t.Fatalf("pair pool slots = %+v", loads)
			}
			if loads[0].Note == loads[1].Note {
				t.Fatalf("two LDP destinations shared one provenance note: %+v", loads)
			}

			edges := ExtractCallEdgesCFG("pair_pool", insts, nil, nil, pool)
			if len(edges) != 1 || edges[0].Via != poolLoadNote(tc.firstIndex+1, pool) {
				t.Fatalf("BLR through second LDP destination = %+v", edges)
			}
		})
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
	res := ScanX86FunctionCFG("3.12.2", code, 0x4000, nil, map[int]string{0: "CodeTarget"}, "block_transfer", nil)
	if len(res.Edges) != 1 || res.Edges[0].Kind != "call_indirect" {
		t.Fatalf("edges = %+v, want one indirect CALL", res.Edges)
	}
	if got, want := res.Edges[0].Via, "pp[0] CodeTarget"; got != want {
		t.Fatalf("cross-block MOV provenance = %q, want %q", got, want)
	}
}

func TestX86FrameLoadIsNotObjectFieldProvenance(t *testing.T) {
	// mov r11,[rbp-8] ; call r11 ; ret
	code := []byte{
		0x4c, 0x8b, 0x5d, 0xf8,
		0x41, 0xff, 0xd3,
		0xc3,
	}
	res := ScanX86FunctionCFG("3.12.2", code, 0x4800, nil, nil, "frame_load", nil)
	if len(res.Edges) != 1 || res.Edges[0].Kind != "call_indirect" {
		t.Fatalf("edges = %+v, want one indirect CALL", res.Edges)
	}
	if got := res.Edges[0].Via; got != "" {
		t.Fatalf("frame load produced call provenance %q", got)
	}
}

func TestARM64ScaledLDRObjectFieldCarriesFieldProvenance(t *testing.T) {
	// First prove X5 came from a concrete object-pool object, then load a field
	// from it. Object fields that are naturally aligned use the scaled unsigned-
	// offset LDR form, not LDUR.
	ldrObj := uint32(0xF9400000 | (2 << 10) | (27 << 5) | 5) // ldr x5,[x27,#0x10] = PP[0]
	ldr := uint32(0xF9400000 | (4 << 10) | (5 << 5) | 17)
	blr := uint32(0xD63F0000 | (17 << 5))
	insts := []Inst{
		{Addr: 0x3900, Raw: ldrObj, Text: "ldr x5, [x27, #0x10]"},
		{Addr: 0x3904, Raw: ldr, Text: "ldr x17, [x5, #0x20]"},
		{Addr: 0x3908, Raw: blr, Text: "blr x17"},
	}
	pool := map[int]string{0: "SomeObject"}
	edges := ExtractCallEdgesCFG("scaled_field", insts, nil, []Annotator{PPAnnotator(pool)}, pool)
	if len(edges) != 1 || edges[0].Via != ObjectFieldViaAt(0x20) {
		t.Fatalf("scaled object-field call provenance = %+v", edges)
	}
}

func TestX86IndexedReservedLoadsDoNotClaimStaticSlots(t *testing.T) {
	for _, tc := range []struct {
		name string
		base x86asm.Reg
	}{
		{name: "pp", base: x86asm.R15},
		{name: "thr", base: x86asm.R14},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var regs x86NoWindowRegs
			var touched [16]bool
			regs[11] = "stale"
			inst := x86asm.Inst{Op: x86asm.MOV, Args: [4]x86asm.Arg{
				x86asm.R11,
				x86asm.Mem{Base: tc.base, Index: x86asm.RCX, Scale: 8, Disp: 0xf},
			}}
			touchX86InstrEffect(archx86.Decoded{Inst: inst}, &regs, &touched, map[int]string{0: "FakePool"}, map[int]string{0xf: "fake_thr"})
			if regs[11] != "" {
				t.Fatalf("indexed %s load fabricated static provenance %q", tc.name, regs[11])
			}
		})
	}
}

func TestX86IndexedCodeLoadDoesNotInheritExactCodeTarget(t *testing.T) {
	var regs x86NoWindowRegs
	var touched [16]bool
	regs[0] = "pp[0] ExactCode"
	inst := x86asm.Inst{Op: x86asm.MOV, Args: [4]x86asm.Arg{
		x86asm.R11,
		x86asm.Mem{Base: x86asm.RAX, Index: x86asm.RCX, Scale: 8, Disp: 7},
	}}
	touchX86InstrEffect(archx86.Decoded{Inst: inst}, &regs, &touched, nil, nil)
	if got := regs[11]; got == "pp[0] ExactCode" || got == ObjectFieldViaAt(7) {
		t.Fatalf("indexed Code load overclaimed exact provenance %q", got)
	}
}
