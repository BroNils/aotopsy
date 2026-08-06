package disasm

import "testing"

// TestExtractCallEdgesCFGBeyondOldWindow is a regression test proving the
// CFG-wide extractor resolves provenance across long straight-line basic
// blocks: a THR-relative load (X26 base -- confirmed against
// dart-lang/sdk's runtime/vm/constants_arm64.h THR=x26, same register role
// already verified elsewhere in this project) followed by more than 8
// unrelated instructions, then a BLR through the loaded register, all
// within a single straight-line basic block. ExtractCallEdgesCFG has no
// fixed instruction-count limit within a block (correctness comes from
// real control-flow reachability, not instruction count) and must
// resolve it.
func TestExtractCallEdgesCFGBeyondOldWindow(t *testing.T) {
	const thrFieldOffset = 0x88
	fields := map[int]string{thrFieldOffset: "SomeRuntimeEntry"}
	thrAnn := THRAnnotator(fields)

	var insts []Inst
	addr := uint64(0x1000)
	push := func(raw uint32, text string) {
		insts = append(insts, Inst{Addr: addr, Raw: raw, Text: text})
		addr += 4
	}

	// LDR X5, [X26, #0x88] -- 64-bit unsigned-offset load from THR.
	// Encoding: 0xF9400000 | (imm12=0x88/8=0x11)<<10 | (Rn=26)<<5 | Rt=5
	const rn, rt = 26, 5
	imm12 := uint32(thrFieldOffset / 8)
	ldrX5FromTHR := uint32(0xF9400000) | (imm12 << 10) | (uint32(rn) << 5) | uint32(rt)
	push(ldrX5FromTHR, "ldr x5, [x26, #0x88]")

	// 12 unrelated NOPs -- more than the old fixed W=8 window would have
	// tolerated before aging the definition out.
	for i := 0; i < 12; i++ {
		push(0xD503201F, "nop")
	}

	// BLR X5.
	blrX5 := uint32(0xD63F0000) | (uint32(5) << 5)
	push(blrX5, "blr x5")

	annotators := []Annotator{thrAnn}

	edges := ExtractCallEdgesCFG("test_fn", insts, nil, annotators)

	var blr *CallEdge
	for i := range edges {
		if edges[i].Kind == "blr" {
			blr = &edges[i]
		}
	}

	if blr == nil {
		t.Fatalf("expected a blr edge from the CFG extractor, got none")
	}
	if blr.Via == "" {
		t.Error("CFG-wide extractor: expected Via to resolve the THR-relative load beyond the old window, got empty")
	}
}
