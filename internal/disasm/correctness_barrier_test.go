package disasm

import (
	"math"
	"testing"

	archx86 "aotopsy/internal/arch/x86"
	"aotopsy/internal/thraudit"
	"golang.org/x/arch/x86/x86asm"
)

func TestARM64BadInstructionIsCFGAndProvenanceBarrier(t *testing.T) {
	const thrOff = 0x88
	ldr := uint32(0xF9400000) | (uint32(thrOff/8) << 10) | (26 << 5) | 5
	blr := uint32(0xD63F0000) | (5 << 5)
	insts := []Inst{
		{Addr: 0x1000, Raw: ldr, Text: "ldr x5,[x26,#0x88]"},
		{Addr: 0x1004, Raw: 0xffffffff, Text: ".word 0xffffffff", Mnemonic: ".word", Bad: true},
		{Addr: 0x1008, Raw: blr, Text: "blr x5"},
	}
	edges := ExtractCallEdgesCFG("barrier", insts, nil, []Annotator{THRContextAnnotator(insts, map[int]string{thrOff: "entry"})}, nil)
	if len(edges) != 1 || edges[0].Kind != "blr" {
		t.Fatalf("edges = %+v, want one BLR", edges)
	}
	if edges[0].Via != "" {
		t.Fatalf("provenance crossed bad ARM64 word: Via=%q", edges[0].Via)
	}
	if cfg := BuildCFG("barrier", insts); len(cfg.Blocks) < 2 || !cfg.Blocks[0].IsTerm {
		t.Fatalf("bad word did not terminate CFG block: %+v", cfg.Blocks)
	}
}

func TestARM64CallKillsReturnRegisterProvenance(t *testing.T) {
	var regs noWindowRegs
	var touched [31]bool
	regs[0] = "pre_call_x0"
	touchInstrEffect(Inst{Addr: 0x1000, Raw: 0x94000000, Text: "bl #0"}, &regs, nil, nil, &touched)
	if regs[0] != "" {
		t.Fatalf("BL retained stale X0 provenance %q", regs[0])
	}
}

func TestX86BadInstructionAndCallKillProvenance(t *testing.T) {
	var regs x86NoWindowRegs
	var touched [16]bool
	regs[0] = "old_rax"
	touchX86InstrEffect(archx86.Decoded{Inst: x86asm.Inst{Op: x86asm.CALL}}, &regs, &touched, nil, nil)
	if regs[0] != "" {
		t.Fatalf("CALL retained stale RAX provenance %q", regs[0])
	}

	for i := range regs {
		regs[i] = "stale"
	}
	touched = [16]bool{}
	touchX86InstrEffect(archx86.Decoded{Bad: true, Len: 1}, &regs, &touched, nil, nil)
	for i, v := range regs {
		if v != "" {
			t.Fatalf("bad instruction retained reg %d provenance %q", i, v)
		}
	}
}

func TestX86BadInstructionTerminatesCFG(t *testing.T) {
	insts := []archx86.Decoded{
		{VA: 0x1000, Inst: x86asm.Inst{Op: x86asm.MOV, Len: 3}, Len: 3},
		{VA: 0x1003, Bad: true, Len: 1},
		{VA: 0x1004, Inst: x86asm.Inst{Op: x86asm.CALL, Len: 2}, Len: 2},
	}
	blocks := buildX86Blocks(insts)
	if len(blocks) < 2 || len(blocks[0].Succs) != 0 {
		t.Fatalf("bad x86 byte did not terminate CFG: %+v", blocks)
	}
}

func TestX86LEAIsAddressComputationNotMemoryProvenance(t *testing.T) {
	var regs x86NoWindowRegs
	var touched [16]bool
	regs[0] = "old"
	inst := x86asm.Inst{Op: x86asm.LEA, Args: [4]x86asm.Arg{
		x86asm.RAX,
		x86asm.Mem{Base: x86asm.R14, Disp: 0x48},
		nil, nil,
	}}
	touchX86InstrEffect(archx86.Decoded{Inst: inst, Len: 4}, &regs, &touched, nil, map[int]string{0x48: "stack_limit"})
	if regs[0] != "" {
		t.Fatalf("LEA fabricated dereference provenance %q", regs[0])
	}

	// 49 8d 46 48 = lea rax,[r14+0x48]. THR audit must not call this a read.
	if got := ExtractX86THRAccesses([]byte{0x49, 0x8d, 0x46, 0x48}, 0x2000, nil); len(got) != 0 {
		t.Fatalf("LEA reported as THR memory access: %+v", got)
	}
}

func TestX86THRReadModifyWritePreservesBothDirections(t *testing.T) {
	// 49 83 46 48 01 = add qword ptr [r14+0x48],1.
	got := ExtractX86THRAccesses([]byte{0x49, 0x83, 0x46, 0x48, 0x01}, 0x3000, nil)
	if len(got) != 1 {
		t.Fatalf("RMW THR access count = %d, want 1: %+v", len(got), got)
	}
	if got[0].Access != thraudit.AccessReadWrite {
		t.Fatalf("RMW THR access mode = %s, want read_write: %+v", got[0].Access, got[0])
	}
}

func TestX86ArgMaskDoesNotCrossBasicBlockStart(t *testing.T) {
	insts := []archx86.Decoded{
		{VA: 0x1000, Inst: x86asm.Inst{Op: x86asm.MOV, Args: [4]x86asm.Arg{x86asm.RDI, x86asm.RAX}}},
		{VA: 0x1003, Inst: x86asm.Inst{Op: x86asm.MOV, Args: [4]x86asm.Arg{x86asm.RSI, x86asm.RAX}}},
		{VA: 0x1006, Inst: x86asm.Inst{Op: x86asm.CALL}},
	}
	if got := inferX86CallArgRegMaskLocal(insts, 2, 1); got != 0b10 {
		t.Fatalf("x86 arg mask crossed block boundary: got 0b%b, want 0b10", got)
	}
}

func TestX86DirectCallToZeroStillGetsArgMask(t *testing.T) {
	// mov rdi,rax ; call rel32 -> VA 0. Target address zero is a valid direct
	// target value and must not be confused with the indirect-call zero value.
	code := []byte{0x48, 0x89, 0xc7, 0xe8, 0xf8, 0xff, 0xff, 0xff}
	res := ScanX86FunctionCFG("3.12.2", ClosureEntry{}, code, 0, nil, nil, "target_zero", nil)
	if len(res.Edges) != 1 || res.Edges[0].Kind != "call" || res.Edges[0].TargetPC != 0 || !res.Edges[0].TargetValid {
		t.Fatalf("edge = %+v, want direct call to VA 0", res.Edges)
	}
	if res.Edges[0].ArgRegMask&1 == 0 {
		t.Fatalf("direct call to VA 0 lost argument-register evidence: %+v", res.Edges[0])
	}
}

func TestOverflowingDirectCallsStayCallsWithoutFakeZeroTarget(t *testing.T) {
	arm := []Inst{{Addr: math.MaxUint64 - 3, Raw: 0x94000001, Text: "bl +4"}}
	aedges := ExtractCallEdgesCFG("overflow_bl", arm, nil, nil, nil)
	if len(aedges) != 1 || aedges[0].Kind != "bl" || aedges[0].TargetValid || aedges[0].TargetPC != 0 {
		t.Fatalf("overflowing BL = %+v, want direct unresolved call", aedges)
	}

	// CALL rel32 +16 whose end-relative target overflows MaxUint64.
	xinst := x86asm.Inst{Op: x86asm.CALL, Len: 5, Args: [4]x86asm.Arg{x86asm.Rel(16)}}
	xedge := classifyX86Call("3.12.2", xinst, math.MaxUint64-2, 5, nil, &x86RegTracker{}, nil, nil)
	if xedge.Kind != "call" || xedge.TargetValid || xedge.TargetPC != 0 {
		t.Fatalf("overflowing x86 CALL = %+v, want direct unresolved call", xedge)
	}
}
