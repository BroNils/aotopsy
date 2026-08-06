package disasm

import "testing"

// makeInst creates a synthetic Inst at the given address with raw encoding.
func makeInst(addr uint64, raw uint32) Inst {
	return Inst{Addr: addr, Raw: raw, Size: 4}
}

func TestBuildCFG_Linear(t *testing.T) {
	// Three NOPs — no branches → one block.
	insts := []Inst{
		makeInst(0x1000, 0xD503201F), // NOP
		makeInst(0x1004, 0xD503201F), // NOP
		makeInst(0x1008, 0xD65F03C0), // RET
	}
	cfg := BuildCFG("linear", insts)
	if len(cfg.Blocks) != 1 {
		t.Fatalf("blocks = %d, want 1", len(cfg.Blocks))
	}
	blk := cfg.Blocks[0]
	if blk.Start != 0 || blk.End != 3 {
		t.Errorf("block range = [%d,%d), want [0,3)", blk.Start, blk.End)
	}
	if !blk.IsTerm {
		t.Error("block should be terminal (RET)")
	}
	if len(blk.Succs) != 0 {
		t.Errorf("succs = %d, want 0", len(blk.Succs))
	}
}

func TestBuildCFG_ConditionalBranch(t *testing.T) {
	// B.EQ to +0x10 (forward to addr 0x1010), then fallthrough.
	//   0x1000: B.EQ #0x10  → target 0x1010
	//   0x1004: NOP          (fallthrough)
	//   0x1008: RET
	//   0x100C: NOP
	//   0x1010: RET          (branch target)
	beq := uint32(0x54000000 | (4 << 5)) // imm19 = 4 → offset = 0x10
	insts := []Inst{
		makeInst(0x1000, beq),        // B.EQ → 0x1010
		makeInst(0x1004, 0xD503201F), // NOP
		makeInst(0x1008, 0xD65F03C0), // RET
		makeInst(0x100C, 0xD503201F), // NOP
		makeInst(0x1010, 0xD65F03C0), // RET (branch target)
	}
	cfg := BuildCFG("cond", insts)

	// Leaders: 0 (entry), 1 (after B.EQ), 3 (after RET at idx 2), 4 (target 0x1010)
	// Block 0: insts[0:1] = B.EQ
	// Block 1: insts[1:3] = NOP, RET
	// Block 2: insts[3:4] = NOP (dead code after RET)
	// Block 3: insts[4:5] = RET (branch target)

	if len(cfg.Blocks) != 4 {
		t.Fatalf("blocks = %d, want 4", len(cfg.Blocks))
	}

	// Block 0 should have T and F successors.
	b0 := cfg.Blocks[0]
	if len(b0.Succs) != 2 {
		t.Fatalf("block 0 succs = %d, want 2", len(b0.Succs))
	}
	// T should point to block 3 (target 0x1010), F to block 1 (fallthrough).
	var hasT, hasF bool
	for _, s := range b0.Succs {
		if s.Cond == "T" && s.BlockID == 3 {
			hasT = true
		}
		if s.Cond == "F" && s.BlockID == 1 {
			hasF = true
		}
	}
	if !hasT {
		t.Errorf("block 0 missing T→block3, succs=%+v", b0.Succs)
	}
	if !hasF {
		t.Errorf("block 0 missing F→block1, succs=%+v", b0.Succs)
	}

	// Block 1 should be terminal (contains RET).
	b1 := cfg.Blocks[1]
	if !b1.IsTerm {
		t.Error("block 1 should be terminal (RET)")
	}

	// Block 3 should be terminal.
	b3 := cfg.Blocks[3]
	if !b3.IsTerm {
		t.Error("block 3 should be terminal (RET)")
	}
}

func TestBuildCFG_UnconditionalBranch(t *testing.T) {
	// B to +0x8 (skip one instruction).
	//   0x2000: B #0x8     → target 0x2008
	//   0x2004: NOP         (dead code)
	//   0x2008: RET         (branch target)
	b := uint32(0x14000000 | 2) // imm26=2 → offset=8
	insts := []Inst{
		makeInst(0x2000, b),          // B → 0x2008
		makeInst(0x2004, 0xD503201F), // NOP
		makeInst(0x2008, 0xD65F03C0), // RET
	}
	cfg := BuildCFG("uncond", insts)

	// Leaders: 0 (entry), 1 (after B), 2 (target of B)
	if len(cfg.Blocks) != 3 {
		t.Fatalf("blocks = %d, want 3", len(cfg.Blocks))
	}

	// Block 0 has one unconditional successor → block 2.
	b0 := cfg.Blocks[0]
	if len(b0.Succs) != 1 {
		t.Fatalf("block 0 succs = %d, want 1", len(b0.Succs))
	}
	if b0.Succs[0].BlockID != 2 || b0.Succs[0].Cond != "" {
		t.Errorf("block 0 succ = {%d, %q}, want {2, \"\"}", b0.Succs[0].BlockID, b0.Succs[0].Cond)
	}
}

func TestBuildCFG_Empty(t *testing.T) {
	cfg := BuildCFG("empty", nil)
	if len(cfg.Blocks) != 0 {
		t.Errorf("blocks = %d, want 0", len(cfg.Blocks))
	}
}
