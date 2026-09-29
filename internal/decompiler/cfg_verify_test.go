package decompiler

import "testing"

func TestVerifyCFGComparesBranchTargetsNotJustCounts(t *testing.T) {
	fir := newFuncIR("f", 0x1000)
	fir.addBlock(Block{
		ID:      0,
		StartVA: 0x1000,
		Instrs:  []Instr{{Op: OpBranch, CondKind: "eqz", CondReg: "x0"}},
		Succs:   []Succ{{BlockID: 1, Cond: "T"}, {BlockID: 2, Cond: "F"}},
	})
	fir.addBlock(Block{ID: 1, StartVA: 0x1010, Instrs: []Instr{{Op: OpReturn}}})
	fir.addBlock(Block{ID: 2, StartVA: 0x1020, Instrs: []Instr{{Op: OpReturn}}})
	fir.addBlock(Block{ID: 3, StartVA: 0x1030, Instrs: []Instr{{Op: OpReturn}}})

	// Same number of apparent branch edges, but one target is unrelated.
	artifact := Artifact{
		Source:        "if (x0 == 0) { return; } else { return; }",
		VisitedBlocks: map[int]bool{0: true, 1: true, 2: true, 3: true},
		EmittedEdges:  []CFGEdge{{From: 0, To: 1}, {From: 0, To: 3}},
	}
	v := VerifyCFG(fir, artifact)
	if v.MismatchedBranches == 0 || v.MismatchedEdges == 0 {
		t.Fatalf("unrelated target set scored as matching: %+v", v)
	}
	if v.MatchedEdges != 1 || v.TotalEdges != 2 {
		t.Fatalf("edge verification = %d/%d, want 1/2", v.MatchedEdges, v.TotalEdges)
	}
}

func TestVerifyCFGAcceptsEmitterRecordedEdges(t *testing.T) {
	fir := newFuncIR("f", 0x1000)
	fir.ArgRegs = []string{"x0"}
	fir.addBlock(Block{ID: 0, StartVA: 0x1000, Instrs: []Instr{{Op: OpBranch, CondKind: "eqz", CondReg: "x0"}}, Succs: []Succ{{BlockID: 1, Cond: "T"}, {BlockID: 2, Cond: "F"}}})
	fir.addBlock(Block{ID: 1, StartVA: 0x1010, Instrs: []Instr{{Op: OpReturn}}})
	fir.addBlock(Block{ID: 2, StartVA: 0x1020, Instrs: []Instr{{Op: OpReturn}}})
	art := EmitPseudocode(fir, nil, nil)
	v := VerifyCFG(fir, art)
	if v.MismatchedEdges != 0 || v.MatchedEdges != v.TotalEdges {
		t.Fatalf("emitter's own edges failed verification: %+v edges=%+v", v, art.EmittedEdges)
	}
}
