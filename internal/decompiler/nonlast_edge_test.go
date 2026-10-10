package decompiler

import "testing"

func TestNonLastBranchInlineRecordsExactCFGEdges(t *testing.T) {
	fir := newFuncIR("nonlast_edges", 0x1000)
	fir.ReturnReg = "x0"
	fir.addBlock(Block{
		ID:      0,
		StartVA: 0x1000,
		Instrs: []Instr{
			{Addr: 0x1000, Op: OpBranch, CondKind: "eqz", CondReg: "x0"},
			{Addr: 0x1004, Op: OpReturn, Src: "ret"},
		},
		Succs: []Succ{{BlockID: 1, Cond: "T"}, {BlockID: 2, Cond: "F"}},
	})
	fir.addBlock(Block{
		ID:      1,
		StartVA: 0x1010,
		Instrs:  []Instr{{Addr: 0x1010, Op: OpOther, Src: "mov x0, #1"}},
		Succs:   []Succ{{BlockID: 3, Cond: ""}},
	})
	fir.addBlock(Block{ID: 2, StartVA: 0x1020, Instrs: []Instr{{Addr: 0x1020, Op: OpReturn, Src: "ret"}}})
	fir.addBlock(Block{ID: 3, StartVA: 0x1030, Instrs: []Instr{{Addr: 0x1030, Op: OpReturn, Src: "ret"}}})
	fir.ComputePreds()

	art := EmitPseudocode(fir, nil, nil)
	v := VerifyCFG(fir, art)
	if v.MismatchedEdges != 0 || v.MismatchedBranches != 0 {
		t.Fatalf("non-last branch output fails CFG verification: %+v edges=%+v\n%s", v, art.EmittedEdges, art.Source)
	}
	want := map[CFGEdge]bool{{From: 0, To: 1}: true, {From: 0, To: 2}: true, {From: 1, To: 3}: true}
	for _, edge := range art.EmittedEdges {
		delete(want, edge)
	}
	if len(want) != 0 {
		t.Fatalf("missing emitted CFG edges: %v (got %+v)", want, art.EmittedEdges)
	}
}
