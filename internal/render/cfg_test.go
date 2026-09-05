package render

import (
	"strings"
	"testing"

	"aotopsy/internal/disasm"
)

func twoBlockCFG() disasm.FuncCFG {
	return disasm.FuncCFG{
		Name: "Foo.bar",
		Insts: []disasm.Inst{
			{Addr: 0x1000, Text: "cmp x0, #0"},
			{Addr: 0x1004, Text: "b.eq #0x1010"},
			{Addr: 0x1008, Text: "bl #0x2000"},
			{Addr: 0x100c, Text: "ret"},
		},
		Blocks: []disasm.BasicBlock{
			{ID: 0, Start: 0, End: 2, IsEntry: true, Succs: []disasm.Succ{{BlockID: 1, Cond: "F"}}},
			{ID: 1, Start: 2, End: 4, IsTerm: true},
		},
	}
}

// TestCFGDOTDrawsCallees is the gate that the previous consolidation
// needed and did not have.
//
// Routing --graph from internal/callgraph's DOTCFG to render.CFGDOT
// dropped the callee edges: the old renderer read BasicBlock.Calls, and
// disasm.BasicBlock has no such field. Nothing failed, because golden
// covers the JSONL artifacts and no test had ever read a .dot. A CFG that
// silently stops showing what a block calls is a analysis regression that
// looks like a rendering preference.
func TestCFGDOTDrawsCallees(t *testing.T) {
	edges := []disasm.CallEdgeRecord{
		{FromFunc: "Foo.bar", FromPC: "0x1008", Kind: "bl", Target: "Baz.qux"},
	}
	dot := CFGDOT(twoBlockCFG(), edges, NASA)

	if !strings.Contains(dot, "Baz.qux") {
		t.Errorf("callee name missing from CFG DOT:\n%s", dot)
	}
	// The call must be attributed to the block that contains 0x1008 (bb1),
	// not to the entry block.
	if !strings.Contains(dot, "bb1 -> "+dotID("Baz.qux")) {
		t.Errorf("call edge not attributed to the calling block:\n%s", dot)
	}
	if strings.Contains(dot, "bb0 -> "+dotID("Baz.qux")) {
		t.Errorf("call edge attributed to the wrong block:\n%s", dot)
	}
}

// TestCFGDOTWithoutEdges keeps the control-flow-only path working: passing
// nil edges must still render blocks and T/F edges.
func TestCFGDOTWithoutEdges(t *testing.T) {
	dot := CFGDOT(twoBlockCFG(), nil, NASA)
	if !strings.Contains(dot, "digraph cfg") {
		t.Fatalf("not a DOT graph:\n%s", dot)
	}
	if !strings.Contains(dot, "bb0 -> bb1") {
		t.Errorf("control-flow edge missing:\n%s", dot)
	}
	if strings.Contains(dot, "style=dashed") {
		t.Errorf("no call edges expected with nil edges:\n%s", dot)
	}
}

// TestCFGDOTUnresolvedCallDrawsNothing: an edge with no resolved target is
// not a callee we can name, and inventing a node for it would be the same
// fabrication the pool-index fallback was removed for.
func TestCFGDOTUnresolvedCallDrawsNothing(t *testing.T) {
	edges := []disasm.CallEdgeRecord{
		{FromFunc: "Foo.bar", FromPC: "0x1008", Kind: "blr"},
	}
	dot := CFGDOT(twoBlockCFG(), edges, NASA)
	if strings.Contains(dot, "style=dashed") {
		t.Errorf("unresolved call must not draw a callee edge:\n%s", dot)
	}
}
