package callgraph_test

import (
	"testing"

	"aotopsy/internal/callgraph"
	"aotopsy/internal/callgraph/render"
	"aotopsy/internal/disasm"
)

func TestBuildCFG_DOTOutput(t *testing.T) {
	insts := []disasm.Inst{
		{Addr: 0x1000, Raw: 0xD2800000, Size: 4, Text: "MOV X0, #0"},
		{Addr: 0x1004, Raw: 0x94000040, Size: 4, Text: "BL 0x1104"},
		{Addr: 0x1008, Raw: 0xB4000080, Size: 4, Text: "CBZ X0, 0x1018"},
		{Addr: 0x100C, Raw: 0xD2800021, Size: 4, Text: "MOV X1, #1"},
		{Addr: 0x1010, Raw: 0x94000080, Size: 4, Text: "BL 0x1210"},
		{Addr: 0x1014, Raw: 0x14000003, Size: 4, Text: "B 0x1020"},
		{Addr: 0x1018, Raw: 0x940000C0, Size: 4, Text: "BL 0x1318"},
		{Addr: 0x101C, Raw: 0xD65F03C0, Size: 4, Text: "RET"},
		{Addr: 0x1020, Raw: 0xD65F03C0, Size: 4, Text: "RET"},
	}

	edges := []disasm.CallEdge{
		{FromPC: 0x1004, Kind: "bl", TargetPC: 0x1104, TargetName: "Foo.bar_a00"},
		{FromPC: 0x1010, Kind: "bl", TargetPC: 0x1210, TargetName: "Baz.qux_b00"},
		{FromPC: 0x1018, Kind: "bl", TargetPC: 0x1318, TargetName: "Quux.run_c00"},
	}

	f, nblocks := callgraph.BuildFuncCFG("MyClass.myMethod_1000", insts, edges)

	if nblocks != 4 {
		t.Fatalf("expected 4 blocks, got %d", nblocks)
	}
	if f.Name != "MyClass.myMethod_1000" {
		t.Errorf("func name = %q", f.Name)
	}
	if len(f.Blocks) != 4 {
		t.Fatalf("expected 4 blocks, got %d", len(f.Blocks))
	}

	b0 := f.Blocks[0]
	if len(b0.Calls) != 1 || b0.Calls[0].Callee != "Foo.bar_a00" {
		t.Errorf("B0 calls = %+v", b0.Calls)
	}
	if len(b0.Succs) != 2 {
		t.Errorf("B0 succs = %+v", b0.Succs)
	}

	b1 := f.Blocks[1]
	if len(b1.Calls) != 1 || b1.Calls[0].Callee != "Baz.qux_b00" {
		t.Errorf("B1 calls = %+v", b1.Calls)
	}

	b2 := f.Blocks[2]
	if len(b2.Calls) != 1 || b2.Calls[0].Callee != "Quux.run_c00" {
		t.Errorf("B2 calls = %+v", b2.Calls)
	}
	if !b2.Term {
		t.Error("B2 should be terminal")
	}

	b3 := f.Blocks[3]
	if !b3.Term {
		t.Error("B3 should be terminal")
	}

	cfg := &callgraph.CFGGraph{Funcs: []*callgraph.FuncCFG{f}}
	dot := render.DOTCFG(cfg, "deflutter CFG example")
	if dot == "" {
		t.Error("expected non-empty DOT output")
	}
}

func TestBuildCallGraph_DOTOutput(t *testing.T) {
	funcs := []callgraph.FuncInfo{
		{
			Name: "main_1000",
			CallEdges: []disasm.CallEdge{
				{FromPC: 0x1004, Kind: "bl", TargetPC: 0x2000, TargetName: "Foo.init_2000"},
				{FromPC: 0x1010, Kind: "bl", TargetPC: 0x3000, TargetName: "Bar.run_3000"},
			},
		},
		{
			Name: "Foo.init_2000",
			CallEdges: []disasm.CallEdge{
				{FromPC: 0x2008, Kind: "bl", TargetPC: 0x4000, TargetName: "Logger.log_4000"},
			},
		},
		{
			Name: "Bar.run_3000",
			CallEdges: []disasm.CallEdge{
				{FromPC: 0x3004, Kind: "bl", TargetPC: 0x4000, TargetName: "Logger.log_4000"},
				{FromPC: 0x3010, Kind: "blr", Reg: "X16", Via: "PP[42] Widget.build"},
			},
		},
		{
			Name: "Logger.log_4000",
		},
	}

	cg := callgraph.BuildCallGraph(funcs)

	if len(cg.Nodes) != 4 {
		t.Errorf("expected 4 nodes, got %d", len(cg.Nodes))
	}

	dot := render.DOT(cg, "deflutter call graph example")
	if dot == "" {
		t.Error("expected non-empty DOT output")
	}
}
