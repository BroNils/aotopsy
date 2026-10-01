package decompiler

import "testing"

// A FuncIR built by newFuncIR has an authoritative block index: a VA that is not
// indexed (a tail-call target outside the function) is a miss, not a reason to
// rescan every block. The scan exists only for hand-built FuncIRs with no index.
func TestBlockByVAIndexIsAuthoritative(t *testing.T) {
	f := newFuncIR("f", 0x1000)
	f.addBlock(Block{StartVA: 0x1000})
	f.Blocks = append(f.Blocks, Block{StartVA: 0x2000}) // bypasses the index

	if id, ok := f.BlockByVA(0x1000); !ok || id != 0 {
		t.Fatalf("indexed block: got (%d, %v), want (0, true)", id, ok)
	}
	if id, ok := f.BlockByVA(0x2000); ok {
		t.Fatalf("unindexed VA resolved by a scan despite an authoritative index: (%d, true)", id)
	}
}

func TestBlockByVAScansWhenNoIndex(t *testing.T) {
	f := &FuncIR{EntryVA: 0x2000, Blocks: []Block{{StartVA: 0x1000}, {StartVA: 0x2000}}}
	if id, ok := f.BlockByVA(0x2000); !ok || id != 1 {
		t.Fatalf("hand-built FuncIR: got (%d, %v), want (1, true)", id, ok)
	}
	if id, ok := f.entryBlockID(); !ok || id != 1 {
		t.Fatalf("entryBlockID: got (%d, %v), want (1, true)", id, ok)
	}
}
