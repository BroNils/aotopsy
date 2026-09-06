package decompiler

import "testing"

// domBlk is a terse CFG-only block: dominance does not read instructions.
func domBlk(id int, va uint64, succs ...int) Block {
	b := Block{ID: id, StartVA: va}
	for _, s := range succs {
		b.Succs = append(b.Succs, Succ{BlockID: s})
	}
	return b
}

func firOf(name string, blocks ...Block) *FuncIR {
	fir := newFuncIR(name, blocks[0].StartVA)
	for _, b := range blocks {
		fir.addBlock(b)
	}
	fir.ComputePreds()
	return fir
}

func TestDominatorsSimpleLoop(t *testing.T) {
	// 0 -> 1 -> 2, and 1 -> 1 via 2. Header is 1.
	fir := firOf("loop", domBlk(0, 0x100, 1), domBlk(1, 0x110, 2), domBlk(2, 0x120, 1))
	idom := dominators(fir)
	if idom[0] != 0 {
		t.Errorf("entry idom = %d, want 0", idom[0])
	}
	if idom[1] != 0 || idom[2] != 1 {
		t.Errorf("idom = %v, want [0 0 1]", idom)
	}
	if !dominates(idom, 1, 2) {
		t.Error("block 1 should dominate block 2")
	}
	if dominates(idom, 2, 1) {
		t.Error("block 2 must not dominate block 1")
	}
	headers := identifyLoopHeaders(fir, idom)
	if len(headers) != 1 || !headers[1] {
		t.Errorf("headers = %v, want {1}", headers)
	}
}

// TestBackEdgeNotStackOverflowSlowPath is the first of the two AOT idioms that
// the old address-order rule mistook for loops (finding 021).
//
// Shape: block 1 checks the stack limit and branches to the slow path at the
// END of the function; the slow path calls the runtime and jumps BACK to
// block 2. That backward jump is not a back edge -- block 3 does not dominate
// anything, and block 2 is reachable without it.
func TestBackEdgeNotStackOverflowSlowPath(t *testing.T) {
	fir := firOf("stackcheck",
		domBlk(0, 0x100, 1),
		domBlk(1, 0x110, 3, 2), // b.ls -> slow (3), else fall through to 2
		domBlk(2, 0x120),       // body + ret
		domBlk(3, 0x200, 2),    // slow path, placed last, jumps BACK to 2
	)
	idom := dominators(fir)
	if headers := identifyLoopHeaders(fir, idom); len(headers) != 0 {
		t.Errorf("stack-overflow slow path read as a loop: headers = %v", headers)
	}
	// The old rule would have flagged it, which is the whole point.
	if fir.Blocks[2].StartVA > fir.Blocks[3].StartVA {
		t.Fatal("test CFG does not reproduce the backward-jump layout")
	}
}

// TestBackEdgeNotMonomorphicEntry is the second idiom: a `dyn:` forwarder whose
// cid check at +8 jumps back toward the function start on a miss.
func TestBackEdgeNotMonomorphicEntry(t *testing.T) {
	fir := firOf("dyncheck",
		domBlk(0, 0x100, 1),    // monomorphic entry
		domBlk(1, 0x108, 0, 2), // cmp cid; jne back to 0, else continue
		domBlk(2, 0x120),
	)
	idom := dominators(fir)
	headers := identifyLoopHeaders(fir, idom)
	// Block 0 is the entry and dominates everything, so 1 -> 0 IS a genuine
	// back edge by the definition -- but only because this synthetic CFG makes
	// block 0 re-enterable. What matters is that block 2, the continuation, is
	// not treated as a header, and that dominance (not the -8 byte distance) is
	// what decided it.
	if headers[2] {
		t.Errorf("continuation block flagged as loop header: %v", headers)
	}
	if !dominates(idom, 0, 2) {
		t.Error("entry must dominate the continuation")
	}
}

func TestDominatorsDiamondHasNoLoop(t *testing.T) {
	//     0
	//    / \
	//   1   2
	//    \ /
	//     3
	fir := firOf("diamond", domBlk(0, 0x100, 1, 2), domBlk(1, 0x110, 3), domBlk(2, 0x120, 3), domBlk(3, 0x130))
	idom := dominators(fir)
	if idom[3] != 0 {
		t.Errorf("join idom = %d, want 0 (neither arm dominates it)", idom[3])
	}
	if dominates(idom, 1, 3) || dominates(idom, 2, 3) {
		t.Error("neither diamond arm may dominate the join")
	}
	if headers := identifyLoopHeaders(fir, idom); len(headers) != 0 {
		t.Errorf("acyclic CFG produced loop headers: %v", headers)
	}
}

func TestDominatorsNestedLoops(t *testing.T) {
	// 0 -> 1 -> 2 -> 3; 2 -> 2 (inner, via 3->2 is outer). Build:
	// 1 is outer header, 2 is inner header.
	fir := firOf("nested",
		domBlk(0, 0x100, 1),
		domBlk(1, 0x110, 2),
		domBlk(2, 0x120, 3),
		domBlk(3, 0x130, 2, 4), // inner back edge to 2
		domBlk(4, 0x140, 1, 5), // outer back edge to 1
		domBlk(5, 0x150),
	)
	idom := dominators(fir)
	headers := identifyLoopHeaders(fir, idom)
	if !headers[1] || !headers[2] {
		t.Errorf("headers = %v, want both 1 and 2", headers)
	}
	if len(headers) != 2 {
		t.Errorf("headers = %v, want exactly {1,2}", headers)
	}
}

// TestDominatorsUnreachableBlocks: a block the entry cannot reach has no
// dominator, and must not seed a loop header. Unreachable blocks are real here
// -- emitOrphanBlocks measures 2.0% of ARM64 and 7.4% of x86_64 blocks.
func TestDominatorsUnreachableBlocks(t *testing.T) {
	fir := firOf("orphan",
		domBlk(0, 0x100, 1),
		domBlk(1, 0x110),
		domBlk(2, 0x120, 2), // unreachable, and self-looping
	)
	idom := dominators(fir)
	if idom[2] != -1 {
		t.Errorf("unreachable block idom = %d, want -1", idom[2])
	}
	if dominates(idom, 2, 2) {
		t.Error("an unreachable block must not be reported as dominating anything")
	}
	if headers := identifyLoopHeaders(fir, idom); headers[2] {
		t.Errorf("unreachable self-loop flagged as a header: %v", headers)
	}
}

func TestDominatorsSelfLoop(t *testing.T) {
	fir := firOf("selfloop", domBlk(0, 0x100, 1), domBlk(1, 0x110, 1, 2), domBlk(2, 0x120))
	idom := dominators(fir)
	if !dominates(idom, 1, 1) {
		t.Error("a block dominates itself")
	}
	if headers := identifyLoopHeaders(fir, idom); !headers[1] {
		t.Errorf("self-loop not detected: %v", headers)
	}
}

func TestDominatorsEmptyAndSingleBlock(t *testing.T) {
	if got := dominators(&FuncIR{}); len(got) != 0 {
		t.Errorf("empty FuncIR: %v", got)
	}
	fir := firOf("single", domBlk(0, 0x100))
	idom := dominators(fir)
	if len(idom) != 1 || idom[0] != 0 {
		t.Errorf("single block idom = %v, want [0]", idom)
	}
	if headers := identifyLoopHeaders(fir, idom); len(headers) != 0 {
		t.Errorf("single block produced headers: %v", headers)
	}
}
