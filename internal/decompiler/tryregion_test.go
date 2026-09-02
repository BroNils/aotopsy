package decompiler

import "testing"

func blk(id int, start uint64, addrs ...uint64) Block {
	b := Block{ID: id, StartVA: start}
	for _, a := range addrs {
		b.Instrs = append(b.Instrs, Instr{Addr: a})
	}
	return b
}

// TestSnapTryRegionsToBlocks pins the widening rule: a try region grows out to
// whole basic blocks, because a block has a single entry so any block holding an
// in-try pc is entirely in-try. Raw PcDescriptor ranges are otherwise
// single-instruction lower bounds.
func TestSnapTryRegionsToBlocks(t *testing.T) {
	// Three contiguous 4-instruction blocks at 0x100, 0x110, 0x120.
	fir := &FuncIR{
		Blocks: []Block{
			blk(0, 0x100, 0x100, 0x104, 0x108, 0x10c),
			blk(1, 0x110, 0x110, 0x114, 0x118, 0x11c),
			blk(2, 0x120, 0x120, 0x124, 0x128, 0x12c),
		},
	}
	// A one-instruction region in the middle of block 1.
	fir.TryRegions = []TryRegionEntry{{StartVA: 0x118, EndVA: 0x11c, TryIndex: 0}}

	if n := fir.SnapTryRegionsToBlocks(); n != 1 {
		t.Errorf("widened %d regions, want 1", n)
	}
	got := fir.TryRegions[0]
	// Block 1 spans [0x110, 0x120): its end comes from the next block's start,
	// which recovers the final instruction's width.
	if got.StartVA != 0x110 || got.EndVA != 0x120 {
		t.Errorf("region = [0x%x, 0x%x), want [0x110, 0x120)", got.StartVA, got.EndVA)
	}

	// A region already spanning two blocks must cover both, not just one.
	//
	// The end is 0x12d, not 0x130: block 2 is the LAST block, so there is no
	// following block whose StartVA would reveal the final instruction's width,
	// and instruction width is not known here (x86_64 is variable length). The
	// implementation falls back to lastAddr+1, which under-claims the tail by a
	// few bytes rather than over-claiming coverage.
	fir.TryRegions = []TryRegionEntry{{StartVA: 0x118, EndVA: 0x124, TryIndex: 0}}
	fir.SnapTryRegionsToBlocks()
	got = fir.TryRegions[0]
	if got.StartVA != 0x110 || got.EndVA != 0x12d {
		t.Errorf("two-block region = [0x%x, 0x%x), want [0x110, 0x12d)", got.StartVA, got.EndVA)
	}

	// Already block-aligned: nothing should change and nothing should be counted.
	fir.TryRegions = []TryRegionEntry{{StartVA: 0x110, EndVA: 0x120, TryIndex: 0}}
	if n := fir.SnapTryRegionsToBlocks(); n != 0 {
		t.Errorf("aligned region reported %d widenings, want 0", n)
	}

	// Degenerate inputs must not panic.
	(&FuncIR{}).SnapTryRegionsToBlocks()
	(&FuncIR{Blocks: []Block{blk(0, 0x100, 0x100)}}).SnapTryRegionsToBlocks()
	empty := &FuncIR{TryRegions: []TryRegionEntry{{StartVA: 1, EndVA: 2}}}
	if n := empty.SnapTryRegionsToBlocks(); n != 0 {
		t.Errorf("no blocks reported %d widenings, want 0", n)
	}
}

// TestCatchClause pins that the catch binding follows the handler's
// needs_stacktrace flag rather than being hardcoded. A source-level `catch (e)`
// clears the flag; `catch (e, s)` sets it. The previous emitter always printed
// `catch (e, st)` and so mis-rendered every single-binding catch, including
// compare_sample's AntiInlineTools.safeDivide.
func TestCatchClause(t *testing.T) {
	noTrace := TryRegionEntry{Handler: ExceptionHandlerEntry{NeedsStacktrace: false}}
	if got := noTrace.CatchClause(); got != "catch (e)" {
		t.Errorf("needs_stacktrace=false -> %q, want %q", got, "catch (e)")
	}
	withTrace := TryRegionEntry{Handler: ExceptionHandlerEntry{NeedsStacktrace: true}}
	if got := withTrace.CatchClause(); got != "catch (e, st)" {
		t.Errorf("needs_stacktrace=true -> %q, want %q", got, "catch (e, st)")
	}
}
