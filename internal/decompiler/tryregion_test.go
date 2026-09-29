package decompiler

import (
	"strings"
	"testing"
)

func blk(id int, start uint64, addrs ...uint64) Block {
	b := Block{ID: id, StartVA: start}
	for _, a := range addrs {
		b.Instrs = append(b.Instrs, Instr{Addr: a})
	}
	return b
}

func TestBuildBlockTryIndexRequiresWholeBlockProof(t *testing.T) {
	fir := &FuncIR{
		Blocks: []Block{
			blk(0, 0x100, 0x100, 0x104, 0x108, 0x10c),
			blk(1, 0x110, 0x110, 0x114, 0x118, 0x11c),
			blk(2, 0x120, 0x120, 0x124, 0x128, 0x12c),
		},
	}
	// Sparse PcDescriptor evidence in the middle of block 1 must NOT widen to
	// claim the whole block.
	fir.TryRegions = []TryRegionEntry{{StartVA: 0x118, EndVA: 0x11c, TryIndex: 0}}
	e := &emitter{fir: fir}
	e.buildBlockTryIndex()
	if _, ok := e.blockTryRegion[1]; ok {
		t.Fatal("mid-block try evidence was widened to the whole block")
	}

	// Exact [block1.start, block2.start) evidence may structure block 1.
	fir.TryRegions = []TryRegionEntry{{StartVA: 0x110, EndVA: 0x120, TryIndex: 0}}
	e = &emitter{fir: fir}
	e.buildBlockTryIndex()
	if got, ok := e.blockTryRegion[1]; !ok || got != 0 {
		t.Fatalf("exact protected block was not indexed: got=%d ok=%v", got, ok)
	}
}

func TestTryEmissionDoesNotInlineSuccessorOutsideRegion(t *testing.T) {
	fir := &FuncIR{
		Name:    "f",
		EntryVA: 0x100,
		Blocks: []Block{
			{ID: 0, StartVA: 0x100, Instrs: []Instr{{Addr: 0x100, Op: OpOther, Src: "mov x0, #1"}}, Succs: []Succ{{BlockID: 1}}},
			{ID: 1, StartVA: 0x110, Instrs: []Instr{{Addr: 0x110, Op: OpReturn, Src: "ret"}}},
		},
		TryRegions: []TryRegionEntry{{StartVA: 0x100, EndVA: 0x110, TryIndex: 0, HandlerVA: 0x999}},
	}
	fir.ComputePreds()
	e := &emitter{fir: fir, state: newLiftState(""), active: map[int]bool{}, visits: map[int]int{}, omittedSet: map[int]bool{}, emittedAnywhere: map[int]bool{}, tryOpened: map[int]bool{}, handlerBlocks: map[int]bool{}}
	e.buildBlockTryIndex()
	e.emitBlock(0, 0, 0)
	src := strings.Join(e.lines, "\n")
	closeIdx := strings.Index(src, "} catch")
	gotoIdx := strings.Index(src, "goto block_1;")
	if closeIdx < 0 || gotoIdx < 0 || gotoIdx > closeIdx {
		t.Fatalf("outside successor escaped try boundary handling:\n%s", src)
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
