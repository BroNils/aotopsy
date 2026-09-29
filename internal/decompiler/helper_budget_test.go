package decompiler

import (
	"strings"
	"testing"
)

func TestHelperBudgetNeverEmitsUndefinedHelperCall(t *testing.T) {
	fir := newFuncIR("f", 0x1000)
	for i := 0; i <= maxHelpers; i++ {
		fir.addBlock(Block{ID: i, StartVA: uint64(0x1000 + i*0x10)})
	}
	e := &emitter{
		fir:        fir,
		state:      newLiftState(""),
		omittedSet: map[int]bool{},
		omitted:    make([]int, maxHelpers),
	}
	e.emitOmittedPath(maxHelpers, 0)
	src := strings.Join(e.lines, "\n")
	if strings.Contains(src, "_block_") && strings.Contains(src, "return _block_") {
		t.Fatalf("helper budget emitted a call with no helper definition: %q", src)
	}
	if e.stats.UnresolvedCF != 1 {
		t.Fatalf("helper exhaustion was not surfaced as unresolved control flow: %+v", e.stats)
	}
}
