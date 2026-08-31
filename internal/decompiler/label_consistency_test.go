package decompiler

import (
	"regexp"
	"strings"
	"testing"

	"aotopsy/internal/sdk"
)

// A block whose middle instruction is a branch: the emitter must produce a
// goto whose label exists, and must not leave labels nobody jumps to.
func TestNonLastBranchGotoHasLabel(t *testing.T) {
	fir := newFuncIR("t", 0x1000)
	fir.ThreadReg = sdk.ARM64ThreadRegStr
	fir.PoolReg = sdk.ARM64PoolRegStr
	fir.addBlock(Block{ID: 0, StartVA: 0x1000, Instrs: []Instr{
		{Addr: 0x1000, Op: OpBranch, CondKind: "cmp", CondOp: "eq"},
		{Addr: 0x1004, Op: OpReturn, Src: "ret"},
	}, Succs: []Succ{{BlockID: 1, Cond: "T"}, {BlockID: 2, Cond: "F"}}})
	fir.addBlock(Block{ID: 1, StartVA: 0x1008, Instrs: []Instr{{Addr: 0x1008, Op: OpReturn, Src: "ret"}}})
	fir.addBlock(Block{ID: 2, StartVA: 0x100c, Instrs: []Instr{{Addr: 0x100c, Op: OpReturn, Src: "ret"}}})
	// Give block 2 a second predecessor so it cannot be inlined.
	fir.Blocks[1].Succs = []Succ{{BlockID: 2, Cond: ""}}

	art := EmitPseudocode(fir, nil, nil)
	gotos := regexp.MustCompile(`goto block_(\d+);`).FindAllStringSubmatch(art.Source, -1)
	labels := regexp.MustCompile(`(?m)^\s*block_(\d+):;`).FindAllStringSubmatch(art.Source, -1)
	have := map[string]bool{}
	for _, l := range labels {
		have[l[1]] = true
	}
	for _, g := range gotos {
		if !have[g[1]] {
			t.Errorf("goto block_%s has no label:\n%s", g[1], art.Source)
		}
	}
	want := map[string]bool{}
	for _, g := range gotos {
		want[g[1]] = true
	}
	for id := range have {
		if !want[id] {
			t.Errorf("label block_%s is never jumped to:\n%s", id, art.Source)
		}
	}
	t.Logf("gotos=%d labels=%d\n%s", len(gotos), len(labels), strings.TrimSpace(art.Source))
}

// An async* body calls _SuspendState._yieldAsyncStar, which also trips the
// "_SuspendState + _yield" rule that sets IsAsync. The emitted signature must
// still say `async*`, exactly once.
func TestGeneratorModifierPrecedence(t *testing.T) {
	tests := []struct {
		name                          string
		isAsync, isSyncStar, isAsyncS bool
		want                          string
	}{
		{"async only", true, false, false, "async "},
		{"sync* only", false, true, false, "sync* "},
		{"async* only", false, false, true, "async* "},
		{"async+async* (yieldAsyncStar)", true, false, true, "async* "},
		{"async+sync* (resume stub)", true, true, false, "sync* "},
		{"none", false, false, false, ""},
	}
	for _, tt := range tests {
		fir := newFuncIR("t", 0x1000)
		fir.ThreadReg, fir.PoolReg = sdk.ARM64ThreadRegStr, sdk.ARM64PoolRegStr
		fir.IsAsync, fir.IsSyncStar, fir.IsAsyncStar = tt.isAsync, tt.isSyncStar, tt.isAsyncS
		fir.addBlock(Block{ID: 0, StartVA: 0x1000, Instrs: []Instr{{Addr: 0x1000, Op: OpReturn, Src: "ret"}}})
		src := EmitPseudocode(fir, nil, nil).Source
		sig := strings.SplitN(src, "\n", 2)[0]
		if !strings.HasPrefix(sig, tt.want) {
			t.Errorf("%s: signature %q, want prefix %q", tt.name, sig, tt.want)
		}
		// No modifier may appear twice, and the two forms must not stack.
		if strings.Count(sig, "async") > 1 || strings.Contains(sig, "async async") ||
			strings.Contains(sig, "sync* async") {
			t.Errorf("%s: stacked modifiers in %q", tt.name, sig)
		}
	}
}
