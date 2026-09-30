package decompiler

import (
	"reflect"
	"strings"
	"testing"

	"aotopsy/internal/sdk"
)

func newLiftStateWith(regs map[string]string) *LiftState {
	s := &LiftState{Regs: map[string]string{}, Locals: map[int64]string{}, RegClass: map[string]int{}}
	for k, v := range regs {
		s.Regs[k] = v
	}
	return s
}

// joinStates keeps a register only when every predecessor agrees on its value;
// disagreement drops it to unknown (never fabricated).
func TestJoinStatesAgreement(t *testing.T) {
	got := joinStates([]*LiftState{
		newLiftStateWith(map[string]string{"x8": "0", "x9": "arg1.f3", "x10": "pathA"}),
		newLiftStateWith(map[string]string{"x8": "0", "x9": "arg1.f3", "x10": "pathB"}),
	})
	if got.Regs["x8"] != "0" {
		t.Errorf("x8 = %q, want 0 (agreed)", got.Regs["x8"])
	}
	if got.Regs["x9"] != "arg1.f3" {
		t.Errorf("x9 = %q, want arg1.f3 (agreed)", got.Regs["x9"])
	}
	if v, ok := got.Regs["x10"]; ok {
		t.Errorf("x10 survived join despite disagreement: %q", v)
	}
}

// A register absent from any one predecessor cannot be agreed, so it drops out.
func TestJoinStatesMissingInOnePred(t *testing.T) {
	got := joinStates([]*LiftState{
		newLiftStateWith(map[string]string{"x8": "0"}),
		newLiftStateWith(map[string]string{}),
	})
	if v, ok := got.Regs["x8"]; ok {
		t.Errorf("x8 survived join despite being unknown in one pred: %q", v)
	}
}

func TestJoinStatesRequiresComparisonWidthAgreement(t *testing.T) {
	a := newLiftStateWith(nil)
	b := newLiftStateWith(nil)
	a.HasCmp, b.HasCmp = true, true
	a.LastCmp, b.LastCmp = [2]string{"a", "b"}, [2]string{"a", "b"}
	a.CmpBits, b.CmpBits = 32, 64
	got := joinStates([]*LiftState{a, b})
	if got.HasCmp || got.CmpBits != 0 {
		t.Fatalf("comparison with disagreeing operand widths survived join: %+v", got)
	}

	b.CmpBits = 32
	got = joinStates([]*LiftState{a, b})
	if !got.HasCmp || got.CmpBits != 32 {
		t.Fatalf("matching comparison width was not preserved: has=%v bits=%d", got.HasCmp, got.CmpBits)
	}
}

func TestFixpointDoesNotSeedEntryArgsIntoPredecessorlessOrphan(t *testing.T) {
	fir := newFuncIR("orphan_seed", 0x1010)
	fir.ArgRegs = []string{"x1"}
	fir.ThreadReg = "x26"
	// Deliberately put the real entry at block 1 to prove runFixpoint uses
	// EntryVA, not slice position 0.
	fir.addBlock(Block{ID: 0, StartVA: 0x1000, Instrs: []Instr{{Op: OpOther, Src: "mov x9, x1"}}})
	fir.addBlock(Block{ID: 1, StartVA: 0x1010, Instrs: []Instr{{Op: OpReturn, Src: "ret"}}})
	fir.ComputePreds()
	entry, _, ok := runFixpoint(fir, nil)
	if !ok {
		t.Fatal("fixpoint unexpectedly failed to converge")
	}
	if got := entry[1].lookupReg("x1"); got != "arg0" {
		t.Fatalf("real entry arg = %q, want arg0", got)
	}
	if _, exists := entry[0].Regs[canonReg("x1")]; exists {
		t.Fatalf("predecessorless orphan inherited entry argument: %+v", entry[0].Regs)
	}
	if got := entry[0].lookupReg("x26"); got != sdk.SymTHR {
		t.Fatalf("pinned THR fact lost for orphan: %q", got)
	}
}

func TestOrphanBlockSurvivesCompactionWithoutMainPathStateLeak(t *testing.T) {
	fir := newFuncIR("orphan_emit", 0x1000)
	fir.ReturnReg = "x0"
	fir.ThreadReg = "x26"
	// Main path establishes x9=42 and returns. Block 1 has no predecessor and
	// reads x9. Its output must remain present, but must not claim the main
	// path's value 42 reaches it.
	fir.addBlock(Block{ID: 0, StartVA: 0x1000, Instrs: []Instr{
		{Op: OpOther, Src: "mov x9, #42"},
		{Op: OpOther, Src: "mov x0, #1"},
		{Op: OpReturn, Src: "ret"},
	}})
	fir.addBlock(Block{ID: 1, StartVA: 0x2000, Instrs: []Instr{
		{Op: OpOther, Src: "mov x0, x9"},
		{Op: OpReturn, Src: "ret"},
	}})
	art := EmitPseudocode(fir, nil, nil)
	if !strings.Contains(art.Source, "orphan block 1") || !strings.Contains(art.Source, "block_1:;") {
		t.Fatalf("orphan body/control-flow boundary was dropped by compaction:\n%s", art.Source)
	}
	if strings.Contains(art.Source, "orphan block 1") && strings.Contains(art.Source, "return 42;") {
		t.Fatalf("orphan inherited main-path register state:\n%s", art.Source)
	}
	if art.Stats.OrphanBlocks != 1 {
		t.Fatalf("OrphanBlocks=%d, want 1", art.Stats.OrphanBlocks)
	}
}

func TestMergeJoinNeverFabricatesDivergentBranchValue(t *testing.T) {
	pre := newLiftStateWith(map[string]string{"x0": "before"})
	taken := pre.Clone()
	fall := pre.Clone()
	taken.setReg("x0", "taken")
	got := pre.MergeJoin(taken, fall)
	if v, ok := got.Regs["x0"]; ok {
		t.Fatalf("divergent branch resurrected/fabricated x0=%q", v)
	}

	pre = newLiftStateWith(nil)
	taken = pre.Clone()
	fall = pre.Clone()
	taken.setReg("x1", "A")
	fall.setReg("x1", "B")
	got = pre.MergeJoin(taken, fall)
	if v, ok := got.Regs["x1"]; ok {
		t.Fatalf("divergent new values chose one path arbitrarily: %q", v)
	}
}

func TestLiftStateEqualityIncludesClassAndComparisonState(t *testing.T) {
	a := newLiftStateWith(map[string]string{"x0": "v"})
	b := a.Clone()
	if !liftStatesEqual(a, b) {
		t.Fatal("identical states are not equal")
	}
	b.RegClass["x0"] = 42
	if liftStatesEqual(a, b) {
		t.Fatal("RegClass difference was ignored")
	}
	b = a.Clone()
	b.HasCmp = true
	b.LastCmp = [2]string{"a", "b"}
	if liftStatesEqual(a, b) {
		t.Fatal("comparison-state difference was ignored")
	}
}

// seedFromFixpoint fills only UNKNOWN live-ins; the walk's own path value wins.
func TestSeedFromFixpointNeverOverridesKnown(t *testing.T) {
	e := &emitter{
		state:           newLiftStateWith(map[string]string{"x8": "currentPathValue"}),
		blockEntryState: []*LiftState{nil, nil, newLiftStateWith(map[string]string{"x8": "0", "x9": "seeded"})},
	}
	e.state.RegClass = map[string]int{}
	e.seedFromFixpoint(2)
	if got := e.state.Regs["x8"]; got != "currentPathValue" {
		t.Errorf("x8 = %q, want currentPathValue (known must not be overridden)", got)
	}
	if got := e.state.Regs["x9"]; got != "seeded" {
		t.Errorf("x9 = %q, want seeded (unknown live-in filled from fixpoint)", got)
	}
}

// A nil fixpoint slot (or out-of-range id) is a safe no-op.
func TestSeedFromFixpointNilSafe(t *testing.T) {
	e := &emitter{state: newLiftStateWith(map[string]string{"x8": "keep"})}
	e.seedFromFixpoint(0) // blockEntryState nil
	e.blockEntryState = []*LiftState{nil}
	e.seedFromFixpoint(0) // slot nil
	e.seedFromFixpoint(9) // out of range
	if got := e.state.Regs["x8"]; got != "keep" {
		t.Errorf("x8 = %q, want keep (no-op paths must not mutate state)", got)
	}
}

func TestInferLiveInArgsIsCFGSensitiveAndSparse(t *testing.T) {
	fir := newFuncIR("f", 0x1000)
	fir.ArgRegs = []string{"x0", "x1", "x2"}
	// Entry branches. Path 1 overwrites x1 before use; path 2 reads incoming x1.
	// A global slice-order `written` bit incorrectly lets path 1 suppress path 2.
	fir.addBlock(Block{ID: 0, StartVA: 0x1000, Succs: []Succ{{BlockID: 1, Cond: "T"}, {BlockID: 2, Cond: "F"}}})
	fir.addBlock(Block{ID: 1, StartVA: 0x1010, Instrs: []Instr{{Op: OpOther, Src: "mov x1, #7"}}})
	fir.addBlock(Block{ID: 2, StartVA: 0x1020, Instrs: []Instr{{Op: OpOther, Src: "add x9, x1, #1"}}})
	if got := LiveInArgIndices(fir); !reflect.DeepEqual(got, []int{1}) {
		t.Fatalf("CFG live-ins = %v, want [1]", got)
	}

	sparse := newFuncIR("sparse", 0x2000)
	sparse.ArgRegs = []string{"x0", "x1", "x2"}
	sparse.addBlock(Block{ID: 0, StartVA: 0x2000, Instrs: []Instr{{Op: OpOther, Src: "add x9, x2, #1"}}})
	if got := LiveInArgIndices(sparse); !reflect.DeepEqual(got, []int{2}) {
		t.Fatalf("sparse live-ins = %v, want [2] without invented x0/x1", got)
	}
}

func TestLiveInX86ArgsRecognizesSubregisterViews(t *testing.T) {
	fir := newFuncIR("x64_args", 0x3000)
	fir.ArgRegs = []string{"rdi", "rsi", "rdx", "rbx", "r8", "r9"}
	fir.ReturnReg = "rax"
	fir.addBlock(Block{ID: 0, StartVA: 0x3000, Instrs: []Instr{
		{Op: OpOther, Src: "movzx eax, bh"},
		{Op: OpOther, Src: "movzx ecx, r8w"},
	}})
	if got := LiveInArgIndices(fir); !reflect.DeepEqual(got, []int{3, 4}) {
		t.Fatalf("x86 subregister live-ins = %v, want [3 4] (RBX/R8)", got)
	}
}

func TestRunFixpointBudgetDisablesPartialSSA(t *testing.T) {
	// Reverse-indexed chain: propagation starts at block 0 -> 29 -> 28 -> ...
	// -> 1, but runFixpoint visits blocks in ascending ID order. The value can
	// therefore advance only one edge per round and needs more than the bounded
	// 24 rounds. A partial result must not be consumed as if it were a fixpoint.
	fir := newFuncIR("slow_fixpoint", 0x1000)
	const last = 29
	for i := 0; i <= last; i++ {
		b := Block{ID: i, StartVA: uint64(0x1000 + i*4)}
		if i == 0 {
			b.Instrs = []Instr{{Op: OpOther, Src: "mov x8, #7"}}
			b.Succs = []Succ{{BlockID: last}}
		} else if i > 1 {
			b.Succs = []Succ{{BlockID: i - 1}}
		}
		fir.addBlock(b)
	}
	fir.ComputePreds()
	entry, exit, converged := runFixpoint(fir, nil)
	if converged || entry != nil || exit != nil {
		t.Fatalf("bounded non-converged fixpoint leaked partial states: converged=%v entry=%v exit=%v", converged, entry != nil, exit != nil)
	}

	src := EmitPseudocode(fir, nil, nil).Source
	if !strings.Contains(src, "SSA enrichment disabled") {
		t.Fatalf("non-convergence was not surfaced in emitted output:\n%s", src)
	}
}
