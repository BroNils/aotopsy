package decompiler

import (
	"reflect"
	"testing"
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
