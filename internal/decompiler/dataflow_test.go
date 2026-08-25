package decompiler

import "testing"

func newLiftStateWith(regs map[string]string) *LiftState {
	s := &LiftState{Regs: map[string]string{}, Locals: map[int64]string{}, RegClass: map[string]int{}}
	for k, v := range regs {
		s.Regs[k] = v
	}
	return s
}

func TestSeedFromEmittedPredsAgreement(t *testing.T) {
	fir := &FuncIR{Blocks: []Block{
		{ID: 0},
		{ID: 1},
		{ID: 2, Preds: []int{0, 1}},
	}}
	e := &emitter{fir: fir, state: &LiftState{Regs: map[string]string{}, RegClass: map[string]int{}}}
	e.blockOut = map[int]*LiftState{
		0: newLiftStateWith(map[string]string{"x8": "0", "x9": "arg1.f3", "x10": "pathA"}),
		1: newLiftStateWith(map[string]string{"x8": "0", "x9": "arg1.f3", "x10": "pathB"}),
	}
	e.seedFromEmittedPreds(2)

	// x8 and x9 agree across both predecessors -> seeded.
	if got := e.state.Regs["x8"]; got != "0" {
		t.Errorf("x8 = %q, want 0 (agreed)", got)
	}
	if got := e.state.Regs["x9"]; got != "arg1.f3" {
		t.Errorf("x9 = %q, want arg1.f3 (agreed)", got)
	}
	// x10 disagrees (pathA vs pathB) -> must stay unknown (never fabricated).
	if _, ok := e.state.Regs["x10"]; ok {
		t.Errorf("x10 was seeded despite predecessor disagreement: %q", e.state.Regs["x10"])
	}
}

func TestSeedFromEmittedPredsNeverOverridesKnown(t *testing.T) {
	fir := &FuncIR{Blocks: []Block{
		{ID: 0}, {ID: 1}, {ID: 2, Preds: []int{0, 1}},
	}}
	e := &emitter{fir: fir, state: newLiftStateWith(map[string]string{"x8": "currentPathValue"})}
	e.state.RegClass = map[string]int{}
	e.blockOut = map[int]*LiftState{
		0: newLiftStateWith(map[string]string{"x8": "0"}),
		1: newLiftStateWith(map[string]string{"x8": "0"}),
	}
	e.seedFromEmittedPreds(2)
	// The walk's own path value must win; the join only fills UNKNOWNs.
	if got := e.state.Regs["x8"]; got != "currentPathValue" {
		t.Errorf("x8 = %q, want currentPathValue (known must not be overridden)", got)
	}
}

func TestSeedFromEmittedPredsSinglePredNoop(t *testing.T) {
	fir := &FuncIR{Blocks: []Block{{ID: 0}, {ID: 1, Preds: []int{0}}}}
	e := &emitter{fir: fir, state: &LiftState{Regs: map[string]string{}, RegClass: map[string]int{}}}
	e.blockOut = map[int]*LiftState{0: newLiftStateWith(map[string]string{"x8": "0"})}
	e.seedFromEmittedPreds(1)
	// A single predecessor's state already flows in along the walk; no join.
	if _, ok := e.state.Regs["x8"]; ok {
		t.Errorf("single-pred block should not be seeded, got x8=%q", e.state.Regs["x8"])
	}
}
