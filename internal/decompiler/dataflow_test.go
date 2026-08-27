package decompiler

import "testing"

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
	e.seedFromFixpoint(0)  // blockEntryState nil
	e.blockEntryState = []*LiftState{nil}
	e.seedFromFixpoint(0)  // slot nil
	e.seedFromFixpoint(9)  // out of range
	if got := e.state.Regs["x8"]; got != "keep" {
		t.Errorf("x8 = %q, want keep (no-op paths must not mutate state)", got)
	}
}
