package decompiler

import "testing"

func TestIsCleanPhiInit(t *testing.T) {
	cases := map[string]bool{
		"arg2":        true,
		"arg1.f7":     true,
		"0":           true,
		"":            false,
		"x9":          false, // raw register token
		"arg0 + x10":  false, // contains raw token
		"pool[?]":     false,
		"/* cond */ ": false,
	}
	for in, want := range cases {
		if got := isCleanPhiInit(in); got != want {
			t.Errorf("isCleanPhiInit(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestPhiNameStable(t *testing.T) {
	if got := phiName(7, "x3"); got != "phi_b7_x3" {
		t.Errorf("phiName(7, x3) = %q, want phi_b7_x3", got)
	}
	// Same reg, different header -> distinct name (no collision).
	if phiName(1, "x9") == phiName(2, "x9") {
		t.Error("phiName must incorporate the header id to avoid collisions")
	}
}

// A pinned register whose value is redefined emits an explicit update to the
// induction local and re-pins; an untouched pin emits nothing.
func TestUpdatePinnedPhis(t *testing.T) {
	e := &emitter{
		state:     newLiftStateWith(map[string]string{"x3": "phi_b7_x3 + 1", "x9": "phi_b7_x9"}),
		pinnedPhi: map[string]string{"x3": "phi_b7_x3", "x9": "phi_b7_x9"},
	}
	e.updatePinnedPhis(0)
	// x3 changed -> one update line emitted, value re-pinned to the name.
	if e.state.Regs["x3"] != "phi_b7_x3" {
		t.Errorf("x3 not re-pinned: %q", e.state.Regs["x3"])
	}
	if e.state.Regs["x9"] != "phi_b7_x9" {
		t.Errorf("x9 should stay pinned: %q", e.state.Regs["x9"])
	}
	wantLine := "phi_b7_x3 = phi_b7_x3 + 1;"
	found := false
	for _, l := range e.lines {
		if trimAll(l) == wantLine {
			found = true
		}
	}
	if !found {
		t.Errorf("expected update line %q, got %v", wantLine, e.lines)
	}
	// Only the changed register produced a line.
	if len(e.lines) != 1 {
		t.Errorf("expected exactly 1 emitted line, got %d: %v", len(e.lines), e.lines)
	}
}

func trimAll(s string) string {
	out := s
	for len(out) > 0 && (out[0] == ' ' || out[0] == '\t') {
		out = out[1:]
	}
	return out
}

// CODE_REG and ARGS_DESC_REG are seeded at entry so their reads before any
// reassignment resolve to honest names instead of leaking the raw register.
func TestSeedEntryStateSpecialRegs(t *testing.T) {
	fir := newFuncIR("f", 0)
	fir.ThreadReg, fir.PoolReg, fir.StackReg = "r14", "r15", "rsp"
	fir.CodeReg, fir.ArgsDescReg = "r12", "r10"
	s := seedEntryState(fir)
	if got := s.Regs[canonReg("r12")]; got != "CODE" {
		t.Errorf("CODE_REG seed = %q, want CODE", got)
	}
	if got := s.Regs[canonReg("r10")]; got != "argsDesc" {
		t.Errorf("ARGS_DESC seed = %q, want argsDesc", got)
	}
}
