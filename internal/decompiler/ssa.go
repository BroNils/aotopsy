package decompiler

import "fmt"

// This file implements a pre-emission reaching-definition FIXPOINT over the CFG
// — the value-flow analysis the recursive, path-sensitive emitter walk cannot do
// on its own. The emitter threads one LiftState along whichever path the
// recursion took, so a register whose value is consistent at a join (or carried
// around a loop back-edge) but was not on the taken path leaked as a raw token.
//
// computeEntryStates runs the transfer function (applyBlockToState) over every
// block to a fixpoint, joining predecessor exit states conservatively at each
// block entry. The emitter then FILLS its live-in registers from the fixpoint
// result (seedFromFixpoint) — additive: it only supplies values the walk left
// unknown, never overwriting the emission's own path values (which carry call
// temps the fixpoint cannot name). This supersedes the earlier
// already-emitted-predecessor forward join with a complete all-predecessor,
// back-edge-including fixpoint.
//
// §2-safety: the join keeps a register only when EVERY predecessor agrees on its
// value; any disagreement (a divergent branch/loop-carried value) drops it to
// unknown — honestly raw, never fabricated. Loop-carried divergent values that
// need a phi variable stay unknown here (phi materialization is a separate,
// gate-guarded step).

const ssaMaxFixpointRounds = 24

// applyBlockToState is the state-only transfer function: it mutates s exactly as
// emitting the block's instructions would mutate the register state, but emits
// nothing. It is the reusable "what does this instruction do to the value state"
// core, separated from the "how do we print it" emission.
func applyBlockToState(fir *FuncIR, s *LiftState, blk *Block, pool PoolLookup) {
	for i := range blk.Instrs {
		ins := blk.Instrs[i]
		s.clearWrittenRegClasses(ins)
		switch ins.Op {
		case OpCall:
			// A call result is opaque to a pre-emission pass (its rendered value
			// is an emission-time temp), so the return register becomes unknown.
			s.clobberReg(fir.ReturnReg)
		case OpLoadPool:
			applyLoadPoolState(s, ins, pool)
		case OpBranch, OpJump, OpReturn:
			// Control-flow ops carry no value definition of their own; the compare
			// that feeds a branch is a preceding OpOther already applied above.
		default:
			ApplyOther(fir, s, ins)
		}
	}
}

// applyLoadPoolState mirrors emitLoadPool's effect on the register state.
func applyLoadPoolState(s *LiftState, ins Instr, pool PoolLookup) {
	if ins.Target == "" {
		return
	}
	dst := ins.Target
	if pool != nil && ins.PoolIndex >= 0 {
		if disp, ok := pool(ins.PoolIndex); ok {
			s.setReg(dst, disp)
			return
		}
	}
	if ins.PoolIndex >= 0 {
		s.setReg(dst, fmt.Sprintf("pool[%d]", ins.PoolIndex))
		return
	}
	s.setReg(dst, "pool[?]")
}

// clobberReg drops the tracked value of reg (and its canonical alias).
func (s *LiftState) clobberReg(reg string) {
	if reg == "" {
		return
	}
	delete(s.Regs, canonReg(reg))
	s.clearRegClass(reg)
}

// seedEntryState builds the register state at the function's entry block: the
// reserved registers with their fixed meanings and arg0..argN, matching what the
// emitter seeds before the walk.
func seedEntryState(fir *FuncIR) *LiftState {
	s := newLiftState(fir.NullReg)
	if fir.ThreadReg != "" {
		s.setReg(fir.ThreadReg, "THR")
	}
	if fir.PoolReg != "" {
		s.setReg(fir.PoolReg, "PP")
	}
	if fir.StackReg != "" {
		s.setReg(fir.StackReg, "SP")
	}
	if fir.HeapBitsReg != "" {
		s.setReg(fir.HeapBitsReg, "HEAP_BITS")
	}
	for ri := 0; ri < len(fir.ArgRegs); ri++ {
		s.setReg(fir.ArgRegs[ri], fmt.Sprintf("arg%d", ri))
	}
	return s
}

// joinStates conservatively merges predecessor exit states: a register survives
// only when every state carries it with the same value. Disagreement (a
// divergent or loop-carried value) drops it to unknown.
func joinStates(states []*LiftState) *LiftState {
	if len(states) == 0 {
		return &LiftState{Regs: map[string]string{}, Locals: map[int64]string{}, RegClass: map[string]int{}}
	}
	out := &LiftState{Regs: make(map[string]string), Locals: states[0].Locals, RegClass: make(map[string]int)}
	base := states[0]
	for reg, val := range base.Regs {
		agree := true
		for _, s := range states[1:] {
			if v, ok := s.Regs[reg]; !ok || v != val {
				agree = false
				break
			}
		}
		if agree {
			out.Regs[reg] = val
		}
	}
	for reg, cid := range base.RegClass {
		agree := true
		for _, s := range states[1:] {
			if c, ok := s.RegClass[reg]; !ok || c != cid {
				agree = false
				break
			}
		}
		if agree {
			out.RegClass[reg] = cid
		}
	}
	return out
}

// computeEntryStates runs the reaching-definition fixpoint and returns, per block
// ID, the register state that reaches its entry. Bounded iteration converges for
// loops (a back-edge that keeps changing a register drops it to unknown, which is
// a stable fixpoint).
func computeEntryStates(fir *FuncIR, pool PoolLookup) []*LiftState {
	n := len(fir.Blocks)
	entry := make([]*LiftState, n)
	exit := make([]*LiftState, n)

	for round := 0; round < ssaMaxFixpointRounds; round++ {
		changed := false
		for bi := 0; bi < n; bi++ {
			blk := &fir.Blocks[bi]
			var in *LiftState
			preds := blk.Preds
			if bi == 0 || len(preds) == 0 {
				in = seedEntryState(fir)
			} else {
				pe := make([]*LiftState, 0, len(preds))
				for _, p := range preds {
					if p >= 0 && p < n && exit[p] != nil {
						pe = append(pe, exit[p])
					}
				}
				in = joinStates(pe)
			}
			out := in.Clone()
			applyBlockToState(fir, out, blk, pool)
			if exit[bi] == nil || !regsEqual(exit[bi].Regs, out.Regs) {
				exit[bi] = out
				entry[bi] = in
				changed = true
			} else {
				entry[bi] = in
			}
		}
		if !changed {
			break
		}
	}
	return entry
}

func regsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// seedFromFixpoint fills e.state's UNKNOWN live-in registers from the fixpoint's
// computed entry state for block id. Additive only: an emission-time value the
// walk already established (e.g. a call temp) is never overwritten.
func (e *emitter) seedFromFixpoint(id int) {
	if e.blockEntryState == nil || id < 0 || id >= len(e.blockEntryState) {
		return
	}
	st := e.blockEntryState[id]
	if st == nil {
		return
	}
	for reg, val := range st.Regs {
		if _, known := e.state.Regs[reg]; !known {
			e.state.Regs[reg] = val
		}
	}
	for reg, cid := range st.RegClass {
		if _, known := e.state.RegClass[reg]; !known {
			e.state.RegClass[reg] = cid
		}
	}
}
