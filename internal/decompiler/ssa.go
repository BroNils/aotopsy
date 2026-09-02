package decompiler

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"aotopsy/internal/sdk"
)

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
		s.setReg(fir.ThreadReg, sdk.SymTHR)
	}
	if fir.PoolReg != "" {
		s.setReg(fir.PoolReg, sdk.SymPP)
	}
	if fir.StackReg != "" {
		s.setReg(fir.StackReg, sdk.SymSP)
	}
	if fir.HeapBitsReg != "" {
		s.setReg(fir.HeapBitsReg, sdk.SymHeapBits)
	}
	if fir.CodeReg != "" {
		s.setReg(fir.CodeReg, sdk.SymCode)
	}
	if fir.ArgsDescReg != "" {
		s.setReg(fir.ArgsDescReg, sdk.SymArgsDesc)
	}
	for ri := 0; ri < len(fir.ArgRegs); ri++ {
		s.setReg(fir.ArgRegs[ri], fmt.Sprintf("arg%d", ri))
	}
	// Floating-point arguments, on the same footing as the integer ones.
	//
	// FpuArgRegs and FpuReturnReg were populated by both lifters and read
	// by nothing at all -- ABI facts written down and never used. The
	// consequence was visible in the output: a function reading a double
	// parameter it never wrote printed the raw register, which is where
	// the remaining v0/v1 (ARM64) and xmm0/xmm1 (x86_64) leaks came from.
	//
	// The index is the position in Dart's FP argument sequence, not the
	// source parameter position: `foo(double a, int b)` passes a in V0 and
	// b in R1, so a is fparg0 AND arg0. Naming it fparg0 states exactly
	// what is known -- which FP argument slot this is -- without claiming
	// a source-level position that would need the parameter types to
	// establish.
	for ri := 0; ri < len(fir.FpuArgRegs); ri++ {
		s.setReg(fir.FpuArgRegs[ri], fmt.Sprintf("fparg%d", ri))
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

// runFixpoint runs the reaching-definition fixpoint and returns, per block ID,
// the register state that reaches its entry (entry) and the state after its
// instructions (exit). Bounded iteration converges for loops (a back-edge that
// keeps changing a register drops it to unknown, which is a stable fixpoint).
//
// entry feeds seedFromFixpoint (fill unknown live-ins); exit feeds
// computeLoopPhis (detect loop-carried registers by comparing a header's entry
// predecessors against its back-edge predecessors).
func runFixpoint(fir *FuncIR, pool PoolLookup) (entry, exit []*LiftState) {
	n := len(fir.Blocks)
	entry = make([]*LiftState, n)
	exit = make([]*LiftState, n)

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
	return entry, exit
}

// computeEntryStates returns just the per-block entry states (see runFixpoint).
func computeEntryStates(fir *FuncIR, pool PoolLookup) []*LiftState {
	entry, _ := runFixpoint(fir, pool)
	return entry
}

// rawRegTokenRe matches a bare physical-register token (ARM64 w/x, x86 named +
// r8-r15). A phi initial value that still contains one is not a resolved value,
// so materializing it would only move the leak into the declaration -- such
// candidates are rejected by isCleanPhiInit.
var rawRegTokenRe = regexp.MustCompile(`\b([wx]\d{1,2}|r[a-d]x|rsi|rdi|rbp|r[89]|r1[0-5])\b`)

// isCleanPhiInit reports whether v is a sane initial value to declare a phi
// induction local with: non-empty, free of raw register tokens, and free of the
// emitter's "gave up" placeholders. A phi is only worth materializing when its
// entry value is itself resolved; otherwise the raw token is merely relocated.
func isCleanPhiInit(v string) bool {
	if v == "" {
		return false
	}
	if rawRegTokenRe.MatchString(v) {
		return false
	}
	for _, bad := range []string{"pool[?]", "/* cond */", "/* void */", "/* pop */"} {
		if strings.Contains(v, bad) {
			return false
		}
	}
	return true
}

// computeLoopPhis identifies, per loop-header block, the registers that are
// genuinely loop-carried -- a value on the entry path that differs from the
// value flowing back around the latch -- together with a clean entry-initial
// value to declare the induction local with. These are exactly the registers the
// conservative join drops to unknown at the header (entry and latch disagree),
// which is why they leaked as raw tokens before phi materialization.
//
// Only registers whose entry value is resolved (isCleanPhiInit) are returned:
// materializing a phi whose initial value is itself a raw token would relocate
// the leak, not resolve it. §2-honest: the induction local names a value that
// genuinely flows around the loop, and its in-loop update is emitted at the real
// definition site (see the emitter's phi-update hook).
func computeLoopPhis(fir *FuncIR, exit []*LiftState) map[int]map[string]string {
	headers := identifyLoopHeaders(fir)
	if len(headers) == 0 {
		return nil
	}
	n := len(fir.Blocks)
	out := map[int]map[string]string{}
	for hid := range headers {
		if hid < 0 || hid >= n {
			continue
		}
		h := &fir.Blocks[hid]
		var entryPreds, latchPreds []*LiftState
		for _, p := range h.Preds {
			if p < 0 || p >= n || exit[p] == nil {
				continue
			}
			// A latch predecessor sits at or after the header (the back-edge
			// source); an entry predecessor sits before it.
			if fir.Blocks[p].StartVA >= h.StartVA {
				latchPreds = append(latchPreds, exit[p])
			} else {
				entryPreds = append(entryPreds, exit[p])
			}
		}
		if len(entryPreds) == 0 || len(latchPreds) == 0 {
			continue
		}
		// Loop body address range: from the header up to the furthest latch. Used
		// to distinguish a genuine loop-carried value from a scratch register that
		// merely happens to hold a different value at the latch.
		var latchMaxVA uint64
		for _, p := range h.Preds {
			if p >= 0 && p < n && fir.Blocks[p].StartVA >= h.StartVA {
				if fir.Blocks[p].StartVA > latchMaxVA {
					latchMaxVA = fir.Blocks[p].StartVA
				}
			}
		}
		entryJoin := joinStates(entryPreds)
		latchJoin := joinStates(latchPreds)
		for reg, ev := range entryJoin.Regs {
			lv, ok := latchJoin.Regs[reg]
			if !ok || lv == ev {
				continue // not loop-carried (absent or unchanged around the loop)
			}
			if !isCleanPhiInit(ev) {
				continue
			}
			// Induction discriminator: a true loop-carried value is written
			// exactly once in the loop body AND that write reads the register
			// itself (i * step, ptr = ptr.next, acc = acc + x). A scratch
			// register reused for many unrelated temporaries is written many
			// times and mostly not self-referentially -- materializing it as a
			// phi would explode into dozens of misleading `phi = <unrelated>`
			// assignments. Reject those.
			if !isInductionRegister(fir, h.StartVA, latchMaxVA, reg) {
				continue
			}
			if out[hid] == nil {
				out[hid] = map[string]string{}
			}
			out[hid][reg] = ev
		}
	}
	return out
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

// isInductionRegister reports whether reg is a genuine loop-carried induction
// value across the loop body in the address range [loVA, hiVA]: it is written
// exactly once in that range, and the single writing instruction also reads reg
// (the update is a function of the previous value -- `i + 1`, `ptr.next`,
// `acc + x`). This rejects scratch registers reused for unrelated temporaries,
// which are written many times and would otherwise bloat the output with
// misleading phi assignments.
func isInductionRegister(fir *FuncIR, loVA, hiVA uint64, reg string) bool {
	canon := canonReg(reg)
	writes := 0
	selfRef := false
	for bi := range fir.Blocks {
		blk := &fir.Blocks[bi]
		if blk.StartVA < loVA || blk.StartVA > hiVA {
			continue
		}
		for i := range blk.Instrs {
			reads, wrs := inspectInstrRegUsage(blk.Instrs[i], "")
			wrote := false
			for _, w := range wrs {
				if canonReg(w) == canon {
					wrote = true
					break
				}
			}
			if !wrote {
				continue
			}
			writes++
			for _, r := range reads {
				if canonReg(r) == canon {
					selfRef = true
					break
				}
			}
		}
	}
	return writes == 1 && selfRef
}

// phiName is the Dart identifier for the induction local materialized for a
// loop-carried register at a given header block. Keyed by header id so two loops
// in one function that both carry (say) x9 never collide.
func phiName(headerID int, reg string) string {
	return fmt.Sprintf("phi_b%d_%s", headerID, reg)
}

// declareLoopPhis emits, just before a loop's `while`, a `var phi_bH_<reg> = init;`
// declaration for each loop-carried register at header id, pins the register to
// that induction local, and seeds the register's value to the local name so its
// header read (and every subsequent read until the register is redefined)
// resolves to the local instead of a raw register token.
func (e *emitter) declareLoopPhis(id, indent int) {
	if e.loopPhis == nil || e.phiDeclared[id] {
		return
	}
	phis := e.loopPhis[id]
	if len(phis) == 0 {
		return
	}
	e.phiDeclared[id] = true
	regs := make([]string, 0, len(phis))
	for r := range phis {
		regs = append(regs, r)
	}
	sort.Strings(regs)
	if e.pinnedPhi == nil {
		e.pinnedPhi = make(map[string]string)
	}
	for _, reg := range regs {
		name := phiName(id, reg)
		e.emit(indent, "var %s = %s;", name, phis[reg])
		e.state.Regs[reg] = name
		e.pinnedPhi[reg] = name
	}
}

// updatePinnedPhis is called after each instruction in the loop body. If an
// instruction redefined a pinned register, its new value expression is emitted as
// an explicit `phi_bH_<reg> = <update>;` statement and the register is re-pinned
// to the stable local name -- so the next iteration's reads stay resolved and the
// loop-carried update is visible at its real definition site (§2-honest: the
// update is the genuine lifted expression, e.g. `phi_b3_x9 = phi_b3_x9 + 1`).
func (e *emitter) updatePinnedPhis(indent int) {
	if len(e.pinnedPhi) == 0 {
		return
	}
	regs := make([]string, 0, len(e.pinnedPhi))
	for r := range e.pinnedPhi {
		regs = append(regs, r)
	}
	sort.Strings(regs)
	for _, reg := range regs {
		name := e.pinnedPhi[reg]
		v, ok := e.state.Regs[reg]
		if ok && v != name {
			e.emit(indent, "%s = %s;", name, v)
			e.state.Regs[reg] = name
		}
	}
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
