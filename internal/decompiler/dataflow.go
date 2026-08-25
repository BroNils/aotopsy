package decompiler

// seedFromEmittedPreds fills unknown live-in registers of block id with values
// that EVERY already-emitted predecessor agrees on. This is a forward dataflow
// join over the recorded per-block OUT lattice (blockOut): the recursive
// structural walk reaches a block through only one predecessor path, so a
// register that is consistent across all predecessors but happened to be
// unknown on the taken path was previously leaking as a raw token. Seeding the
// agreed value resolves it.
//
// It is deliberately CONSERVATIVE and §2-safe:
//   - only predecessors already emitted (present in blockOut) contribute; a
//     back-edge predecessor emitted later cannot vote, so loop-carried values
//     that genuinely diverge are never fabricated -- they stay honestly raw
//     (resolving those needs phi-variable materialization, a separate lever);
//   - a register is seeded only when it is currently UNKNOWN in e.state and
//     ALL contributing predecessors carry the SAME concrete value for it, so
//     the walk's own path values are never overwritten and a disagreement never
//     invents a value;
//   - RegClass is joined the same way (agreement-only) so a seeded value keeps
//     its type only when every predecessor agrees on it.
func (e *emitter) seedFromEmittedPreds(id int) {
	if e.blockOut == nil || id < 0 || id >= len(e.fir.Blocks) {
		return
	}
	preds := e.fir.Blocks[id].Preds
	if len(preds) < 2 {
		// A single predecessor's out-state already flows in along the walk; a
		// join only adds information when several predecessors converge.
		return
	}
	var contributors []*LiftState
	for _, p := range preds {
		if st, ok := e.blockOut[p]; ok && st != nil {
			contributors = append(contributors, st)
		}
	}
	if len(contributors) < 2 {
		return
	}
	// Agreed register values: present with an identical value in every
	// contributor, and currently unknown in e.state.
	base := contributors[0]
	for reg, val := range base.Regs {
		if _, known := e.state.Regs[reg]; known {
			continue
		}
		agree := true
		for _, c := range contributors[1:] {
			if cv, ok := c.Regs[reg]; !ok || cv != val {
				agree = false
				break
			}
		}
		if agree {
			e.state.Regs[reg] = val
		}
	}
	// Agreed register classes, same rule.
	for reg, cid := range base.RegClass {
		if _, known := e.state.RegClass[reg]; known {
			continue
		}
		agree := true
		for _, c := range contributors[1:] {
			if cc, ok := c.RegClass[reg]; !ok || cc != cid {
				agree = false
				break
			}
		}
		if agree {
			e.state.RegClass[reg] = cid
		}
	}
}

// recordBlockOut snapshots block id's OUT register state the first time its own
// instructions finish emitting, so downstream joins (seedFromEmittedPreds) can
// read it. Recorded once per block: the structural walk re-emits blocks, and a
// later re-emission carries a path-specific state that must not overwrite the
// first, canonical OUT snapshot.
func (e *emitter) recordBlockOut(id int) {
	if id < 0 {
		return
	}
	if e.blockOut == nil {
		e.blockOut = map[int]*LiftState{}
	}
	if _, done := e.blockOut[id]; done {
		return
	}
	e.blockOut[id] = e.state.Clone()
}
