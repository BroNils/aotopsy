package disasm

import (
	"slices"
)

type provBlockEffect struct {
	touched []bool
	final   []lvalue
}

// runProvFixpoint runs the monotonic reaching-definitions dataflow fixpoint
// across CFG blocks for a given register count.
// It converges monotonically to the least fixed point or terminates at maxVisits.
func runProvFixpoint(
	nblocks int,
	nregs int,
	succsOf func(int) []Succ,
	effects []provBlockEffect,
) [][]lvalue {
	if nblocks == 0 {
		return nil
	}

	preds := make([][]int, nblocks)
	for bi := 0; bi < nblocks; bi++ {
		for _, s := range succsOf(bi) {
			if s.BlockID >= 0 && s.BlockID < nblocks {
				preds[s.BlockID] = append(preds[s.BlockID], bi)
			}
		}
	}

	entryState := make([][]lvalue, nblocks)
	exitState := make([][]lvalue, nblocks)
	for i := range nblocks {
		entryState[i] = make([]lvalue, nregs)
		exitState[i] = make([]lvalue, nregs)
	}

	worklist := make([]int, nblocks)
	inWorklist := make([]bool, nblocks)
	for i := range worklist {
		worklist[i] = i
		inWorklist[i] = true
	}

	maxVisits := nblocks*nblocks + 64
	visits := 0

	in := make([]lvalue, nregs)
	out := make([]lvalue, nregs)

	for len(worklist) > 0 && visits < maxVisits {
		id := worklist[0]
		worklist = worklist[1:]
		inWorklist[id] = false
		visits++

		switch {
		case id == 0:
			for r := range nregs {
				in[r] = lvalue{kind: lvBottom}
			}
		case len(preds[id]) == 0:
			for r := range nregs {
				in[r] = lvalue{kind: lvBottom}
			}
		default:
			for r := range nregs {
				in[r] = lvalue{kind: lvTop}
			}
			for _, p := range preds[id] {
				for r := 0; r < nregs; r++ {
					in[r] = meetLvalue(in[r], exitState[p][r])
				}
			}
		}

		changed := !slices.Equal(in, entryState[id])
		copy(entryState[id], in)

		copy(out, in)
		eff := effects[id]
		for r := 0; r < nregs; r++ {
			if r < len(eff.touched) && eff.touched[r] {
				out[r] = eff.final[r]
			}
		}
		if !slices.Equal(out, exitState[id]) {
			changed = true
			copy(exitState[id], out)
		}

		if changed {
			for _, s := range succsOf(id) {
				if s.BlockID >= 0 && s.BlockID < nblocks && !inWorklist[s.BlockID] {
					worklist = append(worklist, s.BlockID)
					inWorklist[s.BlockID] = true
				}
			}
		}
	}

	return entryState
}
