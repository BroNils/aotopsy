package disasm

import (
	"slices"
	"strconv"
	"strings"
)

type provBlockEffect struct {
	touched []bool
	final   []lvalue
	// copyFrom records state-dependent definitions such as x86 MOV dst,src or
	// a Code entry-point load whose result inherits its base provenance. A value
	// >= 0 means the destination receives that entry register's lattice value.
	// Untouched/constant/kill effects use -1.
	copyFrom []int
}

const provInputPrefix = "\x00aotopsy-prov-input:"

func provInputNote(reg int) string {
	return provInputPrefix + strconv.Itoa(reg)
}

func provInputReg(note string) (int, bool) {
	if !strings.HasPrefix(note, provInputPrefix) {
		return 0, false
	}
	r, err := strconv.Atoi(strings.TrimPrefix(note, provInputPrefix))
	if err != nil || r < 0 {
		return 0, false
	}
	return r, true
}

// runProvFixpoint runs the monotonic reaching-definitions dataflow fixpoint
// across CFG blocks for a given register count.
// It converges monotonically to the least fixed point. A defensive visit cap
// bounds malformed/adversarial inputs; if that cap is ever exhausted, the
// result fails closed to Bottom rather than publishing a partially-converged
// Known provenance as if it were trustworthy.
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

	maxVisits := provVisitLimit(nblocks)
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
				if r < len(eff.copyFrom) && eff.copyFrom[r] >= 0 && eff.copyFrom[r] < nregs {
					out[r] = in[eff.copyFrom[r]]
				} else {
					out[r] = eff.final[r]
				}
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
	if len(worklist) != 0 {
		for b := range entryState {
			for r := range entryState[b] {
				entryState[b][r] = lvalue{kind: lvBottom}
			}
		}
	}

	return entryState
}

func provVisitLimit(nblocks int) int {
	const slack = 64
	maxInt := int(^uint(0) >> 1)
	if nblocks <= 0 {
		return slack
	}
	if nblocks > (maxInt-slack)/nblocks {
		return maxInt
	}
	return nblocks*nblocks + slack
}
