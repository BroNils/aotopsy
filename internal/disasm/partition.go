package disasm

import (
	"slices"
)

// FlowKind classifies an instruction's control-flow behavior for basic-block partitioning.
type FlowKind int

const (
	FlowNormal FlowKind = iota
	FlowJump
	FlowCondJump
	FlowRet
	FlowIndirect
)

// FlowInfo describes the control-flow transfer of a single instruction.
type FlowInfo struct {
	Kind      FlowKind
	Target    uint64
	HasTarget bool
}

// PartitionBlocks partitions an instruction sequence into basic blocks and computes successor edges.
// It is architecture-neutral and used by both ARM64 and x86_64 CFG builders.
func PartitionBlocks(
	n int,
	instAddr func(i int) uint64,
	instLen func(i int) int,
	instFlow func(i int) FlowInfo,
) []BasicBlock {
	if n == 0 {
		return nil
	}

	funcStart := instAddr(0)
	lastIdx := n - 1
	funcEnd := instAddr(lastIdx) + uint64(instLen(lastIdx))

	addrToIdx := make(map[uint64]int, n)
	flow := make([]FlowInfo, n)

	leaders := map[int]bool{0: true}
	for i := range n {
		addrToIdx[instAddr(i)] = i
		fl := instFlow(i)
		flow[i] = fl

		if fl.Kind != FlowNormal {
			if i+1 < n {
				leaders[i+1] = true
			}
		}
	}

	for i := range n {
		fl := flow[i]
		if fl.HasTarget && fl.Target >= funcStart && fl.Target < funcEnd {
			if idx, ok := addrToIdx[fl.Target]; ok {
				leaders[idx] = true
			}
		}
	}

	sorted := make([]int, 0, len(leaders))
	for idx := range leaders {
		sorted = append(sorted, idx)
	}
	slices.Sort(sorted)

	leaderToBlock := make(map[int]int, len(sorted))
	blocks := make([]BasicBlock, len(sorted))
	for i, start := range sorted {
		end := n
		if i+1 < len(sorted) {
			end = sorted[i+1]
		}
		blocks[i] = BasicBlock{
			ID:      i,
			Start:   start,
			End:     end,
			IsEntry: start == 0,
		}
		leaderToBlock[start] = i
	}

	for bi := range blocks {
		blk := &blocks[bi]
		if blk.End <= blk.Start {
			continue
		}
		last := blk.End - 1
		fl := flow[last]

		switch fl.Kind {
		case FlowRet, FlowIndirect:
			blk.IsTerm = true
		case FlowJump:
			if fl.HasTarget {
				if idx, ok := addrToIdx[fl.Target]; ok {
					if tb, ok := leaderToBlock[idx]; ok {
						blk.Succs = append(blk.Succs, Succ{BlockID: tb})
						continue
					}
				}
			}
			blk.IsTerm = true
		case FlowCondJump:
			if fl.HasTarget {
				if idx, ok := addrToIdx[fl.Target]; ok {
					if tb, ok := leaderToBlock[idx]; ok {
						blk.Succs = append(blk.Succs, Succ{BlockID: tb, Cond: "T"})
					}
				}
			}
			if nb, ok := leaderToBlock[blk.End]; ok {
				blk.Succs = append(blk.Succs, Succ{BlockID: nb, Cond: "F"})
			}
		default:
			if nb, ok := leaderToBlock[blk.End]; ok {
				blk.Succs = append(blk.Succs, Succ{BlockID: nb})
			}
		}
	}

	return blocks
}
