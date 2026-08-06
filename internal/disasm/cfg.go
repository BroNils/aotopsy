package disasm

import "sort"

// BasicBlock represents a sequence of instructions with a single entry point.
type BasicBlock struct {
	ID      int
	Start   int    // index into FuncCFG.Insts (inclusive)
	End     int    // index into FuncCFG.Insts (exclusive)
	Succs   []Succ // successor edges
	IsEntry bool
	IsTerm  bool // ends with RET or unconditional branch out of function
}

// Succ describes a control-flow successor edge.
type Succ struct {
	BlockID int
	Cond    string // "" = unconditional, "T" = taken/true, "F" = fallthrough/false
}

// FuncCFG is a per-function control flow graph.
type FuncCFG struct {
	Name   string
	Blocks []BasicBlock
	Insts  []Inst
}

// BuildCFG constructs a control flow graph from a function's instruction stream.
// The algorithm:
//  1. Find block leaders: index 0, branch targets, instructions after terminators.
//  2. Partition instructions into blocks by leaders.
//  3. Compute successor edges from each block's last instruction.
func BuildCFG(name string, insts []Inst) FuncCFG {
	if len(insts) == 0 {
		return FuncCFG{Name: name, Insts: insts}
	}

	funcStart := insts[0].Addr
	funcEnd := insts[len(insts)-1].Addr + 4

	// Map address → instruction index for branch target resolution.
	addrToIdx := make(map[uint64]int, len(insts))
	for i, inst := range insts {
		addrToIdx[inst.Addr] = i
	}

	// Pass 1: Identify block leaders.
	leaders := make(map[int]bool)
	leaders[0] = true // entry point is always a leader

	for i, inst := range insts {
		bi := DecodeBranch(inst.Raw, inst.Addr)
		if bi == nil {
			continue
		}
		// Instruction after a terminator is a leader (if it exists).
		if i+1 < len(insts) {
			leaders[i+1] = true
		}
		// Branch target within this function is a leader.
		if !bi.IsRet && bi.Target >= funcStart && bi.Target < funcEnd {
			if idx, ok := addrToIdx[bi.Target]; ok {
				leaders[idx] = true
			}
		}
	}

	// Sort leaders for partitioning.
	sorted := make([]int, 0, len(leaders))
	for idx := range leaders {
		sorted = append(sorted, idx)
	}
	sort.Ints(sorted)

	// Pass 2: Partition into blocks.
	blocks := make([]BasicBlock, len(sorted))
	leaderToBlock := make(map[int]int, len(sorted))
	for i, start := range sorted {
		end := len(insts) // last block extends to end
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

	// Pass 3: Compute successors.
	for i := range blocks {
		blk := &blocks[i]
		if blk.End <= blk.Start {
			continue
		}
		lastInst := insts[blk.End-1]
		bi := DecodeBranch(lastInst.Raw, lastInst.Addr)

		if bi == nil {
			// Not a branch — fallthrough to next block.
			if nextBlk, ok := leaderToBlock[blk.End]; ok {
				blk.Succs = append(blk.Succs, Succ{BlockID: nextBlk})
			}
			continue
		}

		if bi.IsRet {
			blk.IsTerm = true
			continue
		}

		// Resolve branch target to a block.
		targetBlockID := -1
		if bi.Target >= funcStart && bi.Target < funcEnd {
			if idx, ok := addrToIdx[bi.Target]; ok {
				if bid, ok := leaderToBlock[idx]; ok {
					targetBlockID = bid
				}
			}
		}

		if bi.Cond {
			// Conditional: taken (T) goes to target, fallthrough (F) goes to next.
			if targetBlockID >= 0 {
				blk.Succs = append(blk.Succs, Succ{BlockID: targetBlockID, Cond: "T"})
			}
			if nextBlk, ok := leaderToBlock[blk.End]; ok {
				blk.Succs = append(blk.Succs, Succ{BlockID: nextBlk, Cond: "F"})
			}
		} else {
			// Unconditional branch.
			if targetBlockID >= 0 {
				blk.Succs = append(blk.Succs, Succ{BlockID: targetBlockID})
			} else {
				// Branch outside function — terminal.
				blk.IsTerm = true
			}
		}
	}

	return FuncCFG{
		Name:   name,
		Blocks: blocks,
		Insts:  insts,
	}
}
