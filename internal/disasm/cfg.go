package disasm

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
func BuildCFG(name string, insts []Inst) FuncCFG {
	if len(insts) == 0 {
		return FuncCFG{Name: name, Insts: insts}
	}

	blocks := PartitionBlocks(
		len(insts),
		func(i int) uint64 { return insts[i].Addr },
		func(i int) int { return 4 },
		func(i int) FlowInfo {
			bi := DecodeBranch(insts[i].Raw, insts[i].Addr)
			if bi == nil {
				return FlowInfo{Kind: FlowNormal}
			}
			if bi.IsRet {
				return FlowInfo{Kind: FlowRet}
			}
			// P6: BR (indirect branch) — terminal, no known target.
			if bi.IsIndirect {
				return FlowInfo{Kind: FlowIndirect}
			}
			if bi.Cond {
				return FlowInfo{Kind: FlowCondJump, Target: bi.Target, HasTarget: true}
			}
			return FlowInfo{Kind: FlowJump, Target: bi.Target, HasTarget: true}
		},
	)

	return FuncCFG{
		Name:   name,
		Blocks: blocks,
		Insts:  insts,
	}
}
