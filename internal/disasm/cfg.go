package disasm

import (
	"strings"

	"aotopsy/internal/arch/arm64"
)

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
			if IsARM64SemanticBarrier(insts[i]) {
				return FlowInfo{Kind: FlowIndirect}
			}
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

// IsARM64SemanticBarrier reports instructions after which static fallthrough is
// not trustworthy. Decoder failures are unknown bytes; BRK/HLT/UDF are traps.
// All remain visible in the disassembly listing, but the CFG must not carry
// provenance through them into later bytes.
func IsARM64SemanticBarrier(inst Inst) bool {
	if inst.Bad {
		return true
	}
	// B.cond NV is not a valid Dart-emitted branch. Treat an injected/corrupt
	// encoding as unknown control flow instead of fabricating either a target or
	// a fallthrough edge.
	if arm64.IsReservedBCond(inst.Raw) {
		return true
	}
	switch strings.ToLower(inst.Mnemonic) {
	case "brk", "hlt", "udf":
		return true
	default:
		return false
	}
}
