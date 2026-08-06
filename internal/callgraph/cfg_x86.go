package callgraph

import (
	"fmt"

	"aotopsy/internal/decompiler"
	"aotopsy/internal/disasm"

	"aotopsy/internal/lattice"
)

// BuildX86FuncCFG builds a single-function lattice.FuncCFG for x86_64,
// mirroring BuildFuncCFG's ARM64 signature/behavior but sourced from
// internal/decompiler's own x86 CFG builder (DecodeX86Range +
// BuildX86IR) instead of disasm.BuildCFG -- x86_64's variable-length
// instructions need real leader/successor computation, which
// internal/decompiler already implements (for its pseudocode pipeline)
// and this reuses rather than re-deriving a second x86 CFG algorithm.
// decompiler.DecodeX86Range's return type is unexported, so this takes
// raw function bytes directly rather than a pre-decoded instruction
// slice (unlike BuildFuncCFG's disasm.Inst-slice signature). Returns the
// FuncCFG and block count (for filtering trivial single-block
// functions, same convention as BuildFuncCFG).
func BuildX86FuncCFG(name string, funcCode []byte, funcVA uint64, edges []disasm.CallEdge) (*lattice.FuncCFG, int) {
	fir := decompiler.BuildX86IR(name, decompiler.DecodeX86Range(funcCode, funcVA))
	return convertX86FuncCFG(fir, edges), len(fir.Blocks)
}

// convertX86FuncCFG maps a decompiler.FuncIR (built for pseudocode lifting)
// onto lattice.FuncCFG (built for DOT rendering + call-graph accumulation)
// -- the two have different purposes but a compatible enough shape
// (blocks with successors, an ordered instruction sequence) to convert
// directly. Block.Start/End are indices into a flattened, in-block-order
// instruction sequence across the whole function -- same convention
// convertFuncCFG uses for ARM64 (there, indices are into disasm.FuncCFG's
// flat Insts slice; here, into blk.Instrs concatenated in block order).
func convertX86FuncCFG(fir *decompiler.FuncIR, edges []disasm.CallEdge) *lattice.FuncCFG {
	edgeByPC := make(map[uint64]disasm.CallEdge, len(edges))
	for _, e := range edges {
		edgeByPC[e.FromPC] = e
	}

	lcfg := &lattice.FuncCFG{Name: fir.Name}
	idx := 0
	for _, blk := range fir.Blocks {
		start := idx
		var calls []lattice.CallSite
		for _, ins := range blk.Instrs {
			if e, ok := edgeByPC[ins.Addr]; ok {
				callee := e.TargetName
				if callee == "" {
					callee = e.Via
				}
				if callee == "" {
					callee = fmt.Sprintf("0x%x", e.TargetPC)
				}
				calls = append(calls, lattice.CallSite{Offset: idx, Callee: callee})
			}
			idx++
		}

		lb := &lattice.BasicBlock{
			ID:    blk.ID,
			Start: start,
			End:   idx,
			Term:  blk.IsTerm,
			Calls: calls,
		}
		for _, s := range blk.Succs {
			lb.Succs = append(lb.Succs, lattice.Successor{BlockID: s.BlockID, Cond: s.Cond})
		}
		lcfg.Blocks = append(lcfg.Blocks, lb)
	}
	return lcfg
}
