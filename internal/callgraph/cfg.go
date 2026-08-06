package callgraph

import (
	"fmt"

	"aotopsy/internal/disasm"

	"aotopsy/internal/lattice"
)

// BuildFuncCFG builds a single-function lattice.FuncCFG from instructions and call edges.
// Returns the FuncCFG and the number of basic blocks (for filtering trivial functions).
func BuildFuncCFG(name string, insts []disasm.Inst, edges []disasm.CallEdge) (*lattice.FuncCFG, int) {
	dcfg := disasm.BuildCFG(name, insts)
	lcfg := convertFuncCFG(&dcfg, edges)
	return lcfg, len(dcfg.Blocks)
}

// convertFuncCFG maps a disasm.FuncCFG to a lattice.FuncCFG.
// Call edges are mapped into blocks by matching instruction PCs.
func convertFuncCFG(dcfg *disasm.FuncCFG, edges []disasm.CallEdge) *lattice.FuncCFG {
	// Build PC → CallEdge map for O(1) lookup.
	edgeByPC := make(map[uint64]disasm.CallEdge, len(edges))
	for _, e := range edges {
		edgeByPC[e.FromPC] = e
	}

	lcfg := &lattice.FuncCFG{Name: dcfg.Name}
	for _, db := range dcfg.Blocks {
		lb := &lattice.BasicBlock{
			ID:    db.ID,
			Start: db.Start,
			End:   db.End,
			Term:  db.IsTerm,
		}

		// Convert successors.
		for _, ds := range db.Succs {
			lb.Succs = append(lb.Succs, lattice.Successor{
				BlockID: ds.BlockID,
				Cond:    ds.Cond,
			})
		}

		// Populate calls from edges that fall within this block's instruction range.
		for idx := db.Start; idx < db.End && idx < len(dcfg.Insts); idx++ {
			if e, ok := edgeByPC[dcfg.Insts[idx].Addr]; ok {
				callee := e.TargetName
				if callee == "" {
					callee = e.Via
				}
				if callee == "" {
					callee = fmt.Sprintf("0x%x", e.TargetPC)
				}
				lb.Calls = append(lb.Calls, lattice.CallSite{
					Offset: idx,
					Callee: callee,
				})
			}
		}

		lcfg.Blocks = append(lcfg.Blocks, lb)
	}
	return lcfg
}
