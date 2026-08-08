package typetrack

import (
	"aotopsy/internal/disasm"
)

// SSA implementation for type inference.
//
// Dart AOT compiler uses SSA form internally (ComputeSSA in flow_graph.cc),
// but the binary output uses physical registers. We reconstruct a simplified
// SSA form from the binary to track types per-definition instead of per-register.
//
// The key insight: in the current per-register lattice, when a register is
// redefined, the previous type is lost. With SSA, each definition gets a
// unique version, and types are tracked per-version. Phi functions at join
// points merge types from different paths.
//
// Implementation:
// 1. Build dominator tree (Cooper-Harvey-Kennedy algorithm)
// 2. Insert phi functions at dominance frontier
// 3. Rename variables (version each definition)
// 4. Track types per SSA version

// SSABlock is a basic block with SSA-specific info.
type SSABlock struct {
	ID            int
	StartVA       uint64
	Insts         []disasm.Inst
	Successors    []int
	Predecessors  []int
	IDom          int   // immediate dominator (-1 for entry)
	DomFrontier   []int // dominance frontier set
	PhiCount      int
}

// SSAValue is a versioned register (e.g., X0_v3).
type SSAValue struct {
	Reg     int    // physical register (0-30)
	Version int    // SSA version
	BlockID int    // block where defined
	InstIdx int    // instruction index in block
}

// SSAPhi is a phi function at a join point.
type SSAPhi struct {
	Reg      int           // physical register
	BlockID  int           // block where phi is
	Operands []SSAValue    // one per predecessor
	Result   SSAValue      // result version
}

// SSAState tracks the current version of each register during renaming.
type SSAState struct {
	// currentVersion[reg] = current SSA version for register reg
	currentVersion [31]int
	// types[version] = type lattice for that SSA version
	types map[SSAValue]TypeLattice
	// phis[blockID] = list of phi functions in that block
	phis map[int][]*SSAPhi
	// defSites[reg] = list of blocks that define reg (for phi insertion)
	defSites [31]map[int]bool
}

// NewSSAState creates a new SSA state.
func NewSSAState() *SSAState {
	s := &SSAState{
		types: make(map[SSAValue]TypeLattice),
		phis:  make(map[int][]*SSAPhi),
	}
	for i := range s.defSites {
		s.defSites[i] = make(map[int]bool)
	}
	return s
}

// BuildDominators computes immediate dominators using the
// Cooper-Harvey-Kennedy algorithm (simple, O(n²) but sufficient
// for function-sized graphs).
// Reference: "A Simple, Fast Dominance Algorithm" (2001)
func BuildDominators(blocks []SSABlock, entry int) []int {
	if len(blocks) == 0 {
		return nil
	}
	idom := make([]int, len(blocks))
	for i := range idom {
		idom[i] = -1
	}
	idom[entry] = entry // entry dominates itself

	// Reverse postorder traversal
	rpo := reversePostorder(blocks, entry)
	rpoIndex := make(map[int]int, len(rpo))
	for i, b := range rpo {
		rpoIndex[b] = i
	}

	changed := true
	for changed {
		changed = false
		for _, b := range rpo {
			if b == entry {
				continue
			}
			// Find the first processed predecessor
			var newIdom int = -1
			for _, pred := range blocks[b].Predecessors {
				if idom[pred] != -1 {
					if newIdom == -1 {
						newIdom = pred
					} else {
						newIdom = intersect(idom, rpoIndex, newIdom, pred)
					}
				}
			}
			if newIdom != -1 && idom[b] != newIdom {
				idom[b] = newIdom
				changed = true
			}
		}
	}
	return idom
}

// intersect finds the common dominator of two blocks.
func intersect(idom []int, rpoIndex map[int]int, b1, b2 int) int {
	for b1 != b2 {
		for rpoIndex[b1] > rpoIndex[b2] {
			b1 = idom[b1]
		}
		for rpoIndex[b2] > rpoIndex[b1] {
			b2 = idom[b2]
		}
	}
	return b1
}

// reversePostorder computes reverse postorder traversal from entry.
func reversePostorder(blocks []SSABlock, entry int) []int {
	visited := make(map[int]bool, len(blocks))
	var postorder []int
	var dfs func(b int)
	dfs = func(b int) {
		if visited[b] {
			return
		}
		visited[b] = true
		for _, succ := range blocks[b].Successors {
			dfs(succ)
		}
		postorder = append(postorder, b)
	}
	dfs(entry)
	// Reverse
	for i, j := 0, len(postorder)-1; i < j; i, j = i+1, j-1 {
		postorder[i], postorder[j] = postorder[j], postorder[i]
	}
	return postorder
}

// ComputeDominanceFrontier computes the dominance frontier for each block.
// DF(b) = { y | b dominates a predecessor of y, but b does not strictly dominate y }
func ComputeDominanceFrontier(blocks []SSABlock, idom []int) [][]int {
	df := make([][]int, len(blocks))
	for b := range blocks {
		if len(blocks[b].Predecessors) < 2 {
			continue
		}
		for _, pred := range blocks[b].Predecessors {
			runner := pred
			for runner != idom[b] && runner != -1 {
				df[runner] = append(df[runner], b)
				runner = idom[runner]
			}
		}
	}
	return df
}

// InsertPhis inserts phi functions at dominance frontier for each register
// that is defined in multiple blocks.
func (s *SSAState) InsertPhis(blocks []SSABlock, df [][]int) {
	// For each register that is defined in any block
	for reg := 0; reg < 31; reg++ {
		if len(s.defSites[reg]) == 0 {
			continue
		}
		// Worklist of blocks that need phi for this register
		worklist := make(map[int]bool)
		hasPhi := make(map[int]bool)
		for b := range s.defSites[reg] {
			worklist[b] = true
		}
		for len(worklist) > 0 {
			var b int
			for k := range worklist {
				b = k
				break
			}
			delete(worklist, b)
			for _, y := range df[b] {
				if hasPhi[y] {
					continue
				}
				hasPhi[y] = true
				// Insert phi for reg at block y
				phi := &SSAPhi{
					Reg:     reg,
					BlockID: y,
				}
				s.phis[y] = append(s.phis[y], phi)
				// y now defines reg
				if !s.defSites[reg][y] {
					s.defSites[reg][y] = true
					worklist[y] = true
				}
			}
		}
	}
}

// Rename performs SSA renaming. Each definition of a register gets a new
// version number. Uses are updated to reference the current version.
// Phi results get their own version.
func (s *SSAState) Rename(blocks []SSABlock, idom []int, entry int) {
	// Initialize versions
	for i := range s.currentVersion {
		s.currentVersion[i] = 0
	}
	// Build children list (dominator tree)
	children := make(map[int][]int)
	for b := range blocks {
		if b != entry && idom[b] >= 0 {
			children[idom[b]] = append(children[idom[b]], b)
		}
	}
	// Recursive renaming
	var rename func(b int)
	rename = func(b int) {
		// Save current versions
		var saved [31]int
		copy(saved[:], s.currentVersion[:])

		// Process phi functions in this block
		for _, phi := range s.phis[b] {
			s.currentVersion[phi.Reg]++
			phi.Result = SSAValue{Reg: phi.Reg, Version: s.currentVersion[phi.Reg], BlockID: b}
		}

		// Process instructions
		for idx, inst := range blocks[b].Insts {
			// Check if this instruction defines a register
			if rd := dstRegOfInstSSA(inst); rd >= 0 && rd < 31 {
				s.currentVersion[rd]++
				// Record the definition
				val := SSAValue{Reg: rd, Version: s.currentVersion[rd], BlockID: b, InstIdx: idx}
				// Type will be set by transferInstruction
				_ = val
			}
		}

		// Update phi operands in successors
		for _, succ := range blocks[b].Successors {
			for _, phi := range s.phis[succ] {
				phi.Operands = append(phi.Operands, SSAValue{
					Reg:     phi.Reg,
					Version: s.currentVersion[phi.Reg],
					BlockID: b,
				})
			}
		}

		// Recurse into dominator tree children
		for _, child := range children[b] {
			rename(child)
		}

		// Restore versions
		copy(s.currentVersion[:], saved[:])
	}
	rename(entry)
}

// dstRegOfInstSSA returns the destination register of an instruction,
// or -1 if it doesn't define a register. Similar to dstRegOfInst but
// for SSA construction (works on raw disasm.Inst).
func dstRegOfInstSSA(inst disasm.Inst) int {
	raw := inst.Raw
	// Use the existing dstRegOfInst from intraproc.go
	return dstRegOfInst(raw)
}

// GetSSAType returns the type lattice for an SSA value.
func (s *SSAState) GetSSAType(v SSAValue) TypeLattice {
	return s.types[v]
}

// SetSSAType sets the type lattice for an SSA value.
func (s *SSAState) SetSSAType(v SSAValue, t TypeLattice) {
	s.types[v] = t
}

// ResolvePhiType computes the meet of all phi operands.
func (s *SSAState) ResolvePhiType(phi *SSAPhi, lca func(int, int) int) TypeLattice {
	if len(phi.Operands) == 0 {
		return Top()
	}
	result := s.types[phi.Operands[0]]
	for _, op := range phi.Operands[1:] {
		result = meetType(result, s.types[op], lca)
	}
	return result
}

// recordFieldStore records a field store for whole-program field-store → field-load tracking.
// Called from transferInstruction when STR/STUR Xt, [Xn, #offset] is detected
// and both Xn (receiver) and Xt (value) have KnownClass.
func recordFieldStore(ctx *TypeContext, receiverCID int, byteOffset int32, valueCID int) {
	if ctx.FieldStoreTypes == nil {
		return
	}
	// Adjust for kHeapObjectTag (same as FieldValueClass lookup)
	lookupOff := byteOffset + 1
	m, ok := ctx.FieldStoreTypes[receiverCID]
	if !ok {
		m = make(map[int32]int)
		ctx.FieldStoreTypes[receiverCID] = m
	}
	// Only record if not already present (first-write-wins, like InstanceFieldTypes unanimity)
	if _, exists := m[lookupOff]; !exists {
		m[lookupOff] = valueCID
	}
}

// recordAllocationSite records an allocation site for allocation site tracking.
// Called from transferInstruction when an allocation stub call is detected.
func recordAllocationSite(ctx *TypeContext, callPC uint64, classID int) {
	if ctx.AllocationSites == nil {
		return
	}
	ctx.AllocationSites[callPC] = classID
	if ctx.InstantiatedClasses != nil {
		ctx.InstantiatedClasses[classID] = true
	}
}
