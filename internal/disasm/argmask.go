package disasm

import (
	"aotopsy/internal/arch/arm64"
	archx86 "aotopsy/internal/arch/x86"

	"golang.org/x/arch/x86/x86asm"
)

// ResolveArgRegIndices reduces per-call-site register-setup masks for one
// direct callee into convention positions that are stable across call sites.
// One site is never enough: register-allocation noise can make a preserved
// value look like an argument. A position is accepted only when EVERY observed
// direct call site independently sets it in the local call-setup window. A
// majority is useful telemetry but not proof: one unrelated register write at
// enough sites can otherwise promote a non-argument to a callee entry fact.
// Returned indices are positions in the SDK register convention, not hardware
// register numbers.
func ResolveArgRegIndices(masks []uint8) ([]int, bool) {
	if len(masks) < 2 {
		return nil, false
	}
	core := masks[0]
	for _, m := range masks[1:] {
		core &= m
	}
	var idx []int
	for i := 0; i < 8; i++ {
		if core&(1<<uint(i)) != 0 {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		return nil, false
	}
	return idx, true
}

// DirectCallArgMasksARM64 returns one setup mask per direct BL, bounded by the
// containing basic block. It deliberately does not run provenance analysis;
// callers that only need calling-convention evidence should not pay for or be
// coupled to unrelated PP/THR dataflow.
func DirectCallArgMasksARM64(insts []Inst) map[uint64]uint8 {
	out := make(map[uint64]uint8)
	if len(insts) == 0 {
		return out
	}
	cfg := BuildCFG("arg-mask", insts)
	for _, blk := range cfg.Blocks {
		for i := blk.Start; i < blk.End && i < len(insts); i++ {
			if _, ok := arm64.BL(insts[i].Raw, insts[i].Addr); ok {
				out[insts[i].Addr] = inferCallArgRegMaskLocal(insts, i, blk.Start)
			}
		}
	}
	return out
}

// DirectCallArgMasksX86 is the x86_64 counterpart of
// DirectCallArgMasksARM64. Indirect CALLs may appear in the returned map too;
// consumers pair the mask with their independently-decoded direct target and
// therefore never promote an indirect site to a direct edge.
func DirectCallArgMasksX86(insts []archx86.Decoded) map[uint64]uint8 {
	out := make(map[uint64]uint8)
	if len(insts) == 0 {
		return out
	}
	for _, blk := range buildX86Blocks(insts) {
		for i := blk.Start; i < blk.End && i < len(insts); i++ {
			if insts[i].Inst.Op == x86asm.CALL {
				out[insts[i].VA] = inferX86CallArgRegMaskLocal(insts, i, blk.Start)
			}
		}
	}
	return out
}
