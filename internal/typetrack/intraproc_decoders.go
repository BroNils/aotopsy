package typetrack

import "aotopsy/internal/arch/arm64"

// ARM64 instruction decoders (isBL, isBLR, isLDR64UnsignedOffset, isSTUR64,
// isADD64Immediate, isUBFX, etc.) are now shared from internal/arm64.
// This file retains only typetrack-specific helpers that are NOT instruction
// decoders.

// isCondBranch detects conditional branches (B.cond, CBZ, CBNZ, TBZ, TBNZ).
// Returns the list of target addresses (branch target only — fall-through is
// implied by the caller). Returns false for historical B.AL (cond=14), which
// is unconditional, and B.NV (cond=15), which is reserved for real code.
func isCondBranch(raw uint32, pc uint64) ([]uint64, bool) {
	if target, ok := arm64.CondBranch(raw, pc); ok {
		return []uint64{target}, true
	}
	return nil, false
}
