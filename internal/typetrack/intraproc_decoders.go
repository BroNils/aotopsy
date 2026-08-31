package typetrack

import "aotopsy/internal/arch/arm64"

// ARM64 instruction decoders (isBL, isBLR, isLDR64UnsignedOffset, isSTUR64,
// isADD64Immediate, isUBFX, etc.) are now shared from internal/arm64.
// This file retains only typetrack-specific helpers that are NOT instruction
// decoders.

// recordFieldStore records a field store for whole-program field-store → field-load tracking.
//
// Unanimity is required, matching InstanceFieldTypes' rule: if two stores
// to the same (receiverCID, byteOffset) pair record different value classes,
// the entry is dropped (set to -1 sentinel) rather than keeping the first
// one. A wrong concrete type is worse than no type, because callers treat
// KnownClass as authoritative (see InstanceFieldTypes' doc comment).
func recordFieldStore(ctx *TypeContext, receiverCID int, byteOffset int32, valueCID int) {
	if ctx.FieldStoreTypes == nil {
		return
	}
	lookupOff := byteOffset + 1
	m, ok := ctx.FieldStoreTypes[receiverCID]
	if !ok {
		m = make(map[int32]int)
		ctx.FieldStoreTypes[receiverCID] = m
	}
	existing, exists := m[lookupOff]
	if !exists {
		m[lookupOff] = valueCID
		return
	}
	// Already recorded: check for conflict.
	if existing != valueCID && existing != -1 {
		// Conflict: drop the entry. -1 sentinel means "conflicting, do not use".
		m[lookupOff] = -1
	}
}

// recordAllocationSite records an allocation site for allocation site tracking.
func recordAllocationSite(ctx *TypeContext, callPC uint64, classID int) {
	if ctx.AllocationSites == nil {
		return
	}
	ctx.AllocationSites[callPC] = classID
	if ctx.InstantiatedClasses != nil {
		ctx.InstantiatedClasses[classID] = true
	}
}

// isCondBranch detects conditional branches (B.cond, CBZ, CBNZ, TBZ, TBNZ).
// Returns the list of target addresses (branch target only — fall-through is
// implied by the caller). Returns false for B.AL (cond=14) and B.NV (cond=15)
// because those are unconditional despite using the B.cond encoding.
func isCondBranch(raw uint32, pc uint64) ([]uint64, bool) {
	if target, ok := arm64.CondBranch(raw, pc); ok {
		return []uint64{target}, true
	}
	return nil, false
}
