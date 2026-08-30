package typetrack

import "aotopsy/internal/arch/arm64"

// ARM64 instruction decoders (isBL, isBLR, isLDR64UnsignedOffset, isSTUR64,
// isADD64Immediate, isUBFX, etc.) are now shared from internal/arm64.
// This file retains only typetrack-specific helpers that are NOT instruction
// decoders.

// dstRegOfInst returns the destination register of common instructions,
// or -1 if not detected. Used to kill types on unknown instructions.
// Delegates to arm64.DstRegOfInst.
func dstRegOfInst(raw uint32) int {
	return arm64.DstRegOfInst(raw)
}

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
	// B.cond: 0101 0100 | imm19 | 0 | cond
	if raw&0xFF000010 == 0x54000000 {
		// cond 0b1110 (AL) and 0b1111 (NV) always branch — they are
		// unconditional despite using the B.cond encoding. Return false
		// so the caller treats them as unconditional (no fall-through).
		// This matches disasm.DecodeBranch's handling.
		if cond := raw & 0xF; cond == 14 || cond == 15 {
			return nil, false
		}
		imm19 := int32(raw>>5) & 0x7FFFF
		if imm19&(1<<18) != 0 {
			imm19 |= ^int32(0x7FFFF)
		}
		target := uint64(int64(pc) + int64(imm19)*4)
		return []uint64{target}, true
	}
	// CBZ: sf | 011 010 | 0 | imm19 | Rt
	if raw&0x7F000000 == 0x34000000 {
		imm19 := int32(raw>>5) & 0x7FFFF
		if imm19&(1<<18) != 0 {
			imm19 |= ^int32(0x7FFFF)
		}
		target := uint64(int64(pc) + int64(imm19)*4)
		return []uint64{target}, true
	}
	// CBNZ: sf | 011 010 | 1 | imm19 | Rt
	if raw&0x7F000000 == 0x35000000 {
		imm19 := int32(raw>>5) & 0x7FFFF
		if imm19&(1<<18) != 0 {
			imm19 |= ^int32(0x7FFFF)
		}
		target := uint64(int64(pc) + int64(imm19)*4)
		return []uint64{target}, true
	}
	// TBZ: b5 | 011 011 | 0 | imm14 | Rt
	if raw&0x7F000000 == 0x36000000 {
		imm14 := int32(raw>>5) & 0x3FFF
		if imm14&(1<<13) != 0 {
			imm14 |= ^int32(0x3FFF)
		}
		target := uint64(int64(pc) + int64(imm14)*4)
		return []uint64{target}, true
	}
	// TBNZ: b5 | 011 011 | 1 | imm14 | Rt
	if raw&0x7F000000 == 0x37000000 {
		imm14 := int32(raw>>5) & 0x3FFF
		if imm14&(1<<13) != 0 {
			imm14 |= ^int32(0x3FFF)
		}
		target := uint64(int64(pc) + int64(imm14)*4)
		return []uint64{target}, true
	}
	return nil, false
}
