package disasm

// ARM64 branch instruction detection from raw 32-bit encoding.
// These functions identify basic-block terminators and extract branch targets.

// BranchInfo describes a decoded branch instruction.
type BranchInfo struct {
	Target     uint64 // absolute target address (0 if RET or indirect)
	Cond       bool   // true if conditional (has fallthrough)
	IsRet      bool   // true if RET
	IsIndirect bool   // true if BR (indirect branch — jump table, tail call)
}

// DecodeBranch attempts to decode a branch instruction from raw encoding at the given PC.
// Returns nil if the instruction is not a branch/ret.
func DecodeBranch(raw uint32, pc uint64) *BranchInfo {
	// RET (0xD65F03C0 exactly, or RET Xn = 0xD65F0000 | Rn<<5)
	if raw&0xFFFFFC1F == 0xD65F0000 {
		return &BranchInfo{IsRet: true}
	}

	// BR xN (indirect branch): 1101011 0 0 00 11111 000000 Rn 00000
	// Encoding: 0xD61F0000 | Rn<<5
	if raw&0xFFFFFC1F == 0xD61F0000 {
		return &BranchInfo{IsIndirect: true}
	}

	// B (unconditional): 000101 imm26
	if raw&0xFC000000 == 0x14000000 {
		imm26 := raw & 0x03FFFFFF
		offset := signExtend(imm26, 26) * 4
		return &BranchInfo{Target: uint64(int64(pc) + int64(offset))}
	}

	// B.cond: 01010100 imm19 0 cond
	if raw&0xFF000010 == 0x54000000 {
		imm19 := (raw >> 5) & 0x7FFFF
		offset := signExtend(imm19, 19) * 4
		return &BranchInfo{Target: uint64(int64(pc) + int64(offset)), Cond: true}
	}

	// CBZ: 0 sf 110100 imm19 Rt
	if raw&0x7F000000 == 0x34000000 {
		imm19 := (raw >> 5) & 0x7FFFF
		offset := signExtend(imm19, 19) * 4
		return &BranchInfo{Target: uint64(int64(pc) + int64(offset)), Cond: true}
	}

	// CBNZ: 0 sf 110101 imm19 Rt
	if raw&0x7F000000 == 0x35000000 {
		imm19 := (raw >> 5) & 0x7FFFF
		offset := signExtend(imm19, 19) * 4
		return &BranchInfo{Target: uint64(int64(pc) + int64(offset)), Cond: true}
	}

	// TBZ: 0 b5 110110 b40 imm14 Rt
	if raw&0x7F000000 == 0x36000000 {
		imm14 := (raw >> 5) & 0x3FFF
		offset := signExtend(imm14, 14) * 4
		return &BranchInfo{Target: uint64(int64(pc) + int64(offset)), Cond: true}
	}

	// TBNZ: 0 b5 110111 b40 imm14 Rt
	if raw&0x7F000000 == 0x37000000 {
		imm14 := (raw >> 5) & 0x3FFF
		offset := signExtend(imm14, 14) * 4
		return &BranchInfo{Target: uint64(int64(pc) + int64(offset)), Cond: true}
	}

	return nil
}

// signExtend sign-extends a value from the given bit width to int32.
func signExtend(val uint32, bits int) int32 {
	sign := uint32(1) << (bits - 1)
	mask := sign - 1
	if val&sign != 0 {
		return int32(val | ^mask) // negative
	}
	return int32(val & mask)
}
