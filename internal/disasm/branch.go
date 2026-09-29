package disasm

import "aotopsy/internal/arch/arm64"

// ARM64 branch instruction detection from raw 32-bit encoding.
// These functions identify basic-block terminators and extract branch targets.

// branchInfo describes a decoded branch instruction.
type branchInfo struct {
	Target     uint64 // absolute target address (0 if RET or indirect)
	Cond       bool   // true if conditional (has fallthrough)
	IsRet      bool   // true if RET
	IsIndirect bool   // true if BR (indirect branch — jump table, tail call)
}

// DecodeBranch attempts to decode a branch instruction from raw encoding at the given PC.
// Returns nil if the instruction is not a branch/ret.
func DecodeBranch(raw uint32, pc uint64) *branchInfo {
	// RET
	if arm64.IsRet(raw) {
		return &branchInfo{IsRet: true}
	}

	// BR xN (indirect branch)
	if _, ok := arm64.IsBR(raw); ok {
		return &branchInfo{IsIndirect: true}
	}

	// B (unconditional): 000101 imm26
	if target, ok := arm64.B(raw, pc); ok {
		return &branchInfo{Target: target}
	}

	// Conditional branches (B.cond, CBZ, CBNZ, TBZ, TBNZ)
	if target, ok := arm64.CondBranch(raw, pc); ok {
		return &branchInfo{Target: target, Cond: true}
	}

	// Dart <=2.14 emitted B.AL using the B.cond encoding. NV is deliberately
	// not accepted here: exact SDK sources use it only as an internal far-branch
	// sentinel which is rewritten to NOP, and from 2.15 assert it is not emitted.
	if target, _, kind, ok := arm64.BCond(raw, pc); ok && kind == arm64.BCondAlways {
		return &branchInfo{Target: target}
	}

	return nil
}
