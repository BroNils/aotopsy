package typetrack

// ARM64 instruction decoders for intraprocedural type tracking.
// These extract register operands and immediates from raw 32-bit
// instruction words using bit-field tests rather than a full disassembly
// pass — they are the building blocks for the handler functions in
// intraproc_handlers.go.

func isBL(raw uint32, pc uint64) (uint64, bool) {
	if raw&0xFC000000 != 0x94000000 {
		return 0, false
	}
	imm26 := int32(raw & 0x03FFFFFF)
	if imm26&(1<<25) != 0 {
		imm26 |= ^int32(0x03FFFFFF)
	}
	return uint64(int64(pc) + int64(imm26)*4), true
}

// isBLR detects BLR (branch with link to register). Returns register number.
func isBLR(raw uint32) (int, bool) {
	if raw&0xFFFFFC1F != 0xD63F0000 {
		return 0, false
	}
	return int((raw >> 5) & 0x1F), true
}

// isB detects unconditional branch B. Returns target address.
func isB(raw uint32, pc uint64) (uint64, bool) {
	if raw&0xFC000000 != 0x14000000 {
		return 0, false
	}
	imm26 := int32(raw & 0x03FFFFFF)
	if imm26&(1<<25) != 0 {
		imm26 |= ^int32(0x03FFFFFF)
	}
	return uint64(int64(pc) + int64(imm26)*4), true
}

// isCondBranch detects conditional branches (B.cond, CBZ, CBNZ, TBZ, TBNZ).
// Returns the list of target addresses (branch target + fall-through).
func isCondBranch(raw uint32, pc uint64) ([]uint64, bool) {
	// B.cond: 0101 0100 | imm19 | 0 | cond
	if raw&0xFF000010 == 0x54000000 {
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

// isLDR64UnsignedOffset detects LDR Xt, [Xn, #imm] (64-bit unsigned offset).
// Returns base register and byte offset.
func isLDR64UnsignedOffset(raw uint32) (baseReg int, byteOffset int, ok bool) {
	if raw&0xFFC00000 != 0xF9400000 {
		return 0, 0, false
	}
	rn := int((raw >> 5) & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	return rn, imm12 << 3, true
}

// isSTR64UnsignedOffset detects STR Xt, [Xn, #imm] (64-bit unsigned offset).
// Returns base register and byte offset.
func isSTR64UnsignedOffset(raw uint32) (baseReg int, byteOffset int, ok bool) {
	if raw&0xFFC00000 != 0xF9000000 {
		return 0, 0, false
	}
	rn := int((raw >> 5) & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	return rn, imm12 << 3, true
}

// isLDRRegExtended detects LDR Xt, [Xn, Xm, LSL #3] (register offset).
// Returns base, index, and destination register.
//
// The mask now covers option (bits 15:13) and S (bit 12), which the old
// 0xFFE00C00 left free. A TODO here used to call that an intentional
// trade-off, on the grounds that tightening "could break the existing
// dispatch table detection". Measured on the 3.12.2 arm64 .text before
// changing anything, over the 3692 words the loose mask accepts:
//
//	option=011 (LSL/UXTX) S=1   3412   92.4%
//	option=011 (LSL/UXTX) S=0    280    7.6%
//
// So no other extend option occurs at all, and the only thing the loose mask
// actually admitted was 280 UNSCALED loads -- `LDR Xt, [Xn, Xm]` -- being
// read as if the index were scaled by 8. The SDK emits the scaled form for a
// dispatch call (`Call(Address(DISPATCH_TABLE_REG, LR, UXTX, Scaled))`,
// flow_graph_compiler_arm64.cc), so those 280 were never this instruction and
// their slot arithmetic was wrong by a factor of eight.
func isLDRRegExtended(raw uint32) (base, rm, rt int, ok bool) {
	if raw&0xFFE0FC00 != 0xF8607800 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	base = int((raw >> 5) & 0x1F)
	rm = int((raw >> 16) & 0x1F)
	return base, rm, rt, true
}

// isLDUR64 detects LDUR Xt, [Xn, #imm9] (unscaled immediate).
func isLDUR64(raw uint32) (base, rt int, ok bool) {
	if raw&0xFFE00C00 != 0xF8400000 {
		return 0, 0, false
	}
	rt = int(raw & 0x1F)
	base = int((raw >> 5) & 0x1F)
	return base, rt, true
}

// isSTUR64 detects STUR Xt, [Xn, #imm9] (unscaled immediate store).
// Encoding: 11 111 0 00 00 imm9 00 Rn Rt
// Mask: 0xFFE00C00, Value: 0xF8000000
// Q1 fix: extract full 9-bit imm9 (bits 12-20), not just 8 bits.
func isSTUR64(raw uint32) (base, rt int, imm9 int, ok bool) {
	if raw&0xFFE00C00 != 0xF8000000 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	base = int((raw >> 5) & 0x1F)
	imm9 = int(int32(raw>>12) & 0x1FF) // 9-bit field, bits 12-20
	if imm9 > 256 {
		imm9 -= 512 // sign-extend 9-bit
	}
	return base, rt, imm9, true
}

// isSTUR32 detects STUR Wt, [Xn, #imm9] (32-bit unscaled store).
// Used for compressed pointer stores in Dart 3.x.
// Encoding: 10 111 0 00 00 imm9 00 Rn Rt
// Mask: 0xFFE00C00, Value: 0xB8000000
func isSTUR32(raw uint32) (base, rt int, imm9 int, ok bool) {
	if raw&0xFFE00C00 != 0xB8000000 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	base = int((raw >> 5) & 0x1F)
	imm9 = int(int32(raw>>12) & 0x1FF)
	if imm9 > 256 {
		imm9 -= 512
	}
	return base, rt, imm9, true
}

// isLDUR32 detects LDUR Wt, [Xn, #imm9] (32-bit unscaled load).
// Used for compressed pointer loads in Dart 3.x.
// Encoding: 10 111 0 00 00 imm9 00 Rn Rt
// Mask: 0xFFE00C00, Value: 0xB8400000
func isLDUR32(raw uint32) (base, rt int, imm9 int, ok bool) {
	if raw&0xFFE00C00 != 0xB8400000 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	base = int((raw >> 5) & 0x1F)
	imm9 = int(int32(raw>>12) & 0x1FF)
	if imm9 > 256 {
		imm9 -= 512
	}
	return base, rt, imm9, true
}

// isLDURH detects LDURH Wt, [Xn, #imm9] (16-bit unscaled load).
// Used in Dart 2.x for class ID extraction:
//
//	LDURH Wt, [Xobj, #1] = load 2 bytes at obj+1+1 = obj+2 = class ID field
//
// (kClassIdTagPos=16, kClassIdTagSize=16 in 2.x; vs 12/20 in 3.x)
// Encoding: 01 111 000 01 0 imm9 00 Rn Rt (size=01, V=0, opc=01)
// Base: 0x78400000, Mask: 0xFFE00C00
func isLDURH(raw uint32) (base, rt int, imm9 int, ok bool) {
	if raw&0xFFE00C00 != 0x78400000 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	base = int((raw >> 5) & 0x1F)
	imm9 = int(int32(raw>>12) & 0x1FF)
	if imm9 > 256 {
		imm9 -= 512
	}
	return base, rt, imm9, true
}

// isLDR32UnsignedOffset detects LDR Wt, [Xn, #imm] (32-bit unsigned offset).
// Used for compressed pointer field loads in Dart 3.x.
// Encoding: 10 111 0 01 01 imm12 Rn Rt
// Mask: 0xFFC00000, Value: 0xB9400000
func isLDR32UnsignedOffset(raw uint32) (baseReg int, byteOffset int, ok bool) {
	if raw&0xFFC00000 != 0xB9400000 {
		return 0, 0, false
	}
	rt := int(raw & 0x1F)
	baseReg = int((raw >> 5) & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	byteOffset = imm12 * 4 // scaled by 4 for 32-bit load
	_ = rt                 // rt is always valid (0-30 are real registers, 31 is WZR which we don't track but still valid)
	return baseReg, byteOffset, true
}

// isADD64Immediate detects ADD Xd, Xn, #imm (64-bit).
// Returns dest, source, and immediate value (with shift applied).
func isADD64Immediate(raw uint32) (rd, rn int, immValue int, ok bool) {
	if raw&0xFF000000 != 0x91000000 {
		return 0, 0, 0, false
	}
	rd = int(raw & 0x1F)
	rn = int((raw >> 5) & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	shift := int((raw >> 22) & 0x3)
	// shift==0: no shift; shift==1: LSL #12. shift==2,3 are RESERVED in
	// the ADD (immediate) encoding -- treat them as unknown (immValue=0)
	// rather than silently applying the unshifted value, which would
	// misinterpret a reserved encoding as a real immediate.
	if shift == 1 {
		immValue = imm12 << 12
	} else if shift == 0 {
		immValue = imm12
	} else {
		// Reserved shift (2 or 3): leave immValue at its zero value.
		immValue = 0
	}
	return rd, rn, immValue, true
}

// isSUB64Immediate detects SUB Xd, Xn, #imm (64-bit).
// Returns dest, source, and immediate value (with shift applied).
func isSUB64Immediate(raw uint32) (rd, rn int, immValue int, ok bool) {
	if raw&0xFF000000 != 0xD1000000 {
		return 0, 0, 0, false
	}
	rd = int(raw & 0x1F)
	rn = int((raw >> 5) & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	shift := int((raw >> 22) & 0x3)
	// shift==0: no shift; shift==1: LSL #12. shift==2,3 are RESERVED in
	// the SUB (immediate) encoding -- treat them as unknown (immValue=0)
	// rather than silently applying the unshifted value.
	if shift == 1 {
		immValue = imm12 << 12
	} else if shift == 0 {
		immValue = imm12
	} else {
		// Reserved shift (2 or 3): leave immValue at its zero value.
		immValue = 0
	}
	return rd, rn, immValue, true
}

// isADD64Register detects ADD Xd, Xn, Xm (register-register, 64-bit).
// Encoding: sf=1 | 00 | 01011 | shift=00 | 0 | Rm | imm6 | Rn | Rd
// Mask: 0xFF200000, Value: 0x8B000000 (with sf=1 → 0x8B000000)
// Fase 4: added for register-register dispatch slot computation.
func isADD64Register(raw uint32) (rd, rn, rm int, ok bool) {
	if raw&0xFF200000 != 0x8B000000 {
		return 0, 0, 0, false
	}
	rd = int(raw & 0x1F)
	rn = int((raw >> 5) & 0x1F)
	rm = int((raw >> 16) & 0x1F)
	return rd, rn, rm, true
}

// isMOVZ64 detects MOVZ Xd, #imm16 (64-bit, shift=0).
// Encoding: sf=1 | 10 | 100101 | hw=00 | imm16 | Rd
// Mask: 0xFFE00000, Value: 0xD2800000 (hw=00 means no shift)
// Returns dest register and the 16-bit immediate.
func isMOVZ64(raw uint32) (rd int, imm int, ok bool) {
	if raw&0xFFE00000 != 0xD2800000 {
		return 0, 0, false
	}
	rd = int(raw & 0x1F)
	imm = int((raw >> 5) & 0xFFFF)
	return rd, imm, true
}

// isUBFX detects UBFM/UBFX Xt, Xn, #lsb, #width (64-bit).
// Encoding: sf=1 | 10 | 100110 | N=1 | immr | imms | Rn | Rd
// Mask: 0xFF800000, Value: 0xD3000000
// Returns dest and source register.
func isUBFX(raw uint32) (rd, rn int, ok bool) {
	if raw&0xFF800000 != 0xD3000000 {
		return 0, 0, false
	}
	rd = int(raw & 0x1F)
	rn = int((raw >> 5) & 0x1F)
	return rd, rn, true
}

// isMOVOrr detects MOV (alias of ORR Xd, XZR, Xm).
// Encoding: sf=1 | 01 | 01010 | 00 | 0 | Rm | 000000 | Rn=31 | Rd
// Mask: 0xFF200000, Value: 0xAA000000 (with sf=1)
func isMOVOrr(raw uint32) (rd int, ok bool) {
	// ORR Xd, XZR, Xm: 0xAA000000 with Rn=31.
	// Mask 0xFF200000 covers sf+opcode+Rm+fixed bits, NOT Rd (bits 0-4) so
	// any destination register matches. The previous mask 0xFF20001F
	// included Rd, so only Rd==0 (MOV X0) ever matched.
	if raw&0xFF200000 == 0xAA000000 {
		// Rn field is bits 5-9. For MOV, Rn = XZR = 31.
		rn := int((raw >> 5) & 0x1F)
		if rn == 31 {
			return int(raw & 0x1F), true
		}
	}
	return 0, false
}

// dstRegOfInst returns the destination register of common instructions,
// or -1 if not detected. Used to kill types on unknown instructions.
func dstRegOfInst(raw uint32) int {
	// LDR X64 unsigned offset
	if raw&0xFFC00000 == 0xF9400000 {
		return int(raw & 0x1F)
	}
	// LDR W32 unsigned offset
	if raw&0xFFC00000 == 0xB9400000 {
		return int(raw & 0x1F)
	}
	// LDUR X64
	if raw&0xFFE00C00 == 0xF8400000 {
		return int(raw & 0x1F)
	}
	// LDR X64 register offset
	if raw&0xFFE00C00 == 0xF8600800 {
		return int(raw & 0x1F)
	}
	// ADD X64 immediate
	if raw&0xFF000000 == 0x91000000 {
		return int(raw & 0x1F)
	}
	// SUB X64 immediate
	if raw&0xFF000000 == 0xD1000000 {
		return int(raw & 0x1F)
	}
	// MOVZ/MOVK/MOVN
	if raw&0xFF800000 == 0xD2800000 || // MOVZ X
		raw&0xFF800000 == 0xF2800000 || // MOVK X
		raw&0xFF800000 == 0x92800000 { // MOVN X
		return int(raw & 0x1F)
	}
	// UBFM/UBFX
	if raw&0xFF800000 == 0xD3000000 {
		return int(raw & 0x1F)
	}
	return -1
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

// isSUBS32Immediate detects SUBS Wd, Wn, #imm (32-bit, sets flags).
// CMP Wn, #imm is an alias for SUBS WZR, Wn, #imm (Wd = W31 = WZR).
// Encoding: sf=0 | 1 | 1 | 100010 | sh | imm12 | Rn | Rd
// Mask: 0xFF000000 (top 8 bits), Value: 0x71000000 (32-bit SUBS immediate)
// Returns dest, source, and immediate value (with shift applied).
func isSUBS32Immediate(raw uint32) (rd, rn int, immValue int, ok bool) {
	if raw&0xFF000000 != 0x71000000 {
		return 0, 0, 0, false
	}
	rd = int(raw & 0x1F)
	rn = int((raw >> 5) & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	shift := int((raw >> 22) & 0x3)
	if shift == 1 {
		immValue = imm12 << 12
	} else if shift == 0 {
		immValue = imm12
	} else {
		immValue = 0 // reserved
	}
	return rd, rn, immValue, true
}
