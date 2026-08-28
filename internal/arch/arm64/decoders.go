// Package arm64 holds ARM64 instruction decoders — bit-field tests that
// extract register operands and immediates from raw 32-bit instruction words.
//
// These decoders were previously duplicated between internal/disasm and
// internal/typetrack (15+ functions with identical bit-mask logic), plus BL
// target decode was copy-pasted in 6 places (decompiler, disasm, typetrack,
// pipeline, symbolmap). This package is the single source.
//
// All encodings are from the ARM Architecture Reference Manual and verified
// against dart-lang/sdk's runtime/vm/compiler/assembler/assembler_arm64.h.
package arm64

// ── Branch instructions ───────────────────────────────────────────────

// BL decodes ARM64 BL (branch with link). Returns the target address
// (sign-extended imm26 * 4 + PC).
// Encoding: 1 | 00101 | imm26
// Mask: 0xFC000000, Value: 0x94000000
func BL(raw uint32, pc uint64) (target uint64, ok bool) {
	if raw&0xFC000000 != 0x94000000 {
		return 0, false
	}
	imm26 := int32(raw & 0x03FFFFFF)
	if imm26&(1<<25) != 0 {
		imm26 |= ^int32(0x03FFFFFF)
	}
	return uint64(int64(pc) + int64(imm26)*4), true
}

// B decodes ARM64 B (unconditional branch). Returns the target address.
// Encoding: 0 | 00101 | imm26
// Mask: 0xFC000000, Value: 0x14000000
func B(raw uint32, pc uint64) (target uint64, ok bool) {
	if raw&0xFC000000 != 0x14000000 {
		return 0, false
	}
	imm26 := int32(raw & 0x03FFFFFF)
	if imm26&(1<<25) != 0 {
		imm26 |= ^int32(0x03FFFFFF)
	}
	return uint64(int64(pc) + int64(imm26)*4), true
}

// BLR decodes ARM64 BLR (branch with link to register). Returns register number.
// Encoding: 1101011 | 0 | 0 | 01 | 11111 | 0000 | 0 | 0 | Rn | 00000
// Mask: 0xFFFFFC1F, Value: 0xD63F0000
func BLR(raw uint32) (rn int, ok bool) {
	if raw&0xFFFFFC1F != 0xD63F0000 {
		return 0, false
	}
	return int((raw >> 5) & 0x1F), true
}

// SignExtend sign-extends a value from the given bit width to int32.
func SignExtend(val uint32, bits int) int32 {
	sign := uint32(1) << (bits - 1)
	mask := sign - 1
	if val&sign != 0 {
		return int32(val | ^mask)
	}
	return int32(val & mask)
}

// ── Load/Store instructions ───────────────────────────────────────────

// LDR64UnsignedOffset detects LDR Xt, [Xn, #imm] (64-bit, unsigned offset).
// Returns base register and byte offset.
// Encoding: size=11 | 111 | V=0 | 01 | opc=01 | imm12 | Rn | Rt
// Mask: 0xFFC00000, Value: 0xF9400000
func LDR64UnsignedOffset(raw uint32) (baseReg int, byteOffset int, ok bool) {
	if raw&0xFFC00000 != 0xF9400000 {
		return 0, 0, false
	}
	rn := int((raw >> 5) & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	return rn, imm12 << 3, true
}

// LDR32UnsignedOffset detects LDR Wt, [Xn, #imm] (32-bit, unsigned offset).
// Returns base register, byte offset, and destination register.
// Encoding: size=10 | 111 | V=0 | 01 | opc=01 | imm12 | Rn | Rt
// Mask: 0xFFC00000, Value: 0xB9400000
func LDR32UnsignedOffset(raw uint32) (baseReg int, byteOffset int, dstReg int, ok bool) {
	if raw&0xFFC00000 != 0xB9400000 {
		return 0, 0, 0, false
	}
	rn := int((raw >> 5) & 0x1F)
	rt := int(raw & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	return rn, imm12 << 2, rt, true
}

// STR64UnsignedOffset detects STR Xt, [Xn, #imm] (64-bit, unsigned offset).
// Returns base register, byte offset, and source register.
// Encoding: size=11 | 111 | V=0 | 01 | opc=00 | imm12 | Rn | Rt
// Mask: 0xFFC00000, Value: 0xF9000000
func STR64UnsignedOffset(raw uint32) (baseReg int, byteOffset int, srcReg int, ok bool) {
	if raw&0xFFC00000 != 0xF9000000 {
		return 0, 0, 0, false
	}
	rn := int((raw >> 5) & 0x1F)
	rt := int(raw & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	return rn, imm12 << 3, rt, true
}

// STR32UnsignedOffset detects STR Wt, [Xn, #imm] (32-bit, unsigned offset).
// Returns base register, byte offset, and source register.
// Encoding: size=10 | 111 | V=0 | 01 | opc=00 | imm12 | Rn | Rt
// Mask: 0xFFC00000, Value: 0xB9000000
func STR32UnsignedOffset(raw uint32) (baseReg int, byteOffset int, srcReg int, ok bool) {
	if raw&0xFFC00000 != 0xB9000000 {
		return 0, 0, 0, false
	}
	rn := int((raw >> 5) & 0x1F)
	rt := int(raw & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	return rn, imm12 << 2, rt, true
}

// LDRRegExtended detects LDR Xt, [Xn, Xm, LSL #3] (register offset).
// Returns base, index, and destination register.
// Encoding: 11|111|V=0|01|opc=01|1|Rm|option|S|10|Rn|Rt
// Mask: 0xFFE0FC00, Value: 0xF8607800 (option=011, S=1 for scaled LSL)
func LDRRegExtended(raw uint32) (base, rm, rt int, ok bool) {
	if raw&0xFFE0FC00 != 0xF8607800 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	base = int((raw >> 5) & 0x1F)
	rm = int((raw >> 16) & 0x1F)
	return base, rm, rt, true
}

// LDUR64 detects LDUR Xt, [Xn, #imm9] (unscaled immediate).
// Returns base, destination register, and signed offset.
// Encoding: 11 111 0 00 00 imm9 00 Rn Rt
// Mask: 0xFFE00C00, Value: 0xF8400000
func LDUR64(raw uint32) (base, rt, off int, ok bool) {
	if raw&0xFFE00C00 != 0xF8400000 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	rn := int((raw >> 5) & 0x1F)
	imm9 := int((raw >> 12) & 0x1FF)
	if imm9&(1<<8) != 0 {
		imm9 |= ^0x1FF
	}
	return rn, rt, imm9, true
}

// STUR64 detects STUR Xt, [Xn, #imm9] (unscaled immediate store).
// Returns base, source register, and signed 9-bit immediate.
// Encoding: 11 111 0 00 00 imm9 00 Rn Rt
// Mask: 0xFFE00C00, Value: 0xF8000000
func STUR64(raw uint32) (base, rt int, imm9 int, ok bool) {
	if raw&0xFFE00C00 != 0xF8000000 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	rn := int((raw >> 5) & 0x1F)
	imm9 = int((raw >> 12) & 0x1FF)
	if imm9&(1<<8) != 0 {
		imm9 |= ^0x1FF
	}
	return rn, rt, imm9, true
}

// STUR32 detects STUR Wt, [Xn, #imm9] (32-bit unscaled store).
// Returns base, source register, and signed 9-bit immediate.
// Encoding: 10 111 0 00 00 imm9 00 Rn Rt
// Mask: 0xFFE00C00, Value: 0xB8000000
func STUR32(raw uint32) (base, rt int, imm9 int, ok bool) {
	if raw&0xFFE00C00 != 0xB8000000 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	rn := int((raw >> 5) & 0x1F)
	imm9 = int((raw >> 12) & 0x1FF)
	if imm9&(1<<8) != 0 {
		imm9 |= ^0x1FF
	}
	return rn, rt, imm9, true
}

// LDUR32 detects LDUR Wt, [Xn, #imm9] (32-bit unscaled load).
// Returns base, destination register, and signed 9-bit immediate.
// Encoding: 10 111 0 00 00 imm9 00 Rn Rt
// Mask: 0xFFE00C00, Value: 0xB8400000
func LDUR32(raw uint32) (base, rt int, imm9 int, ok bool) {
	if raw&0xFFE00C00 != 0xB8400000 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	rn := int((raw >> 5) & 0x1F)
	imm9 = int((raw >> 12) & 0x1FF)
	if imm9&(1<<8) != 0 {
		imm9 |= ^0x1FF
	}
	return rn, rt, imm9, true
}

// LDURH detects LDURH Wt, [Xn, #imm9] (16-bit unscaled load).
// Used in Dart 2.x for class ID extraction.
// Encoding: 01 111 000 01 0 imm9 00 Rn Rt
// Base: 0x78400000, Mask: 0xFFE00C00
func LDURH(raw uint32) (base, rt int, imm9 int, ok bool) {
	if raw&0xFFE00C00 != 0x78400000 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	rn := int((raw >> 5) & 0x1F)
	imm9 = int((raw >> 12) & 0x1FF)
	if imm9&(1<<8) != 0 {
		imm9 |= ^0x1FF
	}
	return rn, rt, imm9, true
}

// ── Arithmetic instructions ───────────────────────────────────────────

// ADD64Immediate detects ADD Xd, Xn, #imm (64-bit).
// Returns dest, source, and immediate value (with shift applied).
// Encoding: sf=1 | op=0 | S=0 | 100010 | sh | imm12 | Rn | Rd
// Mask: 0xFF000000, Value: 0x91000000
func ADD64Immediate(raw uint32) (rd, rn int, immValue int, ok bool) {
	if raw&0xFF000000 != 0x91000000 {
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

// SUB64Immediate detects SUB Xd, Xn, #imm (64-bit).
// Returns dest, source, and immediate value (with shift applied).
// Encoding: sf=1 | op=1 | S=0 | 100010 | sh | imm12 | Rn | Rd
// Mask: 0xFF000000, Value: 0xD1000000
func SUB64Immediate(raw uint32) (rd, rn int, immValue int, ok bool) {
	if raw&0xFF000000 != 0xD1000000 {
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

// ADD64Register detects ADD Xd, Xn, Xm (register-register, 64-bit).
// Returns dest, source, and operand register.
// Encoding: sf=1 | 00 | 01011 | shift=00 | 0 | Rm | imm6 | Rn | Rd
// Mask: 0xFF200000, Value: 0x8B000000
func ADD64Register(raw uint32) (rd, rn, rm int, ok bool) {
	if raw&0xFF200000 != 0x8B000000 {
		return 0, 0, 0, false
	}
	rd = int(raw & 0x1F)
	rn = int((raw >> 5) & 0x1F)
	rm = int((raw >> 16) & 0x1F)
	return rd, rn, rm, true
}

// SUBS32Immediate detects SUBS Wd, Wn, #imm (32-bit, sets flags).
// CMP Wn, #imm is an alias for SUBS WZR, Wn, #imm.
// Encoding: sf=0 | 1 | 1 | 100010 | sh | imm12 | Rn | Rd
// Mask: 0xFF000000, Value: 0x71000000
func SUBS32Immediate(raw uint32) (rd, rn int, immValue int, ok bool) {
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

// ── Data processing instructions ──────────────────────────────────────

// MOVZ64 detects MOVZ Xd, #imm16 (64-bit, shift=0).
// Returns dest register and the 16-bit immediate.
// Encoding: sf=1 | 10 | 100101 | hw=00 | imm16 | Rd
// Mask: 0xFFE00000, Value: 0xD2800000
func MOVZ64(raw uint32) (rd int, imm int, ok bool) {
	if raw&0xFFE00000 != 0xD2800000 {
		return 0, 0, false
	}
	rd = int(raw & 0x1F)
	imm = int((raw >> 5) & 0xFFFF)
	return rd, imm, true
}

// UBFX detects UBFM/UBFX Xt, Xn, #lsb, #width (64-bit).
// Returns dest, source register, lsb, and width.
// Encoding: sf=1 | 10 | 100110 | N=1 | immr | imms | Rn | Rd
// Mask: 0xFF800000, Value: 0xD3000000
func UBFX(raw uint32) (rd, rn int, lsb, width int, ok bool) {
	if raw&0xFF800000 != 0xD3000000 {
		return 0, 0, 0, 0, false
	}
	rd = int(raw & 0x1F)
	rn = int((raw >> 5) & 0x1F)
	immr := int((raw >> 16) & 0x3F)
	imms := int((raw >> 10) & 0x3F)
	lsb = immr
	width = imms - immr + 1
	return rd, rn, lsb, width, true
}

// MOVOrr detects MOV (alias of ORR Xd, XZR, Xm).
// Returns destination register.
// Encoding: sf=1 | 01 | 01010 | 00 | 0 | Rm | 000000 | Rn=31 | Rd
// Mask: 0xFF200000, Value: 0xAA000000
func MOVOrr(raw uint32) (rd int, ok bool) {
	if raw&0xFF20001F == 0xAA000000 {
		// Check Rn=31 (XZR)
		if (raw>>5)&0x1F == 31 {
			return int(raw & 0x1F), true
		}
	}
	return 0, false
}

// DstRegOfInst returns the destination register of common instructions,
// or -1 if not detected. Used to know which register an instruction defines.
func DstRegOfInst(raw uint32) int {
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
	// LDUR W32
	if raw&0xFFE00C00 == 0xB8400000 {
		return int(raw & 0x1F)
	}
	// ADD Xd, Xn, #imm
	if raw&0xFF000000 == 0x91000000 {
		return int(raw & 0x1F)
	}
	// SUB Xd, Xn, #imm
	if raw&0xFF000000 == 0xD1000000 {
		return int(raw & 0x1F)
	}
	// MOVZ Xd, #imm
	if raw&0xFFE00000 == 0xD2800000 {
		return int(raw & 0x1F)
	}
	// UBFX
	if raw&0xFF800000 == 0xD3000000 {
		return int(raw & 0x1F)
	}
	// ADD Xd, Xn, Xm
	if raw&0xFF200000 == 0x8B000000 {
		return int(raw & 0x1F)
	}
	// ORR (MOV alias)
	if raw&0xFF20001F == 0xAA000000 {
		if (raw>>5)&0x1F == 31 {
			return int(raw & 0x1F)
		}
	}
	return -1
}
