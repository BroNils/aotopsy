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

// IsRet reports whether raw is a RET instruction (0xD65F03C0 / 0xD65F0000|Rn<<5).
func IsRet(raw uint32) bool {
	return raw&0xFFFFFC1F == 0xD65F0000
}

// IsBR decodes BR Xn (indirect branch). Returns register number.
// Mask: 0xFFFFFC1F, Value: 0xD61F0000
func IsBR(raw uint32) (rn int, ok bool) {
	if raw&0xFFFFFC1F != 0xD61F0000 {
		return 0, false
	}
	return int((raw >> 5) & 0x1F), true
}

// CondBranch detects ARM64 conditional branches (B.cond, CBZ, CBNZ, TBZ, TBNZ).
// Returns the branch target address (excluding fall-through) and true, or ok=false
// if not a conditional branch.
// Note: B.AL (cond=14) and B.NV (cond=15) are unconditional despite using the
// B.cond encoding, so they return ok=false.
func CondBranch(raw uint32, pc uint64) (target uint64, ok bool) {
	// B.cond: 01010100 imm19 0 cond
	if raw&0xFF000010 == 0x54000000 {
		cond := raw & 0xF
		if cond == 14 || cond == 15 {
			return 0, false // unconditional AL/NV
		}
		imm19 := (raw >> 5) & 0x7FFFF
		offset := SignExtend(imm19, 19) * 4
		return uint64(int64(pc) + int64(offset)), true
	}
	// CBZ: 0 sf 110100 imm19 Rt
	if raw&0x7F000000 == 0x34000000 {
		imm19 := (raw >> 5) & 0x7FFFF
		offset := SignExtend(imm19, 19) * 4
		return uint64(int64(pc) + int64(offset)), true
	}
	// CBNZ: 0 sf 110101 imm19 Rt
	if raw&0x7F000000 == 0x35000000 {
		imm19 := (raw >> 5) & 0x7FFFF
		offset := SignExtend(imm19, 19) * 4
		return uint64(int64(pc) + int64(offset)), true
	}
	// TBZ: 0 b5 110110 b40 imm14 Rt
	if raw&0x7F000000 == 0x36000000 {
		imm14 := (raw >> 5) & 0x3FFF
		offset := SignExtend(imm14, 14) * 4
		return uint64(int64(pc) + int64(offset)), true
	}
	// TBNZ: 0 b5 110111 b40 imm14 Rt
	if raw&0x7F000000 == 0x37000000 {
		imm14 := (raw >> 5) & 0x3FFF
		offset := SignExtend(imm14, 14) * 4
		return uint64(int64(pc) + int64(offset)), true
	}
	return 0, false
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
	return addSubImmediate(raw, 0x91000000)
}

// addSubImmediate decodes the shared add/subtract-immediate encoding.
//
// ADD64/SUB64/SUBS32 differ ONLY in the sf|op|S bits of the opcode, i.e.
// in the value the top byte is compared against; the register and imm12
// extraction and the shift handling are identical. They were written out
// three times, so seeing that was a matter of diffing three 16-line
// functions -- and a correction to the shift decoding would have had to
// land in all three.
func addSubImmediate(raw, opcode uint32) (rd, rn int, immValue int, ok bool) {
	if raw&0xFF000000 != opcode {
		return 0, 0, 0, false
	}
	rd = int(raw & 0x1F)
	rn = int((raw >> 5) & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	switch (raw >> 22) & 0x3 {
	case 0:
		immValue = imm12
	case 1:
		immValue = imm12 << 12
	default:
		immValue = 0 // reserved shift encoding
	}
	return rd, rn, immValue, true
}

// SUB64Immediate detects SUB Xd, Xn, #imm (64-bit).
// Returns dest, source, and immediate value (with shift applied).
// Encoding: sf=1 | op=1 | S=0 | 100010 | sh | imm12 | Rn | Rd
// Mask: 0xFF000000, Value: 0xD1000000
func SUB64Immediate(raw uint32) (rd, rn int, immValue int, ok bool) {
	return addSubImmediate(raw, 0xD1000000)
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
	return addSubImmediate(raw, 0x71000000)
}

// A 64-bit SUBS/CMP decoder is deliberately absent.
//
// It was written and wired into typetrack's class-id narrowing, then
// removed on the measurement: narrow_hits went 5872 -> 68313 on
// dart-3.9.2-arm64 while resolved_blr moved by 0, and dart-2.12.0-arm64
// lost a monomorphic call. Class ids are extracted into W registers, so a
// CMP on an X register is comparing a tagged value or a Smi, and treating
// the immediate as a class id is wrong 62000 times over.
//
// If a caller ever needs 64-bit comparisons for something other than
// class-id narrowing -- a range lattice, say -- add the decoder together
// with that caller and its own measurement.

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
	if raw&0xFF200000 == 0xAA000000 {
		// Check Rn=31 (XZR)
		if (raw>>5)&0x1F == 31 {
			return int(raw & 0x1F), true
		}
	}
	return 0, false
}

// LDP64UnsignedOffset detects LDP Xt1, Xt2, [Xn, #imm] (64-bit pair load).
// Returns base register, destination registers, and byte offset.
// Encoding: opc=10 | 101 | V=0 | 010 | L=1 | imm7 | Rt2 | Rn | Rt1
// Mask: 0xFFC00000, Value: 0xA9400000
func LDP64UnsignedOffset(raw uint32) (baseReg, rt1, rt2 int, byteOffset int, ok bool) {
	if raw&0xFFC00000 != 0xA9400000 {
		return 0, 0, 0, 0, false
	}
	rt1 = int(raw & 0x1F)
	baseReg = int((raw >> 5) & 0x1F)
	rt2 = int((raw >> 10) & 0x1F)
	imm7 := int((raw >> 15) & 0x7F)
	if imm7&(1<<6) != 0 {
		imm7 |= ^0x7F
	}
	return baseReg, rt1, rt2, imm7 << 3, true
}

// STP64UnsignedOffset detects STP Xt1, Xt2, [Xn, #imm] (64-bit pair store).
// Returns base register, source registers, and byte offset.
// Encoding: opc=10 | 101 | V=0 | 010 | L=0 | imm7 | Rt2 | Rn | Rt1
// Mask: 0xFFC00000, Value: 0xA9000000
func STP64UnsignedOffset(raw uint32) (baseReg, rt1, rt2 int, byteOffset int, ok bool) {
	if raw&0xFFC00000 != 0xA9000000 {
		return 0, 0, 0, 0, false
	}
	rt1 = int(raw & 0x1F)
	baseReg = int((raw >> 5) & 0x1F)
	rt2 = int((raw >> 10) & 0x1F)
	imm7 := int((raw >> 15) & 0x7F)
	if imm7&(1<<6) != 0 {
		imm7 |= ^0x7F
	}
	return baseReg, rt1, rt2, imm7 << 3, true
}

// DstRegsOfInst returns all general-purpose destination registers defined by
// the instruction (0-30), or an empty slice if no GPR is written (or if CMP/TST).
// For pair loads (LDP), returns both registers []int{rt1, rt2}.
func DstRegsOfInst(raw uint32) []int {
	// ── 1. Load Pair (LDP) ──
	// Bits: [31:30]=opc, [29:27]=101, [26]=V(0 for GPR), [22]=L(1 for Load)
	// Mask 0x3E400000 == 0x28400000 covers 32-bit, 64-bit, and LDPSW.
	if raw&0x3E400000 == 0x28400000 {
		rt1 := int(raw & 0x1F)
		rt2 := int((raw >> 10) & 0x1F)
		var res []int
		if rt1 < 31 {
			res = append(res, rt1)
		}
		if rt2 < 31 && rt2 != rt1 {
			res = append(res, rt2)
		}
		return res
	}

	// ── 2. Single-register loads ──
	// LDR literal (32/64 bit): mask 0x3B000000 == 0x18000000
	if raw&0x3B000000 == 0x18000000 {
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}
	// Load register, unsigned immediate offset. Encoding:
	//   [31:30]=size [29:27]=111 [26]=V [25:24]=01 [23:22]=opc [21:10]=imm12
	// opc selects load vs store and the extension, so the mask MUST cover
	// bits 23:22 (0xFFC00000). Masks that left bit 22 out matched the STORE
	// with the same size and reported its source register as a destination --
	// see the comment on the unscaled group below.
	if (raw&0xFFC00000 == 0xF9400000) || // LDR   Xt
		(raw&0xFFC00000 == 0xB9400000) || // LDR   Wt
		(raw&0xFFC00000 == 0xB9800000) || // LDRSW Xt
		(raw&0xFFC00000 == 0x79400000) || // LDRH  Wt
		(raw&0xFFC00000 == 0x79800000) || // LDRSH Xt
		(raw&0xFFC00000 == 0x79C00000) || // LDRSH Wt
		(raw&0xFFC00000 == 0x39400000) || // LDRB  Wt
		(raw&0xFFC00000 == 0x39800000) || // LDRSB Xt
		(raw&0xFFC00000 == 0x39C00000) { // LDRSB Wt
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}
	// Load register, unscaled/post-index/pre-index/unprivileged. Encoding:
	//   [31:30]=size [29:27]=111 [26]=V [25:24]=00 [23:22]=opc [21]=0
	//   [20:12]=imm9 [11:10]=mode
	// Mask bits 31:21 (0xFFE00000): that pins opc, so only loads match, and
	// bit 21 = 0 excludes the register-offset form handled below.
	//
	// Two bugs lived here. The masks omitted bits 23:22, so STUR Wt, STURB
	// and STURH all reported Rt as a destination -- every 8/16/32-bit store
	// killed a live register's tracked type, which is why intra-procedural
	// type inference collapsed on ARM64 (blr_at_top +4967, add_class_hits
	// -36632 on dart-2.12.0) once transferInstruction started using this
	// function to invalidate registers. And bits 11:10 were pinned to 00, so
	// only LDUR matched: post-index (01) and pre-index (11) were missed
	// entirely, which hid every `ldr x19,[sp],#8` epilogue restore. All four
	// modes write Rt.
	if (raw&0xFFE00000 == 0xF8400000) || // LDUR/LDR (post/pre) Xt
		(raw&0xFFE00000 == 0xB8400000) || // ... Wt
		(raw&0xFFE00000 == 0xB8800000) || // LDURSW Xt
		(raw&0xFFE00000 == 0x78400000) || // LDURH  Wt
		(raw&0xFFE00000 == 0x78800000) || // LDURSH Xt
		(raw&0xFFE00000 == 0x78C00000) || // LDURSH Wt
		(raw&0xFFE00000 == 0x38400000) || // LDURB  Wt
		(raw&0xFFE00000 == 0x38800000) || // LDURSB Xt
		(raw&0xFFE00000 == 0x38C00000) { // LDURSB Wt
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}
	// LDR register extended (scaled / unscaled): mask 0x3FE00800 == 0x38600800
	if raw&0x3FE00800 == 0x38600800 {
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}

	// ── 3. Data Processing - Immediate ──
	// ADD/SUB immediate: mask 0x1F000000 == 0x11000000
	if raw&0x1F000000 == 0x11000000 {
		// ADDS/SUBS (S=1, bits 30:29 == 11 -> 0x71000000 / 0xF1000000)
		if raw&0x7F000000 == 0x71000000 {
			rd := int(raw & 0x1F)
			if rd == 31 { // CMP / CMN: discards result into XZR
				return nil
			}
			return []int{rd}
		}
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return []int{31} // SP write (ADD/SUB SP, SP, #imm)
	}
	// MOVZ / MOVK / MOVN: mask 0x1F800000 == 0x12800000
	if raw&0x1F800000 == 0x12800000 {
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}
	// Bitfield: UBFM/UBFX, SBFM/SBFX, BFM/BFI: mask 0x1F800000 == 0x13000000
	if raw&0x1F800000 == 0x13000000 {
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}
	// Logical immediate: AND, ORR, EOR, ANDS: mask 0x1F800000 == 0x12000000
	if raw&0x1F800000 == 0x12000000 {
		if raw&0x7F800000 == 0x72000000 { // ANDS (TST immediate)
			rd := int(raw & 0x1F)
			if rd == 31 {
				return nil
			}
			return []int{rd}
		}
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}
	// ADR / ADRP: mask 0x1F000000 == 0x10000000
	if raw&0x1F000000 == 0x10000000 {
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}

	// ── 4. Data Processing - Register ──
	// Logical shifted register: AND, BIC, ORR, ORN, EOR, EON, ANDS, BICS (mask 0x1F000000 == 0x0A000000)
	if raw&0x1F000000 == 0x0A000000 {
		if raw&0x7F000000 == 0x6A000000 { // ANDS / BICS (TST reg)
			rd := int(raw & 0x1F)
			if rd == 31 {
				return nil
			}
			return []int{rd}
		}
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}
	// Add/Sub shifted register: ADD, SUB, ADDS, SUBS (mask 0x1F200000 == 0x0B000000)
	if raw&0x1F200000 == 0x0B000000 {
		if raw&0x7F200000 == 0x6B000000 { // ADDS / SUBS (CMP reg)
			rd := int(raw & 0x1F)
			if rd == 31 {
				return nil
			}
			return []int{rd}
		}
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return []int{31}
	}
	// Add/Sub extended register: ADD, SUB, ADDS, SUBS extended (mask 0x1FE00000 == 0x0B200000)
	if raw&0x1FE00000 == 0x0B200000 {
		if raw&0x7FE00000 == 0x6B200000 { // ADDS / SUBS extended
			rd := int(raw & 0x1F)
			if rd == 31 {
				return nil
			}
			return []int{rd}
		}
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return []int{31}
	}
	// Conditional Select: CSEL, CSINC, CSINV, CSNEG, CSET (mask 0x1FE00000 == 0x1A800000)
	if raw&0x1FE00000 == 0x1A800000 {
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}
	// Data-processing 2-source: SDIV, UDIV, LSLV, LSRV, ASRV, RORV (mask 0x5FE00000 == 0x1AC00000)
	if raw&0x5FE00000 == 0x1AC00000 {
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}
	// Data-processing 1-source: RBIT, REV16, REV, REV32, CLZ, CLS (mask 0x5FE00000 == 0x5AC00000)
	if raw&0x5FE00000 == 0x5AC00000 {
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}
	// Data-processing 3-source: MADD, MSUB, SMADDL, SMSUBL, SMULH, UMADDL, UMSUBL, UMULH (mask 0x1F000000 == 0x1B000000)
	if raw&0x1F000000 == 0x1B000000 {
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}

	return nil
}

// DstRegOfInst returns the first destination register of an instruction,
// or -1 if no register is defined.
func DstRegOfInst(raw uint32) int {
	regs := DstRegsOfInst(raw)
	if len(regs) == 0 {
		return -1
	}
	return regs[0]
}
