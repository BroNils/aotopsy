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

import (
	"encoding/binary"

	"golang.org/x/arch/arm64/arm64asm"
)

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
	return PCRelativeTarget(pc, int64(imm26)*4)
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
	return PCRelativeTarget(pc, int64(imm26)*4)
}

// PCRelativeTarget adds a signed ARM64 PC-relative byte displacement without
// allowing malformed virtual addresses to wrap around the uint64 address
// space. ELF input controls the section VA, so converting pc to int64 first is
// not safe: a valid-looking high VA can otherwise wrap to a small address and
// accidentally match a real symbol/CFG node.
func PCRelativeTarget(pc uint64, offset int64) (uint64, bool) {
	if offset >= 0 {
		u := uint64(offset)
		if pc > ^uint64(0)-u {
			return 0, false
		}
		return pc + u, true
	}
	// Avoid negating MinInt64 directly.
	mag := uint64(-(offset + 1)) + 1
	if mag > pc {
		return 0, false
	}
	return pc - mag, true
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
// Note: historical Dart B.AL (cond=14) is unconditional despite using the
// B.cond encoding, so it returns ok=false here. B.NV (cond=15) is reserved for
// branches in the Dart-supported ISA/codegen contract and also returns false.

// BCondKind classifies the condition field of a B.cond encoding. ARM's
// architectural condition code 0b1111 (NV) is not a valid branch condition;
// Dart only used it internally as a far-branch sentinel and rewrote that guard
// to NOP before publishing code. AL (0b1110), on the other hand, was emitted as
// B.cond by Dart through 2.14 and is an unconditional branch.
type BCondKind uint8

const (
	BCondConditional BCondKind = iota
	BCondAlways
	BCondReserved
)

// BCondClass classifies a B.cond word without doing address arithmetic. This
// is useful to preserve terminator semantics even when a malicious section VA
// makes the encoded PC-relative target overflow.
func BCondClass(raw uint32) (cond uint8, kind BCondKind, ok bool) {
	if raw&0xFF000010 != 0x54000000 {
		return 0, 0, false
	}
	cond = uint8(raw & 0xF)
	switch cond {
	case 14:
		return cond, BCondAlways, true
	case 15:
		return cond, BCondReserved, true
	default:
		return cond, BCondConditional, true
	}
}

// BCond decodes the B.cond instruction family and returns its target,
// condition code, and semantic class. ok reports that raw has the B.cond
// encoding and that any required target arithmetic did not wrap. For the
// reserved NV encoding the target is deliberately zero: consumers must treat
// it as malformed control flow, not as a jump or fallthrough.
func BCond(raw uint32, pc uint64) (target uint64, cond uint8, kind BCondKind, ok bool) {
	cond, kind, encoded := BCondClass(raw)
	if !encoded {
		return 0, 0, 0, false
	}
	if kind == BCondReserved {
		return 0, cond, BCondReserved, true
	}
	imm19 := (raw >> 5) & 0x7FFFF
	offset := signExtend(imm19, 19) * 4
	target, ok = PCRelativeTarget(pc, int64(offset))
	if !ok {
		return 0, cond, 0, false
	}
	return target, cond, kind, true
}

// IsReservedBCond reports the architecturally invalid B.cond NV encoding.
func IsReservedBCond(raw uint32) bool {
	return raw&0xFF00001F == 0x5400000F
}

func CondBranch(raw uint32, pc uint64) (target uint64, ok bool) {
	if target, _, kind, bok := BCond(raw, pc); bok {
		if kind == BCondConditional {
			return target, true
		}
		return 0, false
	}
	// CBZ: 0 sf 110100 imm19 Rt
	if raw&0x7F000000 == 0x34000000 {
		imm19 := (raw >> 5) & 0x7FFFF
		offset := signExtend(imm19, 19) * 4
		return PCRelativeTarget(pc, int64(offset))
	}
	// CBNZ: 0 sf 110101 imm19 Rt
	if raw&0x7F000000 == 0x35000000 {
		imm19 := (raw >> 5) & 0x7FFFF
		offset := signExtend(imm19, 19) * 4
		return PCRelativeTarget(pc, int64(offset))
	}
	// TBZ: 0 b5 110110 b40 imm14 Rt
	if raw&0x7F000000 == 0x36000000 {
		imm14 := (raw >> 5) & 0x3FFF
		offset := signExtend(imm14, 14) * 4
		return PCRelativeTarget(pc, int64(offset))
	}
	// TBNZ: 0 b5 110111 b40 imm14 Rt
	if raw&0x7F000000 == 0x37000000 {
		imm14 := (raw >> 5) & 0x3FFF
		offset := signExtend(imm14, 14) * 4
		return PCRelativeTarget(pc, int64(offset))
	}
	return 0, false
}

// signExtend sign-extends a value from the given fixed-width instruction field.
// It is intentionally private: callers should use a decoder that knows the
// field width rather than supplying an unchecked width themselves.
func signExtend(val uint32, bits int) int32 {
	sign := uint32(1) << (bits - 1)
	mask := sign - 1
	if val&sign != 0 {
		return int32(val | ^mask)
	}
	return int32(val & mask)
}

// AddressMode describes the addressing semantics of a 64-bit GPR load/store.
// Offset and Unprivileged do not update the base; PreIndex updates it before
// the access; PostIndex updates it after the access.
type AddressMode uint8

const (
	AddressOffset AddressMode = iota
	AddressPostIndex
	AddressUnprivileged
	AddressPreIndex
)

// Mem64 is a decoded 64-bit GPR single-register immediate load/store.
type Mem64 struct {
	BaseReg    int
	Reg        int
	ByteOffset int
	Mode       AddressMode
}

// Load64Immediate decodes 64-bit GPR immediate loads (LDR/LDUR/LDTR),
// including pre/post-index addressing.
func Load64Immediate(raw uint32) (Mem64, bool) {
	if raw&0xFFC00000 == 0xF9400000 { // unsigned scaled offset
		return Mem64{
			BaseReg:    int((raw >> 5) & 0x1F),
			Reg:        int(raw & 0x1F),
			ByteOffset: int((raw>>10)&0xFFF) << 3,
			Mode:       AddressOffset,
		}, true
	}
	if raw&0xFFE00000 != 0xF8400000 {
		return Mem64{}, false
	}
	imm9 := int(signExtend((raw>>12)&0x1FF, 9))
	return Mem64{
		BaseReg:    int((raw >> 5) & 0x1F),
		Reg:        int(raw & 0x1F),
		ByteOffset: imm9,
		Mode:       AddressMode((raw >> 10) & 0x3),
	}, true
}

// Store64Immediate decodes 64-bit GPR immediate stores (STR/STUR/STTR),
// including pre/post-index addressing.
func Store64Immediate(raw uint32) (Mem64, bool) {
	if raw&0xFFC00000 == 0xF9000000 { // unsigned scaled offset
		return Mem64{
			BaseReg:    int((raw >> 5) & 0x1F),
			Reg:        int(raw & 0x1F),
			ByteOffset: int((raw>>10)&0xFFF) << 3,
			Mode:       AddressOffset,
		}, true
	}
	if raw&0xFFE00000 != 0xF8000000 {
		return Mem64{}, false
	}
	imm9 := int(signExtend((raw>>12)&0x1FF, 9))
	return Mem64{
		BaseReg:    int((raw >> 5) & 0x1F),
		Reg:        int(raw & 0x1F),
		ByteOffset: imm9,
		Mode:       AddressMode((raw >> 10) & 0x3),
	}, true
}

// PairMode describes the four A64 pair-addressing encodings.
type PairMode uint8

const (
	PairNonTemporal PairMode = iota
	PairPostIndex
	PairOffset
	PairPreIndex
)

// Pair64 is a decoded 64-bit GPR pair load/store.
type Pair64 struct {
	BaseReg    int
	Reg1       int
	Reg2       int
	ByteOffset int
	Mode       PairMode
}

func decodePair64(raw uint32, load bool) (Pair64, bool) {
	top := raw & 0xFFC00000
	var mode PairMode
	if load {
		switch top {
		case 0xA8400000:
			mode = PairNonTemporal
		case 0xA8C00000:
			mode = PairPostIndex
		case 0xA9400000:
			mode = PairOffset
		case 0xA9C00000:
			mode = PairPreIndex
		default:
			return Pair64{}, false
		}
	} else {
		switch top {
		case 0xA8000000:
			mode = PairNonTemporal
		case 0xA8800000:
			mode = PairPostIndex
		case 0xA9000000:
			mode = PairOffset
		case 0xA9800000:
			mode = PairPreIndex
		default:
			return Pair64{}, false
		}
	}
	return Pair64{
		BaseReg:    int((raw >> 5) & 0x1F),
		Reg1:       int(raw & 0x1F),
		Reg2:       int((raw >> 10) & 0x1F),
		ByteOffset: int(signExtend((raw>>15)&0x7F, 7)) << 3,
		Mode:       mode,
	}, true
}

// LoadPair64 decodes every 64-bit GPR pair-load addressing mode, including
// ordinary LDP and non-temporal LDNP.
func LoadPair64(raw uint32) (Pair64, bool) { return decodePair64(raw, true) }

// StorePair64 decodes every 64-bit GPR pair-store addressing mode, including
// ordinary STP and non-temporal STNP.
func StorePair64(raw uint32) (Pair64, bool) { return decodePair64(raw, false) }

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
	// Bit 23 is fixed 0 for the ordinary add/sub-immediate class. Matching
	// only the top byte also admits the ARMv8.5-MTE ADDG/SUBG space (and the
	// reserved encodings beside it), which is not the same instruction even
	// though the register/immediate fields overlap.
	if raw&0xFF800000 != opcode {
		return 0, 0, 0, false
	}
	rd = int(raw & 0x1F)
	rn = int((raw >> 5) & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	switch (raw >> 22) & 0x1 {
	case 0:
		immValue = imm12
	case 1:
		immValue = imm12 << 12
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

// ShiftKind is the shift applied to the second register operand of a shifted
// register instruction. Keeping it in the decode result is correctness-critical:
// ADD Xd,Xn,Xm,LSR #7 is not interchangeable with ADD Xd,Xn,Xm, and Dart's
// compressed-pointer decompression specifically uses LSL #32.
type ShiftKind uint8

const (
	ShiftLSL ShiftKind = iota
	ShiftLSR
	ShiftASR
)

// ADD64Register detects ADD Xd, Xn, Xm, <shift> #amount (64-bit).
// Returns dest, sources, shift kind, and shift amount. The reserved shift
// encoding is rejected rather than normalized into a valid operation.
// Encoding: sf=1 | 00 | 01011 | shift | 0 | Rm | imm6 | Rn | Rd
// Mask: 0xFF200000, Value: 0x8B000000
func ADD64Register(raw uint32) (rd, rn, rm int, shift ShiftKind, amount int, ok bool) {
	if raw&0xFF200000 != 0x8B000000 {
		return 0, 0, 0, 0, 0, false
	}
	shiftBits := (raw >> 22) & 0x3
	if shiftBits == 0x3 {
		return 0, 0, 0, 0, 0, false
	}
	rd = int(raw & 0x1F)
	rn = int((raw >> 5) & 0x1F)
	rm = int((raw >> 16) & 0x1F)
	shift = ShiftKind(shiftBits)
	amount = int((raw >> 10) & 0x3F)
	return rd, rn, rm, shift, amount, true
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
// Mask: 0xFFC00000, Value: 0xD3400000. N must be 1 for the 64-bit form;
// accepting N=0 admits reserved/malformed encodings that the architecture
// decoder rejects.
func UBFX(raw uint32) (rd, rn int, lsb, width int, ok bool) {
	if raw&0xFFC00000 != 0xD3400000 {
		return 0, 0, 0, 0, false
	}
	rd = int(raw & 0x1F)
	rn = int((raw >> 5) & 0x1F)
	immr := int((raw >> 16) & 0x3F)
	imms := int((raw >> 10) & 0x3F)
	// UBFM with imms < immr is the wrapping form used by aliases such as
	// LSL. It is not a contiguous UBFX-style extraction and the old width
	// formula even became negative for valid LSL encodings.
	if imms < immr {
		return 0, 0, 0, 0, false
	}
	lsb = immr
	width = imms - immr + 1
	return rd, rn, lsb, width, true
}

// MOVOrr detects MOV (alias of ORR Xd, XZR, Xm).
// Returns destination register.
// Encoding: sf=1 | 01 | 01010 | 00 | 0 | Rm | 000000 | Rn=31 | Rd
// Mask: 0xFF200000, Value: 0xAA000000
func MOVOrr(raw uint32) (rd int, ok bool) {
	// MOV Xd, Xm is exactly ORR Xd, XZR, Xm, LSL #0. The shift kind and
	// imm6 are part of the alias contract: accepting ORR ... LSL/LSR #N as
	// a move copies provenance/types across a value-transforming instruction.
	if raw&0xFFE0FFE0 == 0xAA0003E0 {
		return int(raw & 0x1F), true
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

// DstRegsOfInst returns all tracked general-purpose destination registers
// defined by the instruction (X0-X30), or an empty slice if no tracked GPR is
// written. Architectural register encoding 31 is deliberately omitted in all
// classes: it denotes either ZR (discarded result) or the hardware SP depending
// on the instruction family, and AOTopsy's register state models neither one.
// Dart's managed stack pointer is X15 and is therefore represented normally.
// For pair loads (LDP), returns both registers []int{rt1, rt2}.
func DstRegsOfInst(raw uint32) []int {
	// Fail closed on architecturally impossible encodings. The family masks
	// below intentionally cover broad writer classes for speed/readability, but
	// many A64 major groups contain reserved holes. Without this validity gate a
	// malformed word can look like a register definition and poison every
	// downstream provenance/type consumer. x/arch accepts every instruction in
	// the supported Dart corpus, so it is a suitable ISA validity oracle here.
	var word [4]byte
	binary.LittleEndian.PutUint32(word[:], raw)
	if _, err := arm64asm.Decode(word[:]); err != nil && !isKnownValidWriterOutsideXArch(raw) {
		return nil
	}

	// Branch-with-link writes LR. Most call-aware consumers handle these before
	// the generic write-set path, but the architectural effect belongs here so a
	// new consumer cannot accidentally retain stale X30 provenance.
	if raw&0xFC000000 == 0x94000000 || raw&0xFFFFFC1F == 0xD63F0000 {
		return []int{30}
	}

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
		// Pair post-index (01) and pre-index (11) update Rn as well.
		mode := (raw >> 23) & 0x3
		if mode == 1 || mode == 3 {
			rn := int((raw >> 5) & 0x1F)
			if rn < 31 && rn != rt1 && rn != rt2 {
				res = append(res, rn)
			}
		}
		return res
	}
	// Store Pair (STP) post/pre-index writes only its base register from the
	// GPR point of view; the stored Rt/Rt2 values are reads.
	if raw&0x3E400000 == 0x28000000 {
		mode := (raw >> 23) & 0x3
		if mode == 1 || mode == 3 {
			rn := int((raw >> 5) & 0x1F)
			if rn < 31 {
				return []int{rn}
			}
		}
		return nil
	}

	// ── 2. Single-register loads ──
	// GPR literal loads only. The broader load-literal class also contains
	// PRFM and FP/SIMD LDR literals; treating their Rt field as a GPR write
	// destroys unrelated integer provenance.
	switch raw & 0xFF000000 {
	case 0x18000000, // LDR Wt, label
		0x58000000, // LDR Xt, label
		0x98000000: // LDRSW Xt, label
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
		var res []int
		if rd < 31 {
			res = append(res, rd)
		}
		mode := (raw >> 10) & 0x3
		if mode == 1 || mode == 3 {
			rn := int((raw >> 5) & 0x1F)
			if rn < 31 && rn != rd {
				res = append(res, rn)
			}
		}
		return res
	}
	// Store register, unscaled/post-index/pre-index/unprivileged. Stores do
	// not define Rt, but post/pre-index addressing does define Rn.
	if (raw&0xFFE00000 == 0xF8000000) || // STUR/STR (post/pre) Xt
		(raw&0xFFE00000 == 0xB8000000) || // ... Wt
		(raw&0xFFE00000 == 0x78000000) || // STURH Wt
		(raw&0xFFE00000 == 0x38000000) { // STURB Wt
		mode := (raw >> 10) & 0x3
		if mode == 1 || mode == 3 {
			rn := int((raw >> 5) & 0x1F)
			if rn < 31 {
				return []int{rn}
			}
		}
		return nil
	}
	// LDR register extended (scaled / unscaled): ordinary zero-extending loads.
	if raw&0x3FE00800 == 0x38600800 {
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}
	// Sign-extending register-offset loads (LDRSB/LDRSH/LDRSW). The SDK emits
	// these in real AOT code and they overwrite a GPR just like ordinary LDR.
	// Bit 22 selects X-result (0x38a...) vs W-result (0x38e...).
	if raw&0x3FE00800 == 0x38A00800 || raw&0x3FE00800 == 0x38E00800 {
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}

	// ── 2b. Exclusive loads/stores ──
	// LDAR[B/H]/LDAR W/X acquire loads are in the load/store-exclusive major
	// group but are not LDXR/LDAXR encodings. They still overwrite Rt. This
	// mask intentionally ignores size while pinning the LDAR opcode fields.
	if raw&0x3FFFFC00 == 0x08DFFC00 {
		rt := int(raw & 0x1F)
		if rt < 31 {
			return []int{rt}
		}
		return nil
	}
	// Masks/values are the ARM encodings used by x/arch v0.23.0. LDXR/LDAXR
	// define Rt; LDXP/LDAXP define both result registers. STXR/STLXR and the
	// pair forms define the Ws status register (success=0/failure=1).
	if raw&0xFFE08000 == 0x88400000 || raw&0xFFE08000 == 0xC8400000 ||
		raw&0xFFE08000 == 0x88408000 || raw&0xFFE08000 == 0xC8408000 {
		rt := int(raw & 0x1F)
		if rt < 31 {
			return []int{rt}
		}
		return nil
	}
	if raw&0xFFE08000 == 0x88600000 || raw&0xFFE08000 == 0xC8600000 ||
		raw&0xFFE08000 == 0x88608000 || raw&0xFFE08000 == 0xC8608000 {
		rt1 := int(raw & 0x1F)
		rt2 := int((raw >> 10) & 0x1F)
		res := make([]int, 0, 2)
		if rt1 < 31 {
			res = append(res, rt1)
		}
		if rt2 < 31 && rt2 != rt1 {
			res = append(res, rt2)
		}
		return res
	}
	if raw&0xFFE08000 == 0x88000000 || raw&0xFFE08000 == 0xC8000000 ||
		raw&0xFFE08000 == 0x88008000 || raw&0xFFE08000 == 0xC8008000 ||
		raw&0xFFE08000 == 0x88200000 || raw&0xFFE08000 == 0xC8200000 ||
		raw&0xFFE08000 == 0x88208000 || raw&0xFFE08000 == 0xC8208000 {
		rs := int((raw >> 16) & 0x1F)
		if rs < 31 {
			return []int{rs}
		}
		return nil
	}

	// FMOV from an FP/SIMD register into a GPR. Dart emits this for negative
	// zero checks and double hashing; missing it leaves a stale integer fact in
	// the destination register. Cover both W<-S and X<-D / X<-V.D[1].
	if raw&0xFFFFFC00 == 0x1E260000 || raw&0xFFFFFC00 == 0x9E660000 ||
		raw&0xFFFFFC00 == 0x9EAE0000 {
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}
	// UMOV (Dart disassembler spells these VMOVW/VMOVX): move one SIMD lane
	// into a W/X GPR. Do not broaden this to the whole SIMD-copy class because
	// most neighboring encodings write vector registers, not GPRs.
	if raw&0xFFE0FC00 == 0x0E003C00 || raw&0xFFE0FC00 == 0x4E003C00 {
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}
	// Scalar FP -> signed-integer conversions used by Dart codegen. These exact
	// masks exclude the vector-result FCVT forms next to them in the encoding
	// space. FCVTZS also has a fixed-point form with an immediate fractional-bit
	// count; it still writes the same GPR destination.
	switch raw & 0xFFFFFC00 {
	case 0x1E300000, 0x9E300000, 0x1E700000, 0x9E700000, // FCVTMS W/X <- S/D
		0x1E280000, 0x9E280000, 0x1E680000, 0x9E680000, // FCVTPS W/X <- S/D
		0x1E380000, 0x9E380000, 0x1E780000, 0x9E780000: // FCVTZS W/X <- S/D
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}
	switch raw & 0xFFFF0000 {
	case 0x1E180000, 0x9E180000, 0x1E580000, 0x9E580000: // FCVTZS W/X <- S/D, #fbits
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}
	// Add/subtract with carry. ADC/ADCS/SBC/SBCS all define Rd; sf (bit 31)
	// only changes the width, so one mask covers W and X forms.
	switch raw & 0x7FE0FC00 {
	case 0x1A000000, 0x3A000000, 0x5A000000, 0x7A000000:
		rd := int(raw & 0x1F)
		if rd < 31 {
			return []int{rd}
		}
		return nil
	}
	// LSE LDCLR/LDSET atomics return the old memory value in Rt. AtomicMemoryMask
	// itself deliberately ignores the operation bits; pin B12/B13 as well so we
	// do not claim GPR writes for neighboring atomic operations without evidence.
	switch raw & 0x3F203C00 {
	case 0x38201000, 0x38203000:
		rt := int(raw & 0x1F)
		if rt < 31 {
			return []int{rt}
		}
		return nil
	}

	// ── 3. Data Processing - Immediate ──
	// ADD/SUB immediate: mask 0x1F000000 == 0x11000000
	if raw&0x1F000000 == 0x11000000 {
		// ADDS/SUBS have S=1 (bit 29). When Rd=31 the result goes to ZR --
		// CMN/CMP are aliases -- rather than updating SP. Checking only the
		// SUBS opcode here misses ADDS/CMN and falsely reports register 31 as a
		// destination.
		if raw&(1<<29) != 0 {
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
		return nil // architectural SP is outside the tracked X0-X30 state
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
		if raw&(1<<29) != 0 { // ADDS / SUBS (CMN / CMP when Rd=31)
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
		return nil // Rd=31 is ZR in the shifted-register class
	}
	// Add/Sub extended register: ADD, SUB, ADDS, SUBS extended (mask 0x1FE00000 == 0x0B200000)
	if raw&0x1FE00000 == 0x0B200000 {
		if raw&(1<<29) != 0 { // ADDS / SUBS extended (CMN / CMP when Rd=31)
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
		return nil // architectural SP is outside the tracked X0-X30 state
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

// x/arch/arm64asm intentionally lags some optional ISA extensions. Keep its
// decoder as the malformed-word gate, but explicitly admit the extension
// writer shapes AOTopsy supports and tests against ISA/codegen evidence.
func isKnownValidWriterOutsideXArch(raw uint32) bool {
	// LSE LDCLR/LDSET atomics: Rt receives the old memory value.
	switch raw & 0x3F203C00 {
	case 0x38201000, 0x38203000:
		return true
	}
	return false
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
