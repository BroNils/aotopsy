package disasm

import "strconv"

const regDT = 21 // X21 = dispatch table register

// CallEdge represents a call site extracted from disassembly.
type CallEdge struct {
	FromPC     uint64 `json:"from_pc"`
	Kind       string `json:"kind"`                // "bl" or "blr"
	TargetPC   uint64 `json:"target_pc,omitempty"` // resolved VA for bl
	TargetName string `json:"target_name,omitempty"`
	Reg        string `json:"reg,omitempty"` // register for blr (e.g. "X16")
	Via        string `json:"via,omitempty"` // provenance: "THR.AllocateArray_ep", "PP[36] foo", ""

	// ArgCountHint is a per-call-site guess at the callee's real argument
	// count, for "bl" edges only (0 for "blr" -- not computed there). It is
	// the count of X0-X7 argument registers freshly defined in the
	// immediate lead-up to this call (see inferCallArgCountLocal) -- NOT
	// ground truth, just one call site's local evidence. Aggregate across
	// every edge targeting the same callee (majority/consistency across
	// independent call sites) before trusting this for anything -- a
	// single call site's hint is not reliable on its own (see
	// ARCHITECTURE.md's "arity reconstruction" section for why the
	// declaration-metadata approach was abandoned in favor of this).
	ArgCountHint int `json:"arg_count_hint,omitempty"`

	// ArgRegMask is ArgCountHint's underlying bitmask (bit i = Xi touched),
	// "bl" edges only. Prefer this over ArgCountHint when aggregating --
	// two call sites can agree on a COUNT while disagreeing on WHICH
	// registers hold the real arguments (e.g. count=1 via X0 alone vs.
	// count=1 via X1 alone are different, contradictory calling shapes,
	// but look identical if you only compare counts).
	ArgRegMask uint8 `json:"-"`
}

// isBL detects ARM64 BL (branch with link) instructions.
// Encoding: 1 | 00101 | imm26
// Mask: 0xFC000000, Value: 0x94000000
// Returns the target address (sign-extended imm26 * 4 + PC).
func isBL(raw uint32, pc uint64) (target uint64, ok bool) {
	if raw&0xFC000000 != 0x94000000 {
		return 0, false
	}
	imm26 := int32(raw & 0x03FFFFFF)
	// Sign extend from 26 bits.
	if imm26&(1<<25) != 0 {
		imm26 |= ^int32(0x03FFFFFF)
	}
	target = uint64(int64(pc) + int64(imm26)*4)
	return target, true
}

// isBLR detects ARM64 BLR (branch with link to register) instructions.
// Encoding: 1101011 | 0 | 0 | 01 | 11111 | 0000 | 0 | 0 | Rn | 00000
// Mask: 0xFFFFFC1F, Value: 0xD63F0000
// Returns the register number.
func isBLR(raw uint32) (rn int, ok bool) {
	if raw&0xFFFFFC1F != 0xD63F0000 {
		return 0, false
	}
	rn = int((raw >> 5) & 0x1F)
	return rn, true
}

// dstRegOfInst returns the destination register of a data-processing or load
// instruction, or -1 if not detected. Used by the register tracker to know
// which register an annotated instruction defines.
func dstRegOfInst(raw uint32) int {
	// LDR X64 unsigned offset
	if raw&0xFFC00000 == 0xF9400000 {
		return int(raw & 0x1F)
	}
	// LDR W32 unsigned offset
	if raw&0xFFC00000 == 0xB9400000 {
		return int(raw & 0x1F)
	}
	// LDUR X64 (unscaled offset): size=11|111|V=0|00|opc=01|imm9|00|Rn|Rt
	// Mask: 0xFFE00C00, Value: 0xF8400000
	if raw&0xFFE00C00 == 0xF8400000 {
		return int(raw & 0x1F)
	}
	// LDUR W32 (unscaled offset): size=10|111|V=0|00|opc=01|imm9|00|Rn|Rt
	if raw&0xFFE00C00 == 0xB8400000 {
		return int(raw & 0x1F)
	}
	// LDR X64 register offset: size=11|111|V=0|01|opc=01|1|Rm|option|S|10|Rn|Rt
	// Mask: 0xFFE00C00, Value: 0xF8600800
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
	// MOV (alias of ORR Rd, XZR, Rm) - wide: MOVZ/MOVK/MOVN
	if raw&0xFF800000 == 0xD2800000 || // MOVZ X
		raw&0xFF800000 == 0xF2800000 || // MOVK X
		raw&0xFF800000 == 0x92800000 { // MOVN X
		return int(raw & 0x1F)
	}
	// UBFX/UBFM (bit field extract): sf=1|opc=10|100110|N=1|...
	if raw&0xFF800000 == 0xD3000000 {
		return int(raw & 0x1F)
	}
	return -1
}

// maxArgSetupBack bounds inferCallArgCountLocal's backward scan -- AOT-
// generated argument setup is a short, contiguous instruction span
// immediately before the call; anything further back belongs to earlier,
// unrelated code, not this call's own argument setup.
const maxArgSetupBack = 12

// inferCallArgCountLocal scans backward from insts[callIdx] (a "bl"
// instruction) counting how many of the X0-X7 argument registers were
// freshly defined in the immediate lead-up to this specific call -- the
// natural argument-setup pattern AOT-compiled Dart emits directly before a
// direct call (verified against a real sample: `MOV X1, #0x6` as the
// single instruction immediately preceding `BL MathTools.factorial`,
// matching the real `factorial(6)` call in source). Stops at the first
// earlier BL/BLR (a previous, unrelated call's own setup) or after
// maxArgSetupBack instructions, whichever comes first.
//
// This is intentionally a LOCAL, per-call-site signal, not ground truth on
// its own: register-allocator reuse can define a register for a reason
// unrelated to this call (see ARCHITECTURE.md), so callers MUST aggregate
// this across every call site targeting the same callee and only trust it
// on cross-site agreement -- a single site's hint is not reliable alone.
func inferCallArgCountLocal(insts []Inst, callIdx int) int {
	return popcount8(inferCallArgRegMaskLocal(insts, callIdx))
}

// inferCallArgRegMaskLocal is inferCallArgCountLocal's underlying primitive:
// same backward scan, but returns WHICH of X0-X7 were touched (bit i set =
// Xi touched) rather than just a count. Needed because the real argument
// registers are not always a contiguous X0..Xn-1 run -- a verified real
// sample had exactly X1 set (bit 1) with X0 untouched, for a genuine
// single-parameter function. Aggregating and comparing masks (not just
// counts) across call sites is what lets callers tell "X1 only" apart from
// "X0 only" instead of conflating both into "1 argument".
func inferCallArgRegMaskLocal(insts []Inst, callIdx int) uint8 {
	var mask uint8
	for i, steps := callIdx-1, 0; i >= 0 && steps < maxArgSetupBack; i, steps = i-1, steps+1 {
		in := insts[i]
		if _, ok := isBL(in.Raw, in.Addr); ok {
			break
		}
		if _, ok := isBLR(in.Raw); ok {
			break
		}
		rd := dstRegOfInst(in.Raw)
		if rd < 0 || rd > 7 {
			continue
		}
		mask |= 1 << uint(rd)
	}
	return mask
}

func popcount8(m uint8) int {
	n := 0
	for m != 0 {
		n += int(m & 1)
		m >>= 1
	}
	return n
}

// isLDRRegExtended detects LDR Xt, [Xn, Xm, LSL #3] (64-bit register offset).
// Returns base, index register, and destination register.
func isLDRRegExtended(raw uint32) (base, rm, rt int, ok bool) {
	// Encoding: 11|111|V=0|01|opc=01|1|Rm|option|S|10|Rn|Rt
	//
	// option (15:13) and S (12) are part of the match: without them the mask
	// also accepts the UNSCALED `LDR Xt, [Xn, Xm]`, whose index is not
	// multiplied by 8, and reading one of those as a dispatch-table load makes
	// the slot arithmetic wrong by a factor of eight. Measured on the 3.12.2
	// arm64 .text: 3412 scaled, 280 unscaled, no other extend option at all.
	// The same tightening and the same measurement are in typetrack's
	// isLDRRegExtended.
	//
	// NOTE the killer in dstRegOfInst above deliberately keeps the LOOSE mask:
	// every LDR-register-offset writes Rt whether or not it is scaled, so a
	// tightened mask there would leave those 280 destinations holding stale
	// types. Detector tight, killer loose.
	if raw&0xFFE0FC00 != 0xF8607800 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	base = int((raw >> 5) & 0x1F)
	rm = int((raw >> 16) & 0x1F)
	return base, rm, rt, true
}

// isLDUR64 detects LDUR Xt, [Xn, #imm9] (64-bit unscaled immediate) and
// returns the signed imm9 alongside the registers.
//
// The offset used to be discarded. It is the only thing that distinguishes one
// object-field call site from another, and without it every such site got the
// bare provenance "object_field" -- which made the largest bucket of
// unresolved indirect calls (954 of 1666 on the 3.12.2 arm64 sample, 57%)
// impossible to break down at all, let alone act on.
func isLDUR64(raw uint32) (base, rt, off int, ok bool) {
	if raw&0xFFE00C00 != 0xF8400000 {
		return 0, 0, 0, false
	}
	rt = int(raw & 0x1F)
	base = int((raw >> 5) & 0x1F)
	// imm9 is signed, bits 20:12.
	imm9 := int32(raw>>12) & 0x1FF
	if imm9&0x100 != 0 {
		imm9 -= 0x200
	}
	return base, rt, int(imm9), true
}

// ObjectFieldVia is the provenance string for a call target loaded out of an
// object field, carrying the field's byte offset.
//
// The offset is the field's displacement as the instruction encodes it, i.e.
// still short by kHeapObjectTag -- the same convention every other field
// offset in this codebase uses before FieldValueClass adds the tag back.
const ObjectFieldVia = "object_field"

// ObjectFieldViaAt formats the provenance for an object-field load at off.
func ObjectFieldViaAt(off int) string {
	if off == 0 {
		return ObjectFieldVia
	}
	if off < 0 {
		return ObjectFieldVia + "-0x" + strconv.FormatInt(int64(-off), 16)
	}
	return ObjectFieldVia + "+0x" + strconv.FormatInt(int64(off), 16)
}
