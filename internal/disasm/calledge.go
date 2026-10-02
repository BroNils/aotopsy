package disasm

import (
	"strconv"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/sdk"
)

const regDT = sdk.ARM64DT // X21 = dispatch table register (shared from sdk)

// CallEdge represents a call site extracted from disassembly.
type CallEdge struct {
	FromPC      uint64 `json:"from_pc"`
	Kind        string `json:"kind"`                // "bl" or "blr"
	TargetPC    uint64 `json:"target_pc,omitempty"` // resolved VA for bl
	TargetValid bool   `json:"-"`                   // distinguishes a valid VA 0 from target arithmetic failure
	TargetName  string `json:"target_name,omitempty"`
	Reg         string `json:"reg,omitempty"` // register for blr (e.g. "X16")
	Via         string `json:"via,omitempty"` // provenance: "THR.AllocateArray_ep", "PP[36] foo", ""

	// ArgCountHint is a per-call-site guess at the callee's real argument
	// count, for "bl" edges only (0 for "blr" -- not computed there). It is
	// the count of SDK-declared Dart argument GPRs freshly defined in the
	// immediate lead-up to this call (see inferCallArgCountLocal) -- NOT
	// ground truth, just one call site's local evidence. Aggregate across
	// every edge targeting the same callee (majority/consistency across
	// independent call sites) before trusting this for anything -- a
	// single call site's hint is not reliable on its own (see
	// ARCHITECTURE.md's "arity reconstruction" section for why the
	// declaration-metadata approach was abandoned in favor of this).
	ArgCountHint int `json:"arg_count_hint,omitempty"`

	// ArgRegMask is ArgCountHint's underlying bitmask (bit i = position i in
	// DartCallingConvention.GPR), "bl" edges only. Prefer this over
	// ArgCountHint when aggregating --
	// two call sites can agree on a COUNT while disagreeing on WHICH
	// registers hold the real arguments (e.g. count=1 via X0 alone vs.
	// count=1 via X1 alone are different, contradictory calling shapes,
	// but look identical if you only compare counts).
	ArgRegMask uint8 `json:"-"`
}

// ARM64 instruction decoders (isBL, isBLR, dstRegOfInst) are now shared
// from internal/arm64.

var arm64ArgRegCanon = func() [6]int {
	cc, ok := sdk.DartRegisterCallingConvention(sdk.FirstRegisterCallingConventionVersion, sdk.ArchARM64)
	if !ok {
		panic("sdk: ARM64 register calling convention missing at first supported version")
	}
	r := cc.GPR
	var arr [6]int
	copy(arr[:], r)
	return arr
}()

// arm64ArgRegBitPos returns which bit of an inferCallArgRegMaskLocal mask a
// canonical ARM64 register index corresponds to (its position in
// arm64ArgRegCanon / DartCallingConvention kCpuRegistersForArgs), or -1 if it
// isn't one of the 6 argument registers.
func arm64ArgRegBitPos(canonIdx int) int {
	for i, c := range arm64ArgRegCanon {
		if c == canonIdx {
			return i
		}
	}
	return -1
}

// maxArgSetupBack bounds inferCallArgCountLocal's backward scan -- AOT-
// generated argument setup is a short, contiguous instruction span
// immediately before the call; anything further back belongs to earlier,
// unrelated code, not this call's own argument setup.
const maxArgSetupBack = 12

// inferCallArgCountLocal scans backward from insts[callIdx] (a "bl"
// instruction) counting how many argument registers were freshly defined in
// the immediate lead-up to this specific call.
func inferCallArgCountLocal(insts []Inst, callIdx int) int {
	return popcount8(inferCallArgRegMaskLocal(insts, callIdx, 0))
}

// inferCallArgRegMaskLocal is inferCallArgCountLocal's underlying primitive:
// same backward scan, but returns WHICH of the 6 argument registers were
// touched (bit i set = arm64ArgRegCanon[i] touched) rather than just a count.
// Uses 0-based argument position indexing matching inferX86CallArgRegMaskLocal.
func inferCallArgRegMaskLocal(insts []Inst, callIdx, blockStart int) uint8 {
	var mask uint8
	if blockStart < 0 {
		blockStart = 0
	}
	for i, steps := callIdx-1, 0; i >= blockStart && steps < maxArgSetupBack; i, steps = i-1, steps+1 {
		in := insts[i]
		if arm64.IsBLEncoding(in.Raw) {
			break
		}
		if _, ok := arm64.BLR(in.Raw); ok {
			break
		}
		for _, rd := range arm64.DstRegsOfInst(in.Raw) {
			pos := arm64ArgRegBitPos(rd)
			if pos >= 0 {
				mask |= 1 << uint(pos)
			}
		}
	}
	return mask
}

func popcount8(m uint8) int {
	n := 0
	for m != 0 {
		n++
		m &= m - 1
	}
	return n
}

// isLDRRegExtended and isLDUR64 are now shared from internal/arm64.

// ObjectFieldVia is the provenance string for a call target loaded out of an
// object field, carrying the field's byte offset.
//
// The offset is the field's displacement as the instruction encodes it, i.e.
// still short by kHeapObjectTag -- the same convention every other field
// offset in this codebase uses before FieldValueClass adds the tag back.
const ObjectFieldVia = "object_field"

// Code entry-point displacements, as an instruction encodes them (byte offset
// minus kHeapObjectTag).
//
// UntaggedCode opens with four generated-code entry-point uwords right after
// the object header:
//
//	uword entry_point_;                       // offset 8  -> displacement 0x7
//	uword monomorphic_entry_point_;           // offset 16 -> displacement 0xf
//	uword unchecked_entry_point_;             // offset 24 -> displacement 0x17
//	uword monomorphic_unchecked_entry_point_; // offset 32 -> displacement 0x1f
//
// (raw_object.h, verified at 2.12.0 and 3.13.0; the entry-point caches are
// uwords, so compressed heap pointers do not shrink these fields.)
// IsCodeEntryPointDisp reports whether a load displacement reads one of a Code
// object's entry points across compressed and uncompressed modes.
//
// This matters because such a load is not really an "object field" at all: the
// entry point OF Code X is X, so a call through it calls X. Wherever the base
// register's provenance is known, the loaded value inherits it rather than
// becoming anonymous.
//
// AOT Code objects keep these entry-point uwords at word-sized offsets even
// when heap pointers are compressed. The 0x3/0xb displacements belong to a
// compressed-pointer layout assumption that is not the AOT Code layout and
// caused arbitrary object fields to inherit Code provenance.
func IsCodeEntryPointDisp(off int) bool {
	switch off {
	case 0x7, 0xf, 0x17, 0x1f:
		return true
	default:
		return false
	}
}

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
