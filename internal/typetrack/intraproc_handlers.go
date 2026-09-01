package typetrack

import (
	"strings"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
)

// closureFunctionOffset is the byte offset of UntaggedClosure.function
// from a TAGGED Closure pointer.
//
// Layout (raw_object.h, verified at 3.9.2): an 8-byte header, then
// instantiator_type_arguments, function_type_arguments,
// delayed_type_arguments, function, context, hash -- all pointer-sized --
// and finally ONLY_IN_PRECOMPILED(uword entry_point_).
//
//	compressed (4-byte fields)   function @ 8+12 = 20 untagged, 19 tagged
//	                             entry_point_ @ 8+24 = 32,      31 tagged
//	uncompressed (8-byte)        function @ 8+24 = 32,          31 tagged
//	                             entry_point_ @ 8+48 = 56,      55 tagged
//
// So 31 means `function` in one build and `entry_point_` in the other.
// Accepting both 19 and 31 unconditionally -- which is what these
// handlers did -- reads the entry point as a Function in every compressed
// build and types the destination as the closure's owner class. That is a
// confident wrong answer, not a missing one.
func closureFunctionOffset(ctx *TypeContext) int {
	word := 8
	if ctx != nil && ctx.WordSize > 0 {
		word = int(ctx.WordSize)
	}
	return 8 + 3*word - 1
}

// closureEntryPointOffset is the byte offset of
// ONLY_IN_PRECOMPILED(entry_point_) from a tagged Closure pointer.
func closureEntryPointOffset(ctx *TypeContext) int {
	word := 8
	if ctx != nil && ctx.WordSize > 0 {
		word = int(ctx.WordSize)
	}
	return 8 + 6*word - 1
}

// This file holds the per-instruction-type handlers that transferInstruction
// (intraproc.go) dispatches to. Each handler returns true if it consumed the
// instruction (set state and the caller should return), false to fall through
// to the next handler.
//
// The order matters and is preserved exactly as the original if-chain: stack
// stores first (they don't kill the source), then THR/PP loads, then dispatch
// table arithmetic, then field loads, then UBFX, MOV, BLR, BL, and finally
// the default kill.

// transferCtx bundles the shared state every handler needs, so the handler
// signatures stay short and the dispatch table reads cleanly.
type transferCtx struct {
	state      *[31]TypeLattice
	inst       disasm.Inst
	prevRaw    uint32
	ctx        *TypeContext
	result     *IntraResult
	lca        func(int, int) int
	stackTypes map[int]TypeLattice
}

// handleStackStore handles case 0: STUR/STR to stack, shadow stack, and
// object fields. These do NOT kill the source register, so they return false
// to let subsequent handlers run (except STR [X29] which returns true).
func handleStackStore(tc *transferCtx) bool {
	raw := tc.inst.Raw

	// 0a-pre. STUR Xt, [X29, #imm9] → save to stack (signed offset).
	if base, rt, imm9, ok := arm64.STUR64(raw); ok && base == sdk.ARM64FrameReg {
		if rt < 31 {
			tc.stackTypes[imm9] = tc.state[rt]
		}
		// Don't return — STUR doesn't kill the source register
	}
	// 0a-pre-bis. STUR Xt, [X15, #imm9] → shadow stack (signed offset).
	if base, rt, imm9, ok := arm64.STUR64(raw); ok && base == sdk.ARM64SPReg {
		if rt < 31 {
			tc.stackTypes[imm9+0x10000] = tc.state[rt]
		}
	}
	// 0a-pre-ter. STUR Xt, [Xn, #imm9] → object field store (signed offset).
	if base, rt, imm9, ok := arm64.STUR64(raw); ok {
		if rt < 31 && base < 31 && base != sdk.ARM64FrameReg && base != sdk.ARM64SPReg &&
			base != sdk.ARM64PP && base != sdk.ARM64THR && base != sdk.ARM64DT {
			if tc.state[base].Kind == LatticeKnownClass {
				recordFieldAccess(tc.result, tc.state[base].ClassID, int32(imm9), true, tc.inst.Addr)
			}
			if tc.state[base].Kind == LatticeKnownClass && tc.state[rt].Kind == LatticeKnownClass {
				key := tc.state[base].ClassID*100000 + imm9
				tc.stackTypes[key+0x20000] = tc.state[rt]
				recordFieldStore(tc.ctx, tc.state[base].ClassID, int32(imm9), tc.state[rt].ClassID)
			}
		}
	}

	// 0a-pre-quater. STUR Wt, [X29, #imm9] → compressed stack store.
	if base, rt, imm9, ok := arm64.STUR32(raw); ok && base == sdk.ARM64FrameReg {
		if rt < 31 {
			tc.stackTypes[imm9] = tc.state[rt]
		}
	}
	// 0a-pre-quater-bis. STUR Wt, [X15, #imm9] → compressed shadow stack.
	if base, rt, imm9, ok := arm64.STUR32(raw); ok && base == sdk.ARM64SPReg {
		if rt < 31 {
			tc.stackTypes[imm9+0x10000] = tc.state[rt]
		}
	}
	// 0a-pre-quater-ter. STUR Wt, [Xn, #imm9] → compressed object field store.
	if base, rt, imm9, ok := arm64.STUR32(raw); ok {
		if rt < 31 && base < 31 && base != sdk.ARM64FrameReg && base != sdk.ARM64SPReg &&
			base != sdk.ARM64PP && base != sdk.ARM64THR && base != sdk.ARM64DT {
			if tc.state[base].Kind == LatticeKnownClass {
				recordFieldAccess(tc.result, tc.state[base].ClassID, int32(imm9), true, tc.inst.Addr)
			}
			if tc.state[base].Kind == LatticeKnownClass && tc.state[rt].Kind == LatticeKnownClass {
				key := tc.state[base].ClassID*100000 + imm9
				tc.stackTypes[key+0x20000] = tc.state[rt]
				recordFieldStore(tc.ctx, tc.state[base].ClassID, int32(imm9), tc.state[rt].ClassID)
			}
		}
	}

	// 0a. STR Xt, [X29, #imm] → save to stack (unsigned offset).
	if baseReg, byteOff, _, ok := arm64.STR64UnsignedOffset(raw); ok && baseReg == sdk.ARM64FrameReg {
		rt := int(raw & 0x1F)
		if rt < 31 {
			tc.stackTypes[byteOff] = tc.state[rt]
		}
		return true
	}

	// 0a-bis. STR Xt, [X15, #imm] → shadow stack (unsigned offset).
	if baseReg, byteOff, _, ok := arm64.STR64UnsignedOffset(raw); ok && baseReg == sdk.ARM64SPReg {
		rt := int(raw & 0x1F)
		if rt < 31 {
			tc.stackTypes[byteOff+0x10000] = tc.state[rt]
		}
		// Don't return — STR to shadow stack doesn't kill the source register
	}

	// 0a-ter. STR Xt, [Xn, #imm] → object field store (unsigned offset).
	if baseReg, byteOff, _, ok := arm64.STR64UnsignedOffset(raw); ok {
		rt := int(raw & 0x1F)
		if rt < 31 && baseReg < 31 && baseReg != sdk.ARM64FrameReg && baseReg != sdk.ARM64SPReg &&
			baseReg != sdk.ARM64PP && baseReg != sdk.ARM64THR && baseReg != sdk.ARM64DT {
			if tc.state[baseReg].Kind == LatticeKnownClass && tc.state[rt].Kind == LatticeKnownClass {
				key := tc.state[baseReg].ClassID*100000 + byteOff
				tc.stackTypes[key+0x20000] = tc.state[rt]
			}
		}
		// Don't return — STR doesn't kill the source register
	}

	return false
}

// handleStackLoad handles case 0b: LDR from stack and shadow stack, plus
// STP/LDP pair operations.
func handleStackLoad(tc *transferCtx) bool {
	raw := tc.inst.Raw

	// 0b. LDR Xt, [X29, #imm] → load from stack.
	if baseReg, byteOff, ok := arm64.LDR64UnsignedOffset(raw); ok && baseReg == sdk.ARM64FrameReg {
		rt := int(raw & 0x1F)
		if rt >= 31 {
			return true
		}
		if t, ok2 := tc.stackTypes[byteOff]; ok2 {
			tc.state[rt] = t
		} else {
			tc.state[rt] = Top()
		}
		return true
	}

	// 0b-bis. LDR Xt, [X15, #imm] → load from shadow stack.
	if baseReg, byteOff, ok := arm64.LDR64UnsignedOffset(raw); ok && baseReg == sdk.ARM64SPReg {
		rt := int(raw & 0x1F)
		if rt >= 31 {
			return true
		}
		if t, ok2 := tc.stackTypes[byteOff+0x10000]; ok2 {
			tc.state[rt] = t
		} else {
			tc.state[rt] = Top()
		}
		return true
	}

	// 0c. STP Xt1, Xt2, [X15, #imm]! → save pair to shadow stack.
	if raw&0xFFC00000 == 0xA9000000 || raw&0xFFC00000 == 0xA9800000 || raw&0xFFC00000 == 0xA8000000 {
		rt1 := int(raw & 0x1F)
		rt2 := int((raw >> 10) & 0x1F)
		rn := int((raw >> 5) & 0x1F)
		imm7 := int((raw >> 15) & 0x7F)
		if imm7 >= 64 {
			imm7 -= 128
		}
		byteOff := imm7 * 8
		if rn == sdk.ARM64SPReg {
			if rt1 < 31 {
				tc.stackTypes[byteOff+0x10000] = tc.state[rt1]
			}
			if rt2 < 31 {
				tc.stackTypes[byteOff+8+0x10000] = tc.state[rt2]
			}
			// Don't return — STP doesn't kill source registers
		}
	}

	// 0d. LDP Xt1, Xt2, [X15, #imm] → load pair from shadow stack.
	if raw&0xFFC00000 == 0xA9C00000 || raw&0xFFC00000 == 0xA9400000 || raw&0xFFC00000 == 0xA8400000 {
		rt1 := int(raw & 0x1F)
		rt2 := int((raw >> 10) & 0x1F)
		rn := int((raw >> 5) & 0x1F)
		imm7 := int((raw >> 15) & 0x7F)
		if imm7 >= 64 {
			imm7 -= 128
		}
		byteOff := imm7 * 8
		if rn == sdk.ARM64SPReg {
			if rt1 < 31 {
				if t, ok2 := tc.stackTypes[byteOff+0x10000]; ok2 {
					tc.state[rt1] = t
				} else {
					tc.state[rt1] = Top()
				}
			}
			if rt2 < 31 {
				if t, ok2 := tc.stackTypes[byteOff+8+0x10000]; ok2 {
					tc.state[rt2] = t
				} else {
					tc.state[rt2] = Top()
				}
			}
			return true
		}
	}

	return false
}

// handleTHRLoad handles case 0-THR: LDR Xt, [X26, #imm] → KnownStub.
func handleTHRLoad(tc *transferCtx) bool {
	raw := tc.inst.Raw
	if baseReg, byteOff, ok := arm64.LDR64UnsignedOffset(raw); ok && baseReg == sdk.ARM64THR {
		rt := int(raw & 0x1F)
		if rt >= 31 {
			return true
		}
		stubName := ""
		if tc.ctx.AllocStubOffsets != nil {
			if name, found := tc.ctx.AllocStubOffsets[int64(byteOff)]; found {
				stubName = name
			}
		}
		if stubName == "" && tc.ctx.THRFields != nil {
			if name, found := tc.ctx.THRFields[byteOff]; found {
				stubName = name
			}
		}
		tc.state[rt] = KnownStub(stubName, byteOff)
		return true
	}
	return false
}

// handlePPLoad handles case 1: LDR Xt, [X27, #imm] → KnownClass from pool.
// Also handles 2-level PP addressing: ADD Xt, X27, #imm → LDR Xd, [Xt, #imm].
func handlePPLoad(tc *transferCtx) bool {
	raw := tc.inst.Raw
	if baseReg, byteOff, ok := arm64.LDR64UnsignedOffset(raw); ok && baseReg == sdk.ARM64PP {
		tc.ctx.PPLoads++
		return resolvePPLoad(tc, byteOff)
	}
	// 2-level PP addressing: LDR Xt, [Xn, #imm] where Xn = PP + upper_offset.
	// The SDK's LoadWordFromPoolIndex emits ADD Xd, PP, #upper20 then
	// LDR Xd, [Xd, #lower12] when the pool offset exceeds 12-bit range.
	// Track PP-derived base registers via a dedicated lattice kind.
	if baseReg, byteOff, ok := arm64.LDR64UnsignedOffset(raw); ok && baseReg < 31 {
		if tc.state[baseReg].Kind == LatticePPBase {
			fullOffset := tc.state[baseReg].PPBaseOffset + byteOff
			tc.ctx.PPLoads++
			return resolvePPLoad(tc, fullOffset)
		}
	}
	return false
}

// resolvePPLoad resolves a PP load at the given byte offset into a KnownClass
// or KnownStub, shared between direct and 2-level PP addressing.
func resolvePPLoad(tc *transferCtx, byteOff int) bool {
	raw := tc.inst.Raw
	rt := int(raw & 0x1F)
	if rt >= 31 {
		return true
	}
	poolIdx, poolIdxOK := disasm.ARM64PoolIndex(byteOff)
	if !poolIdxOK {
		return true
	}
	// The lookup order lives in ResolvePoolEntry, shared with x86_64.
	// Notes that used to sit inline here and still apply:
	//
	//   - PoolCodeNames is checked before PoolClassByIndex, because a
	//     Code object in the pool is useful as a name, not as kCodeCid.
	//   - type_test_stub_entry_point_ is at offset 7 from a Type's tagged
	//     pointer (raw_object.h@2.12.0: first field of
	//     UntaggedAbstractType, 8 untagged). handleFieldLoad's imm9 == 7
	//     case preserves the KnownStub through the LDUR, and handleBLR
	//     resolves "TTS:name".
	lat, hit := ResolvePoolEntry(tc.ctx, poolIdx, byteOff)
	tc.state[rt] = lat
	if hit {
		tc.ctx.PPHits++
	}
	return true
}

// handleDispatchTableLoad handles case 1b/2: LDR from dispatch table base
// register or from a register holding KnownDispatchIndex.
func handleDispatchTableLoad(tc *transferCtx) bool {
	raw := tc.inst.Raw

	// 1b. LDR Xt, [Xn, #imm] where Xn has KnownDispatchIndex.
	if baseReg, byteOff, ok := arm64.LDR64UnsignedOffset(raw); ok && baseReg < 31 {
		rt := int(raw & 0x1F)
		if rt >= 31 {
			return true
		}
		if tc.state[baseReg].Kind == LatticeKnownDispatchIndex {
			slot := tc.state[baseReg].DispatchIndex + byteOff/8
			tc.state[rt] = KnownDispatch(slot)
			return true
		}
		// Don't return — fall through to other checks.
	}

	// 2. LDR Xt, [X21, Xm, LSL #3] → dispatch table load.
	if base, rm, rt, ok := arm64.LDRRegExtended(raw); ok && base == sdk.ARM64DT {
		if rt >= 31 {
			return true
		}
		if rm < 31 && tc.state[rm].Kind == LatticeKnownDispatchIndex {
			if tc.state[rm].SelectorOnly {
				// Selector-only: the index register holds a selector
				// offset, not an absolute slot. Preserve SelectorOnly
				// so resolveBLR uses the selector scan path instead
				// of a direct slot lookup (which would fail because
				// the selector offset is negative/invalid as a slot).
				// This is the common 2.x dispatch pattern:
				//   SUB X0, X0, #imm  ; SelectorDispatch(-imm)
				//   LDR X30, [X21, X0, LSL #3]
				//   BLR X30
				tc.state[rt] = tc.state[rm]
			} else {
				tc.state[rt] = KnownDispatch(tc.state[rm].DispatchIndex)
			}
		} else if rm < 31 && tc.state[rm].Kind == LatticeKnownClass {
			slot := tc.state[rm].ClassID - tc.ctx.KOriginElement
			tc.state[rt] = KnownDispatch(slot)
			tc.ctx.ADDClassHits++
		} else {
			tc.state[rt] = Bottom()
		}
		return true
	}
	return false
}

// handleDispatchArith handles cases 3/4/4b/4c: ADD/SUB for dispatch slot
// computation, including compressed-pointer decompression.
func handleDispatchArith(tc *transferCtx) bool {
	raw := tc.inst.Raw

	// 3. ADD Xd, X21, #imm → KnownDispatchIndex(imm/8).
	if rd, rn, imm, ok := arm64.ADD64Immediate(raw); ok && rn == sdk.ARM64DT {
		if rd >= 31 {
			return true
		}
		slot := imm / 8
		tc.state[rd] = KnownDispatch(slot)
		return true
	}

	// 4. ADD Xd, Xn, #imm where Xn is KnownDispatchIndex or KnownClass.
	if rd, rn, imm, ok := arm64.ADD64Immediate(raw); ok {
		if rd >= 31 || rn >= 31 {
			// Fall through to default kill
		} else if tc.state[rn].Kind == LatticeKnownDispatchIndex {
			tc.state[rd] = KnownDispatch(tc.state[rn].DispatchIndex + imm)
			return true
		} else if tc.state[rn].Kind == LatticeKnownClass {
			tc.state[rd] = KnownDispatch(tc.state[rn].ClassID + imm)
			tc.ctx.ADDClassHits++
			return true
		} else if tc.state[rn].Kind == LatticeBottom {
			tc.state[rd] = SelectorDispatch(imm)
			tc.ctx.ADDClassHits++
			return true
		}
	}

	// 4b. SUB Xd, Xn, #imm — dispatch slot with negative offset.
	if rd, rn, imm, ok := arm64.SUB64Immediate(raw); ok {
		if rd >= 31 || rn >= 31 {
			// Fall through to default kill
		} else if tc.state[rn].Kind == LatticeKnownDispatchIndex {
			tc.state[rd] = KnownDispatch(tc.state[rn].DispatchIndex - imm)
			return true
		} else if tc.state[rn].Kind == LatticeKnownClass {
			tc.state[rd] = KnownDispatch(tc.state[rn].ClassID - imm)
			tc.ctx.ADDClassHits++
			return true
		} else if tc.state[rn].Kind == LatticeBottom {
			tc.state[rd] = SelectorDispatch(-imm)
			tc.ctx.ADDClassHits++
			return true
		}
	}

	// 4c. ADD Xd, Xn, Xm (register-register) — dispatch slot or decompression.
	if rd, rn, rm, ok := arm64.ADD64Register(raw); ok {
		if rd < 31 && rn < 31 && tc.state[rn].Kind == LatticeKnownClass {
			if rm == sdk.ARM64HeapBits { // HEAP_BITS — decompress
				tc.state[rd] = tc.state[rn]
				return true
			}
			if rm < 31 && tc.state[rm].Kind == LatticeKnownDispatchIndex {
				tc.state[rd] = KnownDispatch(tc.state[rn].ClassID + tc.state[rm].DispatchIndex)
				tc.ctx.ADDClassHits++
				return true
			}
			tc.state[rd] = KnownDispatch(tc.state[rn].ClassID)
			tc.ctx.ADDClassHits++
			return true
		}
	}

	// 4d. ADD Xd, X27, #imm — 2-level PP addressing.
	// The SDK's LoadWordFromPoolIndex emits this when the pool offset
	// exceeds 12-bit range: ADD Xd, PP, #upper20 → LDR Xd, [Xd, #lower12].
	// Track the PP base offset so handlePPLoad can resolve the full index.
	if rd, rn, imm, ok := arm64.ADD64Immediate(raw); ok && rn == sdk.ARM64PP && rd < 31 {
		tc.state[rd] = TypeLattice{Kind: LatticePPBase, PPBaseOffset: imm}
		return true
	}

	return false
}

// handleFieldLoad handles case 5: LDUR/LDURH/LDUR32/LDR-unsigned field loads
// and header loads.
func handleFieldLoad(tc *transferCtx) bool {
	raw := tc.inst.Raw

	// 5. LDUR Xt, [Xn, #imm9] — field/header/stack load.
	if base, rt, _, ok := arm64.LDUR64(raw); ok {
		if rt >= 31 {
			return true
		}
		imm9 := int(int32(raw>>12) & 0x1FF)
		if imm9 > 256 {
			imm9 -= 512
		}
		if base == sdk.ARM64FrameReg {
			if t, ok2 := tc.stackTypes[imm9]; ok2 {
				tc.state[rt] = t
			} else {
				tc.state[rt] = Top()
			}
			return true
		}
		if base == sdk.ARM64SPReg {
			if t, ok2 := tc.stackTypes[imm9+0x10000]; ok2 {
				tc.state[rt] = t
			} else {
				tc.state[rt] = Top()
			}
			return true
		}
		if base < 31 && tc.state[base].Kind == LatticeKnownClass {
			if imm9 == -1 {
				tc.state[rt] = KnownClass(tc.state[base].ClassID)
				tc.ctx.HeaderHits++
				return true
			}
			recordFieldAccess(tc.result, tc.state[base].ClassID, int32(imm9), false, tc.inst.Addr)
			if classID, ok2 := tc.ctx.FieldValueClass(tc.state[base].ClassID, int32(imm9)); ok2 {
				tc.state[rt] = KnownClass(classID)
				return true
			}
		}
		if imm9 == 7 && base < 31 && tc.state[base].Kind == LatticeKnownStub {
			sn := tc.state[base].StubName
			// PPCode: Code.entry_point_ at offset 7 from tagged Code pointer
			// TTS: AbstractType.type_test_stub_entry_point_ at offset 7
			// from tagged Type pointer (verified via gh api to
			// raw_object.h @2.12.0: type_test_stub_entry_point_ is a
			// uword at offset 8 from untagged = 7 from tagged)
			if strings.HasPrefix(sn, "PPCode:") || strings.HasPrefix(sn, "TTS:") {
				tc.state[rt] = KnownStub(sn, imm9)
				return true
			}
		}
		// Closure.function: UntaggedClosure.function is field 3
		// (after instantiator_type_arguments, function_type_arguments,
		// delayed_type_arguments). SDK-verified against raw_object.h@3.9.2.
		// StubOff holds the PP index; PoolClosureClass maps it to
		// owner class ID. The function field contains a Function
		// whose owner class IS the closure's owner class.
		//
		// The offset is derived from the word size, not accepted from a
		// set. This used to match 19 OR 31 without asking which build it
		// was looking at -- and in a compressed build 31 is not `function`
		// at all, it is `entry_point_`, a uword. Reading it as a Function
		// and typing the destination as the closure's owner class was a
		// confident wrong answer at every tear-off call site.
		if base < 31 && tc.state[base].Kind == LatticeKnownStub {
			sn := tc.state[base].StubName
			if strings.HasPrefix(sn, "Closure:") && imm9 == closureFunctionOffset(tc.ctx) {
				poolIdx := tc.state[base].StubOff
				if tc.ctx.PoolClosureClass != nil {
					if ownerCID, ok := tc.ctx.PoolClosureClass[poolIdx]; ok && ownerCID >= 0 {
						tc.state[rt] = KnownClass(ownerCID)
						return true
					}
				}
			}
			// entry_point_ is the cached code address, not a Function.
			// It is what a closure call actually branches to, so carry it
			// as a stub whose name handleBLR can resolve -- rather than
			// mistyping the register as the closure's owner class, which
			// is what matching offset 31 unconditionally used to do.
			if strings.HasPrefix(sn, "Closure:") && imm9 == closureEntryPointOffset(tc.ctx) {
				tc.state[rt] = KnownStub("ClosureEntry:"+sn[len("Closure:"):], tc.state[base].StubOff)
				return true
			}
		}
		if imm9 == -1 && base < 31 {
			tc.state[rt] = Bottom()
			tc.ctx.HeaderHits++
			return true
		}
		tc.state[rt] = Top()
		return true
	}

	// 5-ldurh. LDURH Wt, [Xn, #imm9] — 16-bit load (Dart 2.x class ID).
	if base, rt, imm9, ok := arm64.LDURH(raw); ok {
		if rt >= 31 {
			return true
		}
		if base == sdk.ARM64FrameReg {
			if t, ok2 := tc.stackTypes[imm9]; ok2 {
				tc.state[rt] = t
			} else {
				tc.state[rt] = Top()
			}
			return true
		}
		if base == sdk.ARM64SPReg {
			if t, ok2 := tc.stackTypes[imm9+0x10000]; ok2 {
				tc.state[rt] = t
			} else {
				tc.state[rt] = Top()
			}
			return true
		}
		if imm9 == 1 && base < 31 {
			if tc.state[base].Kind == LatticeKnownClass {
				tc.state[rt] = KnownClass(tc.state[base].ClassID)
			} else {
				tc.state[rt] = Bottom()
			}
			tc.ctx.HeaderHits++
			return true
		}
		if base < 31 && tc.state[base].Kind == LatticeKnownClass {
			if classID, ok2 := tc.ctx.FieldValueClass(tc.state[base].ClassID, int32(imm9)); ok2 {
				tc.state[rt] = KnownClass(classID)
				return true
			}
		}
		tc.state[rt] = Top()
		return true
	}

	// 5-compressed. LDUR Wt, [Xn, #imm9] — 32-bit compressed pointer load.
	if base, rt, imm9, ok := arm64.LDUR32(raw); ok {
		if rt >= 31 {
			return true
		}
		if base == sdk.ARM64FrameReg {
			if t, ok2 := tc.stackTypes[imm9]; ok2 {
				tc.state[rt] = t
			} else {
				tc.state[rt] = Top()
			}
			return true
		}
		if base == sdk.ARM64SPReg {
			if t, ok2 := tc.stackTypes[imm9+0x10000]; ok2 {
				tc.state[rt] = t
			} else {
				tc.state[rt] = Top()
			}
			return true
		}
		if base < 31 && tc.state[base].Kind == LatticeKnownClass {
			key := tc.state[base].ClassID*100000 + imm9
			if storedType, ok2 := tc.stackTypes[key+0x20000]; ok2 && storedType.Kind != LatticeTop {
				tc.state[rt] = storedType
				return true
			}
			if classID, ok2 := tc.ctx.FieldValueClass(tc.state[base].ClassID, int32(imm9)); ok2 {
				tc.state[rt] = KnownClass(classID)
				return true
			}
			tc.state[rt] = KnownClass(tc.state[base].ClassID)
			tc.ctx.HeaderHits++
			return true
		}
		// Closure.function via compressed LDUR32. A 32-bit load of this
		// field only occurs in a compressed build, where the offset is 19.
		if base < 31 && tc.state[base].Kind == LatticeKnownStub {
			sn := tc.state[base].StubName
			if strings.HasPrefix(sn, "Closure:") && imm9 == closureFunctionOffset(tc.ctx) {
				poolIdx := tc.state[base].StubOff
				if tc.ctx.PoolClosureClass != nil {
					if ownerCID, ok2 := tc.ctx.PoolClosureClass[poolIdx]; ok2 && ownerCID >= 0 {
						tc.state[rt] = KnownClass(ownerCID)
						return true
					}
				}
			}
		}
		tc.state[rt] = Top()
		return true
	}

	// 5b. LDR Xt, [Xn, #imm] (unsigned offset) — field load.
	if baseReg, byteOff, ok := arm64.LDR64UnsignedOffset(raw); ok {
		rt := int(raw & 0x1F)
		if rt >= 31 {
			// Don't return — let other handlers process
		} else if baseReg < 31 && tc.state[baseReg].Kind == LatticeKnownStub {
			sn := tc.state[baseReg].StubName
			if strings.HasPrefix(sn, "UnlinkedCall:") {
				tc.state[rt] = tc.state[baseReg]
				return true
			}
			// Closure.function via LDR64 unsigned offset. The offset
			// depends on the word size; see closureFunctionOffset.
			if strings.HasPrefix(sn, "Closure:") && byteOff == closureFunctionOffset(tc.ctx) {
				poolIdx := tc.state[baseReg].StubOff
				if tc.ctx.PoolClosureClass != nil {
					if ownerCID, ok2 := tc.ctx.PoolClosureClass[poolIdx]; ok2 && ownerCID >= 0 {
						tc.state[rt] = KnownClass(ownerCID)
						return true
					}
				}
			}
		} else if baseReg < 31 && baseReg != sdk.ARM64PP && baseReg != sdk.ARM64THR && baseReg != sdk.ARM64DT && baseReg != sdk.ARM64FrameReg && baseReg != sdk.ARM64SPReg {
			if tc.state[baseReg].Kind == LatticeKnownClass {
				key := tc.state[baseReg].ClassID*100000 + byteOff
				if storedType, ok2 := tc.stackTypes[key+0x20000]; ok2 && storedType.Kind != LatticeTop {
					tc.state[rt] = storedType
					return true
				}
				if classID, ok2 := tc.ctx.FieldValueClass(tc.state[baseReg].ClassID, int32(byteOff)); ok2 {
					tc.state[rt] = KnownClass(classID)
					return true
				}
				tc.state[rt] = KnownClass(tc.state[baseReg].ClassID)
				tc.ctx.HeaderHits++
				return true
			}
		}
	}

	// 5b-compressed. LDR Wt, [Xn, #imm] (unsigned offset) — compressed field load.
	if baseReg, byteOff, _, ok := arm64.LDR32UnsignedOffset(raw); ok {
		rt := int(raw & 0x1F)
		if rt >= 31 {
			// Don't return — let other handlers process
		} else if baseReg < 31 && baseReg != sdk.ARM64PP && baseReg != sdk.ARM64THR && baseReg != sdk.ARM64DT && baseReg != sdk.ARM64FrameReg && baseReg != sdk.ARM64SPReg {
			if tc.state[baseReg].Kind == LatticeKnownClass {
				key := tc.state[baseReg].ClassID*100000 + byteOff
				if storedType, ok2 := tc.stackTypes[key+0x20000]; ok2 && storedType.Kind != LatticeTop {
					tc.state[rt] = storedType
					return true
				}
				if classID, ok2 := tc.ctx.FieldValueClass(tc.state[baseReg].ClassID, int32(byteOff)); ok2 {
					tc.state[rt] = KnownClass(classID)
					return true
				}
				tc.state[rt] = KnownClass(tc.state[baseReg].ClassID)
				tc.ctx.HeaderHits++
				return true
			}
		}
	}

	return false
}
