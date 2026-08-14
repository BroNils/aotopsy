package typetrack

import (
	"strings"

	"aotopsy/internal/disasm"
)

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
	if base, rt, imm9, ok := isSTUR64(raw); ok && base == 29 {
		if rt < 31 {
			tc.stackTypes[imm9] = tc.state[rt]
		}
		// Don't return — STUR doesn't kill the source register
	}
	// 0a-pre-bis. STUR Xt, [X15, #imm9] → shadow stack (signed offset).
	if base, rt, imm9, ok := isSTUR64(raw); ok && base == 15 {
		if rt < 31 {
			tc.stackTypes[imm9+0x10000] = tc.state[rt]
		}
	}
	// 0a-pre-ter. STUR Xt, [Xn, #imm9] → object field store (signed offset).
	if base, rt, imm9, ok := isSTUR64(raw); ok {
		if rt < 31 && base < 31 && base != 29 && base != 15 &&
			base != regPP && base != regTHR && base != regDT {
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
	if base, rt, imm9, ok := isSTUR32(raw); ok && base == 29 {
		if rt < 31 {
			tc.stackTypes[imm9] = tc.state[rt]
		}
	}
	// 0a-pre-quater-bis. STUR Wt, [X15, #imm9] → compressed shadow stack.
	if base, rt, imm9, ok := isSTUR32(raw); ok && base == 15 {
		if rt < 31 {
			tc.stackTypes[imm9+0x10000] = tc.state[rt]
		}
	}
	// 0a-pre-quater-ter. STUR Wt, [Xn, #imm9] → compressed object field store.
	if base, rt, imm9, ok := isSTUR32(raw); ok {
		if rt < 31 && base < 31 && base != 29 && base != 15 &&
			base != regPP && base != regTHR && base != regDT {
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
	if baseReg, byteOff, ok := isSTR64UnsignedOffset(raw); ok && baseReg == 29 {
		rt := int(raw & 0x1F)
		if rt < 31 {
			tc.stackTypes[byteOff] = tc.state[rt]
		}
		return true
	}

	// 0a-bis. STR Xt, [X15, #imm] → shadow stack (unsigned offset).
	if baseReg, byteOff, ok := isSTR64UnsignedOffset(raw); ok && baseReg == 15 {
		rt := int(raw & 0x1F)
		if rt < 31 {
			tc.stackTypes[byteOff+0x10000] = tc.state[rt]
		}
		// Don't return — STR to shadow stack doesn't kill the source register
	}

	// 0a-ter. STR Xt, [Xn, #imm] → object field store (unsigned offset).
	if baseReg, byteOff, ok := isSTR64UnsignedOffset(raw); ok {
		rt := int(raw & 0x1F)
		if rt < 31 && baseReg < 31 && baseReg != 29 && baseReg != 15 &&
			baseReg != regPP && baseReg != regTHR && baseReg != regDT {
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
	if baseReg, byteOff, ok := isLDR64UnsignedOffset(raw); ok && baseReg == 29 {
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
	if baseReg, byteOff, ok := isLDR64UnsignedOffset(raw); ok && baseReg == 15 {
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
		if rn == 15 {
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
		if rn == 15 {
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
	if baseReg, byteOff, ok := isLDR64UnsignedOffset(raw); ok && baseReg == regTHR {
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
func handlePPLoad(tc *transferCtx) bool {
	raw := tc.inst.Raw
	if baseReg, byteOff, ok := isLDR64UnsignedOffset(raw); ok && baseReg == regPP {
		rt := int(raw & 0x1F)
		if rt >= 31 {
			return true
		}
		poolIdx, poolIdxOK := disasm.ARM64PoolIndex(byteOff)
		if !poolIdxOK {
			return true
		}
		if tc.ctx.PoolUnlinkedCallNames != nil {
			if name, ok3 := tc.ctx.PoolUnlinkedCallNames[poolIdx]; ok3 && name != "" {
				tc.state[rt] = KnownStub("UnlinkedCall:"+name, byteOff)
				return true
			}
		}
		if classID, ok2 := tc.ctx.PoolClassByIndex[poolIdx]; ok2 && classID >= 0 {
			tc.state[rt] = KnownClass(classID)
			tc.ctx.PPHits++
			if tc.ctx.InstantiatedClasses != nil {
				tc.ctx.InstantiatedClasses[classID] = true
			}
		} else if tc.ctx.PoolCodeNames != nil {
			if name, ok3 := tc.ctx.PoolCodeNames[poolIdx]; ok3 && name != "" {
				tc.state[rt] = KnownStub("PPCode:"+name, byteOff)
				tc.ctx.PPHits++
				return true
			}
		}
		if tc.ctx.PoolClosureClass != nil {
			if classID, ok3 := tc.ctx.PoolClosureClass[poolIdx]; ok3 && classID >= 0 {
				tc.state[rt] = KnownClass(classID)
				tc.ctx.PPHits++
				return true
			}
			tc.state[rt] = Top()
		} else {
			tc.state[rt] = Top()
		}
		return true
	}
	return false
}

// handleDispatchTableLoad handles case 1b/2: LDR from dispatch table base
// register or from a register holding KnownDispatchIndex.
func handleDispatchTableLoad(tc *transferCtx) bool {
	raw := tc.inst.Raw

	// 1b. LDR Xt, [Xn, #imm] where Xn has KnownDispatchIndex.
	if baseReg, byteOff, ok := isLDR64UnsignedOffset(raw); ok && baseReg < 31 {
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
	if base, rm, rt, ok := isLDRRegExtended(raw); ok && base == regDT {
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
	if rd, rn, imm, ok := isADD64Immediate(raw); ok && rn == regDT {
		if rd >= 31 {
			return true
		}
		slot := imm / 8
		tc.state[rd] = KnownDispatch(slot)
		return true
	}

	// 4. ADD Xd, Xn, #imm where Xn is KnownDispatchIndex or KnownClass.
	if rd, rn, imm, ok := isADD64Immediate(raw); ok {
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
	if rd, rn, imm, ok := isSUB64Immediate(raw); ok {
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
	if rd, rn, rm, ok := isADD64Register(raw); ok {
		if rd < 31 && rn < 31 && tc.state[rn].Kind == LatticeKnownClass {
			if rm == 28 { // X28 = HEAP_BITS — decompress
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

	return false
}

// handleFieldLoad handles case 5: LDUR/LDURH/LDUR32/LDR-unsigned field loads
// and header loads.
func handleFieldLoad(tc *transferCtx) bool {
	raw := tc.inst.Raw

	// 5. LDUR Xt, [Xn, #imm9] — field/header/stack load.
	if base, rt, ok := isLDUR64(raw); ok {
		if rt >= 31 {
			return true
		}
		imm9 := int(int32(raw>>12) & 0x1FF)
		if imm9 > 256 {
			imm9 -= 512
		}
		if base == 29 {
			if t, ok2 := tc.stackTypes[imm9]; ok2 {
				tc.state[rt] = t
			} else {
				tc.state[rt] = Top()
			}
			return true
		}
		if base == 15 {
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
			if strings.HasPrefix(sn, "PPCode:") {
				tc.state[rt] = KnownStub(sn, imm9)
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
	if base, rt, imm9, ok := isLDURH(raw); ok {
		if rt >= 31 {
			return true
		}
		if base == 29 {
			if t, ok2 := tc.stackTypes[imm9]; ok2 {
				tc.state[rt] = t
			} else {
				tc.state[rt] = Top()
			}
			return true
		}
		if base == 15 {
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
	if base, rt, imm9, ok := isLDUR32(raw); ok {
		if rt >= 31 {
			return true
		}
		if base == 29 {
			if t, ok2 := tc.stackTypes[imm9]; ok2 {
				tc.state[rt] = t
			} else {
				tc.state[rt] = Top()
			}
			return true
		}
		if base == 15 {
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
		tc.state[rt] = Top()
		return true
	}

	// 5b. LDR Xt, [Xn, #imm] (unsigned offset) — field load.
	if baseReg, byteOff, ok := isLDR64UnsignedOffset(raw); ok {
		rt := int(raw & 0x1F)
		if rt >= 31 {
			// Don't return — let other handlers process
		} else if baseReg < 31 && tc.state[baseReg].Kind == LatticeKnownStub {
			if strings.HasPrefix(tc.state[baseReg].StubName, "UnlinkedCall:") {
				tc.state[rt] = tc.state[baseReg]
				return true
			}
		} else if baseReg < 31 && baseReg != regPP && baseReg != regTHR && baseReg != regDT && baseReg != 29 && baseReg != 15 {
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
	if baseReg, byteOff, ok := isLDR32UnsignedOffset(raw); ok {
		rt := int(raw & 0x1F)
		if rt >= 31 {
			// Don't return — let other handlers process
		} else if baseReg < 31 && baseReg != regPP && baseReg != regTHR && baseReg != regDT && baseReg != 29 && baseReg != 15 {
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

// handleUBFX handles case 5b-ubfx: UBFX/UBFM bitfield extract for class ID.
func handleUBFX(tc *transferCtx) bool {
	raw := tc.inst.Raw
	if rd, rn, ok := isUBFX(raw); ok {
		if rd >= 31 {
			return true
		}
		if rn < 31 && tc.state[rn].Kind == LatticeKnownClass {
			tc.state[rd] = tc.state[rn]
			tc.ctx.UBFXHits++
			return true
		}
		if rn < 31 && tc.state[rn].Kind == LatticeBottom {
			if _, rt, ok2 := isLDUR64(tc.prevRaw); ok2 && rt == rn {
				imm9 := int(int32(tc.prevRaw>>12) & 0x1FF)
				if imm9 > 256 {
					imm9 -= 512
				}
				if imm9 == -1 {
					tc.state[rd] = Bottom()
					tc.ctx.UBFXHits++
					return true
				}
			}
			if _, rt, _, ok2 := isLDUR32(tc.prevRaw); ok2 && rt == rn {
				tc.state[rd] = Bottom()
				tc.ctx.UBFXHits++
				return true
			}
		}
		if rd >= 0 && rd < 31 {
			tc.state[rd] = Top()
		}
		return true
	}
	return false
}

// handleMOV handles case 6: MOV (ORR Xd, XZR, Xm) → copy type.
func handleMOV(tc *transferCtx) bool {
	raw := tc.inst.Raw
	if rd, ok := isMOVOrr(raw); ok {
		rm := int((raw >> 16) & 0x1F)
		if rd >= 31 {
			return true
		}
		if rm < 31 {
			tc.state[rd] = tc.state[rm]
		} else {
			tc.state[rd] = Top()
		}
		return true
	}
	return false
}

// handleBLR handles case 7: BLR — dispatch resolution + allocation detection.
func handleBLR(tc *transferCtx) bool {
	raw := tc.inst.Raw
	if rn, ok := isBLR(raw); ok {
		if rn < 31 {
			resolveBLR(tc.state, rn, tc.inst, tc.ctx, tc.result)
		}
		if rn < 31 && tc.state[rn].Kind == LatticeKnownStub {
			sn := tc.state[rn].StubName
			if strings.HasPrefix(sn, "UnlinkedCall:") {
				methodName := sn[len("UnlinkedCall:"):]
				tc.result.BLRResolutions = append(tc.result.BLRResolutions, BlrResolution{
					PC: tc.inst.Addr, Reg: rn, TargetName: methodName, Resolved: true,
				})
			} else if strings.HasPrefix(sn, "PPCode:") {
				funcName := sn[len("PPCode:"):]
				tc.result.BLRResolutions = append(tc.result.BLRResolutions, BlrResolution{
					PC: tc.inst.Addr, Reg: rn, TargetName: funcName, Resolved: true,
				})
			} else if sn != "" && !strings.HasPrefix(sn, "Allocate") && !strings.HasPrefix(sn, "allocate") {
				tc.result.BLRResolutions = append(tc.result.BLRResolutions, BlrResolution{
					PC: tc.inst.Addr, Reg: rn, TargetName: sn, Resolved: true,
				})
			}
		}
		isAllocation := false
		if rn < 31 && tc.state[rn].Kind == LatticeKnownStub {
			sn := tc.state[rn].StubName
			if strings.HasPrefix(sn, "Allocate") || strings.HasPrefix(sn, "allocate") {
				isAllocation = true
			}
		}
		if !isAllocation && rn < 31 && tc.state[rn].Kind == LatticeKnownStub {
			off := tc.state[rn].StubOff
			if tc.ctx.AllocStubOffsets != nil {
				if name, found := tc.ctx.AllocStubOffsets[int64(off)]; found {
					if strings.Contains(strings.ToLower(name), "allocate") {
						isAllocation = true
					}
				}
			}
		}
		if isAllocation {
			if tc.state[0].Kind == LatticeKnownClass {
				recordAllocationSite(tc.ctx, tc.inst.Addr, tc.state[0].ClassID)
			}
			for r := 1; r <= 7; r++ {
				tc.state[r] = Top()
			}
		} else {
			tc.state[0] = Top()
			for r := 1; r <= 7; r++ {
				tc.state[r] = Top()
			}
		}
		return true
	}
	return false
}

// handleBL handles case 8: BL — direct call with callee exit type propagation.
func handleBL(tc *transferCtx) bool {
	raw := tc.inst.Raw
	if target, ok := isBL(raw, tc.inst.Addr); ok {
		tc.ctx.BLTotal++
		if tc.result.BLCallSiteTypes == nil {
			tc.result.BLCallSiteTypes = make(map[uint64][31]TypeLattice)
		}
		var callSiteState [31]TypeLattice
		copy(callSiteState[:], tc.state[:])
		tc.result.BLCallSiteTypes[target] = callSiteState

		calleeAllExit, hasFull := tc.ctx.CalleeAllExitTypes[target]
		if hasFull {
			tc.ctx.BLHasExitType++
			if calleeAllExit[0].Kind == LatticeKnownClass {
				tc.ctx.BLExitKnown++
			} else if calleeAllExit[0].Kind == LatticeBottom {
				tc.ctx.BLExitBottom++
			}
			for r := 0; r <= 7; r++ {
				if calleeAllExit[r].Kind != LatticeTop {
					tc.state[r] = calleeAllExit[r]
				} else {
					tc.state[r] = Top()
				}
			}
		} else {
			calleeExit := tc.ctx.CalleeExitTypes[target]
			if calleeExit.Kind != LatticeTop {
				tc.ctx.BLHasExitType++
				if calleeExit.Kind == LatticeKnownClass {
					tc.ctx.BLExitKnown++
				}
				tc.state[0] = calleeExit
			} else {
				tc.state[0] = Top()
			}
			for r := 1; r <= 7; r++ {
				tc.state[r] = Top()
			}
		}
		return true
	}
	return false
}
