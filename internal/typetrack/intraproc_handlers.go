package typetrack

import (
	"strings"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
)

// The closure field offsets and the shared load resolver live in
// closurefield.go, so the x86_64 transfer function can use them too.

// This file holds the per-instruction-type handlers that transferInstruction
// (intraproc.go) dispatches to. Each handler returns true if it consumed the
// instruction (set state and the caller should return), false to fall through
// to the next handler.
//
// The order matters and is preserved exactly as the original if-chain: stack
// stores first (they don't kill the source), then THR/PP loads, then dispatch
// table arithmetic, then field loads, then UBFX, MOV, BLR, BL, and finally
// the default kill.

const (
	shadowStackOffsetBase = 0x10000
)

// shadowSPState tracks Dart's software stack pointer X15 relative to the
// current frame pointer X29. A relative coordinate is stable across the
// compiler's pre/post-index Push/Pop sequences, unlike the old key of
// shadowStackOffsetBase+instructionImmediate.
type shadowSPState struct {
	Known bool
	RelFP int
}

func (s shadowSPState) Equal(other shadowSPState) bool {
	return s.Known == other.Known && (!s.Known || s.RelFP == other.RelFP)
}

func meetShadowSP(a, b shadowSPState) shadowSPState {
	if !a.Known || !b.Known || a.RelFP != b.RelFP {
		return shadowSPState{}
	}
	return a
}

func (s *shadowSPState) singleAccess(mode arm64.AddressMode, byteOff int) (int, bool) {
	if s == nil || !s.Known {
		return 0, false
	}
	switch mode {
	case arm64.AddressPreIndex:
		s.RelFP += byteOff
		return s.RelFP, true
	case arm64.AddressPostIndex:
		access := s.RelFP
		s.RelFP += byteOff
		return access, true
	default:
		return s.RelFP + byteOff, true
	}
}

func (s *shadowSPState) pairAccess(mode arm64.PairMode, byteOff int) (int, bool) {
	if s == nil || !s.Known {
		return 0, false
	}
	switch mode {
	case arm64.PairPreIndex:
		s.RelFP += byteOff
		return s.RelFP, true
	case arm64.PairPostIndex:
		access := s.RelFP
		s.RelFP += byteOff
		return access, true
	default:
		return s.RelFP + byteOff, true
	}
}

func shadowStackKey(relFP int) int { return shadowStackOffsetBase + relFP }

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
	shadowSP   *shadowSPState
}

// observeShadowFrameUpdate handles non-memory instructions that establish or
// move Dart's X15 software stack pointer relative to X29. Memory writeback is
// intentionally handled by the load/store handlers so they can use the
// pre-vs-post access address before mutating the relation.
func observeShadowFrameUpdate(raw uint32, s *shadowSPState) {
	if s == nil {
		return
	}
	if m, ok := arm64.Load64Immediate(raw); ok && m.BaseReg == sdk.ARM64SPReg {
		return
	}
	if m, ok := arm64.Store64Immediate(raw); ok && m.BaseReg == sdk.ARM64SPReg {
		return
	}
	if p, ok := arm64.LoadPair64(raw); ok && p.BaseReg == sdk.ARM64SPReg {
		return
	}
	if p, ok := arm64.StorePair64(raw); ok && p.BaseReg == sdk.ARM64SPReg {
		return
	}

	if rd, rm, ok := arm64.MOVOrr(raw); ok {
		switch {
		case rd == sdk.ARM64FrameReg && rm == sdk.ARM64SPReg,
			rd == sdk.ARM64SPReg && rm == sdk.ARM64FrameReg:
			s.Known = true
			s.RelFP = 0
		case rd == sdk.ARM64FrameReg || rd == sdk.ARM64SPReg:
			*s = shadowSPState{}
		}
		return
	}

	if rd, rn, imm, ok := arm64.ADD64Immediate(raw); ok {
		switch {
		case rd == sdk.ARM64SPReg && rn == sdk.ARM64SPReg:
			if s.Known {
				s.RelFP += imm
			}
		case rd == sdk.ARM64SPReg && rn == sdk.ARM64FrameReg:
			s.Known, s.RelFP = true, imm
		case rd == sdk.ARM64FrameReg && rn == sdk.ARM64SPReg:
			s.Known, s.RelFP = true, -imm
		case rd == sdk.ARM64FrameReg && rn == sdk.ARM64FrameReg:
			if s.Known {
				s.RelFP -= imm
			}
		case rd == sdk.ARM64FrameReg || rd == sdk.ARM64SPReg:
			*s = shadowSPState{}
		}
		return
	}

	if rd, rn, imm, ok := arm64.SUB64Immediate(raw); ok {
		switch {
		case rd == sdk.ARM64SPReg && rn == sdk.ARM64SPReg:
			if s.Known {
				s.RelFP -= imm
			}
		case rd == sdk.ARM64SPReg && rn == sdk.ARM64FrameReg:
			s.Known, s.RelFP = true, -imm
		case rd == sdk.ARM64FrameReg && rn == sdk.ARM64SPReg:
			s.Known, s.RelFP = true, imm
		case rd == sdk.ARM64FrameReg && rn == sdk.ARM64FrameReg:
			if s.Known {
				s.RelFP += imm
			}
		case rd == sdk.ARM64FrameReg || rd == sdk.ARM64SPReg:
			*s = shadowSPState{}
		}
		return
	}

	for _, rd := range arm64.DstRegsOfInst(raw) {
		if rd == sdk.ARM64FrameReg || rd == sdk.ARM64SPReg {
			*s = shadowSPState{}
			return
		}
	}
}

// handleStackStore handles case 0: STUR/STR to stack, shadow stack, and
// object fields. These do NOT kill the source register, so they return false
// to let subsequent handlers run (except STR [X29] which returns true).
func handleStackStore(tc *transferCtx) bool {
	raw := tc.inst.Raw

	// STR/STUR/STR(pre/post) Xt through Dart's software SP (X15). The access
	// address differs for pre- vs post-index, so canonicalize it through the
	// tracked X15-relative-to-X29 coordinate before recording the slot.
	if mem, ok := arm64.Store64Immediate(raw); ok && mem.BaseReg == sdk.ARM64SPReg {
		if rel, tracked := tc.shadowSP.singleAccess(mem.Mode, mem.ByteOffset); tracked && mem.Reg < 31 {
			tc.stackTypes[shadowStackKey(rel)] = tc.state[mem.Reg]
		}
	}

	// 0a-pre. STUR Xt, [X29, #imm9] → save to stack (signed offset).
	if base, rt, imm9, ok := arm64.STUR64(raw); ok && base == sdk.ARM64FrameReg {
		if rt < 31 {
			tc.stackTypes[imm9] = tc.state[rt]
		}
		// Don't return — STUR doesn't kill the source register
	}
	// 0a-pre-ter. STUR Xt, [Xn, #imm9] → object field store (signed offset).
	if base, rt, imm9, ok := arm64.STUR64(raw); ok {
		if rt < 31 && base < 31 && base != sdk.ARM64FrameReg && base != sdk.ARM64SPReg &&
			base != sdk.ARM64PP && base != sdk.ARM64THR && base != sdk.ARM64DT {
			if receiverCID, ok := objectClassID(tc.state[base]); ok {
				recordFieldAccess(tc.result, tc.ctx, receiverCID, int32(imm9), true, tc.inst.Addr)
			}
		}
	}

	// 0a-pre-quater. STUR Wt, [X29, #imm9] → compressed stack store.
	if base, rt, imm9, ok := arm64.STUR32(raw); ok && base == sdk.ARM64FrameReg {
		if rt < 31 {
			tc.stackTypes[imm9] = tc.state[rt]
		}
	}
	// 0a-pre-quater-ter. STUR Wt, [Xn, #imm9] → compressed object field store.
	if base, rt, imm9, ok := arm64.STUR32(raw); ok {
		if rt < 31 && base < 31 && base != sdk.ARM64FrameReg && base != sdk.ARM64SPReg &&
			base != sdk.ARM64PP && base != sdk.ARM64THR && base != sdk.ARM64DT {
			if receiverCID, ok := objectClassID(tc.state[base]); ok {
				recordFieldAccess(tc.result, tc.ctx, receiverCID, int32(imm9), true, tc.inst.Addr)
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

	// 0a-ter. STR Xt, [Xn, #imm] → object field store (unsigned offset).
	if baseReg, byteOff, _, ok := arm64.STR64UnsignedOffset(raw); ok {
		rt := int(raw & 0x1F)
		if rt < 31 && baseReg < 31 && baseReg != sdk.ARM64FrameReg && baseReg != sdk.ARM64SPReg &&
			baseReg != sdk.ARM64PP && baseReg != sdk.ARM64THR && baseReg != sdk.ARM64DT {
			if receiverCID, ok := objectClassID(tc.state[baseReg]); ok {
				recordFieldAccess(tc.result, tc.ctx, receiverCID, int32(byteOff), true, tc.inst.Addr)
			}
		}
		// Don't return — STR doesn't kill the source register
	}

	// 0a-quater. STR Wt, [Xn, #imm] is the normal compressed-pointer object
	// field store emitted by Dart AOT. Track it exactly like STUR32/STR64.
	if baseReg, byteOff, rt, ok := arm64.STR32UnsignedOffset(raw); ok {
		if rt < 31 && baseReg < 31 && baseReg != sdk.ARM64FrameReg && baseReg != sdk.ARM64SPReg &&
			baseReg != sdk.ARM64PP && baseReg != sdk.ARM64THR && baseReg != sdk.ARM64DT {
			if receiverCID, ok := objectClassID(tc.state[baseReg]); ok {
				recordFieldAccess(tc.result, tc.ctx, receiverCID, int32(byteOff), true, tc.inst.Addr)
			}
		}
	}

	return false
}

// handleStackLoad handles case 0b: LDR from stack and shadow stack, plus
// STP/LDP pair operations.
func handleStackLoad(tc *transferCtx) bool {
	raw := tc.inst.Raw

	// All 64-bit immediate LDR forms through Dart's X15 software SP, including
	// the post-index Pop shape emitted by every supported SDK.
	if mem, ok := arm64.Load64Immediate(raw); ok && mem.BaseReg == sdk.ARM64SPReg {
		rel, tracked := tc.shadowSP.singleAccess(mem.Mode, mem.ByteOffset)
		if mem.Reg < 31 {
			if tracked {
				if t, ok2 := tc.stackTypes[shadowStackKey(rel)]; ok2 {
					tc.state[mem.Reg] = t
				} else {
					tc.state[mem.Reg] = Top()
				}
			} else {
				tc.state[mem.Reg] = Top()
			}
		}
		if mem.Mode == arm64.AddressPreIndex || mem.Mode == arm64.AddressPostIndex {
			tc.state[sdk.ARM64SPReg] = Top()
		}
		if mem.Reg == sdk.ARM64FrameReg && tc.shadowSP != nil {
			*tc.shadowSP = shadowSPState{}
		}
		return true
	}

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

	// STP pair stores, including the PairPreIndex PushPair shape. Non-temporal
	// and offset forms do not write back; post/pre do.
	if pair, ok := arm64.StorePair64(raw); ok && pair.BaseReg == sdk.ARM64SPReg {
		if rel, tracked := tc.shadowSP.pairAccess(pair.Mode, pair.ByteOffset); tracked {
			if pair.Reg1 < 31 {
				tc.stackTypes[shadowStackKey(rel)] = tc.state[pair.Reg1]
			}
			if pair.Reg2 < 31 {
				tc.stackTypes[shadowStackKey(rel+8)] = tc.state[pair.Reg2]
			}
		}
	}

	// LDP pair loads, including PairPostIndex PopPair. Resolve the access before
	// invalidating a restored X29 frame pointer.
	if pair, ok := arm64.LoadPair64(raw); ok && pair.BaseReg == sdk.ARM64SPReg {
		rel, tracked := tc.shadowSP.pairAccess(pair.Mode, pair.ByteOffset)
		for i, reg := range []int{pair.Reg1, pair.Reg2} {
			if reg >= 31 {
				continue
			}
			if tracked {
				if t, ok2 := tc.stackTypes[shadowStackKey(rel+i*8)]; ok2 {
					tc.state[reg] = t
				} else {
					tc.state[reg] = Top()
				}
			} else {
				tc.state[reg] = Top()
			}
		}
		if pair.Mode == arm64.PairPreIndex || pair.Mode == arm64.PairPostIndex {
			tc.state[sdk.ARM64SPReg] = Top()
		}
		if (pair.Reg1 == sdk.ARM64FrameReg || pair.Reg2 == sdk.ARM64FrameReg) && tc.shadowSP != nil {
			*tc.shadowSP = shadowSPState{}
		}
		return true
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

// handlePPLoad handles case 1: LDR Xt, [X27, #imm] → runtime-object fact or
// named stub handle from the pool.
// Also handles 2-level PP addressing: ADD Xt, X27, #imm → LDR Xd, [Xt, #imm].
func handlePPLoad(tc *transferCtx) bool {
	raw := tc.inst.Raw
	if baseReg, byteOff, ok := arm64.LDR64UnsignedOffset(raw); ok && baseReg == sdk.ARM64PP {
		tc.ctx.hitMetric(metricPPLoad, tc.inst.Addr, &tc.ctx.PPLoads)
		return resolvePPLoad(tc, byteOff)
	}
	// 2-level PP addressing: LDR Xt, [Xn, #imm] where Xn = PP + upper_offset.
	// The SDK's LoadWordFromPoolIndex emits ADD Xd, PP, #upper20 then
	// LDR Xd, [Xd, #lower12] when the pool offset exceeds 12-bit range.
	// Track PP-derived base registers via a dedicated lattice kind.
	if baseReg, byteOff, ok := arm64.LDR64UnsignedOffset(raw); ok && baseReg < 31 {
		if tc.state[baseReg].Kind == LatticePPBase {
			fullOffset := tc.state[baseReg].PPBaseOffset + byteOff
			tc.ctx.hitMetric(metricPPLoad, tc.inst.Addr, &tc.ctx.PPLoads)
			return resolvePPLoad(tc, fullOffset)
		}
	}
	return false
}

// resolvePPLoad resolves a PP load at the given byte offset into a semantic
// lattice value, shared between direct and 2-level PP addressing.
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
		tc.ctx.hitMetric(metricPPHit, tc.inst.Addr, &tc.ctx.PPHits)
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
		} else if rm < 31 && tc.state[rm].Kind == LatticeExactClassID {
			// DISPATCH_TABLE_REG points at ArrayOrigin(), so a raw CID index
			// corresponds to selector_offset == kOriginElement: relative slot=cid.
			tc.state[rt] = KnownDispatch(tc.state[rm].ClassID)
			tc.ctx.hitMetric(metricADDClass, tc.inst.Addr, &tc.ctx.ADDClassHits)
		} else if rm < 31 && tc.state[rm].Kind == LatticeUnknownClassID {
			// The table load itself proves dispatch provenance, but without the
			// selector arithmetic there is no selector to scan safely.
			tc.state[rt] = Top()
		} else {
			tc.state[rt] = Top()
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

	// 4. ADD Xd, Xn, #imm where Xn is a dispatch index or class-ID scalar.
	if rd, rn, imm, ok := arm64.ADD64Immediate(raw); ok {
		if rd >= 31 || rn >= 31 {
			// Fall through to default kill
		} else if tc.state[rn].Kind == LatticeKnownDispatchIndex {
			tc.state[rd] = KnownDispatch(tc.state[rn].DispatchIndex + imm)
			return true
		} else if tc.state[rn].Kind == LatticeExactClassID {
			tc.state[rd] = KnownDispatch(tc.state[rn].ClassID + imm)
			tc.ctx.hitMetric(metricADDClass, tc.inst.Addr, &tc.ctx.ADDClassHits)
			return true
		} else if tc.state[rn].Kind == LatticeUnknownClassID {
			tc.state[rd] = SelectorDispatch(imm)
			tc.ctx.hitMetric(metricADDClass, tc.inst.Addr, &tc.ctx.ADDClassHits)
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
		} else if tc.state[rn].Kind == LatticeExactClassID {
			tc.state[rd] = KnownDispatch(tc.state[rn].ClassID - imm)
			tc.ctx.hitMetric(metricADDClass, tc.inst.Addr, &tc.ctx.ADDClassHits)
			return true
		} else if tc.state[rn].Kind == LatticeUnknownClassID {
			tc.state[rd] = SelectorDispatch(-imm)
			tc.ctx.hitMetric(metricADDClass, tc.inst.Addr, &tc.ctx.ADDClassHits)
			return true
		}
	}

	// 4c. ADD Xd, Xn, Xm (register-register) — dispatch slot or decompression.
	if rd, rn, rm, shift, amount, ok := arm64.ADD64Register(raw); ok {
		if rd < 31 && rn < 31 && isObjectClass(tc.state[rn].Kind) {
			if tc.ctx != nil {
				if heapReg, heapShift, ok := sdk.ARM64PointerDecompressionSpec(tc.ctx.DartVersion); ok &&
					rm == heapReg && shift == arm64.ShiftLSL && amount == heapShift {
					tc.state[rd] = tc.state[rn]
					return true
				}
			}
			// Any other transformed/additional operand changes the value. Do not
			// silently discard it and fabricate a dispatch index from rn alone.
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
	if base, rt, imm9, ok := arm64.LDUR64(raw); ok {
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
		// X15-relative 64-bit loads are consumed earlier by handleStackLoad,
		// which tracks pre/post-index writeback in a stable FP-relative coordinate.
		if base < 31 && isObjectClass(tc.state[base].Kind) {
			if imm9 == -1 {
				if cid, exact := exactObjectClassID(tc.state[base]); exact {
					tc.state[rt] = ExactHeaderTags(cid)
				} else {
					tc.state[rt] = UnknownHeaderTags()
				}
				tc.ctx.hitMetric(metricHeader, tc.inst.Addr, &tc.ctx.HeaderHits)
				return true
			}
			recordFieldAccess(tc.result, tc.ctx, tc.state[base].ClassID, int32(imm9), false, tc.inst.Addr)
			if fieldType, ok2 := tc.ctx.FieldValueType(tc.state[base].ClassID, int32(imm9), tc.inst.Addr); ok2 {
				tc.state[rt] = fieldType
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
		if base < 31 {
			if lat, ok := ResolveClosureField(tc.ctx, tc.state[base], imm9); ok {
				tc.state[rt] = lat
				return true
			}
		}
		if imm9 == -1 && base < 31 {
			tc.state[rt] = UnknownHeaderTags()
			tc.ctx.hitMetric(metricHeader, tc.inst.Addr, &tc.ctx.HeaderHits)
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
			// No supported Dart CodeRange in the 93-sample corpus uses a halfword
			// X15 stack load. The old immediate-only slot key ignored X15 movement
			// and was unsound, so unsupported shapes fail closed instead.
			tc.state[rt] = Top()
			return true
		}
		if imm9 == 1 && base < 31 {
			if cid, exact := exactObjectClassID(tc.state[base]); exact {
				tc.state[rt] = ExactClassID(cid)
			} else {
				tc.state[rt] = UnknownClassID()
			}
			tc.ctx.hitMetric(metricHeader, tc.inst.Addr, &tc.ctx.HeaderHits)
			return true
		}
		if base < 31 && isObjectClass(tc.state[base].Kind) {
			recordFieldAccess(tc.result, tc.ctx, tc.state[base].ClassID, int32(imm9), false, tc.inst.Addr)
			if fieldType, ok2 := tc.ctx.FieldValueType(tc.state[base].ClassID, int32(imm9), tc.inst.Addr); ok2 {
				tc.state[rt] = fieldType
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
			// Likewise, no supported Dart CodeRange emits an unscaled 32-bit
			// X15 stack load. Do not fabricate a slot identity from imm9 alone.
			tc.state[rt] = Top()
			return true
		}
		if base < 31 && isObjectClass(tc.state[base].Kind) {
			recordFieldAccess(tc.result, tc.ctx, tc.state[base].ClassID, int32(imm9), false, tc.inst.Addr)
			if fieldType, ok2 := tc.ctx.FieldValueType(tc.state[base].ClassID, int32(imm9), tc.inst.Addr); ok2 {
				tc.state[rt] = fieldType
				return true
			}
			// An unknown object field is not evidence that the field has the
			// receiver's class. The old fallback fabricated self-typed fields and
			// turned them into authoritative dispatch facts downstream.
			tc.state[rt] = Top()
			return true
		}
		// Closure field via compressed LDUR32.
		if base < 31 {
			if lat, ok2 := ResolveClosureField(tc.ctx, tc.state[base], imm9); ok2 {
				tc.state[rt] = lat
				return true
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
			// Closure field via LDR64 unsigned offset.
			if lat, ok2 := ResolveClosureField(tc.ctx, tc.state[baseReg], byteOff); ok2 {
				tc.state[rt] = lat
				return true
			}
		} else if baseReg < 31 && baseReg != sdk.ARM64PP && baseReg != sdk.ARM64THR && baseReg != sdk.ARM64DT && baseReg != sdk.ARM64FrameReg && baseReg != sdk.ARM64SPReg {
			if isObjectClass(tc.state[baseReg].Kind) {
				recordFieldAccess(tc.result, tc.ctx, tc.state[baseReg].ClassID, int32(byteOff), false, tc.inst.Addr)
				if fieldType, ok2 := tc.ctx.FieldValueType(tc.state[baseReg].ClassID, int32(byteOff), tc.inst.Addr); ok2 {
					tc.state[rt] = fieldType
					return true
				}
				tc.state[rt] = Top()
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
			if isObjectClass(tc.state[baseReg].Kind) {
				recordFieldAccess(tc.result, tc.ctx, tc.state[baseReg].ClassID, int32(byteOff), false, tc.inst.Addr)
				if fieldType, ok2 := tc.ctx.FieldValueType(tc.state[baseReg].ClassID, int32(byteOff), tc.inst.Addr); ok2 {
					tc.state[rt] = fieldType
					return true
				}
				tc.state[rt] = Top()
				return true
			}
		}
	}

	return false
}
