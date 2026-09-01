package typetrack

import (
	"strings"

	"aotopsy/internal/arch/arm64"
)

// handleUBFX handles case 5b-ubfx: UBFX/UBFM bitfield extract for class ID.
func handleUBFX(tc *transferCtx) bool {
	raw := tc.inst.Raw
	if rd, rn, _, _, ok := arm64.UBFX(raw); ok {
		if rd >= 31 {
			return true
		}
		if rn < 31 && tc.state[rn].Kind == LatticeKnownClass {
			tc.state[rd] = tc.state[rn]
			tc.ctx.UBFXHits++
			return true
		}
		// UBFX from Bottom: extracting class ID bits from an unknown
		// header still yields "a class ID, but unknown which one" —
		// Bottom, not Top. The previous code only preserved Bottom
		// when the immediately preceding instruction was a LDUR at
		// offset -1, which missed cases with intervening instructions
		// (e.g., LDR W0, [X1, #-1] → MOV W2, W0 → UBFX W0, W2, ...).
		// Bottom is strictly more useful than Top: it enables narrowing
		// via CMP+BEQ downstream, and it enables SelectorDispatch
		// (selector-only) instead of Top (no info at all) at the ADD.
		if rn < 31 && tc.state[rn].Kind == LatticeBottom {
			tc.state[rd] = Bottom()
			tc.ctx.UBFXHits++
			return true
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
	if rd, ok := arm64.MOVOrr(raw); ok {
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
	if rn, ok := arm64.BLR(raw); ok {
		if rn < 31 {
			resolveBLR(tc.state, rn, tc.inst, tc.ctx, tc.result)
		}
		if rn < 31 && tc.state[rn].Kind == LatticeKnownStub {
			sn := tc.state[rn].StubName
			if strings.HasPrefix(sn, "UnlinkedCall:") {
				methodName := sn[len("UnlinkedCall:"):]
				if selectorOffsets, hasOffsets := tc.ctx.MethodNameToSelectorOffsets[methodName]; hasOffsets && len(selectorOffsets) > 0 {
					res := BlrResolution{
						PC: tc.inst.Addr, Reg: rn, SlotIndex: -1,
						Confidence: "static_inferred",
					}
					var allTargets []string
					for _, selOff := range selectorOffsets {
						allTargets = append(allTargets, tc.ctx.selectorCandidates(selOff)...)
					}
					applySelectorCandidates(&res, allTargets)
					if res.Polymorphic {
						res.Confidence = "polymorphic"
					}
					tc.result.BLRResolutions = append(tc.result.BLRResolutions, res)
				} else {
					tc.result.BLRResolutions = append(tc.result.BLRResolutions, BlrResolution{
						PC: tc.inst.Addr, Reg: rn, TargetName: methodName, Resolved: true,
						Confidence: "stub",
					})
				}
			} else if strings.HasPrefix(sn, "PPCode:") {
				funcName := sn[len("PPCode:"):]
				tc.result.BLRResolutions = append(tc.result.BLRResolutions, BlrResolution{
					PC: tc.inst.Addr, Reg: rn, TargetName: funcName, Resolved: true,
					Confidence: "stub",
				})
			} else if strings.HasPrefix(sn, "TTS:") {
				stubName := sn[len("TTS:"):]
				tc.result.BLRResolutions = append(tc.result.BLRResolutions, BlrResolution{
					PC: tc.inst.Addr, Reg: rn, TargetName: stubName, Resolved: true,
					Confidence: "stub",
				})
			} else if strings.HasPrefix(sn, "Closure:") || strings.HasPrefix(sn, "ClosureEntry:") {
				// ClosureEntry is the cached entry_point_ of the same
				// closure, and it is what the call actually branches to.
				// Both resolve through the same pool index.
				poolIdx := tc.state[rn].StubOff
				if tc.ctx.PoolClosureFunctionNames != nil {
					if funcName, ok := tc.ctx.PoolClosureFunctionNames[poolIdx]; ok && funcName != "" {
						tc.result.BLRResolutions = append(tc.result.BLRResolutions, BlrResolution{
							PC: tc.inst.Addr, Reg: rn, TargetName: funcName, Resolved: true,
							Confidence: "stub",
						})
					}
				}
			} else if sn != "" && !strings.HasPrefix(sn, "Allocate") && !strings.HasPrefix(sn, "allocate") {
				tc.result.BLRResolutions = append(tc.result.BLRResolutions, BlrResolution{
					PC: tc.inst.Addr, Reg: rn, TargetName: sn, Resolved: true,
					Confidence: "stub",
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
	if target, ok := arm64.BL(raw, tc.inst.Addr); ok {
		tc.ctx.BLTotal++
		if tc.result.BLCallSiteTypes == nil {
			tc.result.BLCallSiteTypes = make(map[uint64][31]TypeLattice)
		}
		var callSiteState [31]TypeLattice
		copy(callSiteState[:], tc.state[:])
		tc.result.BLCallSiteTypes[tc.inst.Addr] = callSiteState

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
