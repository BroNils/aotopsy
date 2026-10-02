package typetrack

import (
	"strings"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/sdk"
)

// handleUBFX handles case 5b-ubfx: UBFX/UBFM bitfield extract for class ID.
func handleUBFX(tc *transferCtx) bool {
	raw := tc.inst.Raw
	if rd, rn, lsb, width, ok := arm64.UBFX(raw); ok {
		// UBFM has several aliases (including LSR) with the same basic decode.
		// Only the exact ClassIdTag slice is evidence that the result is a class
		// id. Anything else is ordinary bit manipulation and must fall through to
		// the generic destination kill instead of copying a type fact.
		if lsb != tc.ctx.ClassIDTagPos || width != tc.ctx.ClassIDTagSize {
			return false
		}
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
	if rd, rm, ok := arm64.MOVOrr(raw); ok {
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
			// Generic allocation stubs return their object in R0. R0 is an
			// output register, not a class-id input (AllocateObjectABI uses R1
			// for type arguments and R2 for tags). Keeping the pre-call R0 fact
			// fabricated both an allocation class and the post-call return type.
			tc.state[0] = Top()
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

		// A call to a per-class allocation stub returns an instance of that
		// class, exactly. AllocateObjectABI::kResultReg is R0 on ARM64.
		// This is the structural answer -- Code.owner is the Class -- so it
		// takes precedence over any inferred exit type for the callee.
		if cid, ok := tc.ctx.AllocationStubCID[target]; ok {
			tc.ctx.AllocStubHits++
			tc.state[sdk.ARM64AllocResultReg] = KnownClass(cid)
			for r := 1; r <= 7; r++ {
				tc.state[r] = Top()
			}
			return true
		}

		calleeAllExit, hasFull := tc.ctx.CalleeAllExitTypes[target]
		if hasFull {
			ret := calleeAllExit[0]
			if ret.Kind == LatticeTop {
				if seeded, ok := tc.ctx.CalleeExitTypes[target]; ok && seeded.Kind != LatticeTop {
					ret = seeded
				}
			}
			tc.ctx.BLHasExitType++
			if ret.Kind == LatticeKnownClass {
				tc.ctx.BLExitKnown++
			} else if ret.Kind == LatticeBottom {
				tc.ctx.BLExitBottom++
			}
			// A callee's exit register file is not the caller's post-call
			// register file. Only the ABI return register crosses the call
			// boundary; argument/caller-clobbered registers become unknown.
			tc.state[0] = ret
			for r := 1; r <= 7; r++ {
				tc.state[r] = Top()
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
