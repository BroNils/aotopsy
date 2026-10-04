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
		if rn < 31 && tc.state[rn].Kind == LatticeExactHeaderTags {
			tc.state[rd] = ExactClassID(tc.state[rn].ClassID)
			tc.ctx.hitMetric(metricUBFX, tc.inst.Addr, &tc.ctx.UBFXHits)
			return true
		}
		if rn < 31 && tc.state[rn].Kind == LatticeUnknownHeaderTags {
			tc.state[rd] = UnknownClassID()
			tc.ctx.hitMetric(metricUBFX, tc.inst.Addr, &tc.ctx.UBFXHits)
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
		_ = isAllocation // generic indirect allocation has no per-class result fact.
		killDartCallClobbered(tc.state, tc.ctx.DartVersion, true)
		return true
	}
	return false
}

// handleBL handles case 8: BL — direct call with callee exit type propagation.
func handleBL(tc *transferCtx) bool {
	raw := tc.inst.Raw
	if target, ok := arm64.BL(raw, tc.inst.Addr); ok {
		tc.ctx.recordBLReturnMetric(tc.inst.Addr, blReturnMetricNone)
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
			tc.ctx.hitMetric(metricAllocStub, tc.inst.Addr, &tc.ctx.AllocStubHits)
			killDartCallClobbered(tc.state, tc.ctx.DartVersion, true)
			if allocABI, abiOK := sdk.AllocateObjectRegs(tc.ctx.DartVersion, sdk.ArchARM64); abiOK {
				tc.state[allocABI.ResultReg] = ExactClass(cid)
			}
			return true
		}

		calleeAllExit, hasFull := tc.ctx.CalleeAllExitTypes[target]
		if hasFull {
			ret := calleeAllExit[0]
			if ret.Kind == LatticeTop || ret.Kind == LatticeBottom {
				if seeded, ok := tc.ctx.CalleeExitTypes[target]; ok && seeded.Kind != LatticeTop && seeded.Kind != LatticeBottom {
					ret = seeded
				}
			}
			if ret.Kind != LatticeTop && ret.Kind != LatticeBottom {
				if isObjectClass(ret.Kind) {
					tc.ctx.recordBLReturnMetric(tc.inst.Addr, blReturnMetricObject)
				} else {
					tc.ctx.recordBLReturnMetric(tc.inst.Addr, blReturnMetricNonObject)
				}
			} else {
				ret = Top()
			}
			// A callee's exit register file is not the caller's post-call
			// register file. Only the ABI return register crosses the call
			// boundary; argument/caller-clobbered registers become unknown.
			killDartCallClobbered(tc.state, tc.ctx.DartVersion, true)
			tc.state[0] = ret
		} else {
			calleeExit := tc.ctx.CalleeExitTypes[target]
			if calleeExit.Kind != LatticeTop && calleeExit.Kind != LatticeBottom {
				if isObjectClass(calleeExit.Kind) {
					tc.ctx.recordBLReturnMetric(tc.inst.Addr, blReturnMetricObject)
				} else {
					tc.ctx.recordBLReturnMetric(tc.inst.Addr, blReturnMetricNonObject)
				}
				killDartCallClobbered(tc.state, tc.ctx.DartVersion, true)
				tc.state[0] = calleeExit
			} else {
				killDartCallClobbered(tc.state, tc.ctx.DartVersion, true)
			}
		}
		return true
	}
	return false
}

func killDartCallClobbered(state *[31]TypeLattice, dartVersion string, isARM64 bool) {
	regs, ok := sdk.DartCallClobberedGPRs(dartVersion, isARM64)
	if !ok {
		// Unknown ABI: no register fact is safe across an ordinary Dart call.
		for i := range state {
			state[i] = Top()
		}
		return
	}
	for _, r := range regs {
		if r >= 0 && r < len(state) {
			state[r] = Top()
		}
	}
}
