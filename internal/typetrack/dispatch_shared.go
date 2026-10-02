package typetrack

import (
	"sort"
	"strings"

	"aotopsy/internal/cluster"
)

// appendKnownStubResolution converts every named KnownStub form produced by
// ResolvePoolEntry into one indirect-call record. It is shared by ARM64 BLR and
// x86 CALL-reg so the same pool fact cannot be resolvable on one architecture
// and silently ignored on the other.
func appendKnownStubResolution(t TypeLattice, pc uint64, reg int, ctx *TypeContext, result *IntraResult) bool {
	if t.Kind != LatticeKnownStub || t.StubName == "" {
		return false
	}
	sn := t.StubName
	if strings.HasPrefix(sn, "Allocate") || strings.HasPrefix(sn, "allocate") {
		return false
	}
	if strings.HasPrefix(sn, "UnlinkedCall:") {
		methodName := strings.TrimPrefix(sn, "UnlinkedCall:")
		if selectorImms := ctx.MethodNameToSelectorImms[methodName]; len(selectorImms) > 0 {
			res := BlrResolution{PC: pc, Reg: reg, SlotIndex: -1, Confidence: ResolutionStaticInferred, Derivation: DerivationUnlinkedCall}
			seen := make(map[string]bool)
			var targets []string
			for _, imm := range selectorImms {
				for _, target := range ctx.selectorCandidates(imm) {
					if target != "" && !seen[target] {
						seen[target] = true
						targets = append(targets, target)
					}
				}
			}
			sort.Strings(targets)
			applySelectorCandidates(&res, targets)
			if res.Polymorphic {
				res.Confidence = ResolutionPolymorphic
			}
			recordBLRResolution(result, res)
			return true
		}
		recordBLRResolution(result, BlrResolution{PC: pc, Reg: reg, TargetName: methodName, Resolved: true, Confidence: ResolutionStub, Derivation: DerivationStub})
		return true
	}
	if strings.HasPrefix(sn, "PPCode:") {
		recordBLRResolution(result, BlrResolution{PC: pc, Reg: reg, TargetName: strings.TrimPrefix(sn, "PPCode:"), Resolved: true, Confidence: ResolutionStub, Derivation: DerivationStub})
		return true
	}
	if strings.HasPrefix(sn, "TTS:") {
		recordBLRResolution(result, BlrResolution{PC: pc, Reg: reg, TargetName: strings.TrimPrefix(sn, "TTS:"), Resolved: true, Confidence: ResolutionStub, Derivation: DerivationStub})
		return true
	}
	if strings.HasPrefix(sn, "Closure:") || strings.HasPrefix(sn, "ClosureEntry:") {
		if name := ctx.PoolClosureFunctionNames[t.StubOff]; name != "" {
			recordBLRResolution(result, BlrResolution{PC: pc, Reg: reg, TargetName: name, Resolved: true, Confidence: ResolutionStub, Derivation: DerivationStub})
			return true
		}
		return false
	}
	recordBLRResolution(result, BlrResolution{PC: pc, Reg: reg, TargetName: sn, Resolved: true, Confidence: ResolutionStub, Derivation: DerivationStub})
	return true
}

// This file holds the dispatch-slot scanning logic shared between ARM64
// (resolveBLR in intraproc.go) and x86_64 (resolveX86Dispatch in
// intraprocx86.go). Both architectures scan nearby dispatch table slots
// when a direct slot lookup fails, using the same candidate-collection
// and deduplication rules.

const dispatchScanRange = 128

// scanDispatchSlots scans up to dispatchScanRange slots starting at baseSlot,
// collecting names of DispatchCode entries. Returns the candidate count,
// the single candidate name (when count==1), and all candidate names.
func scanDispatchSlots(ctx *TypeContext, baseSlot int) (candidates int, candidateName string, allCandidates []string) {
	if ctx.DispatchBySlot == nil {
		return
	}
	for offset := 0; offset < dispatchScanRange; offset++ {
		slot := baseSlot + offset
		entry, ok := ctx.DispatchBySlot[slot]
		if !ok || entry.Kind != cluster.DispatchCode {
			continue
		}
		if name, ok := ctx.DispatchCodeIndexToName[entry.ClusterIndex]; ok && name != "" {
			candidates++
			candidateName = name
			allCandidates = append(allCandidates, name)
		}
	}
	return
}

// applyDispatchCandidates sets the resolution fields from the scan result.
// One candidate → monomorphic; multiple → deduplicated candidate set.
// Identical names collapse to a monomorphic resolution.
func applyDispatchCandidates(res *BlrResolution, candidates int, candidateName string, allCandidates []string) {
	if candidates == 1 {
		res.TargetName = candidateName
		res.Resolved = true
		res.Candidates = 1
	} else if candidates > 1 {
		uniqueNames := map[string]bool{}
		var unique []string
		for _, n := range allCandidates {
			if !uniqueNames[n] {
				uniqueNames[n] = true
				unique = append(unique, n)
			}
		}
		sort.Strings(unique)
		applySelectorCandidates(res, unique)
	}
}
