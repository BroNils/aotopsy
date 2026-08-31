package typetrack

import (
	"sort"

	"aotopsy/internal/cluster"
)

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
