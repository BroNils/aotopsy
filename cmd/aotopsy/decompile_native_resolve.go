package main

// resolveArgRegIndices finds the common argument register indices from
// a set of register masks collected from call sites.
func resolveArgRegIndices(masks []uint8) ([]int, bool) {
	// Require at least TWO call sites to agree before claiming a declared arity
	// (audit C3): a single call site's ArgRegMask is explicitly documented as
	// unreliable (CallEdge.ArgCountHint). With fewer than two sites we return
	// "unresolved" and let the caller fall back to the honest intraprocedural
	// liveness heuristic rather than trusting one noisy site.
	if len(masks) < 2 {
		return nil, false
	}
	// For 2+ masks: count frequency of each bit across masks
	counts := make([]int, 8)
	for _, m := range masks {
		for i := 0; i < 8; i++ {
			if m&(1<<uint(i)) != 0 {
				counts[i]++
			}
		}
	}
	threshold := (len(masks) + 1) / 2 // at least 50% majority
	var idx []int
	for i := 0; i < 8; i++ {
		if counts[i] >= threshold {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		core := masks[0]
		for _, m := range masks[1:] {
			core &= m
		}
		for i := 0; i < 8; i++ {
			if core&(1<<uint(i)) != 0 {
				idx = append(idx, i)
			}
		}
	}
	if len(idx) == 0 {
		return nil, false
	}
	return idx, true
}
