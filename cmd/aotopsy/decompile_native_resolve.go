package main

// resolveArgRegIndices finds the common argument register indices from
// a set of register masks collected from call sites.
func resolveArgRegIndices(masks []uint8) ([]int, bool) {
	if len(masks) == 0 {
		return nil, false
	}
	if len(masks) == 1 {
		if masks[0] == 0 {
			return nil, false
		}
		var idx []int
		for i := 0; i < 8; i++ {
			if masks[0]&(1<<uint(i)) != 0 {
				idx = append(idx, i)
			}
		}
		return idx, len(idx) > 0
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
