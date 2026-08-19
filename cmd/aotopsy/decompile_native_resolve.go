package main

// resolveArgRegIndices finds the common argument register indices from
// a set of register masks. ANDs all masks together to find registers
// that are arguments in ALL functions, then returns their indices.
func resolveArgRegIndices(masks []uint8) ([]int, bool) {
	if len(masks) < 2 {
		return nil, false
	}
	core := masks[0]
	for _, m := range masks[1:] {
		core &= m
	}
	var idx []int
	for i := 0; i < 8; i++ { // L-4: 8 covers both ARM64 (X0-X7) and x86_64 (6 regs, bits 6-7 always 0)
		if core&(1<<uint(i)) != 0 {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		return nil, false
	}
	return idx, true
}
