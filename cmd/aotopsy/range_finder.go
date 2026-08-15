package main

import "aotopsy/internal/cluster"

// findRangeContainingVA returns the tightest CodeRange that contains
// targetVA, or nil if no range covers it. "Tightest" means the smallest
// range; ties prefer ranges with RefID >= 0 (real functions over stubs).
//
// This replaces the inline range-search loop that was duplicated in
// decompile_native_cmd.go, x64refs.go (dumpFuncDisasm), and x64refs.go
// (indirectInFunc).
func findRangeContainingVA(ranges []cluster.CodeRange, codeVA, codeOff, targetVA uint64) *cluster.CodeRange {
	var found *cluster.CodeRange
	for i := range ranges {
		r := &ranges[i]
		if r.Size == 0 {
			continue
		}
		funcStart := uint64(r.PCOffset) - codeOff
		funcVA := codeVA + funcStart
		if targetVA < funcVA || targetVA >= funcVA+uint64(r.Size) {
			continue
		}
		if found == nil || r.Size < found.Size || (r.Size == found.Size && r.RefID >= 0 && found.RefID < 0) {
			found = r
		}
	}
	return found
}
