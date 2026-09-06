package cluster

// FindRangeContainingVA returns the tightest CodeRange that contains
// targetVA, or nil if no range covers it. "Tightest" means the smallest
// range; ties prefer ranges with RefID >= 0 (real functions over stubs).
//
// This replaces the inline range-search loop that was duplicated in
// decompile_native_cmd.go, x64refs.go (dumpFuncDisasm), and x64refs.go
// (indirectInFunc).
func FindRangeContainingVA(ranges []CodeRange, codeVA, codeOff, targetVA uint64) *CodeRange {
	im := CodeImage{CodeVA: codeVA, CodeOff: codeOff}
	var found *CodeRange
	for i := range ranges {
		r := &ranges[i]
		funcVA, ok := im.FuncVA(*r)
		if !ok {
			continue
		}
		if targetVA < funcVA || targetVA >= funcVA+uint64(r.Size) {
			continue
		}
		if found == nil || r.Size < found.Size || (r.Size == found.Size && r.RefID >= 0 && found.RefID < 0) {
			found = r
		}
	}
	return found
}
