package analysis

import "aotopsy/internal/cluster"

// BuildFieldTypeByClassOffset maps (ownerClassID, field byte offset) -> the
// field's declared type's class ID. This types field-load chains (`this.a.b`):
// loading field `a` of a known class yields an object whose class is `a`'s
// declared type, so the next `.b` resolves. Only populated where the type
// resolves to a concrete class; elsewhere it stays unknown (honest).
//
// Shared by Context.ensureDecompileMaps and the cmd funcIRBuilder so both the
// pipeline and cmd decompile paths type field chains identically instead of one
// silently lacking it.
func BuildFieldTypeByClassOffset(result *cluster.Result) map[int]map[int64]int {
	classByRef := make(map[int]*cluster.ClassInfo, len(result.Classes))
	for i := range result.Classes {
		classByRef[result.Classes[i].RefID] = &result.Classes[i]
	}
	typeClassByRef := make(map[int]int32, len(result.Types))
	for i := range result.Types {
		if result.Types[i].ClassID > 0 {
			typeClassByRef[result.Types[i].RefID] = result.Types[i].ClassID
		}
	}
	out := map[int]map[int64]int{}
	for i := range result.Fields {
		f := &result.Fields[i]
		if f.HostOffset < 0 || f.TypeRefID < 0 {
			continue
		}
		tc, ok := typeClassByRef[f.TypeRefID]
		if !ok || tc <= 0 {
			continue
		}
		ownerClass, ok := classByRef[f.OwnerRefID]
		if !ok || ownerClass.ClassID <= 0 {
			continue
		}
		ocid := int(ownerClass.ClassID)
		if out[ocid] == nil {
			out[ocid] = map[int64]int{}
		}
		out[ocid][int64(f.HostOffset)] = int(tc)
	}
	return out
}

// BuildClassNameToID maps a class name to its class ID, from class layouts.
// Shared by both FuncIR-building paths so the decompiler's explicit-type
// injection (which resolves a class name to an ID) works identically.
func BuildClassNameToID(layouts []DartClassLayout) map[string]int {
	m := make(map[string]int, len(layouts))
	for _, cl := range layouts {
		if cl.ClassName != "" && cl.ClassID > 0 {
			m[cl.ClassName] = int(cl.ClassID)
		}
	}
	return m
}

// ResolveArgRegIndices decides a confident real arity from a callee's aggregated
// per-call-site ArgRegMask values (one mask per direct call site targeting it):
// a bit that is set in a majority of call sites (falling back to the bitwise-AND
// intersection) is a real argument register. Fewer than two call sites is
// unresolvable -- a single mask is documented-unreliable noise. Returns the
// argument register indices and whether they are trustworthy. Shared by both
// FuncIR-building paths.
//
// Two sites are required because a single mask is call-site-specific noise: on a
// real sample _CompareHomePageState._runAll (one call site) gave a DIFFERENT arg
// count on ARM64 vs x86_64 for the SAME Dart function -- real arity cannot differ
// by architecture, so one single-sample answer was wrong. The AND-intersection
// fallback recovers the consistent signal when sites disagree on noise bits
// (MathTools.factorial: recursion mask 0b11 & the _runAll mask 0b10 = 0b10, the
// real X1-only argument).
func ResolveArgRegIndices(masks []uint8) ([]int, bool) {
	if len(masks) < 2 {
		return nil, false
	}
	counts := make([]int, 8)
	for _, m := range masks {
		for i := 0; i < 8; i++ {
			if m&(1<<uint(i)) != 0 {
				counts[i]++
			}
		}
	}
	threshold := (len(masks) + 1) / 2
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
