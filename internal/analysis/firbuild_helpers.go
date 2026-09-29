package analysis

import (
	"aotopsy/internal/cluster"
	"aotopsy/internal/naming"
)

// BuildFieldTypeByClassOffset maps (ownerClassID, field byte offset) -> the
// field's declared type's class ID. This types field-load chains (`this.a.b`):
// loading field `a` of a known class yields an object whose class is `a`'s
// declared type, so the next `.b` resolves. Only populated where the type
// resolves to a concrete class; elsewhere it stays unknown (honest).
//
// Shared by Context.ensureDecompileMaps and the cmd funcIRBuilder so both the
// pipeline and cmd decompile paths type field chains identically instead of one
// silently lacking it.
func BuildFieldTypeByClassOffset(result *cluster.Result, pl *naming.PoolLookups, compressedPtrs bool) map[int]map[int64]int {
	wordSize := int64(8)
	if compressedPtrs {
		wordSize = 4
	}
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
	owners := NewLibraryResolver(result, pl)
	for i := range result.Fields {
		f := &result.Fields[i]
		if f.HostOffset < 0 || f.TypeRefID < 0 {
			continue
		}
		// Field.host_offset_or_field_id is serialized as a reference. For an
		// instance field that ref resolves to a Smi/Mint containing the WORD
		// offset; it is not itself the byte offset. Keep this coordinate system
		// identical to BuildClassLayouts and typetrack.FieldByOwnerOffset.
		wordOff, ok := result.MintValues[int(f.HostOffset)]
		if !ok || wordOff < 0 {
			continue
		}
		tc, ok := typeClassByRef[f.TypeRefID]
		if !ok || tc <= 0 {
			continue
		}
		ownerClass, ok := classByRef[owners.EffectiveClassRef(f.OwnerRefID)]
		if !ok || ownerClass.ClassID <= 0 {
			continue
		}
		ocid := int(ownerClass.ClassID)
		if out[ocid] == nil {
			out[ocid] = map[int64]int{}
		}
		out[ocid][wordOff*wordSize] = int(tc)
	}
	return out
}

// BuildClassNameToID maps a class name to its class ID, from class layouts.
// Shared by both FuncIR-building paths so the decompiler's explicit-type
// injection (which resolves a class name to an ID) works identically.
func BuildClassNameToID(layouts []DartClassLayout) map[string]int {
	m := make(map[string]int, len(layouts))
	ambiguous := make(map[string]bool)
	for _, cl := range layouts {
		if cl.ClassName == "" || cl.ClassID <= 0 || ambiguous[cl.ClassName] {
			continue
		}
		if existing, ok := m[cl.ClassName]; ok && existing != int(cl.ClassID) {
			delete(m, cl.ClassName)
			ambiguous[cl.ClassName] = true
			continue
		}
		m[cl.ClassName] = int(cl.ClassID)
	}
	return m
}
