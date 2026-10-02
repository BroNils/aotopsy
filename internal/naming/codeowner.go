package naming

import (
	"aotopsy/internal/cluster"
	"aotopsy/internal/snapshot"
)

// isAllocationStubOwner reports whether a Code's owner makes it the allocation
// stub for a class.
func isAllocationStubOwner(owner *cluster.NamedObject, ct *snapshot.CIDTable) bool {
	return owner != nil && ct != nil && ct.Class != 0 && owner.CID == ct.Class
}

// CodeIndexToFunc maps a Code's ClusterIndex to its unambiguous owning
// Function NamedObject via the Function->CodeIndex direction.
//
// The serialized Function field changed domains at Dart 2.16.0:
//
//   - <=2.15: it is the absolute snapshot reference ID of the Code object
//     (`d->Ref(code_index)`). Resolve that ref through Result.Codes first.
//
//   - >=2.16: it is a one-based InstructionsTable slot, not a Code-cluster
//     index. The VM's Deserializer::CodeIndexToClusterIndex conversion is:
//
//     code_index - 1 - first_entry_with_code
//
// Exact SDK boundary: clustered_snapshot.cc/app_snapshot.cc @2.15.0 reads the
// field with d->Ref(code_index), while @2.16.0 serializes GetCodeIndex(code) and
// defines CodeIndexToClusterIndex. firstEntryWithCode must therefore be supplied
// in the one-based era. Pass -1 when unavailable; mapping is then deliberately
// disabled rather than fabricated in the wrong numbering domain.
func CodeIndexToFunc(result *cluster.Result, ct *snapshot.CIDTable, codeIndexOneBased bool, firstEntryWithCode int) map[int]*cluster.NamedObject {
	if result == nil || ct == nil {
		return nil
	}
	if codeIndexOneBased && firstEntryWithCode < 0 {
		return nil
	}
	legacyCodeRefToCluster := make(map[int]int, len(result.Codes))
	legacyAmbiguousRef := make(map[int]bool)
	if !codeIndexOneBased {
		for i := range result.Codes {
			code := &result.Codes[i]
			if code.RefID <= cluster.RefNull || code.ClusterIndex < 0 {
				continue
			}
			if _, exists := legacyCodeRefToCluster[code.RefID]; exists {
				legacyAmbiguousRef[code.RefID] = true
				continue
			}
			legacyCodeRefToCluster[code.RefID] = code.ClusterIndex
		}
		for ref := range legacyAmbiguousRef {
			delete(legacyCodeRefToCluster, ref)
		}
	}
	m := make(map[int]*cluster.NamedObject)
	ambiguous := make(map[int]bool)
	for i := range result.Named {
		no := &result.Named[i]
		if no.CID != ct.Function || no.CodeIndex < 0 {
			continue
		}
		clusterIdx := -1
		if codeIndexOneBased {
			clusterIdx = no.CodeIndex - 1 - firstEntryWithCode
		} else {
			var ok bool
			clusterIdx, ok = legacyCodeRefToCluster[no.CodeIndex]
			if !ok {
				continue
			}
		}
		if clusterIdx < 0 {
			continue
		}
		if _, exists := m[clusterIdx]; exists {
			ambiguous[clusterIdx] = true
			continue
		}
		m[clusterIdx] = no
	}
	for idx := range ambiguous {
		delete(m, idx)
	}
	return m
}

// ResolveCodeOwner finds the Function/Closure/FfiTrampolineData
// NamedObject that owns ce, preferring the reliable CodeIndex
// cross-reference over the documented-unreliable Code.OwnerRef.
func ResolveCodeOwner(ce cluster.CodeEntry, refToNamed map[int]*cluster.NamedObject, byCodeIndex map[int]*cluster.NamedObject, ct *snapshot.CIDTable) (*cluster.NamedObject, bool) {
	if ce.ClusterIndex >= 0 {
		if owner, ok := byCodeIndex[ce.ClusterIndex]; ok {
			return owner, true
		}
	}
	if ce.OwnerRef <= 0 {
		return nil, false
	}
	owner, ok := refToNamed[ce.OwnerRef]
	if !ok || owner == nil || ct == nil {
		return nil, false
	}
	// Code::set_owner permits Function, Class, or AbstractType. AbstractType
	// owners are type-testing stubs and deliberately do not use this fallback:
	// they are resolved through the exact Type/TypeParameter naming path. A
	// NamedObject of any other CID here is a malformed/stale OwnerRef and must
	// not become a plausible function label.
	isFunction := ct.Function != 0 && owner.CID == ct.Function
	isClass := ct.Class != 0 && owner.CID == ct.Class
	if !isFunction && !isClass {
		return nil, false
	}
	return owner, true
}
