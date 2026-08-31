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
func CodeIndexToFunc(result *cluster.Result, ct *snapshot.CIDTable, codeIndexOneBased bool) map[int]*cluster.NamedObject {
	if ct == nil {
		return nil
	}
	m := make(map[int]*cluster.NamedObject)
	ambiguous := make(map[int]bool)
	for i := range result.Named {
		no := &result.Named[i]
		if no.CID != ct.Function || no.CodeIndex < 0 {
			continue
		}
		clusterIdx := no.CodeIndex
		if codeIndexOneBased {
			clusterIdx = no.CodeIndex - 1
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
func ResolveCodeOwner(ce cluster.CodeEntry, refToNamed map[int]*cluster.NamedObject, byCodeIndex map[int]*cluster.NamedObject) (*cluster.NamedObject, bool) {
	if ce.ClusterIndex >= 0 {
		if owner, ok := byCodeIndex[ce.ClusterIndex]; ok {
			return owner, true
		}
	}
	if ce.OwnerRef <= 0 {
		return nil, false
	}
	owner, ok := refToNamed[ce.OwnerRef]
	return owner, ok
}
