package analysis

import (
	"fmt"

	"aotopsy/internal/cluster"
	comparepkg "aotopsy/internal/decompiler/compare"
	"aotopsy/internal/naming"
)

// countFingerprintDictionaryCandidates compares unnamed target functions to a
// version/architecture-pinned bytes-only dictionary. A match is a HEURISTIC
// candidate, never authoritative naming evidence: identical instructions can
// read different object-pool contents in different binaries, and tiny functions
// in the same owner can legitimately compile to identical bytes. Consequently
// this function must not mutate PoolLookups.CodeNames/CodeRefDisplay.
func countFingerprintDictionaryCandidates(
	pl *naming.PoolLookups,
	ranges []cluster.CodeRange,
	code []byte,
	codeOff, codeVA uint64,
	dict *comparepkg.FunctionDictionary,
) (int, error) {
	if pl == nil || dict == nil {
		return 0, fmt.Errorf("nil pool lookups or dictionary")
	}
	image := cluster.CodeImage{Code: code, CodeVA: codeVA, CodeOff: codeOff}
	candidates := 0
	for _, r := range ranges {
		if r.RefID < 0 {
			continue // VM/isolate stubs are not Dart Function naming seeds.
		}
		ci := pl.CodeNames[r.RefID]
		if ci.FuncName != "" {
			continue
		}
		body, _, ok := image.SliceExact(r)
		if !ok {
			return 0, fmt.Errorf("range pc=0x%x size=%d falls outside code image", r.PCOffset, r.Size)
		}
		name, owner, ok := dict.LookupCode(body)
		if !ok || name == "" {
			continue
		}
		if owner != "" && ci.OwnerName != "" && owner != ci.OwnerName {
			// Same bytes can occur in tiny/trivial functions. Existing snapshot
			// ownership is stronger evidence than a cross-sample hash.
			continue
		}
		candidates++
	}
	return candidates, nil
}
