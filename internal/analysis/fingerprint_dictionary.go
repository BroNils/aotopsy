package analysis

import (
	"fmt"

	"aotopsy/internal/cluster"
	comparepkg "aotopsy/internal/decompiler/compare"
	"aotopsy/internal/naming"
)

// applyFingerprintDictionary mutates the shared naming source before disasm so
// every downstream artifact sees the same recovered name. It deliberately
// refuses to rename functions that already have a semantic name and refuses a
// target-owner contradiction even when raw machine-code hashes collide.
func applyFingerprintDictionary(
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
	if pl.CodeNames == nil {
		pl.CodeNames = make(map[int]naming.CodeNameInfo)
	}
	if pl.CodeRefDisplay == nil {
		pl.CodeRefDisplay = make(map[int]string)
	}
	recovered := 0
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
		ci.FuncName = name
		if ci.OwnerName == "" {
			ci.OwnerName = owner
		}
		pl.CodeNames[r.RefID] = ci
		if ci.OwnerName != "" {
			pl.CodeRefDisplay[r.RefID] = ci.OwnerName + "." + ci.FuncName
		} else {
			pl.CodeRefDisplay[r.RefID] = ci.FuncName
		}
		recovered++
	}
	return recovered, nil
}
