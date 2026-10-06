package analysis

import (
	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/naming"
)

// BuildCallSiteLookup resolves object-pool indices to the CallSiteData objects
// (UnlinkedCall / MegamorphicCache) stored there: selector from target_name,
// argument shape from the decoded args_descriptor. A call site whose descriptor
// does not decode is left out, so the decompiler never prints a call whose
// arity it cannot vouch for.
func BuildCallSiteLookup(result *cluster.Result, pl *naming.PoolLookups, dartVersion string) func(int) (decompiler.CallSite, bool) {
	decoder := cluster.NewArgsDescriptorDecoder(result, dartVersion)
	byRef := make(map[int]decompiler.CallSite, len(result.CallSites))
	for _, cs := range result.CallSites {
		selector, ok := pl.StringForRef(cs.TargetNameRef)
		if !ok || selector == "" {
			continue
		}
		desc, ok := decoder.Decode(cs.ArgsDescRef)
		if !ok {
			continue
		}
		site := decompiler.CallSite{
			Selector:    selector,
			Count:       desc.Count,
			TypeArgsLen: desc.TypeArgsLen,
			Positional:  desc.Positional,
		}
		complete := true
		for _, na := range desc.Named {
			name, ok := pl.StringForRef(na.NameRef)
			if !ok || name == "" {
				complete = false
				break
			}
			if site.NamedArgs == nil {
				site.NamedArgs = make(map[int]string, len(desc.Named))
			}
			site.NamedArgs[na.Position] = name
		}
		if complete {
			byRef[cs.RefID] = site
		}
	}
	byIndex := make(map[int]decompiler.CallSite, len(byRef))
	for _, pe := range result.Pool {
		if pe.Kind != cluster.PoolTagged {
			continue
		}
		if site, ok := byRef[pe.RefID]; ok {
			byIndex[pe.Index] = site
		}
	}
	return func(poolIndex int) (decompiler.CallSite, bool) {
		site, ok := byIndex[poolIndex]
		return site, ok
	}
}
