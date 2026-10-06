package typetrack

import (
	"sort"
	"strings"
)

// appendKnownStubResolution converts every named KnownStub form produced by
// ResolvePoolEntry into one indirect-call record. It is shared by ARM64 BLR and
// x86 CALL-reg so the same pool fact cannot be resolvable on one architecture
// and silently ignored on the other.
func appendKnownStubResolution(t TypeLattice, pc uint64, reg int, ctx *TypeContext, result *IntraResult) bool {
	if t.Kind != LatticeKnownStub || t.StubName == "" {
		return false
	}
	sn := t.StubName
	if strings.HasPrefix(sn, "Allocate") || strings.HasPrefix(sn, "allocate") {
		return false
	}
	if strings.HasPrefix(sn, "UnlinkedCall:") {
		// A `dyn:foo` call resolves to a dyn:foo forwarder if the class has one,
		// else to the function `foo`: Resolver::ResolveDynamic* demangles the
		// name with DemangleDynamicInvocationForwarderName before the lookup
		// (resolver.cc, same logic at 2.12.0 and 3.9.2, present in every
		// supported version). The implementations are therefore those of `foo`.
		methodName := strings.TrimPrefix(strings.TrimPrefix(sn, "UnlinkedCall:"), "dyn:")
		if selectorImms := ctx.MethodNameToSelectorImms[methodName]; len(selectorImms) > 0 {
			res := BlrResolution{PC: pc, Reg: reg, SlotIndex: -1, Confidence: ResolutionStaticInferred, Derivation: DerivationUnlinkedCall}
			seen := make(map[string]bool)
			var targets []string
			for _, imm := range selectorImms {
				for _, target := range ctx.selectorCandidates(imm) {
					if target != "" && !seen[target] {
						seen[target] = true
						targets = append(targets, target)
					}
				}
			}
			sort.Strings(targets)
			applySelectorCandidates(&res, targets)
			if res.Polymorphic {
				res.Confidence = ResolutionPolymorphic
			}
			recordBLRResolution(result, res)
			return true
		}
		// A selector leaf is not a callee identity. Without an independently
		// recovered selector offset we cannot know which implementation receives
		// the call, so leave the site unresolved instead of emitting `foo` as if it
		// were a concrete function.
		return false
	}
	if strings.HasPrefix(sn, "PPCode:") {
		recordBLRResolution(result, BlrResolution{PC: pc, Reg: reg, TargetName: strings.TrimPrefix(sn, "PPCode:"), Resolved: true, Confidence: ResolutionStub, Derivation: DerivationStub})
		return true
	}
	if strings.HasPrefix(sn, "TTS:") {
		recordBLRResolution(result, BlrResolution{PC: pc, Reg: reg, TargetName: strings.TrimPrefix(sn, "TTS:"), Resolved: true, Confidence: ResolutionStub, Derivation: DerivationStub})
		return true
	}
	if sn == "Closure" || sn == "ClosureEntry" {
		if name := ctx.PoolClosureFunctionNames[t.StubOff]; name != "" {
			recordBLRResolution(result, BlrResolution{PC: pc, Reg: reg, TargetName: name, Resolved: true, Confidence: ResolutionStub, Derivation: DerivationStub})
			return true
		}
		return false
	}
	// Raw THR field names include data/code-object fields as well as callable
	// entry-point addresses. Only the entry-point form is a proven direct control
	// target when loaded and branched to as-is.
	if strings.Contains(sn, "entry_point") || strings.HasSuffix(sn, "_entry") {
		recordBLRResolution(result, BlrResolution{PC: pc, Reg: reg, TargetName: sn, Resolved: true, Confidence: ResolutionStub, Derivation: DerivationStub})
		return true
	}
	return false
}
