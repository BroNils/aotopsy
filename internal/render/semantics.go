package render

import (
	"fmt"
	"slices"
	"strings"

	"aotopsy/internal/disasm"
)

// callSiteSemantics is the renderer-facing interpretation of one call-site
// record. Static and runtime evidence stay on separate axes: a runtime
// observation never becomes a static callee merely because it was seen once.
type callSiteSemantics struct {
	StaticTargets       []string
	RawTarget           string
	CandidateCount      int
	CandidateCountKnown bool
	TargetsComplete     bool
	Unresolved          bool
	RuntimeTargets      []disasm.RuntimeTargetObservation
	RuntimeAgreement    disasm.RuntimeAgreement
}

func inspectCallSite(e disasm.CallEdgeRecord) callSiteSemantics {
	var out callSiteSemantics

	if e.Target != "" {
		if isRawCallAddress(e.Target) {
			out.RawTarget = e.Target
		} else {
			out.StaticTargets = []string{e.Target}
		}
		out.CandidateCount = e.Candidates
		if out.CandidateCount == 0 && len(out.StaticTargets) > 0 {
			out.CandidateCount = 1
		}
		out.CandidateCountKnown = true
		out.TargetsComplete = true
	} else if len(e.Targets) > 0 {
		seen := make(map[string]bool, len(e.Targets))
		for _, target := range e.Targets {
			if target == "" || isRawCallAddress(target) || seen[target] {
				continue
			}
			seen[target] = true
			out.StaticTargets = append(out.StaticTargets, target)
		}
		slices.Sort(out.StaticTargets)
		out.CandidateCount = e.Candidates
		out.CandidateCountKnown = e.Candidates > 0
		if out.CandidateCount < len(out.StaticTargets) {
			// A malformed/stale producer count must never make the rendered set look
			// more complete than the evidence actually present in the record.
			out.CandidateCount = len(out.StaticTargets)
		}
		out.TargetsComplete = out.CandidateCountKnown && e.Candidates == len(out.StaticTargets)
	} else if isDirectCallKind(e.Kind) && e.TargetAddress != "" {
		out.RawTarget = e.TargetAddress
		out.TargetsComplete = true
	} else if e.Kind == "blr" || e.Kind == "call_indirect" {
		out.Unresolved = true
	}

	if e.Runtime != nil {
		out.RuntimeAgreement = e.Runtime.Agreement
		out.RuntimeTargets = append([]disasm.RuntimeTargetObservation(nil), e.Runtime.Targets...)
		slices.SortFunc(out.RuntimeTargets, func(a, b disasm.RuntimeTargetObservation) int {
			if a.Target < b.Target {
				return -1
			}
			if a.Target > b.Target {
				return 1
			}
			if a.Count < b.Count {
				return -1
			}
			if a.Count > b.Count {
				return 1
			}
			return 0
		})
	}
	return out
}

func (s callSiteSemantics) omittedCandidates() int {
	if !s.CandidateCountKnown {
		return 0
	}
	if s.CandidateCount <= len(s.StaticTargets) {
		return 0
	}
	return s.CandidateCount - len(s.StaticTargets)
}

func (s callSiteSemantics) candidateCountUnknown() bool {
	return len(s.StaticTargets) > 0 && !s.CandidateCountKnown
}

func callSiteKey(e disasm.CallEdgeRecord, suffix string) string {
	return "\x00callsite\x00" + e.FromFunc + "\x00" + strings.ToLower(strings.TrimSpace(e.FromPC)) + "\x00" + suffix
}

func callSitePopulationKey(e disasm.CallEdgeRecord, ordinal int) string {
	pc := strings.ToLower(strings.TrimSpace(e.FromPC))
	if pc == "" {
		return fmt.Sprintf("%s\x00<missing-pc:%d>\x00%s", e.FromFunc, ordinal, e.Kind)
	}
	return e.FromFunc + "\x00" + pc + "\x00" + e.Kind
}

func callSitePC(e disasm.CallEdgeRecord) string {
	pc := strings.TrimSpace(e.FromPC)
	if pc == "" {
		return "unknown pc"
	}
	return pc
}

func unresolvedCallSiteLabel(e disasm.CallEdgeRecord) string {
	label := fmt.Sprintf("unresolved indirect @ %s", callSitePC(e))
	if via := strings.TrimSpace(e.Via); via != "" {
		label += "\nvia " + via
	}
	return label
}

func incompleteCallSiteLabel(e disasm.CallEdgeRecord, omitted int) string {
	return fmt.Sprintf("+%d unlisted candidates @ %s", omitted, callSitePC(e))
}

func unknownCandidateCountLabel(e disasm.CallEdgeRecord) string {
	return fmt.Sprintf("candidate count unknown @ %s", callSitePC(e))
}

func unsupportedCallKindLabel(e disasm.CallEdgeRecord) string {
	pc := strings.TrimSpace(e.FromPC)
	if pc == "" {
		pc = "unknown pc"
	}
	return fmt.Sprintf("unsupported call kind %q @ %s", e.Kind, pc)
}

func directAddressLabel(e disasm.CallEdgeRecord, target string) string {
	return fmt.Sprintf("direct target %s @ %s", target, callSitePC(e))
}
