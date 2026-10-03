package signal

import (
	"sort"
	"strconv"
	"strings"

	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
)

// ClassifiedStringRef is a string reference with its signal categories.
type ClassifiedStringRef struct {
	Func       string   `json:"func"`
	PC         string   `json:"pc"`
	Kind       string   `json:"kind"`
	PoolIdx    int      `json:"pool_idx"`
	Value      string   `json:"value"`
	Categories []string `json:"categories,omitempty"`
}

// SignalFunc is a function in the signal graph.
type SignalFunc struct {
	Name            string                `json:"name"`
	Owner           string                `json:"owner,omitempty"`
	PC              string                `json:"pc"`
	Size            int                   `json:"size"`
	StringRefs      []ClassifiedStringRef `json:"string_refs,omitempty"`
	Categories      []string              `json:"categories"`
	Severity        string                `json:"severity"` // "high", "medium", "low"
	Role            string                `json:"role"`     // "signal", "context", ""
	IsRootCandidate bool                  `json:"is_root_candidate,omitempty"`
}

const (
	ResolutionDirect               = "direct"
	ResolutionMonomorphic          = "monomorphic"
	ResolutionPolymorphicCandidate = "polymorphic_candidate"
	ResolutionUnresolved           = "unresolved"
	ResolutionAddressOnly          = "address_only"
	ResolutionRuntimeObserved      = "runtime_observed"
	ResolutionUnsupported          = "unsupported"
)

type signalEdgeKey struct {
	from, pc, to, kind, via, resolution, targetAddress string
	agreement                                          disasm.RuntimeAgreement
}

// SignalEdge is an edge in the signal graph.
type SignalEdge struct {
	From                string                  `json:"from"`
	FromPC              string                  `json:"from_pc"`
	To                  string                  `json:"to,omitempty"`
	Kind                string                  `json:"kind"` // "bl"/"call" (direct), "blr"/"call_indirect" (indirect)
	Via                 string                  `json:"via,omitempty"`
	TargetAddress       string                  `json:"target_address,omitempty"`
	Resolution          string                  `json:"resolution"`
	CandidateCount      int                     `json:"candidate_count,omitempty"`
	CandidateCountKnown bool                    `json:"candidate_count_known"`
	TargetsComplete     bool                    `json:"targets_complete"`
	RuntimeAgreement    disasm.RuntimeAgreement `json:"runtime_agreement,omitempty"`
	RuntimeObservations int                     `json:"runtime_observations,omitempty"`
}

// SignalGraph is the complete signal graph.
type SignalGraph struct {
	Funcs []SignalFunc `json:"funcs"`
	Edges []SignalEdge `json:"edges"`
	Stats SignalStats  `json:"stats"`
}

// SignalStats holds summary statistics.
type SignalStats struct {
	TotalFuncs                 int            `json:"total_funcs"`
	SignalFuncs                int            `json:"signal_funcs"`
	ContextFuncs               int            `json:"context_funcs"`
	CallSites                  int            `json:"call_sites"`
	StaticRelations            int            `json:"static_relations"`
	UnresolvedIndirectSites    int            `json:"unresolved_indirect_sites"`
	IncompletePolymorphicSites int            `json:"incomplete_polymorphic_sites"`
	UnknownCandidateCountSites int            `json:"unknown_candidate_count_sites"`
	RuntimeObservedSites       int            `json:"runtime_observed_sites"`
	RuntimeRelations           int            `json:"runtime_relations"`
	UnsupportedCallSites       int            `json:"unsupported_call_sites"`
	StringRefCount             int            `json:"string_ref_count"`
	Categories                 map[string]int `json:"categories"`
}

// BuildSignalGraph constructs a signal graph from disasm artifacts.
// k = number of context hops from each signal function.
// rootCandidates is the structural source-component set from render's static
// call graph (may be nil). It is not a language-level entry-point claim.
func BuildSignalGraph(
	dartVersion string,
	funcs []disasm.FuncRecord,
	edges []disasm.CallEdgeRecord,
	stringRefs []disasm.StringRefRecord,
	k int,
	rootCandidates map[string]bool,
) *SignalGraph {
	funcSet := make(map[string]bool, len(funcs))
	for _, f := range funcs {
		funcSet[f.Name] = true
	}
	// Group string refs by function and classify each string individually.
	type funcSignal struct {
		refs       []ClassifiedStringRef
		categories map[string]bool
	}
	funcSignals := make(map[string]*funcSignal)

	catCounts := make(map[string]int)
	validStringRefCount := 0

	for _, sr := range stringRefs {
		if !funcSet[sr.Func] {
			continue
		}
		validStringRefCount++
		cats := ClassifyString(dartVersion, sr.Value)
		if len(cats) == 0 {
			continue
		}
		fs, ok := funcSignals[sr.Func]
		if !ok {
			fs = &funcSignal{categories: make(map[string]bool)}
			funcSignals[sr.Func] = fs
		}
		csr := ClassifiedStringRef{
			Func:       sr.Func,
			PC:         sr.PC,
			Kind:       sr.Kind,
			PoolIdx:    sr.PoolIdx,
			Value:      sr.Value,
			Categories: cats,
		}
		fs.refs = append(fs.refs, csr)
		for _, c := range cats {
			if !fs.categories[c] {
				fs.categories[c] = true
				catCounts[c]++
			}
		}
	}

	// Also mark functions with non-mundane THR calls.
	// H-3 fix: also check "call_indirect" for x86_64 (was only "blr" for ARM64).
	for _, e := range edges {
		if !funcSet[e.FromFunc] {
			continue
		}
		if (e.Kind != "blr" && e.Kind != "call_indirect") || e.Via == "" {
			continue
		}
		if !strings.HasPrefix(e.Via, "THR.") {
			continue
		}
		thrName := e.Via[4:]
		if sdk.IsMundaneStub(dartVersion, thrName) {
			continue
		}
		// Recognized suspendable-function stubs carry source-level kind
		// evidence; unknown names remain CatTHR as a table-coverage gap.
		cat := CatTHR
		switch sdk.ClassifyStubRole(dartVersion, thrName) {
		case sdk.StubRoleAsyncInit, sdk.StubRoleAsyncAwait, sdk.StubRoleAsyncReturn:
			cat = CatAsync
		case sdk.StubRoleAsyncStarInit, sdk.StubRoleAsyncStarYield, sdk.StubRoleAsyncStarReturn,
			sdk.StubRoleSyncStarInit, sdk.StubRoleSyncStarSuspend, sdk.StubRoleSyncStarReturn:
			cat = CatGenerator
		}
		// Mark the calling function as signal.
		fs, ok := funcSignals[e.FromFunc]
		if !ok {
			fs = &funcSignal{categories: make(map[string]bool)}
			funcSignals[e.FromFunc] = fs
		}
		if !fs.categories[cat] {
			fs.categories[cat] = true
			catCounts[cat]++
		}
	}

	// Signal function set.
	signalSet := make(map[string]bool, len(funcSignals))
	for name := range funcSignals {
		signalSet[name] = true
	}

	// Build bidirectional STATIC adjacency for BFS context expansion.
	// Include BL/call edges AND non-mundane BLR/call_indirect edges
	// (matching allEdges' edge-inclusion logic below). Without BLR/
	// call_indirect edges, signal functions reachable only via indirect
	// calls (dispatch_table, PP, object_field) won't pull their
	// callers/callees into the context set — context expansion is
	// incomplete for indirect-call-heavy Dart AOT code. (P1-4 / F-017)
	//
	// H-1 (oracle-audit): x86_64 uses "call"/"call_indirect" edge kinds,
	// not "bl"/"blr". Without mapping these, x86_64 signal graphs get
	// zero edges (confirmed: a Dart 3.7.0 x86_64 sample had 3207 signal funcs but 0
	// edges/context). ARM64 uses "bl"/"blr".
	fwd := make(map[string][]string) // caller → callees
	rev := make(map[string][]string) // callee → callers
	for _, e := range edges {
		if !funcSet[e.FromFunc] || !supportedSignalCallKind(e.Kind) {
			continue
		}
		// Skip mundane THR stubs (same filter as allEdges).
		if strings.HasPrefix(e.Via, "THR.") && sdk.IsMundaneStub(dartVersion, e.Via[4:]) {
			continue
		}
		targets := signalStaticTargets(e)
		if len(targets) == 0 {
			continue
		}
		for _, to := range targets {
			if !funcSet[to] {
				continue
			}
			fwd[e.FromFunc] = append(fwd[e.FromFunc], to)
			rev[to] = append(rev[to], e.FromFunc)
		}
	}

	// BFS k hops from signal functions.
	contextSet := make(map[string]bool)
	visited := make(map[string]bool)
	type queueItem struct {
		name  string
		depth int
	}
	var queue []queueItem
	for name := range signalSet {
		visited[name] = true
		queue = append(queue, queueItem{name, 0})
	}
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		if item.depth >= k {
			continue
		}
		// Forward neighbors.
		for _, next := range fwd[item.name] {
			if !visited[next] {
				visited[next] = true
				contextSet[next] = true
				queue = append(queue, queueItem{next, item.depth + 1})
			}
		}
		// Reverse neighbors.
		for _, prev := range rev[item.name] {
			if !visited[prev] {
				visited[prev] = true
				contextSet[prev] = true
				queue = append(queue, queueItem{prev, item.depth + 1})
			}
		}
	}

	// Build ALL funcs with role annotations.
	var allFuncs []SignalFunc
	seenFuncs := make(map[string]bool, len(funcSet))
	for _, f := range funcs {
		if seenFuncs[f.Name] {
			continue
		}
		seenFuncs[f.Name] = true
		sf := SignalFunc{
			Name:            f.Name,
			Owner:           f.Owner,
			PC:              f.PC,
			Size:            f.Size,
			IsRootCandidate: rootCandidates[f.Name],
		}
		if signalSet[f.Name] {
			sf.Role = "signal"
		} else if contextSet[f.Name] {
			sf.Role = "context"
		}
		if fs, ok := funcSignals[f.Name]; ok {
			sort.Slice(fs.refs, func(i, j int) bool {
				a, b := fs.refs[i], fs.refs[j]
				if a.PC != b.PC {
					return a.PC < b.PC
				}
				if a.Value != b.Value {
					return a.Value < b.Value
				}
				if a.Kind != b.Kind {
					return a.Kind < b.Kind
				}
				if a.PoolIdx != b.PoolIdx {
					return a.PoolIdx < b.PoolIdx
				}
				return strings.Join(a.Categories, "\x00") < strings.Join(b.Categories, "\x00")
			})
			sf.StringRefs = fs.refs
			for c := range fs.categories {
				sf.Categories = append(sf.Categories, c)
			}
			sort.Strings(sf.Categories)
			sf.Severity = MaxSeverity(sf.Categories)
		}
		allFuncs = append(allFuncs, sf)
	}

	// Sort: signal → context → other.
	// Within signal: structural root candidates first, then severity/category.
	roleOrd := map[string]int{"signal": 0, "context": 1, "": 2}
	sevOrd := map[string]int{"high": 0, "medium": 1, "low": 2, "": 3}
	sort.Slice(allFuncs, func(i, j int) bool {
		si, sj := &allFuncs[i], &allFuncs[j]
		if si.Role != sj.Role {
			return roleOrd[si.Role] < roleOrd[sj.Role]
		}
		if si.Role == "signal" && si.IsRootCandidate != sj.IsRootCandidate {
			return si.IsRootCandidate
		}
		if si.Severity != sj.Severity {
			return sevOrd[si.Severity] < sevOrd[sj.Severity]
		}
		if len(si.Categories) != len(sj.Categories) {
			return len(si.Categories) > len(sj.Categories)
		}
		return si.Name < sj.Name
	})

	// Preserve the call-site resolution contract in the graph schema. Static
	// candidates, unresolved sites, address-only direct calls, and runtime-only
	// observations are distinct records; renderers choose the projection they
	// need rather than reverse-engineering certainty from a callee string.
	var allEdges []SignalEdge
	seen := make(map[signalEdgeKey]int)
	callSiteSet := make(map[string]bool)
	unresolvedSiteSet := make(map[string]bool)
	incompleteSiteSet := make(map[string]bool)
	unknownCandidateSiteSet := make(map[string]bool)
	runtimeObservedSiteSet := make(map[string]bool)
	unsupportedSiteSet := make(map[string]bool)
	for edgeIndex, e := range edges {
		if !funcSet[e.FromFunc] {
			continue
		}
		siteKey := signalCallSiteKey(e, edgeIndex)
		callSiteSet[siteKey] = true
		if !supportedSignalCallKind(e.Kind) {
			unsupportedSiteSet[siteKey] = true
			appendSignalEdge(&allEdges, seen, SignalEdge{
				From: e.FromFunc, FromPC: e.FromPC, Kind: e.Kind, Via: e.Via,
				TargetAddress: e.TargetAddress, Resolution: ResolutionUnsupported,
			})
			continue
		}
		if e.Kind == "blr" || e.Kind == "call_indirect" {
			// Skip mundane THR.
			if strings.HasPrefix(e.Via, "THR.") && sdk.IsMundaneStub(dartVersion, e.Via[4:]) {
				continue
			}
		}
		targets := signalStaticTargets(e)
		polymorphicRecord := len(e.Targets) > 0
		candidateCount := e.Candidates
		candidateCountKnown := polymorphicRecord && e.Candidates > 0
		if polymorphicRecord && !candidateCountKnown {
			unknownCandidateSiteSet[siteKey] = true
		}
		if candidateCount < len(targets) {
			candidateCount = len(targets)
		}
		targetsComplete := false
		if polymorphicRecord {
			targetsComplete = candidateCountKnown && e.Candidates == len(targets) && len(targets) == len(e.Targets)
			if candidateCountKnown && !targetsComplete {
				incompleteSiteSet[siteKey] = true
			}
		}

		resolution := ResolutionDirect
		if e.Kind == "blr" || e.Kind == "call_indirect" {
			switch {
			case e.Target != "" && len(targets) > 0:
				resolution = ResolutionMonomorphic
				targetsComplete = true
			case polymorphicRecord:
				resolution = ResolutionPolymorphicCandidate
			default:
				resolution = ResolutionUnresolved
				unresolvedSiteSet[siteKey] = true
			}
		} else if len(targets) > 0 {
			targetsComplete = true
		}
		if len(targets) == 0 {
			address := ""
			if isDirectSignalKind(e.Kind) {
				address = e.TargetAddress
				if address == "" && isRawSignalTarget(e.Target) {
					address = strings.TrimSpace(e.Target)
				}
				if address != "" {
					resolution = ResolutionAddressOnly
					targetsComplete = true
				}
			}
			se := SignalEdge{
				From: e.FromFunc, FromPC: e.FromPC, Kind: e.Kind, Via: e.Via,
				TargetAddress: address, Resolution: resolution,
				CandidateCount: candidateCount, CandidateCountKnown: candidateCountKnown, TargetsComplete: targetsComplete,
			}
			appendSignalEdge(&allEdges, seen, se)
		} else {
			for _, to := range targets {
				if to == "" {
					continue
				}
				se := SignalEdge{
					From: e.FromFunc, FromPC: e.FromPC, To: to, Kind: e.Kind, Via: e.Via,
					TargetAddress: e.TargetAddress, Resolution: resolution,
					CandidateCount: candidateCount, CandidateCountKnown: candidateCountKnown, TargetsComplete: targetsComplete,
				}
				appendSignalEdge(&allEdges, seen, se)
			}
		}

		if e.Runtime != nil && (e.Runtime.Observations > 0 || len(e.Runtime.Targets) > 0) {
			runtimeObservedSiteSet[siteKey] = true
			for _, observed := range e.Runtime.Targets {
				if observed.Target == "" {
					continue
				}
				count := observed.Count
				if count <= 0 {
					count = 1
				}
				se := SignalEdge{
					From: e.FromFunc, FromPC: e.FromPC, To: observed.Target, Kind: e.Kind, Via: e.Via,
					Resolution: ResolutionRuntimeObserved, RuntimeAgreement: e.Runtime.Agreement,
					RuntimeObservations: count,
				}
				appendSignalEdge(&allEdges, seen, se)
			}
		}
	}
	sort.Slice(allEdges, func(i, j int) bool { return signalEdgeLess(allEdges[i], allEdges[j]) })
	staticRelations, runtimeRelations := 0, 0
	for _, edge := range allEdges {
		if edge.Resolution == ResolutionRuntimeObserved {
			runtimeRelations++
		} else if edge.To != "" && (edge.Resolution == ResolutionDirect || edge.Resolution == ResolutionMonomorphic || edge.Resolution == ResolutionPolymorphicCandidate) {
			staticRelations++
		}
	}

	return &SignalGraph{
		Funcs: allFuncs,
		Edges: allEdges,
		Stats: SignalStats{
			TotalFuncs:                 len(funcSet),
			SignalFuncs:                len(signalSet),
			ContextFuncs:               len(contextSet),
			CallSites:                  len(callSiteSet),
			StaticRelations:            staticRelations,
			UnresolvedIndirectSites:    len(unresolvedSiteSet),
			IncompletePolymorphicSites: len(incompleteSiteSet),
			UnknownCandidateCountSites: len(unknownCandidateSiteSet),
			RuntimeObservedSites:       len(runtimeObservedSiteSet),
			RuntimeRelations:           runtimeRelations,
			UnsupportedCallSites:       len(unsupportedSiteSet),
			StringRefCount:             validStringRefCount,
			Categories:                 catCounts,
		},
	}
}

func signalCallSiteKey(e disasm.CallEdgeRecord, ordinal int) string {
	pc := strings.ToLower(strings.TrimSpace(e.FromPC))
	if pc == "" {
		pc = "<missing-pc:" + strconv.Itoa(ordinal) + ">"
	}
	return e.FromFunc + "\x00" + pc + "\x00" + e.Kind
}

func supportedSignalCallKind(kind string) bool {
	switch kind {
	case "bl", "call", "blr", "call_indirect":
		return true
	default:
		return false
	}
}

func isDirectSignalKind(kind string) bool { return kind == "bl" || kind == "call" }

func signalStaticTargets(e disasm.CallEdgeRecord) []string {
	if target := strings.TrimSpace(e.Target); target != "" {
		if isRawSignalTarget(target) {
			return nil
		}
		return []string{target}
	}
	if len(e.Targets) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(e.Targets))
	out := make([]string, 0, len(e.Targets))
	for _, target := range e.Targets {
		target = strings.TrimSpace(target)
		if target == "" || isRawSignalTarget(target) || seen[target] {
			continue
		}
		seen[target] = true
		out = append(out, target)
	}
	sort.Strings(out)
	return out
}

func isRawSignalTarget(target string) bool {
	target = strings.TrimSpace(target)
	if len(target) <= 2 || (target[:2] != "0x" && target[:2] != "0X") {
		return false
	}
	_, err := strconv.ParseUint(target[2:], 16, 64)
	return err == nil
}

func appendSignalEdge(out *[]SignalEdge, seen map[signalEdgeKey]int, edge SignalEdge) {
	key := signalEdgeKey{
		from: edge.From, pc: edge.FromPC, to: edge.To, kind: edge.Kind,
		via: edge.Via, resolution: edge.Resolution, targetAddress: edge.TargetAddress,
		agreement: edge.RuntimeAgreement,
	}
	if idx, ok := seen[key]; ok {
		if edge.RuntimeObservations > 0 {
			(*out)[idx].RuntimeObservations += edge.RuntimeObservations
		}
		return
	}
	seen[key] = len(*out)
	*out = append(*out, edge)
}

func signalEdgeLess(a, b SignalEdge) bool {
	if a.From != b.From {
		return a.From < b.From
	}
	if a.FromPC != b.FromPC {
		return a.FromPC < b.FromPC
	}
	if a.To != b.To {
		return a.To < b.To
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Resolution != b.Resolution {
		return a.Resolution < b.Resolution
	}
	if a.Via != b.Via {
		return a.Via < b.Via
	}
	if a.TargetAddress != b.TargetAddress {
		return a.TargetAddress < b.TargetAddress
	}
	return a.RuntimeAgreement < b.RuntimeAgreement
}
