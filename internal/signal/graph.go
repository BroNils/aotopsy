package signal

import (
	"sort"
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
	Name         string                `json:"name"`
	Owner        string                `json:"owner,omitempty"`
	PC           string                `json:"pc"`
	Size         int                   `json:"size"`
	StringRefs   []ClassifiedStringRef `json:"string_refs,omitempty"`
	Categories   []string              `json:"categories"`
	Severity     string                `json:"severity"` // "high", "medium", "low"
	Role         string                `json:"role"`     // "signal", "context", ""
	IsEntryPoint bool                  `json:"is_entry_point,omitempty"`
}

// SignalEdge is an edge in the signal graph.
type SignalEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"` // "bl"/"call" (direct), "blr"/"call_indirect" (indirect)
	Via  string `json:"via,omitempty"`
}

// SignalGraph is the complete signal graph.
type SignalGraph struct {
	Funcs []SignalFunc `json:"funcs"`
	Edges []SignalEdge `json:"edges"`
	Stats SignalStats  `json:"stats"`
}

// SignalStats holds summary statistics.
type SignalStats struct {
	TotalFuncs     int            `json:"total_funcs"`
	SignalFuncs    int            `json:"signal_funcs"`
	ContextFuncs   int            `json:"context_funcs"`
	TotalEdges     int            `json:"total_edges"`
	StringRefCount int            `json:"string_ref_count"`
	Categories     map[string]int `json:"categories"`
}

// BuildSignalGraph constructs a signal graph from disasm artifacts.
// k = number of context hops from each signal function.
// entryPoints is the set of functions with no incoming BL edges (may be nil).
func BuildSignalGraph(
	funcs []disasm.FuncRecord,
	edges []disasm.CallEdgeRecord,
	stringRefs []disasm.StringRefRecord,
	k int,
	entryPoints map[string]bool,
) *SignalGraph {
	// Group string refs by function and classify each string individually.
	type funcSignal struct {
		refs       []ClassifiedStringRef
		categories map[string]bool
	}
	funcSignals := make(map[string]*funcSignal)

	catCounts := make(map[string]int)

	for _, sr := range stringRefs {
		cats := ClassifyString(sr.Value)
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
		if (e.Kind != "blr" && e.Kind != "call_indirect") || e.Via == "" {
			continue
		}
		if !strings.HasPrefix(e.Via, "THR.") {
			continue
		}
		thrName := e.Via[4:]
		if sdk.IsMundaneStub(thrName) {
			continue
		}
		// Mark the calling function as signal.
		fs, ok := funcSignals[e.FromFunc]
		if !ok {
			fs = &funcSignal{categories: make(map[string]bool)}
			funcSignals[e.FromFunc] = fs
		}
		if !fs.categories["thr"] {
			fs.categories["thr"] = true
			catCounts["thr"]++
		}
	}

	// Signal function set.
	signalSet := make(map[string]bool, len(funcSignals))
	for name := range funcSignals {
		signalSet[name] = true
	}

	// Build bidirectional adjacency for BFS context expansion.
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
		var to string
		if e.Kind == "bl" || e.Kind == "call" {
			if e.Target == "" {
				continue
			}
			to = e.Target
		} else if e.Kind == "blr" || e.Kind == "call_indirect" {
			if e.Via == "" {
				continue
			}
			// Skip mundane THR (same filter as allEdges).
			// x86_64 call_indirect edges don't use THR. prefix
			// (THR-cached calls are classified as direct "call"),
			// so this filter is a no-op on x86_64 — correct.
			if strings.HasPrefix(e.Via, "THR.") && sdk.IsMundaneStub(e.Via[4:]) {
				continue
			}
			to = e.Via
		} else {
			continue
		}
		fwd[e.FromFunc] = append(fwd[e.FromFunc], to)
		rev[to] = append(rev[to], e.FromFunc)
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
	for _, f := range funcs {
		sf := SignalFunc{
			Name:         f.Name,
			Owner:        f.Owner,
			PC:           f.PC,
			Size:         f.Size,
			IsEntryPoint: entryPoints[f.Name],
		}
		if signalSet[f.Name] {
			sf.Role = "signal"
		} else if contextSet[f.Name] {
			sf.Role = "context"
		}
		if fs, ok := funcSignals[f.Name]; ok {
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
	// Within signal: entry points first, then severity, then category count.
	roleOrd := map[string]int{"signal": 0, "context": 1, "": 2}
	sevOrd := map[string]int{"high": 0, "medium": 1, "low": 2, "": 3}
	sort.Slice(allFuncs, func(i, j int) bool {
		si, sj := &allFuncs[i], &allFuncs[j]
		if si.Role != sj.Role {
			return roleOrd[si.Role] < roleOrd[sj.Role]
		}
		if si.Role == "signal" && si.IsEntryPoint != sj.IsEntryPoint {
			return si.IsEntryPoint
		}
		if si.Severity != sj.Severity {
			return sevOrd[si.Severity] < sevOrd[sj.Severity]
		}
		if len(si.Categories) != len(sj.Categories) {
			return len(si.Categories) > len(sj.Categories)
		}
		return si.Name < sj.Name
	})

	// Include ALL BL/call edges (deduped), plus non-mundane BLR/
	// call_indirect edges. H-1: x86_64 uses "call"/"call_indirect".
	var allEdges []SignalEdge
	seen := make(map[string]bool)
	for _, e := range edges {
		var to string
		if e.Kind == "bl" || e.Kind == "call" {
			if e.Target == "" {
				continue
			}
			to = e.Target
		} else if e.Kind == "blr" || e.Kind == "call_indirect" {
			if e.Via == "" {
				continue
			}
			// Skip mundane THR.
			if strings.HasPrefix(e.Via, "THR.") && sdk.IsMundaneStub(e.Via[4:]) {
				continue
			}
			to = e.Via
		} else {
			continue
		}

		key := e.FromFunc + "|" + to + "|" + e.Kind
		if seen[key] {
			continue
		}
		seen[key] = true

		se := SignalEdge{From: e.FromFunc, To: to, Kind: e.Kind}
		if e.Kind == "blr" || e.Kind == "call_indirect" {
			se.Via = e.Via
		}
		allEdges = append(allEdges, se)
	}

	return &SignalGraph{
		Funcs: allFuncs,
		Edges: allEdges,
		Stats: SignalStats{
			TotalFuncs:     len(funcs),
			SignalFuncs:    len(signalSet),
			ContextFuncs:   len(contextSet),
			TotalEdges:     len(allEdges),
			StringRefCount: len(stringRefs),
			Categories:     catCounts,
		},
	}
}
