package render

import (
	"sort"

	"aotopsy/internal/disasm"
)

// concreteCallTargets returns function targets backed by call-resolution
// evidence. Via is intentionally excluded: it can be a provenance label such
// as "dispatch_table" or "object_field+0x30", not a function name.
func concreteCallTargets(e disasm.CallEdgeRecord) []string {
	return inspectCallSite(e).StaticTargets
}

func isRawCallAddress(s string) bool {
	if len(s) <= 2 || (s[:2] != "0x" && s[:2] != "0X") {
		return false
	}
	for _, r := range s[2:] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// FindRootCandidates returns the functions in source strongly-connected
// components of the resolved static call graph. For an acyclic component this
// is the familiar "no incoming call" root. For a root cycle there is no honest
// single entry point, so every member is returned as a candidate rather
// than making the entire cycle disappear from reachability.
//
// These are structural root candidates, not a claim that Dart/VM metadata proved
// a language-level entry point.
func FindRootCandidates(funcs []disasm.FuncRecord, edges []disasm.CallEdgeRecord) []string {
	funcSet := make(map[string]bool, len(funcs))
	for _, f := range funcs {
		funcSet[f.Name] = true
	}

	adj := make(map[string][]string, len(funcs))
	for _, e := range edges {
		if !funcSet[e.FromFunc] || !isSupportedCallKind(e.Kind) {
			continue
		}
		seen := make(map[string]bool)
		for _, target := range concreteCallTargets(e) {
			if funcSet[target] && !seen[target] {
				seen[target] = true
				adj[e.FromFunc] = append(adj[e.FromFunc], target)
			}
		}
		sort.Strings(adj[e.FromFunc])
	}

	// Tarjan SCC. Function names are visited in lexical order so the result is
	// independent of functions.jsonl ordering.
	names := make([]string, 0, len(funcSet))
	for name := range funcSet {
		names = append(names, name)
	}
	sort.Strings(names)
	index := 0
	indices := make(map[string]int, len(names))
	lowlink := make(map[string]int, len(names))
	onStack := make(map[string]bool, len(names))
	stack := make([]string, 0, len(names))
	componentOf := make(map[string]int, len(names))
	var components [][]string
	var strongConnect func(string)
	strongConnect = func(v string) {
		indices[v] = index + 1 // zero means unseen
		lowlink[v] = index + 1
		index++
		stack = append(stack, v)
		onStack[v] = true
		for _, w := range adj[v] {
			if indices[w] == 0 {
				strongConnect(w)
				if lowlink[w] < lowlink[v] {
					lowlink[v] = lowlink[w]
				}
			} else if onStack[w] && indices[w] < lowlink[v] {
				lowlink[v] = indices[w]
			}
		}
		if lowlink[v] != indices[v] {
			return
		}
		componentID := len(components)
		var component []string
		for {
			w := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			onStack[w] = false
			componentOf[w] = componentID
			component = append(component, w)
			if w == v {
				break
			}
		}
		sort.Strings(component)
		components = append(components, component)
	}
	for _, name := range names {
		if indices[name] == 0 {
			strongConnect(name)
		}
	}

	hasIncomingComponent := make([]bool, len(components))
	for from, targets := range adj {
		fromComp := componentOf[from]
		for _, to := range targets {
			toComp := componentOf[to]
			if fromComp != toComp {
				hasIncomingComponent[toComp] = true
			}
		}
	}

	var roots []string
	for componentID, component := range components {
		if hasIncomingComponent[componentID] {
			continue
		}
		roots = append(roots, component...)
	}
	sort.Strings(roots)
	return roots
}
