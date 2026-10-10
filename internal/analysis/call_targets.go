package analysis

import (
	"sort"
	"strings"

	"aotopsy/internal/disasm"
)

func functionNamesByPC(funcs []disasm.FuncRecord) map[string]string {
	out := make(map[string]string, len(funcs))
	for _, f := range funcs {
		if f.PC != "" && f.Name != "" {
			out[strings.ToLower(strings.TrimSpace(f.PC))] = f.Name
		}
	}
	return out
}

// resolvedFunctionTargets returns static function identities only. A direct
// encoded destination is promoted to a name only when functions.jsonl proves
// that exact PC; provenance and runtime observations are never callees here.
func resolvedFunctionTargets(e disasm.CallEdgeRecord, namesByPC map[string]string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, target := range e.ResolvedTargets() {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		lowerTarget := strings.ToLower(target)
		if name := namesByPC[lowerTarget]; name != "" {
			target = name
		} else if strings.HasPrefix(lowerTarget, "0x") {
			continue
		}
		if !seen[target] {
			seen[target] = true
			out = append(out, target)
		}
	}
	if len(out) == 0 && e.TargetAddress != "" {
		if name := namesByPC[strings.ToLower(strings.TrimSpace(e.TargetAddress))]; name != "" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
