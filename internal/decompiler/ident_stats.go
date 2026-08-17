package decompiler

import (
	"regexp"
	"sort"
	"strings"
)

// IdentStats tracks how often each identifier appears in the emitted
// pseudocode, and in what role (assignment target, call argument,
// condition, return value). This is the data structure behind
// flutterdec's naming.rs IdentStats-based re-classification pass,
// which was documented as "a future extension" in naming.go.
//
// The pass works by:
//  1. Counting every identifier occurrence in the pseudocode.
//  2. Classifying each by context (LHS of assignment, RHS, condition,
//     return, argument).
//  3. Re-classifying identifiers that appear in multiple roles:
//     a temporary that is only ever assigned and immediately returned
//     is a "result" variable; one that is only used in conditions is
//     a "flag"; one that accumulates across loop iterations is a
//     "counter" or "accumulator".
//
// This is a text-rewriting pass, not an AST pass — it operates on
// the emitted pseudocode lines, matching flutterdec's approach.
type IdentStats struct {
	Name      string
	Assign    int // appears on LHS of assignment
	Use       int // appears on RHS or in expression
	Condition int // appears in if/while condition
	Return    int // appears in return statement
	Argument  int // appears as call argument
	Total     int
}

// ClassifyIdent returns a semantic name for an identifier based on
// its usage pattern, or "" if no re-classification is warranted.
func (s IdentStats) ClassifyIdent() string {
	// Only re-classify generic temp names (t0, t1, etc.) and arg names.
	if !strings.HasPrefix(s.Name, "t") && !strings.HasPrefix(s.Name, "arg") {
		return ""
	}

	// Result variable: assigned once, returned once, rarely used elsewhere.
	if s.Assign == 1 && s.Return == 1 && s.Use <= 1 && s.Condition == 0 {
		return "result"
	}

	// Flag variable: used primarily in conditions.
	if s.Condition >= 2 && s.Assign >= 1 && s.Use <= s.Condition {
		return "flag"
	}

	// Counter: assigned multiple times, used in conditions and arithmetic.
	if s.Assign >= 2 && s.Condition >= 1 && s.Use >= 2 {
		return "counter"
	}

	// Accumulator: assigned multiple times, used in return or argument.
	if s.Assign >= 2 && (s.Return >= 1 || s.Argument >= 1) {
		return "accumulator"
	}

	return ""
}

// applyIdentReclassification runs the IdentStats-based re-classification
// pass on the emitted pseudocode. It counts identifier usage, classifies
// each identifier, and renames generic temps to semantic names.
//
// This is the port of flutterdec's naming.rs IdentStats pass that was
// documented as a future extension in naming.go.
func applyIdentReclassification(source string) string {
	stats := collectIdentStats(source)

	// Build rename map: old name → new semantic name.
	renames := make(map[string]string)
	for name, s := range stats {
		if newName := s.ClassifyIdent(); newName != "" {
			// Avoid collisions: if the semantic name is already
			// used as an identifier, skip.
			if _, exists := stats[newName]; !exists {
				renames[name] = newName
			}
		}
	}

	if len(renames) == 0 {
		return source
	}

	// Apply renames in order (longest first to avoid prefix collisions).
	names := make([]string, 0, len(renames))
	for old := range renames {
		names = append(names, old)
	}
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })

	for _, old := range names {
		source = replaceIdentToken(source, old, renames[old])
	}
	return source
}

// collectIdentStats scans pseudocode lines and counts identifier
// usage by context.
func collectIdentStats(source string) map[string]*IdentStats {
	stats := make(map[string]*IdentStats)
	lines := strings.Split(source, "\n")

	get := func(name string) *IdentStats {
		if s, ok := stats[name]; ok {
			return s
		}
		s := &IdentStats{Name: name}
		stats[name] = s
		return s
	}

	// Regex for identifiers (Dart-like: letter/_ followed by alnum/_).
	identRe := regexp.MustCompile(`\b([a-zA-Z_]\w*)\b`)

	// Keywords to skip.
	keywords := map[string]bool{
		"if": true, "else": true, "while": true, "for": true,
		"return": true, "break": true, "continue": true,
		"var": true, "final": true, "const": true,
		"true": true, "false": true, "null": true,
		"try": true, "catch": true, "throw": true, "rethrow": true,
		"switch": true, "case": true, "default": true,
		"await": true, "async": true, "sync": true,
		"new": true, "this": true, "super": true,
		"void": true, "dynamic": true, "int": true, "double": true,
		"String": true, "bool": true, "List": true, "Map": true,
		"Set": true, "Object": true, "num": true,
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Check context.
		isReturn := strings.HasPrefix(trimmed, "return ")
		isCondition := strings.HasPrefix(trimmed, "if (") ||
			strings.HasPrefix(trimmed, "if(") ||
			strings.HasPrefix(trimmed, "while (") ||
			strings.HasPrefix(trimmed, "while(")
		isAssignment := strings.Contains(trimmed, " = ") &&
			!strings.Contains(trimmed, "==") &&
			!strings.HasPrefix(trimmed, "if")

		// Find all identifiers in the line.
		matches := identRe.FindAllStringSubmatch(trimmed, -1)
		for _, m := range matches {
			name := m[1]
			if keywords[name] {
				continue
			}

			s := get(name)
			s.Total++

			if isReturn {
				s.Return++
			}
			if isCondition {
				s.Condition++
			}

			// Check if it's on LHS of assignment.
			if isAssignment {
				lhs := strings.SplitN(trimmed, " = ", 2)[0]
				if strings.Contains(lhs, name) {
					s.Assign++
				} else {
					s.Use++
				}
			} else if !isReturn && !isCondition {
				s.Use++
			}

			// Check if it's a call argument (inside parentheses).
			if strings.Contains(trimmed, name+"(") || strings.Contains(trimmed, "("+name) ||
				strings.Contains(trimmed, ", "+name) || strings.Contains(trimmed, ", "+name+",") {
				s.Argument++
			}
		}
	}

	return stats
}
