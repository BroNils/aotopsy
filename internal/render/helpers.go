// Package render produces Graphviz DOT and HTML output from aotopsy JSONL.
package render

import (
	"fmt"
	"strings"
)

// dotEscape escapes a string for use in DOT HTML labels.
func dotEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

// dotID creates a safe DOT identifier from a function name.
func dotID(name string) string {
	var b strings.Builder
	b.WriteString("n_")
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteRune(c)
		} else {
			fmt.Fprintf(&b, "_%04x", c)
		}
	}
	return b.String()
}

// stripMethodName removes the owner prefix from a fully qualified function name.
// "Owner.methodName_1234" → "methodName_1234". Returns the original if no match.
func stripMethodName(funcName, owner string) string {
	prefix := owner + "."
	if strings.HasPrefix(funcName, prefix) {
		return funcName[len(prefix):]
	}
	return funcName
}

// truncLabel shortens a label to maxLen, appending "..." if truncated.
func truncLabel(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
