// Package render produces Graphviz DOT and HTML output from aotopsy JSONL.
package render

import (
	"encoding/hex"
	"io"
	"net/url"
	"path"
	"strings"
	"unicode/utf8"
)

// errorWriter remembers the first write failure (including a short write) so
// renderers can keep their straightforward fmt.Fprintf structure without ever
// turning a partial artifact into an apparent success.
type errorWriter struct {
	w   io.Writer
	err error
}

func (w *errorWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.w.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.err = err
	}
	return n, err
}

// dotEscape escapes a string for use in DOT HTML labels.
func dotEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

// dotID creates an injective DOT identifier from a semantic node name.
// Hex-encoding the UTF-8 bytes avoids the old escape scheme's collision
// between a literal substring such as "_002d" and the escaped spelling of
// '-'. The n_ prefix keeps the result in DOT's unquoted identifier grammar.
func dotID(name string) string {
	return "n_" + hex.EncodeToString([]byte(name))
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

// truncLabel shortens a label to maxLen Unicode code points, appending "..."
// when truncated. It never slices in the middle of a UTF-8 sequence.
func truncLabel(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return strings.Repeat(".", maxLen)
	}
	runes := []rune(s)
	return string(runes[:maxLen-3]) + "..."
}

// IsAllCaps returns true if the name looks like a constant (all uppercase + underscores).
func IsAllCaps(s string) bool {
	if len(s) < 2 {
		return false
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// safeRelativeArtifactLink converts a report-relative artifact path into a
// browser-safe href. Render data is untrusted: absolute paths, traversal,
// URL-like first segments, backslashes, and NULs must never turn an artifact
// reference into navigation outside the published report directory.
func safeRelativeArtifactLink(rel string) (string, bool) {
	if rel == "" || strings.ContainsRune(rel, '\x00') || strings.Contains(rel, "\\") {
		return "", false
	}
	if strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "//") {
		return "", false
	}
	clean := path.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	parts := strings.Split(clean, "/")
	if len(parts) == 0 || strings.Contains(parts[0], ":") {
		return "", false
	}
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", false
		}
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/"), true
}
