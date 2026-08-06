// Package strutil provides shared string utility functions used across
// multiple aotopsy packages. Created to consolidate 4 different
// filename-sanitization implementations (P4-5 / G-004, H-032).
package strutil

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// SanitizeFilename strips non-printable runes and replaces filesystem-unsafe
// characters with underscores. This is the single canonical implementation
// for all filename sanitization in aotopsy.
//
// Replaces: / \ : * ? " < > | and space with _.
// Strips non-printable runes (keeps valid Unicode including CJK, emoji).
// Truncates to 200 characters.
func SanitizeFilename(name string) string {
	var clean strings.Builder
	for _, r := range name {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			clean.WriteByte('_')
		} else {
			clean.WriteRune(r)
		}
	}
	r := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		" ", "_",
	)
	s := r.Replace(clean.String())
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// SanitizeIdentifier replaces all non-identifier characters with underscores,
// producing a valid C/Dart-style identifier. Prefixes with _ if the result
// starts with a digit. Returns "unknown_fn" if the result is empty.
//
// This is the canonical implementation for code-generation contexts (decompiler
// output, struct field names) where a valid identifier is required.
func SanitizeIdentifier(name string) string {
	if name == "" {
		return "unknown_fn"
	}
	var b strings.Builder
	for _, r := range name {
		if r == '_' || r == '$' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" {
		return "unknown_fn"
	}
	if out[0] >= '0' && out[0] <= '9' {
		out = "_" + out
	}
	return out
}
