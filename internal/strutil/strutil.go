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

// SanitizeR2FlagName makes a name usable as a radare2 flag name.
//
// The rule comes from radare2 itself (libr/util/name.c, r_name_check): a flag
// name may contain only [A-Za-z0-9_.:], and its FIRST character may only be
// [A-Za-z_:]. Anything else and r2 rejects the whole `f` command with
// "Invalid flag name".
//
// This is written as an allowlist for that reason. The two hand-rolled
// denylists it replaced each enumerated the punctuation someone had run into,
// and each still let characters through that r_name_check rejects -- between
// them !"%',/;=?\^`{|}~ -- because a denylist is only ever as complete as the
// last bug report. An allowlist that is a strict subset of what r2 accepts
// cannot produce an invalid name at all.
//
// '.' and ':' are deliberately NOT kept even though r2 allows them: a dot puts
// the flag in a sub-flag namespace, so keeping the dots in a Dart name would
// scatter one class's methods across as many namespaces as it has name parts.
//
// '@' becomes "_at_" rather than "_": Dart mangles a private library name into
// the symbol as Owner@141024595, and collapsing it to an underscore makes
// Foo@1 and Foo_1 the same flag.
func SanitizeR2FlagName(name string) string {
	// A name with no alphanumeric character at all carries nothing once the
	// separators are gone, so there is no flag worth emitting. Checked on the
	// INPUT: doing it on the output would let "@@@" survive as "_at__at__at_",
	// a technically valid flag naming nothing.
	hasAlnum := false
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			hasAlnum = true
			break
		}
	}
	if !hasAlnum {
		return ""
	}
	name = strings.ReplaceAll(name, "@", "_at_")
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch {
		case r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	// r_name_validate_first rejects a leading digit.
	if out[0] >= '0' && out[0] <= '9' {
		out = "f_" + out
	}
	return out
}
