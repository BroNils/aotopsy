package strutil

import "testing"

// r2NameCheck is a Go transcription of radare2's r_name_check
// (libr/util/name.c): a flag name may contain only [A-Za-z0-9_.:], and its
// first character may only be [A-Za-z_:]. A name failing this makes r2 reject
// the whole `f` command with "Invalid flag name".
//
// The test asserts SanitizeR2FlagName's output against this rather than
// against a fixed expected string, because that is the actual contract -- and
// it is what the two denylist sanitizers this replaced were never checked
// against.
func r2NameCheck(s string) bool {
	if s == "" {
		return false
	}
	first := s[0]
	okFirst := (first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') ||
		first == '_' || first == ':'
	if !okFirst {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_', c == '.', c == ':':
		default:
			return false
		}
	}
	return true
}

func TestSanitizeR2FlagNameProducesValidFlags(t *testing.T) {
	// Real recovered-name shapes, plus every character class the old
	// denylists let through: !"%',/;=?\^`{|}~
	names := []string{
		"Duration.compareTo",
		"_ViewState@141024595.didChangeViewFocus",
		"new _GrowableList@0150898.of",
		"dyn:*",
		"TypeTestingStub_Iterable<X0>",
		"operator []=",
		"_MixinApplication164&Object&Foo",
		"foo(bar, baz)",
		"a+b-c*d/e%f",
		"weird!\"'`~^|{}\\;=?,name",
		"package:flutter/src/widgets/framework.dart",
		"123startsWithDigit",
		"0",
		"stub_1a2b",
		"main",
	}
	for _, n := range names {
		got := SanitizeR2FlagName(n)
		if got == "" {
			t.Errorf("SanitizeR2FlagName(%q) = \"\" -- a real name was dropped entirely", n)
			continue
		}
		if !r2NameCheck(got) {
			t.Errorf("SanitizeR2FlagName(%q) = %q, which r_name_check rejects", n, got)
		}
	}
}

// Names that carry nothing once separators are stripped must come back empty
// so the caller can skip them, rather than emitting a bare "_" flag.
func TestSanitizeR2FlagNameDropsEmptyNames(t *testing.T) {
	for _, n := range []string{"", "___", "...", "@@@", "   ", "-.-"} {
		if got := SanitizeR2FlagName(n); got != "" {
			t.Errorf("SanitizeR2FlagName(%q) = %q, want \"\"", n, got)
		}
	}
}

func TestSanitizeR2FlagNameSpecifics(t *testing.T) {
	cases := []struct{ in, want string }{
		// '@' is spelled out, so Foo@1 and Foo_1 stay distinct flags.
		{"Foo@1", "Foo_at_1"},
		{"Foo_1", "Foo_1"},
		// A leading digit is invalid as a first character.
		{"9lives", "f_9lives"},
		// Dots become underscores on purpose: r2 reads a dot as a sub-flag
		// namespace separator.
		{"Duration.compareTo", "Duration_compareTo"},
		{"main", "main"},
	}
	for _, c := range cases {
		if got := SanitizeR2FlagName(c.in); got != c.want {
			t.Errorf("SanitizeR2FlagName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
