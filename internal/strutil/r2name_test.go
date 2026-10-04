package strutil

import (
	"strings"
	"testing"
)

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
		got := SanitizeR2FlagName(n, 0x1234)
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
func TestSanitizeR2FlagNameDropsOnlyAbsentNames(t *testing.T) {
	for _, n := range []string{"", "   ", "\t\r\n"} {
		if got := SanitizeR2FlagName(n, 0x1234); got != "" {
			t.Errorf("SanitizeR2FlagName(%q) = %q, want \"\"", n, got)
		}
	}
}

func TestSanitizeR2FlagNameKeepsOperatorAndUnicodeIdentity(t *testing.T) {
	for _, n := range []string{"[]=", "___", "...", "@@@", "正常中文"} {
		got := SanitizeR2FlagName(n, 0x1234)
		if got == "" || !r2NameCheck(got) {
			t.Errorf("semantic name %q was lost or produced invalid r2 flag %q", n, got)
		}
	}
}

func TestSanitizeR2FlagNamePreservesGrammarAndIdentity(t *testing.T) {
	if got := SanitizeR2FlagName("Duration.compareTo", 0x1000); !strings.HasPrefix(got, "Duration.compareTo_") {
		t.Fatalf("r2-accepted dot was unnecessarily destroyed: %q", got)
	}
	if got := SanitizeR2FlagName(":namespace:name", 0x1000); !strings.HasPrefix(got, ":namespace:name_") {
		t.Fatalf("r2-accepted colon was unnecessarily destroyed: %q", got)
	}
	a := SanitizeR2FlagName("Foo@1", 0x1000)
	b := SanitizeR2FlagName("Foo_at_1", 0x1000)
	c := SanitizeR2FlagName("Foo@1", 0x2000)
	if a == b || a == c || b == c {
		t.Fatalf("distinct r2 identities collided: %q %q %q", a, b, c)
	}
	if got := SanitizeR2FlagName("9lives", 0x1000); !strings.HasPrefix(got, "f_9lives_") {
		t.Fatalf("leading digit was not repaired: %q", got)
	}
}
