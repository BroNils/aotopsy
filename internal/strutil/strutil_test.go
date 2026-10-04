package strutil

import (
	"strings"
	"testing"
	"unicode/utf8"

	"aotopsy/internal/artifactfs"
)

func TestSanitizeFilename(t *testing.T) {
	if got := SanitizeFilename("simple"); got != "simple" {
		t.Fatalf("safe lowercase ASCII name changed: %q", got)
	}
	for _, input := range []string{
		"path/to/file", "name:with*special?chars", "with space",
		`with"quotes<and>brackets`, "with|pipe\\backslash", "正常中文",
		"CON", "con.txt", "NUL", "COM1", "LPT9", "trailing.",
	} {
		got := SanitizeFilename(input)
		if got == "" {
			t.Errorf("SanitizeFilename(%q) returned empty", input)
			continue
		}
		if !utf8.ValidString(got) {
			t.Errorf("SanitizeFilename(%q) returned invalid UTF-8 %q", input, got)
		}
		if err := artifactfs.ValidateRelativePath(got); err != nil {
			t.Errorf("SanitizeFilename(%q) returned non-portable component %q: %v", input, got, err)
		}
	}
}

func TestSanitizeFilename_Truncation(t *testing.T) {
	long := ""
	for i := 0; i < 300; i++ {
		long += "a"
	}
	got := SanitizeFilename(long)
	if len(got) > portableFilenameMaxBytes {
		t.Errorf("SanitizeFilename should truncate to %d bytes, got %d", portableFilenameMaxBytes, len(got))
	}
}

func TestSanitizeFilename_TruncationKeepsValidUTF8AndUniqueness(t *testing.T) {
	prefix := strings.Repeat("界", 80)
	a := SanitizeFilename(prefix + "_first")
	b := SanitizeFilename(prefix + "_second")
	if !utf8.ValidString(a) || !utf8.ValidString(b) {
		t.Fatalf("truncation produced invalid UTF-8: %q / %q", a, b)
	}
	if len(a) > portableFilenameMaxBytes || len(b) > portableFilenameMaxBytes {
		t.Fatalf("truncation exceeded 200 bytes: %d / %d", len(a), len(b))
	}
	if a == b {
		t.Fatalf("distinct long names collided after truncation: %q", a)
	}
}

func TestSanitizeFilenameDoesNotCollapseDistinctRawNames(t *testing.T) {
	pairs := [][2]string{
		{"a:b", "a?b"},
		{"a:b", "a_b"},
		{"Foo", "foo"},
		{"CON", "_CON"},
		{"é", "É"},
	}
	for _, pair := range pairs {
		a, b := SanitizeFilename(pair[0]), SanitizeFilename(pair[1])
		if strings.EqualFold(a, b) {
			t.Errorf("distinct raw names still collide under Windows case-folding: %q -> %q, %q -> %q", pair[0], a, pair[1], b)
		}
	}
	generated := SanitizeFilename("a:b")
	if literal := SanitizeFilename(generated); literal == generated {
		t.Fatalf("generated filename namespace collides with literal raw input %q", generated)
	}
}

func TestSanitizeFilenameDistinguishesReplacementRuneFromInvalidUTF8(t *testing.T) {
	valid := SanitizeFilename("a\uFFFDb")
	invalid := SanitizeFilename(string([]byte{'a', 0xff, 'b'}))
	if !strings.ContainsRune(valid, '\uFFFD') {
		t.Fatalf("legitimate U+FFFD was discarded: %q", valid)
	}
	if !utf8.ValidString(invalid) {
		t.Fatalf("invalid UTF-8 was not repaired: %q", invalid)
	}
	if valid == invalid {
		t.Fatalf("valid U+FFFD and malformed byte sequence collapsed to %q", valid)
	}
}

func TestSanitizeFilenameRejectsUnsafeCharacters(t *testing.T) {
	inputs := []string{
		"simple",
		"path/to/file",
		"name with spaces",
		"special:chars*here",
	}
	for _, input := range inputs {
		got := SanitizeFilename(input)
		if got == "" {
			t.Errorf("SanitizeFilename(%q) returned empty", input)
		}
		// Should not contain any unsafe characters
		for _, ch := range got {
			if ch == '/' || ch == '\\' || ch == ':' || ch == '*' || ch == '?' || ch == '"' || ch == '<' || ch == '>' || ch == '|' || ch == ' ' {
				t.Errorf("SanitizeFilename(%q) still contains unsafe char %q in %q", input, string(ch), got)
			}
		}
	}
}
