package strutil

import "testing"

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"path/to/file", "path_to_file"},
		{"name:with*special?chars", "name_with_special_chars"},
		{"with space", "with_space"},
		{`with"quotes<and>brackets`, "with_quotes_and_brackets"},
		{"with|pipe\\backslash", "with_pipe_backslash"},
		{"正常中文", "正常中文"}, // CJK should be preserved
	}
	for _, tt := range tests {
		got := SanitizeFilename(tt.input)
		if got != tt.want {
			t.Errorf("SanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeFilename_Truncation(t *testing.T) {
	long := ""
	for i := 0; i < 300; i++ {
		long += "a"
	}
	got := SanitizeFilename(long)
	if len(got) > 200 {
		t.Errorf("SanitizeFilename should truncate to 200 chars, got %d", len(got))
	}
}

func TestSanitizeIdentifier(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "unknown_fn"},
		{"simple_name", "simple_name"},
		{"name.with.dots", "name_with_dots"},
		{"name/slash", "name_slash"},
		{"123starts_with_digit", "_123starts_with_digit"},
		{"name:with*special", "name_with_special"},
	}
	for _, tt := range tests {
		got := SanitizeIdentifier(tt.input)
		if got != tt.want {
			t.Errorf("SanitizeIdentifier(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeFilename_MatchesOldImplementation(t *testing.T) {
	// Verify that the shared implementation handles the same characters
	// that the old safeFuncNameHTML handled.
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
