package fingerprint

import (
	"testing"
)

func TestExtractSemverToken(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Flutter Engine 3.24.1 (stable)", "3.24.1"},
		{"Dart VM version: 3.9.2 (stable) on linux_arm64", "3.9.2"},
		{"Build 12.3", ""},
		{"Version 2.12.0-dev", "2.12.0"},
		{"No semver here", ""},
	}

	for _, tt := range tests {
		got := extractSemverToken(tt.input)
		if got != tt.want {
			t.Errorf("extractSemverToken(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFirstSemverFromMarkers(t *testing.T) {
	markers := []string{
		"Engine revision abcdef",
		"Flutter Engine 3.10.7 (main)",
	}
	got := firstSemverFromMarkers(markers)
	if got != "3.10.7" {
		t.Errorf("firstSemverFromMarkers() = %q, want 3.10.7", got)
	}
}

func TestAsciiStrings(t *testing.T) {
	data := []byte("abc\x00defghijkl\x00mno")
	got := asciiStrings(data, 4)
	if len(got) != 1 || got[0] != "defghijkl" {
		t.Errorf("asciiStrings(minLen 4) = %v, want [defghijkl]", got)
	}
}
