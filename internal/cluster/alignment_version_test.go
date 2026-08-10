package cluster

import (
	"testing"

	"aotopsy/internal/snapshot"
)

// --- dartVersionAtLeast tests ---

func TestDartVersionAtLeast(t *testing.T) {
	tests := []struct {
		version string
		minimum string
		want    bool
	}{
		{"3.9.2", "2.19.0", true},
		{"2.19.0", "2.19.0", true},
		{"2.18.0", "2.19.0", false},
		{"2.12.0", "2.19.0", false},
		{"3.12.2", "2.19.0", true},
		{"3.0.0", "2.19.0", true},
		{"2.19.1", "2.19.0", true},
		{"4.0.0", "3.0.0", true},
		{"2.10.0", "2.10.0", true},
		{"2.10.0", "2.12.0", false},
		{"0.0.0", "0.0.0", true},
		{"1.0.0", "0.0.1", true},
	}
	for _, tt := range tests {
		got := dartVersionAtLeast(tt.version, tt.minimum)
		if got != tt.want {
			t.Errorf("dartVersionAtLeast(%q, %q) = %v, want %v", tt.version, tt.minimum, got, tt.want)
		}
	}
}

func TestParseDartVersion(t *testing.T) {
	tests := []struct {
		input string
		want  [3]int
	}{
		{"3.9.2", [3]int{3, 9, 2}},
		{"2.12.0", [3]int{2, 12, 0}},
		{"2.19.0", [3]int{2, 19, 0}},
		{"10.20.30", [3]int{10, 20, 30}},
		{"1.0", [3]int{1, 0, 0}},
		{"", [3]int{0, 0, 0}},
		{"garbage", [3]int{0, 0, 0}},
		{"3.9.2-edge", [3]int{3, 9, 2}},
	}
	for _, tt := range tests {
		got := parseDartVersion(tt.input)
		if got != tt.want {
			t.Errorf("parseDartVersion(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// --- dataImageAlignment tests ---

func TestDataImageAlignment(t *testing.T) {
	tests := []struct {
		version string
		want    int64
	}{
		{"2.10.0", 16},
		{"2.12.0", 16},
		{"2.15.0", 16},
		{"2.17.6", 16},
		{"2.18.0", 16},
		{"2.19.0", 64},
		{"2.19.1", 64},
		{"3.0.5", 64},
		{"3.9.2", 64},
		{"3.12.2", 64},
		{"4.0.0", 64},
	}
	for _, tt := range tests {
		profile := &snapshot.VersionProfile{DartVersion: tt.version}
		got := dataImageAlignment(profile)
		if got != tt.want {
			t.Errorf("dataImageAlignment(version=%q) = %d, want %d", tt.version, got, tt.want)
		}
	}
}
