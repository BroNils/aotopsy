package symbolmap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveTarget(t *testing.T) {
	symbols := map[uint64]string{
		0x1000: "main",
		0x2000: "helper",
		0x3000: "subroutine",
	}
	sortedVAs := []uint64{0x1000, 0x2000, 0x3000}

	tests := []struct {
		targetVA uint64
		maxDist  uint64
		wantKind MatchKind
		wantSym  string
		wantOff  uint64
	}{
		{0x1000, 100, MatchExact, "main", 0},
		{0x2000, 100, MatchExact, "helper", 0},
		{0x2010, 100, MatchNearest, "helper", 16},
		{0x2200, 100, MatchUnresolved, "", 0},
		{0x500, 100, MatchUnresolved, "", 0},
	}

	for _, tt := range tests {
		match, name, symVA, off := resolveTarget(symbols, sortedVAs, tt.targetVA, tt.maxDist)
		if match != tt.wantKind {
			t.Errorf("resolveTarget(0x%x) match = %s, want %s", tt.targetVA, match, tt.wantKind)
		}
		if name != tt.wantSym {
			t.Errorf("resolveTarget(0x%x) name = %s, want %s", tt.targetVA, name, tt.wantSym)
		}
		if off != tt.wantOff {
			t.Errorf("resolveTarget(0x%x) off = %d, want %d", tt.targetVA, off, tt.wantOff)
		}
		if match == MatchExact && symVA != tt.targetVA {
			t.Errorf("resolveTarget(0x%x) symVA = 0x%x, want 0x%x", tt.targetVA, symVA, tt.targetVA)
		}
	}
}

func TestWriteCallSitesTSV(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "call_sites.tsv")

	sites := []CallSite{
		{FromVA: 0x1000, TargetVA: 0x2000, Match: MatchExact, SymbolName: "helper", SymbolVA: 0x2000, SymbolOffset: 0},
		{FromVA: 0x1020, TargetVA: 0x3010, Match: MatchNearest, SymbolName: "subroutine", SymbolVA: 0x3000, SymbolOffset: 16},
	}

	if err := WriteCallSitesTSV(path, sites); err != nil {
		t.Fatalf("WriteCallSitesTSV failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read TSV failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines (1 header + 2 rows), got %d", len(lines))
	}
	if !strings.HasPrefix(lines[0], "from_va\ttarget_va") {
		t.Errorf("header line = %q", lines[0])
	}
	if !strings.Contains(lines[1], "helper") {
		t.Errorf("row 1 = %q, want contains helper", lines[1])
	}
}
