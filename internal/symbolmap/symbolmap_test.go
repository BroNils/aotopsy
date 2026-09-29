package symbolmap

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func armWords(words ...uint32) []byte {
	out := make([]byte, len(words)*4)
	for i, w := range words {
		binary.LittleEndian.PutUint32(out[i*4:], w)
	}
	return out
}

func TestResolveTarget(t *testing.T) {
	symbols := map[uint64]symbolInfo{
		0x1000: {Name: "main", VA: 0x1000, Size: 0x100},
		0x2000: {Name: "helper", VA: 0x2000, Size: 0x100},
		0x3000: {Name: "subroutine", VA: 0x3000, Size: 0x100},
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

func TestARM64ScannerIncludesIndirectBLR(t *testing.T) {
	sec := execSection{Name: ".text", Addr: 0x1000, Data: armWords(
		0x94000004, // BL 0x1010
		0xD63F0200, // BLR X16
		0xD65F03C0, // RET
	)}
	sec.Size = uint64(len(sec.Data))
	syms := map[uint64]symbolInfo{
		0x1000: {Name: "entry", VA: 0x1000, Size: sec.Size, Type: elf.STT_FUNC},
	}
	sites := scanARM64CallSites([]execSection{sec}, syms, []uint64{0x1000}, false)
	if len(sites) != 2 {
		t.Fatalf("ARM64 sites = %+v, want BL + BLR", sites)
	}
	if sites[0].Indirect || sites[0].TargetVA != 0x1010 {
		t.Fatalf("direct BL = %+v", sites[0])
	}
	if !sites[1].Indirect || sites[1].Reg != "X16" || sites[1].TargetVA != 0 {
		t.Fatalf("indirect BLR = %+v, want X16 unresolved indirect", sites[1])
	}
}

func TestX86ScannerIncludesIndirectCall(t *testing.T) {
	// CALL +0 ; CALL RAX ; RET
	data := []byte{0xE8, 0, 0, 0, 0, 0xFF, 0xD0, 0xC3}
	sec := execSection{Name: ".text", Addr: 0x2000, Size: uint64(len(data)), Data: data}
	syms := map[uint64]symbolInfo{
		0x2000: {Name: "entry", VA: 0x2000, Size: uint64(len(data)), Type: elf.STT_FUNC},
	}
	sites := scanX86CallSites([]execSection{sec}, syms, []uint64{0x2000}, false)
	if len(sites) != 2 {
		t.Fatalf("x86 sites = %+v, want direct + indirect CALL", sites)
	}
	if sites[0].Indirect || sites[0].TargetVA != 0x2005 {
		t.Fatalf("direct CALL = %+v", sites[0])
	}
	if !sites[1].Indirect || sites[1].Reg != "RAX" || sites[1].TargetVA != 0 {
		t.Fatalf("indirect CALL = %+v, want RAX unresolved indirect", sites[1])
	}
}

func TestExportSymbolsPreservesReverseMapMetadataAndAliases(t *testing.T) {
	syms := map[uint64]symbolInfo{
		0x3000: {
			Name: "stub Foo", VA: 0x3000, Size: 0x40,
			Type: elf.STT_FUNC, Binding: elf.STB_GLOBAL,
			SectionName: ".text", Aliases: []string{"FooAlias"}, Category: "stub",
		},
	}
	got := exportSymbols(syms, []uint64{0x3000})
	if len(got) != 1 {
		t.Fatalf("reverse symbols = %+v", got)
	}
	r := got[0]
	if r.Name != "stub Foo" || r.Size != 0x40 || r.Type != "STT_FUNC" || r.Binding != "STB_GLOBAL" || r.Section != ".text" || r.Category != "stub" {
		t.Fatalf("reverse symbol metadata lost: %+v", r)
	}
	if len(r.Aliases) != 1 || r.Aliases[0] != "FooAlias" {
		t.Fatalf("aliases lost: %+v", r.Aliases)
	}
}

func TestScanChunksCoverExecutableBytesAndAreBounded(t *testing.T) {
	data := make([]byte, maxScanChunkBytes+64)
	sec := execSection{Name: ".text", Addr: 0x4000, Size: uint64(len(data)), Data: data}
	syms := map[uint64]symbolInfo{
		0x4020: {Name: "f", VA: 0x4020, Size: 0x20, Type: elf.STT_FUNC},
	}
	chunks := buildARM64ScanChunks([]execSection{sec}, syms, []uint64{0x4020})
	var total int
	for _, c := range chunks {
		if len(c.Data) > maxScanChunkBytes {
			t.Fatalf("chunk exceeded budget: %d", len(c.Data))
		}
		total += len(c.Data)
	}
	if total != len(data) {
		t.Fatalf("chunks cover %d bytes, want %d", total, len(data))
	}
}

func TestX86ScanChunksSplitAtInstructionBoundary(t *testing.T) {
	data := make([]byte, maxScanChunkBytes+32)
	for i := range data {
		data[i] = 0x90 // NOP
	}
	// A five-byte CALL that would straddle the old raw 1 MiB split.
	callOff := maxScanChunkBytes - 2
	copy(data[callOff:], []byte{0xE8, 0, 0, 0, 0})
	sec := execSection{Name: ".text", Addr: 0x400000, Size: uint64(len(data)), Data: data}
	syms := map[uint64]symbolInfo{
		sec.Addr: {Name: "entry", VA: sec.Addr, Size: sec.Size, Type: elf.STT_FUNC},
	}
	chunks := buildX86ScanChunks([]execSection{sec}, syms, []uint64{sec.Addr})
	if len(chunks) < 2 {
		t.Fatalf("x86 chunks = %d, want at least 2", len(chunks))
	}
	wantSplit := sec.Addr + uint64(callOff)
	gotSplit := chunks[0].VA + uint64(len(chunks[0].Data))
	if gotSplit != wantSplit {
		t.Fatalf("first x86 chunk ends at %#x, want CALL boundary %#x", gotSplit, wantSplit)
	}
	if chunks[1].VA != wantSplit || len(chunks[1].Data) < 5 || chunks[1].Data[0] != 0xE8 {
		t.Fatalf("second x86 chunk does not start at complete CALL: va=%#x head=%x", chunks[1].VA, chunks[1].Data[:min(5, len(chunks[1].Data))])
	}
	inst, err := x86asm.Decode(chunks[1].Data, 64)
	if err != nil || inst.Op != x86asm.CALL || inst.Len != 5 {
		t.Fatalf("boundary CALL decode = %v len=%d err=%v", inst.Op, inst.Len, err)
	}
}

func TestWriteArtifactsPublishesOneGenerationAndRemovesStaleReverseMap(t *testing.T) {
	dir := t.TempDir()
	rep := &Report{
		Machine: "EM_X86_64",
		CallSites: []CallSite{{
			FromVA: 0x1000, Kind: SiteCall, Indirect: true, Reg: "RAX", Match: MatchUnresolved,
		}},
		Targets: []TargetSummary{},
		Symbols: []SymbolRecord{{VA: 0x2000, Name: "f", Type: "STT_FUNC", Binding: "STB_GLOBAL", Section: ".text"}},
	}
	if err := WriteArtifacts(dir, rep); err != nil {
		t.Fatalf("WriteArtifacts with reverse map: %v", err)
	}
	for _, name := range []string{"symbol_call_sites.tsv", "symbol_target_summary.json", "symbol_map_report.json", "symbol_reverse_map.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s missing after publish: %v", name, err)
		}
	}

	// A later generation without --import-symbols must remove, not preserve,
	// the previous reverse map.
	rep.Symbols = nil
	rep.CallSites = nil
	if err := WriteArtifacts(dir, rep); err != nil {
		t.Fatalf("WriteArtifacts without reverse map: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "symbol_reverse_map.json")); !os.IsNotExist(err) {
		t.Fatalf("stale reverse map survived new generation: err=%v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "symbol_call_sites.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "RAX") {
		t.Fatalf("old call-site generation survived transaction:\n%s", data)
	}
}
