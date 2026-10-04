package symbolmap

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aotopsy/internal/elfx"
	"aotopsy/internal/snapshot"

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
		0x1000: {Name: "main", VA: 0x1000, Size: 0x100, Type: elf.STT_FUNC, SectionEnd: 0x1100},
		0x2000: {Name: "helper", VA: 0x2000, Size: 0x100, Type: elf.STT_FUNC, SectionEnd: 0x2100},
		0x3000: {Name: "subroutine", VA: 0x3000, Size: 0x100, Type: elf.STT_FUNC, SectionEnd: 0x3100},
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

func TestResolveTargetNearestRejectsNonFunctionAndBoundsZeroSizeFunction(t *testing.T) {
	symbols := map[uint64]symbolInfo{
		0x1000: {Name: "label", VA: 0x1000, Type: elf.STT_NOTYPE, SectionEnd: 0x1800},
		0x1100: {Name: "zero_func", VA: 0x1100, Type: elf.STT_FUNC, SectionEnd: 0x1120},
		0x1120: {Name: "interior_label", VA: 0x1120, Type: elf.STT_NOTYPE, SectionEnd: 0x1800},
		0x1140: {Name: "next_func", VA: 0x1140, Size: 0x20, Type: elf.STT_FUNC, SectionEnd: 0x1160},
		0x1200: {Name: snapshot.SymIsolateSnapshotInstructions, VA: 0x1200, Size: 0x100, Type: elf.STT_FUNC, SectionEnd: 0x1300},
	}
	nearest := []uint64{0x1100, 0x1140}
	if kind, name, _, _ := resolveTarget(symbols, nearest, 0x1000, 64); kind != MatchExact || name != "label" {
		t.Fatalf("exact STT_NOTYPE label = (%s,%q), want exact label", kind, name)
	}
	if kind, _, _, _ := resolveTarget(symbols, nearest, 0x1008, 64); kind != MatchUnresolved {
		t.Fatalf("STT_NOTYPE preceding label became nearest function match: %s", kind)
	}
	if kind, name, _, off := resolveTarget(symbols, nearest, 0x111c, 64); kind != MatchNearest || name != "zero_func" || off != 0x1c {
		t.Fatalf("zero-size FUNC bounded interval = (%s,%q,%d), want nearest zero_func+0x1c", kind, name, off)
	}
	if kind, name, _, _ := resolveTarget(symbols, nearest, 0x1120, 64); kind != MatchExact || name != "interior_label" {
		t.Fatalf("next STT_NOTYPE boundary = (%s,%q), want exact interior_label", kind, name)
	}
	if kind, _, _, _ := resolveTarget(symbols, nearest, 0x1130, 64); kind != MatchUnresolved {
		t.Fatalf("zero-size FUNC crossed next-symbol boundary: %s", kind)
	}
	if kind, name, _, off := resolveTarget(symbols, nearest, 0x1148, 64); kind != MatchNearest || name != "next_func" || off != 8 {
		t.Fatalf("next function boundary = (%s,%q,%d), want nearest next_func+8", kind, name, off)
	}
	if kind, _, _, _ := resolveTarget(symbols, nearest, 0x1160, 64); kind != MatchUnresolved {
		t.Fatalf("target at sized function end became nearest: %s", kind)
	}
	if kind, _, _, _ := resolveTarget(symbols, nearest, 0x1200, 64); kind != MatchUnresolved {
		t.Fatalf("snapshot instruction container became exact callable match: %s", kind)
	}
}

func TestPairIdentityRequiresUniqueMatchingBuildID(t *testing.T) {
	if err := requireSameBuildID(
		elfx.BuildIDEvidence{ID: "abcd"},
		elfx.BuildIDEvidence{ID: "abcd"},
	); err != nil {
		t.Fatalf("matching build ids rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		a    elfx.BuildIDEvidence
		b    elfx.BuildIDEvidence
	}{
		{"missing stripped", elfx.BuildIDEvidence{}, elfx.BuildIDEvidence{ID: "abcd"}},
		{"conflicted oracle", elfx.BuildIDEvidence{ID: "abcd"}, elfx.BuildIDEvidence{Conflicts: []string{"conflict"}}},
		{"different builds", elfx.BuildIDEvidence{ID: "abcd"}, elfx.BuildIDEvidence{ID: "ef01"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := requireSameBuildID(tc.a, tc.b); err == nil {
				t.Fatal("unverified build identity accepted")
			}
		})
	}
}

func TestCompareExecLayoutsRequiresStructuralAndByteIdentity(t *testing.T) {
	base := execSection{Index: 7, Name: ".text", Type: elf.SHT_PROGBITS, Addr: 0x1000, Size: 4, Offset: 0x200, Flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, Align: 16, Data: []byte{1, 2, 3, 4}}
	if layout, bytesOK := compareExecLayouts([]execSection{base}, []execSection{base}); !layout || !bytesOK {
		t.Fatalf("identical executable section rejected: layout=%v bytes=%v", layout, bytesOK)
	}
	changedLayout := base
	changedLayout.Offset++
	if layout, bytesOK := compareExecLayouts([]execSection{base}, []execSection{changedLayout}); layout || bytesOK {
		t.Fatalf("different executable layout accepted: layout=%v bytes=%v", layout, bytesOK)
	}
	changedLayout = base
	changedLayout.Type = elf.SHT_NOTE
	if layout, bytesOK := compareExecLayouts([]execSection{base}, []execSection{changedLayout}); layout || bytesOK {
		t.Fatalf("different executable section type accepted: layout=%v bytes=%v", layout, bytesOK)
	}
	changedLayout = base
	changedLayout.Align = 32
	if layout, bytesOK := compareExecLayouts([]execSection{base}, []execSection{changedLayout}); layout || bytesOK {
		t.Fatalf("different executable section alignment accepted: layout=%v bytes=%v", layout, bytesOK)
	}
	changedBytes := base
	changedBytes.Data = []byte{1, 2, 3, 5}
	if layout, bytesOK := compareExecLayouts([]execSection{base}, []execSection{changedBytes}); !layout || bytesOK {
		t.Fatalf("different executable bytes classification = layout=%v bytes=%v", layout, bytesOK)
	}
}

func TestWriteCallSitesTSV(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "call_sites.tsv")

	sites := []CallSite{
		{FromVA: 0x1000, TargetVA: 0x2000, TargetValid: true, Match: MatchExact, SymbolName: "helper", SymbolVA: 0x2000, SymbolOffset: 0},
		{FromVA: 0x1020, TargetVA: 0x3010, TargetValid: true, Match: MatchNearest, SymbolName: "subroutine", SymbolVA: 0x3000, SymbolOffset: 16},
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

func TestWriteCallSitesTSVPreservesResolvedSymbolAtAddressZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "call_sites.tsv")
	sites := []CallSite{{
		FromVA: 0x10, TargetVA: 0, TargetValid: true, Match: MatchExact,
		SymbolName: "zero", SymbolVA: 0,
	}}
	if err := WriteCallSitesTSV(path, sites); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("TSV lines = %d, want header + one row:\n%s", len(lines), data)
	}
	fields := strings.Split(lines[1], "\t")
	if len(fields) != 10 || fields[1] != "0x0" || fields[6] != string(MatchExact) || fields[7] != "zero" || fields[8] != "0x0" {
		t.Fatalf("resolved VA zero was serialized as missing: fields=%q", fields)
	}
}

func TestWriteCallSitesTSVEscapesSpreadsheetFormulas(t *testing.T) {
	data, err := encodeCallSitesTSV([]CallSite{{
		FromVA: 0x10, Kind: SiteCall, Indirect: true,
		Reg: "=1+1", Via: "@evil", Match: MatchExact, SymbolName: "+cmd", SymbolVA: 0x20,
	}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"'=1+1", "'@evil", "'+cmd"} {
		if !strings.Contains(text, want) {
			t.Fatalf("TSV lost spreadsheet-safe prefix %q:\n%s", want, text)
		}
	}
}

func TestARM64ScannerIncludesIndirectBLR(t *testing.T) {
	sec := execSection{Name: ".text", Addr: 0x1000, Data: armWords(
		0x94000004, // BL 0x1010
		0xD63F0200, // BLR X16
		0xD65F03C0, // RET
	)}
	sec.Size = uint64(len(sec.Data))
	sites, err := scanARM64CallSites([]execSection{sec}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 2 {
		t.Fatalf("ARM64 sites = %+v, want BL + BLR", sites)
	}
	if sites[0].Indirect || !sites[0].TargetValid || sites[0].TargetVA != 0x1010 {
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
	sites, err := scanX86CallSites([]execSection{sec}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 2 {
		t.Fatalf("x86 sites = %+v, want direct + indirect CALL", sites)
	}
	if sites[0].Indirect || !sites[0].TargetValid || sites[0].TargetVA != 0x2005 {
		t.Fatalf("direct CALL = %+v", sites[0])
	}
	if !sites[1].Indirect || sites[1].Reg != "RAX" || sites[1].TargetVA != 0 {
		t.Fatalf("indirect CALL = %+v, want RAX unresolved indirect", sites[1])
	}
}

func TestBranchScanIncludesOnlyDirectBranches(t *testing.T) {
	t.Run("arm64", func(t *testing.T) {
		sec := execSection{Name: ".text", Addr: 0x3000, Data: armWords(
			0x14000001, // B 0x3004
			0xD61F0200, // BR X16: indirect, deliberately not emitted
			0xD65F03C0, // RET
		)}
		sec.Size = uint64(len(sec.Data))
		sites, err := scanARM64CallSites([]execSection{sec}, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(sites) != 1 || sites[0].Kind != SiteBranch || sites[0].Indirect || !sites[0].TargetValid || sites[0].TargetVA != 0x3004 {
			t.Fatalf("ARM64 branch sites = %+v, want direct B only", sites)
		}
	})

	t.Run("x86", func(t *testing.T) {
		// JMP +0 ; JMP RAX ; RET. Symbolmap's branch surface is explicitly
		// direct-only, so the register-indirect JMP is not promoted to a target.
		data := []byte{0xEB, 0x00, 0xFF, 0xE0, 0xC3}
		sec := execSection{Name: ".text", Addr: 0x4000, Size: uint64(len(data)), Data: data}
		sites, err := scanX86CallSites([]execSection{sec}, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(sites) != 1 || sites[0].Kind != SiteBranch || sites[0].Indirect || !sites[0].TargetValid || sites[0].TargetVA != 0x4002 {
			t.Fatalf("x86 branch sites = %+v, want relative JMP only", sites)
		}
	})
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

func TestSymbolCategoryDoesNotMislabelDartPaddingClasses(t *testing.T) {
	if got := symbolCategory("RenderPadding.performLayout"); got != "" {
		t.Fatalf("RenderPadding function category = %q, want empty", got)
	}
}

func TestScanChunksCoverExecutableBytesAndAreBounded(t *testing.T) {
	data := make([]byte, maxScanChunkBytes+64)
	sec := execSection{Name: ".text", Addr: 0x4000, Size: uint64(len(data)), Data: data}
	chunks := buildARM64ScanChunks([]execSection{sec})
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
	chunks := buildX86ScanChunks([]execSection{sec})
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
		SchemaVersion: ReportSchemaVersion,
		Machine:       "EM_X86_64",
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
	reportData, err := os.ReadFile(filepath.Join(dir, "symbol_map_report.json"))
	if err != nil {
		t.Fatal(err)
	}
	reportText := string(reportData)
	if !strings.Contains(reportText, `"schema_version": 1`) || !strings.Contains(reportText, `"indirect_count": 0`) {
		t.Fatalf("report schema omitted required version/count fields:\n%s", reportText)
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
