package thraudit

import (
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aotopsy/internal/jsonutil"
)

const testSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func intp(v int) *int { return &v }

func auditRecord(arch string, off int64) THRAuditRecord {
	insn := "LDR X16, [X26,#0x100]"
	context := []string{
		"> 0x1000: LDR X16, [X26,#0x100]",
		"  0x1004: BLR X16",
	}
	if arch == ArchX64 {
		insn = "MOV RAX, [R14+0x100]"
		context = []string{
			"> 0x1000: MOV RAX, [R14+0x100]",
			"  0x1007: CALL RAX",
		}
	}
	dst := 16
	if arch == ArchX64 {
		dst = 0
	}
	return THRAuditRecord{
		Provenance: Provenance{
			Sample: "sample.so", SampleSHA256: testSHA256,
			DartVersion: "3.12.2", Arch: arch, BuildMode: "product", CompressedPointers: true,
		},
		SchemaVersion: SchemaV1,
		PC:            "0x1000",
		Insn:          insn,
		THROffset:     off,
		Access:        AccessRead,
		DstReg:        intp(dst),
		Width:         8,
		FuncName:      "f",
		Context:       context,
	}
}

func TestClusterBandsSignedOffsetsAndProvenance(t *testing.T) {
	records := []THRAuditRecord{
		auditRecord(ArchARM64, -0x10),
		auditRecord(ArchARM64, -0x8),
		auditRecord(ArchARM64, 0x20),
	}
	for i := range records {
		records[i].PC = "0x100" + string(rune('0'+i))
	}
	bands, err := ClusterBands(records, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(bands.Bands) != 2 || bands.Bands[0].MinOff != -0x10 || bands.Bands[0].MaxOff != -0x8 || bands.Bands[1].MinOff != 0x20 {
		t.Fatalf("signed bands = %+v", bands.Bands)
	}

	mixed := []THRAuditRecord{auditRecord(ArchARM64, 0x100), auditRecord(ArchARM64, 0x108)}
	mixed[1].SampleSHA256 = strings.Repeat("a", 64)
	if _, err := ClusterBands(mixed, 0x18); err == nil {
		t.Fatal("ClusterBands accepted mixed sample identity")
	}
	mixed[1] = auditRecord(ArchX64, 0x108)
	if _, err := ClusterBands(mixed, 0x18); err == nil {
		t.Fatal("ClusterBands accepted mixed architectures")
	}
	if _, err := ClusterBands([]THRAuditRecord{auditRecord(ArchARM64, 0x100)}, -1); err == nil {
		t.Fatal("ClusterBands accepted negative max gap")
	}
}

func TestClusterBandsDoesNotOverflowExtremeSignedOffsets(t *testing.T) {
	records := []THRAuditRecord{auditRecord(ArchX64, math.MinInt64), auditRecord(ArchX64, math.MaxInt64)}
	records[1].PC = "0x2000"
	bands, err := ClusterBands(records, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if len(bands.Bands) != 2 {
		t.Fatalf("extreme signed offsets collapsed into one band: %+v", bands.Bands)
	}
	if FormatTHROffset(math.MinInt64) != "-0x8000000000000000" {
		t.Fatalf("MinInt64 formatting = %q", FormatTHROffset(math.MinInt64))
	}
}

func TestClusterBandsAndClassifyStructuralARM64Evidence(t *testing.T) {
	records := []THRAuditRecord{auditRecord(ArchARM64, 0x100), auditRecord(ArchARM64, 0x108)}
	records[1].PC = "0x2000"
	records[1].Insn = "LDR X0, [X26,#0x108]"
	records[1].DstReg = intp(0)
	records[1].Context = []string{
		"> 0x2000: LDR X0, [X26,#0x108]",
		"  0x2004: STR X0, [X1,#8]",
	}
	bands, err := ClusterBands(records, 0x18)
	if err != nil {
		t.Fatal(err)
	}
	classified, err := ClassifyRecords(records, bands)
	if err != nil {
		t.Fatal(err)
	}
	if classified[0].HeuristicClass != ClassIndirectControlTarget || classified[0].Confidence != ConfidenceHeuristic {
		t.Fatalf("direct ARM64 BLR evidence = %+v", classified[0])
	}
	if classified[1].HeuristicClass != ClassValueStored {
		t.Fatalf("ARM64 store-use evidence = %+v", classified[1])
	}
}

func TestWriteAndReadWriteNeverGainSemanticHeuristic(t *testing.T) {
	for _, mode := range []AccessMode{AccessWrite, AccessReadWrite} {
		r := auditRecord(ArchARM64, 0x100)
		r.Access = mode
		r.DstReg = nil
		r.SrcReg = intp(16)
		r.Insn = "STR X16, [X26,#0x100]"
		if got := ClassifyFromContext(r); got != ClassUnknown {
			t.Fatalf("%s access classified %s, want UNKNOWN", mode, got)
		}
	}
}

func TestClassifyARM64StackPushDoesNotImplyIsolateGroup(t *testing.T) {
	r := auditRecord(ArchARM64, 0x90)
	r.DartVersion = "3.9.2"
	r.Insn = "LDR X30, [X26,#144]"
	r.DstReg = intp(30)
	r.Context = []string{
		"  0x138528: LDR X16, [X27,#712]",
		"> 0x13852c: LDR X30, [X26,#144]",
		"  0x138530: STP X30, X16, [X15]",
		"  0x138534: BL .+0x98",
	}
	if got := ClassifyFromContext(r); got != ClassUnknown {
		t.Fatalf("ARM64 stack-push/call class = %s, want UNKNOWN", got)
	}
}

func TestClassifyX64IndirectControlEvidence(t *testing.T) {
	r := auditRecord(ArchX64, 0x100)
	r.DstReg = intp(0)
	if got := ClassifyFromContext(r); got != ClassIndirectControlTarget {
		t.Fatalf("x64 CALL-through-loaded-register class = %s", got)
	}
	r.Context[1] = "  0x1007: CALL RCX"
	if got := ClassifyFromContext(r); got != ClassUnknown {
		t.Fatalf("x64 unrelated CALL class = %s, want UNKNOWN", got)
	}
	r.DstReg = nil
	r.Insn = "CALL [R14+0x100]"
	if got := ClassifyFromContext(r); got != ClassIndirectControlTarget {
		t.Fatalf("x64 memory-indirect CALL class = %s", got)
	}
}

func TestExactRecordNeverEntersHeuristicClassification(t *testing.T) {
	r := auditRecord(ArchARM64, 0xa0)
	r.Resolved = true
	r.FieldName = "dynamic_type"
	bands, err := ClusterBands([]THRAuditRecord{r}, 0x18)
	if err != nil {
		t.Fatal(err)
	}
	if bands.TotalUnresolved != 0 {
		t.Fatalf("exact record counted unresolved: %+v", bands)
	}
	classified, err := ClassifyRecords([]THRAuditRecord{r}, bands)
	if err != nil {
		t.Fatal(err)
	}
	if len(classified) != 0 {
		t.Fatalf("exact record entered heuristic classifier: %+v", classified)
	}
}

func TestValidateRecordSchemaRejectsContradictoryFacts(t *testing.T) {
	tests := []struct {
		name string
		edit func(*THRAuditRecord)
	}{
		{"schema", func(r *THRAuditRecord) { r.SchemaVersion = 0 }},
		{"sha", func(r *THRAuditRecord) { r.SampleSHA256 = "BAD" }},
		{"pc", func(r *THRAuditRecord) { r.PC = "1000" }},
		{"mode", func(r *THRAuditRecord) { r.Access = "store-ish" }},
		{"width", func(r *THRAuditRecord) { r.Width = 3 }},
		{"reg", func(r *THRAuditRecord) { r.DstReg = intp(99) }},
		{"read-with-src", func(r *THRAuditRecord) { r.SrcReg = intp(1) }},
		{"write-with-dst", func(r *THRAuditRecord) { r.Access = AccessWrite; r.DstReg = intp(1); r.SrcReg = intp(2) }},
		{"resolved-without-name", func(r *THRAuditRecord) { r.Resolved = true }},
		{"name-without-resolved", func(r *THRAuditRecord) { r.FieldName = "x" }},
		{"context", func(r *THRAuditRecord) { r.Context = []string{"  0x1000: nop"} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := auditRecord(ArchARM64, 0x100)
			tc.edit(&r)
			if _, err := ClusterBands([]THRAuditRecord{r}, 0x18); err == nil {
				t.Fatal("contradictory record accepted")
			}
		})
	}
}

func TestValidateRecordSchemaAllowsReadWriteRegisterRoles(t *testing.T) {
	r := auditRecord(ArchX64, 0x100)
	r.Access = AccessReadWrite
	r.DstReg = intp(0) // e.g. CMPXCHG old value in RAX
	r.SrcReg = intp(11)
	if _, err := ClusterBands([]THRAuditRecord{r}, 0x18); err != nil {
		t.Fatalf("read_write register roles rejected: %v", err)
	}
}

func TestClassifyRejectsBandProvenanceMismatchAndMissingOffset(t *testing.T) {
	records := []THRAuditRecord{auditRecord(ArchARM64, 0x100)}
	bands, err := ClusterBands(records, 0x18)
	if err != nil {
		t.Fatal(err)
	}
	bad := bands
	bad.Sample = "other.so"
	if _, err := ClassifyRecords(records, bad); err == nil {
		t.Fatal("ClassifyRecords accepted mismatched provenance")
	}
	bad = bands
	bad.Bands = nil
	if _, err := ClassifyRecords(records, bad); err == nil {
		t.Fatal("ClassifyRecords silently assigned missing offset to band zero")
	}
}

func TestReadAuditRecordsStrictBoundedJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	rec := auditRecord(ArchARM64, -0x10)
	if _, err := jsonutil.WriteJSONLFile(path, []THRAuditRecord{rec}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadAuditRecords(path, jsonutil.Limits{MaxBytes: 4096, MaxRecords: 1, MaxRecordBytes: 4096})
	if err != nil || len(got) != 1 || got[0].THROffset != -0x10 {
		t.Fatalf("ReadAuditRecords = %+v, %v", got, err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(b))
	unknown := strings.TrimSuffix(line, "}") + `,"unexpected":1}` + "\n"
	if err := os.WriteFile(path, []byte(unknown), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAuditRecords(path, jsonutil.StandardLimits); err == nil {
		t.Fatal("unknown JSON key accepted")
	}

	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAuditRecords(path, jsonutil.Limits{MaxBytes: 8, MaxRecords: 1, MaxRecordBytes: 4096}); err == nil {
		t.Fatal("byte limit ignored")
	}
}

func TestTopNDeterministicOnFrequencyTie(t *testing.T) {
	got := topN([]BandOffset{{Offset: 0x20, Freq: 2}, {Offset: -0x8, Freq: 2}, {Offset: 0x10, Freq: 3}}, 3)
	if got != "0x10(3) -0x8(2) 0x20(2)" {
		t.Fatalf("topN tie ordering = %q", got)
	}
}

type failWriter struct{ err error }

func (w failWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWriteBandsMDPropagatesWriterError(t *testing.T) {
	want := errors.New("disk full")
	err := WriteBandsMD(failWriter{err: want}, BandResult{Provenance: Provenance{Sample: "s", DartVersion: "3.12.2", Arch: ArchARM64}})
	if !errors.Is(err, want) {
		t.Fatalf("WriteBandsMD error = %v, want %v", err, want)
	}
}

func TestWriteBandsMDUsesSignedRangesAndNoFakeEightByteSlotCount(t *testing.T) {
	var b strings.Builder
	br := BandResult{
		Provenance:      Provenance{Sample: "s", DartVersion: "3.12.2", Arch: ArchX64},
		TotalUnresolved: 2,
		Bands:           []Band{{ID: 0, MinOff: -8, MaxOff: 4, Count: 2, Offsets: []BandOffset{{Offset: -8, Freq: 1}, {Offset: 4, Freq: 1}}}},
	}
	if err := WriteBandsMD(&b, br); err != nil {
		t.Fatal(err)
	}
	text := b.String()
	if !strings.Contains(text, "Dart 3.12.2, x64") || !strings.Contains(text, "-0x8–0x4") || !strings.Contains(text, "Distinct Offsets") {
		t.Fatalf("markdown lost signed/provenance semantics: %q", text)
	}
}

var _ io.Writer = failWriter{}
