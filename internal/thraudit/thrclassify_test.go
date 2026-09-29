package thraudit

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aotopsy/internal/jsonutil"
)

func auditRecord(arch, off string) THRAuditRecord {
	return THRAuditRecord{
		Sample:      "sample.so",
		DartVersion: "3.12.2",
		Arch:        arch,
		PC:          "0x1000",
		Insn:        "LDR X16, [X26,#0x100]",
		THROffset:   off,
		Width:       8,
		FuncName:    "f",
		Resolved:    false,
		Context: []string{
			"> 0x1000: LDR X16, [X26,#0x100]",
			"  0x1004: BLR X16",
		},
	}
}

func TestClusterBandsStrictOffsetsAndProvenance(t *testing.T) {
	for _, bad := range []string{"", "garbage", "10", "0x", "0x10junk", "-0x10", "0xffffffffffffffffffff"} {
		r := auditRecord(ArchARM64, bad)
		if _, err := ClusterBands([]THRAuditRecord{r}, 0x18); err == nil {
			t.Fatalf("ClusterBands accepted malformed offset %q", bad)
		}
	}

	mixed := []THRAuditRecord{auditRecord(ArchARM64, "0x100"), auditRecord(ArchARM64, "0x108")}
	mixed[1].Sample = "other.so"
	if _, err := ClusterBands(mixed, 0x18); err == nil {
		t.Fatal("ClusterBands accepted mixed samples")
	}
	mixed[1] = auditRecord(ArchX64, "0x108")
	if _, err := ClusterBands(mixed, 0x18); err == nil {
		t.Fatal("ClusterBands accepted mixed architectures")
	}
	if _, err := ClusterBands([]THRAuditRecord{auditRecord(ArchARM64, "0x100")}, -1); err == nil {
		t.Fatal("ClusterBands accepted negative max gap")
	}
}

func TestClusterBandsAndClassifyARM64Entrypoint(t *testing.T) {
	records := []THRAuditRecord{
		auditRecord(ArchARM64, "0x100"),
		auditRecord(ArchARM64, "0x108"),
	}
	records[1].PC = "0x2000"
	records[1].Insn = "LDR X0, [X26,#0x108]"
	records[1].Context = []string{
		"> 0x2000: LDR X0, [X26,#0x108]",
		"  0x2004: STR X0, [X1,#8]",
	}

	bands, err := ClusterBands(records, 0x18)
	if err != nil {
		t.Fatal(err)
	}
	if bands.Arch != ArchARM64 || len(bands.Bands) != 1 || bands.TotalUnresolved != 2 {
		t.Fatalf("unexpected bands: %+v", bands)
	}
	classified, err := ClassifyRecords(records, bands)
	if err != nil {
		t.Fatal(err)
	}
	if classified[0].Class != ClassRuntimeEntrypoint {
		t.Fatalf("direct ARM64 BLR class = %s", classified[0].Class)
	}
	if classified[1].Class != ClassObjectStoreCache {
		t.Fatalf("ARM64 object-store class = %s", classified[1].Class)
	}
}

func TestUnresolvedStoreIsNotRuntimeEntrypoint(t *testing.T) {
	r := auditRecord(ArchARM64, "0x100")
	r.IsStore = true
	r.SrcReg = 16
	r.Insn = "STR X16, [X26,#0x100]"
	if got := ClassifyFromContext(r); got != ClassUnknown {
		t.Fatalf("arbitrary THR store classified %s, want UNKNOWN", got)
	}
}

func TestClassifyARM64StackPushDoesNotImplyIsolateGroup(t *testing.T) {
	// Exact Dart 3.9.2 PRODUCT+ARM64+DCP Thread layout places empty_array_ at
	// 0x90 and isolate_group_ at 0x778. This real stack-push/call shape therefore
	// cannot, by itself, identify an isolate/group pointer.
	r := auditRecord(ArchARM64, "0x90")
	r.DartVersion = "3.9.2"
	r.Insn = "LDR X30, [X26,#144]"
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

func TestClassifyX64DirectIndirectCall(t *testing.T) {
	r := auditRecord(ArchX64, "0x100")
	r.DstReg = 0 // RAX
	r.Insn = "MOV RAX, [R14+0x100]"
	r.Context = []string{
		"> 0x1000: MOV RAX, [R14+0x100]",
		"  0x1007: CALL RAX",
	}
	if got := ClassifyFromContext(r); got != ClassRuntimeEntrypoint {
		t.Fatalf("x64 CALL-through-loaded-register class = %s", got)
	}
	r.Context[1] = "  0x1007: CALL RCX"
	if got := ClassifyFromContext(r); got != ClassUnknown {
		t.Fatalf("x64 unrelated CALL class = %s, want UNKNOWN", got)
	}
}

func TestClassifyRejectsBandProvenanceMismatchAndMissingOffset(t *testing.T) {
	records := []THRAuditRecord{auditRecord(ArchARM64, "0x100")}
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
	rec := auditRecord(ArchARM64, "0x100")
	if _, err := jsonutil.WriteJSONLFile(path, []THRAuditRecord{rec}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadAuditRecords(path, jsonutil.Limits{MaxBytes: 4096, MaxRecords: 1, MaxRecordBytes: 4096})
	if err != nil || len(got) != 1 {
		t.Fatalf("ReadAuditRecords = %d, %v", len(got), err)
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

type failWriter struct{ err error }

func (w failWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWriteBandsMDPropagatesWriterError(t *testing.T) {
	want := errors.New("disk full")
	err := WriteBandsMD(failWriter{err: want}, BandResult{Sample: "s", DartVersion: "3.12.2", Arch: ArchARM64})
	if !errors.Is(err, want) {
		t.Fatalf("WriteBandsMD error = %v, want %v", err, want)
	}
}

func TestWriteBandsMD(t *testing.T) {
	var b strings.Builder
	if err := WriteBandsMD(&b, BandResult{Sample: "s", DartVersion: "3.12.2", Arch: ArchX64}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Dart 3.12.2, x64") {
		t.Fatalf("markdown lost provenance: %q", b.String())
	}
}

var _ io.Writer = failWriter{}
