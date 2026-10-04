package analysis

import (
	"archive/zip"
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/disasm"
	"aotopsy/internal/elfx"
	"aotopsy/internal/evidence"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/naming"
	"aotopsy/internal/output"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/strutil"
	"aotopsy/internal/vmtables"
)

func publishAuditTestGeneration(t *testing.T, target string, files map[string][]byte) {
	t.Helper()
	tx, err := output.BeginDirTransaction(target)
	if err != nil {
		t.Fatal(err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Abort()
		}
	}()
	for name, data := range files {
		if err := output.WriteArtifactFile(tx.StageDir(), name, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	committed = true
}

func auditFixtureProvenance(t *testing.T, arch, version string) Provenance {
	t.Helper()
	return Provenance{
		Source:      filepath.Join(t.TempDir(), "libapp.so"),
		SourceName:  "libapp.so",
		SHA256:      strings.Repeat("0", 64),
		Size:        1,
		Arch:        arch,
		DartVersion: version,
	}
}

func TestSemanticPipelineRejectsPartialLegacyVMSnapshot(t *testing.T) {
	libPath := sampleARM64(t)
	source, err := LoadSnapshot(libPath, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
	if err != nil {
		t.Fatalf("load source: %v", err)
	}
	if source.Info.UnifiedSnapshot {
		_ = source.Close()
		t.Fatal("fixture must use a legacy split VM snapshot")
	}
	vmStart, err := snapshot.FindClusterDataStart(source.Info.VmData.Data)
	if err != nil {
		_ = source.Close()
		t.Fatalf("VM cluster start: %v", err)
	}
	corruptAt := source.Info.VmData.FileOffset + uint64(vmStart)
	if err := source.Close(); err != nil {
		t.Fatalf("close source: %v", err)
	}

	b, err := os.ReadFile(libPath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if corruptAt > uint64(len(b)) || uint64(len(b))-corruptAt < 16 {
		t.Fatalf("VM cluster offset 0x%x outside file size 0x%x", corruptAt, len(b))
	}
	for i := uint64(0); i < 16; i++ {
		b[corruptAt+i] = 0xff
	}
	corruptPath := filepath.Join(t.TempDir(), "corrupt-vm-libapp.so")
	if err := os.WriteFile(corruptPath, b, 0o600); err != nil {
		t.Fatalf("write corrupt fixture: %v", err)
	}

	// Low-level best-effort loading deliberately preserves the isolate half for
	// diagnostics, but marks the legacy VM half unusable.
	partial, err := LoadSnapshot(corruptPath, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
	if err != nil {
		t.Fatalf("best-effort LoadSnapshot: %v", err)
	}
	if partial.VMError == nil || partial.VMResult != nil {
		_ = partial.Close()
		t.Fatalf("partial VM state = error %v result %#v, want error + nil result", partial.VMError, partial.VMResult)
	}
	if err := partial.RequireCompleteVM(); err == nil {
		_ = partial.Close()
		t.Fatal("RequireCompleteVM accepted a corrupt legacy VM snapshot")
	}
	_ = partial.Close()

	if ctx, err := LoadContext(corruptPath); err == nil {
		_ = ctx.Close()
		t.Fatal("LoadContext published semantic state from a partial VM snapshot")
	}

	out := filepath.Join(t.TempDir(), "published")
	if _, err := Run(Opts{LibPath: corruptPath, OutDir: out, Quiet: true}); err == nil {
		t.Fatal("pipeline accepted a partial VM snapshot")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("failed pipeline published output directory: stat err=%v", err)
	}
}

func TestResolveArgRegIndicesRequiresAllObservedCallSites(t *testing.T) {
	got, ok := disasm.ResolveArgRegIndices([]uint8{0b11, 0b10})
	if !ok {
		t.Fatal("two call sites with a common argument should resolve")
	}
	if want := []int{1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveArgRegIndices = %v, want %v", got, want)
	}
	if got, ok := disasm.ResolveArgRegIndices([]uint8{0b11, 0b10, 0}); ok || len(got) != 0 {
		t.Fatalf("zero-mask observed call site must veto register consensus: got=%v ok=%v", got, ok)
	}
}

func TestCheckedCodeEndOffsetRejectsTruncationAndWrap(t *testing.T) {
	max := uint64(^uint32(0))
	if got, err := CheckedCodeEndOffset(max-7, 7); err != nil || uint64(got) != max {
		t.Fatalf("boundary extent = %#x, %v; want %#x", got, err, max)
	}
	for _, tc := range []struct {
		off, size uint64
	}{
		{max + 1, 0},
		{0, max + 1},
		{max - 3, 8},
	} {
		if got, err := CheckedCodeEndOffset(tc.off, tc.size); err == nil {
			t.Fatalf("overflow extent off=%d size=%d accepted as %#x", tc.off, tc.size, got)
		}
	}
}

func TestCheckedCodeVARejectsWrap(t *testing.T) {
	max := ^uint64(0)
	if got, ok := checkedCodeVA(max-7, 7); !ok || got != max {
		t.Fatalf("boundary VA = %#x, %v; want %#x, true", got, ok, max)
	}
	if got, ok := checkedCodeVA(max-3, 8); ok {
		t.Fatalf("wrapped VA accepted as %#x", got)
	}
}

func TestBuildThreadCallableTargetsRejectsDataAndKeepsSDKCallableFields(t *testing.T) {
	thrFields := map[int]string{
		0x10: "dispatch_table_array",
		0x18: "field_table_values",
		0x20: "LibcPow_entry_point",
		0x28: "suspend_state_await_entry_point",
		0x30: "enter_safepoint_stub",
		0x38: "exit_safepoint_stub",
		0x40: "wb_wrapper_R3",
		0x48: "allocate_object_entry_point",
	}
	stubOffsets := map[int64]string{
		0x48: "AllocateObject",
	}

	got := buildThreadCallableTargets(thrFields, stubOffsets)
	for _, dataField := range []string{"dispatch_table_array", "field_table_values"} {
		if target, ok := got[dataField]; ok {
			t.Fatalf("data field %q classified as callable target %q", dataField, target)
		}
	}
	want := map[string]string{
		"LibcPow_entry_point":             "LibcPow",
		"suspend_state_await_entry_point": "suspend_state_await",
		"enter_safepoint_stub":            "EnterSafepoint",
		"exit_safepoint_stub":             "ExitSafepoint",
		"wb_wrapper_R3":                   "wb_wrapper_R3",
		"allocate_object_entry_point":     "AllocateObject",
	}
	for field, target := range want {
		if got[field] != target {
			t.Errorf("callable field %q = %q, want %q", field, got[field], target)
		}
	}
}

func writeFridaTestProvenance(t *testing.T, dir, version string, arm64, compressed bool) *elfx.File {
	t.Helper()
	arch := "x64"
	machine := elf.EM_X86_64
	if arm64 {
		arch = "arm64"
		machine = elf.EM_AARCH64
	}
	libPath := filepath.Join(dir, "libapp.so")
	b := make([]byte, 256)
	copy(b[:4], []byte{0x7f, 'E', 'L', 'F'})
	b[4], b[5], b[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(b[16:18], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(b[18:20], uint16(machine))
	binary.LittleEndian.PutUint32(b[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint64(b[32:40], 64)
	binary.LittleEndian.PutUint16(b[52:54], 64)
	binary.LittleEndian.PutUint16(b[54:56], 56)
	binary.LittleEndian.PutUint16(b[56:58], 1)
	// One file-backed executable PT_LOAD is enough to exercise Frida's runtime
	// identity binding without pulling a corpus binary into these unit tests.
	binary.LittleEndian.PutUint32(b[64:68], uint32(elf.PT_LOAD))
	binary.LittleEndian.PutUint32(b[68:72], uint32(elf.PF_R|elf.PF_X))
	binary.LittleEndian.PutUint64(b[96:104], uint64(len(b)))
	binary.LittleEndian.PutUint64(b[104:112], uint64(len(b)))
	binary.LittleEndian.PutUint64(b[112:120], 0x1000)
	if err := os.WriteFile(libPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	ef, err := elfx.Open(libPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ef.Close() })
	sha, err := ef.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	p := Provenance{
		Source:             libPath,
		SourceName:         "libapp.so",
		SHA256:             sha,
		Size:               ef.FileSize(),
		Arch:               arch,
		DartVersion:        version,
		CompressedPointers: compressed,
	}
	if err := output.WriteJSONFile(filepath.Join(dir, ProvenanceFileName), p); err != nil {
		t.Fatal(err)
	}
	return ef
}

func TestBuildFridaMetadataIncludesX64IndirectCalls(t *testing.T) {
	dir := t.TempDir()
	ef := writeFridaTestProvenance(t, dir, "3.12.2", false, false)
	if err := os.WriteFile(filepath.Join(dir, "functions.jsonl"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	line := `{"kind":"call_indirect","from_func":"f","from_pc":"0x1234","reg":"rax","via":"","target":""}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "call_edges.jsonl"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := &AnalysisContext{
		Info:        &snapshot.Info{Version: &snapshot.VersionProfile{DartVersion: "3.12.2"}},
		DartVersion: "3.12.2",
		EF:          ef,
	}
	meta, err := BuildFridaMetadata(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.CallProbes) != 1 || meta.CallProbes[0].VA != "0x1234" {
		t.Fatalf("x64 indirect call was not exported: %+v", meta.CallProbes)
	}
	if len(meta.RuntimeIdentity) != 1 || meta.RuntimeIdentity[0].Kind != "executable" || len(meta.RuntimeIdentity[0].SHA256) != 64 {
		t.Fatalf("runtime identity regions were not derived from ELF load bytes: %+v", meta.RuntimeIdentity)
	}
}

func TestBuildFridaMetadataRejectsRuntimeEnrichedGeneration(t *testing.T) {
	for _, tc := range []struct {
		name          string
		runtimeOnEdge bool
		runtimeInEv   bool
	}{
		{name: "runtime on call edge", runtimeOnEdge: true},
		{name: "runtime in evidence", runtimeInEv: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ef := writeFridaTestProvenance(t, dir, "3.12.2", false, false)
			if _, err := jsonutil.WriteJSONLFile[disasm.FuncRecord](filepath.Join(dir, "functions.jsonl"), nil); err != nil {
				t.Fatal(err)
			}
			edge := disasm.CallEdgeRecord{FromFunc: "F", FromPC: "0x100", Kind: "call_indirect", Reg: "RAX"}
			if tc.runtimeOnEdge {
				edge.Runtime = &disasm.RuntimeEvidence{}
			}
			if _, err := jsonutil.WriteJSONLFile(filepath.Join(dir, "call_edges.jsonl"), []disasm.CallEdgeRecord{edge}); err != nil {
				t.Fatal(err)
			}
			if tc.runtimeInEv {
				rt := disasm.RuntimeEvidence{
					Source: "frida", GenerationID: strings.Repeat("b", 64), SourceSHA256: strings.Repeat("a", 64),
					SourceSize: 256, ModuleName: "libapp.so", DartVersion: "3.12.2", Architecture: "x64",
					Agreement: disasm.RuntimeObservedOnly,
					Targets:   []disasm.RuntimeTargetObservation{{Target: "A", Count: 1}}, Observations: 1,
				}
				record := evidence.Evidence{
					PC: "0x100", Function: "F", Kind: "call", Source: evidence.SourceCallEdges,
					Confidence: evidence.ConfUnknown, Rule: evidence.RuleIndirectUnresolved,
					Result: map[string]any{"resolved": false}, Runtime: &rt,
				}
				if _, err := jsonutil.WriteJSONLFile(filepath.Join(dir, "evidence.jsonl"), []evidence.Evidence{record}); err != nil {
					t.Fatal(err)
				}
			}
			ctx := &AnalysisContext{
				Info:        &snapshot.Info{Version: &snapshot.VersionProfile{DartVersion: "3.12.2"}},
				DartVersion: "3.12.2",
				EF:          ef,
			}
			if _, err := BuildFridaMetadata(ctx, dir); err == nil {
				t.Fatal("runtime-enriched directory was accepted as a new static Frida generation")
			}
		})
	}
}

func TestBuildFridaMetadataUsesExactVersionedHeaderAndHeapABI(t *testing.T) {
	tests := []struct {
		name, version                   string
		arm64, compressed               bool
		pos, width                      int
		heapMode, heapReg, heapTHRField string
	}{
		{"2.13 arm64 legacy heap base", "2.13.0", true, true, 16, 16, "register", "x23", ""},
		{"2.18 x64 thread heap base", "2.18.0", false, true, 16, 16, "thread_field", "", "heap_base"},
		{"2.19 x64 modern class id", "2.19.0", false, true, 12, 20, "thread_field", "", "heap_base"},
		{"3.12 arm64 heap bits", "3.12.2", true, true, 12, 20, "heap_bits", "x28", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			ef := writeFridaTestProvenance(t, dir, tt.version, tt.arm64, tt.compressed)
			if err := os.WriteFile(filepath.Join(dir, "functions.jsonl"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "call_edges.jsonl"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			ctx := &AnalysisContext{
				Info: &snapshot.Info{Version: &snapshot.VersionProfile{
					DartVersion: tt.version, CompressedPointers: tt.compressed,
				}},
				DartVersion: tt.version,
				IsARM64:     tt.arm64,
				EF:          ef,
			}
			meta, err := BuildFridaMetadata(ctx, dir)
			if err != nil {
				t.Fatal(err)
			}
			if meta.HeaderBitOffset != tt.pos || meta.HeaderBitWidth != tt.width {
				t.Fatalf("class-id layout = (%d,%d), want (%d,%d)", meta.HeaderBitOffset, meta.HeaderBitWidth, tt.pos, tt.width)
			}
			if meta.HeapBaseMode != tt.heapMode || meta.HeapBaseReg != tt.heapReg || meta.HeapBaseTHRField != tt.heapTHRField {
				t.Fatalf("heap source = (%q,%q,%q), want (%q,%q,%q)", meta.HeapBaseMode, meta.HeapBaseReg, meta.HeapBaseTHRField, tt.heapMode, tt.heapReg, tt.heapTHRField)
			}
		})
	}
}

func TestBuildFridaMetadataUsesVersionedDispatchCIDRegister(t *testing.T) {
	tests := []struct {
		name, version, want string
		arm64               bool
	}{
		{"arm64 2.12 mutates cid register", "2.12.0", "", true},
		{"arm64 2.13 preserves cid register", "2.13.0", "x0", true},
		{"x64 2.12 preserves observed cid register", "2.12.0", "rdx", false},
		{"x64 2.13 uses fixed cid register", "2.13.0", "rcx", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			ef := writeFridaTestProvenance(t, dir, tt.version, tt.arm64, false)
			if err := os.WriteFile(filepath.Join(dir, "functions.jsonl"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			reg := "[RAX+RDX*8+0x20]"
			kind := "call_indirect"
			if tt.arm64 {
				reg = "X16"
				kind = "blr"
			} else if tt.version != "2.12.0" {
				reg = "[RAX+RCX*8+0x20]"
			}
			edge := disasm.CallEdgeRecord{Kind: kind, FromFunc: "F", FromPC: "0x100", Reg: reg, Via: "dispatch_table"}
			b, err := json.Marshal(edge)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "call_edges.jsonl"), append(b, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
			ctx := &AnalysisContext{
				Info: &snapshot.Info{Version: &snapshot.VersionProfile{
					DartVersion: tt.version, CompressedPointers: false,
				}},
				DartVersion: tt.version,
				IsARM64:     tt.arm64,
				EF:          ef,
			}
			meta, err := BuildFridaMetadata(ctx, dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(meta.CallProbes) != 1 || meta.CallProbes[0].ClassIDReg != tt.want {
				t.Fatalf("dispatch probe=%+v, want class-id register %q", meta.CallProbes, tt.want)
			}
			if len(meta.InstalledCallProbes) != 1 || meta.InstalledCallProbes[0].ClassIDReg != tt.want {
				t.Fatalf("installed dispatch probe=%+v, want class-id register %q", meta.InstalledCallProbes, tt.want)
			}
		})
	}
}

func TestArchiveEntryLimitRejectsDeclaredExpansion(t *testing.T) {
	f := &zip.File{FileHeader: zip.FileHeader{Name: "lib/arm64-v8a/libapp.so", UncompressedSize64: maxLibappEntryBytes + 1}}
	if _, _, _, err := extractZipEntryToTemp(f, "never-*.so", maxLibappEntryBytes, &archiveWorkBudget{}); err == nil {
		t.Fatal("oversized zip entry was accepted")
	}
}

func TestArchiveWorkBudgetAggregatesAcrossNestedEntries(t *testing.T) {
	b := &archiveWorkBudget{}
	chunk := maxArchiveWorkBytes / 2
	if err := b.reserveDeclared("a.apk", chunk); err != nil {
		t.Fatal(err)
	}
	if err := b.reserveDeclared("b.apk", chunk); err != nil {
		t.Fatal(err)
	}
	if err := b.reserveDeclared("c.apk", 1); err == nil {
		t.Fatal("cumulative declared expansion above operation budget was accepted")
	}
	if err := b.chargeExpanded("a.apk", chunk); err != nil {
		t.Fatal(err)
	}
	if err := b.chargeExpanded("b.apk", chunk); err != nil {
		t.Fatal(err)
	}
	if err := b.chargeExpanded("c.apk", 1); err == nil {
		t.Fatal("cumulative expanded bytes above operation budget were accepted")
	}
}

func TestInventoryExtractLibappRejectsMalformedNestedAPK(t *testing.T) {
	outerPath := filepath.Join(t.TempDir(), "outer.zip")
	f, err := os.Create(outerPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("payload/base.apk")
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("not a zip archive")); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	_, _, err = InventoryExtractLibapp(outerPath)
	if err == nil {
		t.Fatal("malformed nested APK was reported as a clean no-libapp result")
	}
	if !strings.Contains(err.Error(), "open nested APK") {
		t.Fatalf("malformed nested APK error = %q, want explicit nested-open failure", err)
	}
}

func TestInventoryExtractLibappDistinguishesCleanAbsenceFromArchiveFailure(t *testing.T) {
	emptyArchive := filepath.Join(t.TempDir(), "empty.zip")
	f, err := os.Create(emptyArchive)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	if err := zw.Close(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := InventoryExtractLibapp(emptyArchive); !errors.Is(err, ErrInventoryNoLibapp) {
		t.Fatalf("valid archive without libapp error = %v, want ErrInventoryNoLibapp", err)
	}

	brokenArchive := filepath.Join(t.TempDir(), "broken.zip")
	if err := os.WriteFile(brokenArchive, []byte("not a zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := InventoryExtractLibapp(brokenArchive); err == nil || errors.Is(err, ErrInventoryNoLibapp) {
		t.Fatalf("corrupt archive error = %v, want a real archive failure", err)
	}
}

func TestRunGraphPublishesOneFreshGeneration(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "graph")
	stale := filepath.Join(outDir, "stale-from-previous-run.txt")
	// Only a directory an earlier aotopsy run published may be replaced.
	publishAuditTestGeneration(t, outDir, map[string][]byte{"stale-from-previous-run.txt": []byte("stale")})

	if err := RunGraph(sample312X64(t), outDir, "isolate", 0); err != nil {
		t.Fatalf("RunGraph: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale graph generation survived successful publication: %v", err)
	}
	objects, err := jsonutil.ReadJSONL[GraphObject](filepath.Join(outDir, "objects.jsonl"), jsonutil.StandardLimits)
	if err != nil || len(objects) == 0 {
		t.Fatalf("objects.jsonl = %d records, err=%v", len(objects), err)
	}
	edges, err := jsonutil.ReadJSONL[GraphEdge](filepath.Join(outDir, "edges.jsonl"), jsonutil.StandardLimits)
	if err != nil || len(edges) == 0 {
		t.Fatalf("edges.jsonl = %d records, err=%v", len(edges), err)
	}
	codeMap, err := jsonutil.ReadJSONL[CodeMapEntry](filepath.Join(outDir, "code_map.jsonl"), jsonutil.StandardLimits)
	if err != nil || len(codeMap) == 0 {
		t.Fatalf("code_map.jsonl = %d records, err=%v", len(codeMap), err)
	}
}

func TestRunGraphRejectsOutputContainingSourceBinary(t *testing.T) {
	dir := t.TempDir()
	lib := filepath.Join(dir, "libapp.so")
	const original = "source-must-survive"
	if err := os.WriteFile(lib, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RunGraph(lib, dir, "isolate", 0); err == nil {
		t.Fatal("RunGraph accepted an output directory containing its source binary")
	}
	got, err := os.ReadFile(lib)
	if err != nil || string(got) != original {
		t.Fatalf("rejected graph output changed source binary: %q, %v", got, err)
	}
}

type alwaysFailWriter struct{}

func (alwaysFailWriter) Write([]byte) (int, error) { return 0, errors.New("forced write failure") }

func TestParityEncodersPropagateWriterErrors(t *testing.T) {
	rows := []ParityRow{{SampleHash: "sample", DartVersion: "3.12.2", Supported: true, Status: "OK"}}
	if err := writeParityCSV(alwaysFailWriter{}, rows); err == nil {
		t.Fatal("CSV encoder swallowed destination write error")
	}
	if err := writeParitySummary(alwaysFailWriter{}, rows); err == nil {
		t.Fatal("summary encoder swallowed destination write error")
	}
}

func TestRunParityPublishesManagedReportsTogether(t *testing.T) {
	samplesDir := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "parity")
	prior, err := output.BeginDirTransaction(outDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"parity.csv", "parity_summary.md"} {
		if err := output.WriteArtifactFile(prior.StageDir(), name, []byte("stale-generation"), 0o600); err != nil {
			prior.Abort()
			t.Fatal(err)
		}
	}
	if err := output.WriteArtifactFile(prior.StageDir(), "obsolete.txt", []byte("old"), 0o600); err != nil {
		prior.Abort()
		t.Fatal(err)
	}
	if err := prior.Commit(); err != nil {
		prior.Abort()
		t.Fatal(err)
	}

	if err := RunParity(samplesDir, outDir); err != nil {
		t.Fatalf("RunParity: %v", err)
	}
	csvData, err := os.ReadFile(filepath.Join(outDir, "parity.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(csvData), "stale-generation") || !strings.Contains(string(csvData), "sample_hash,dart_version,status") {
		t.Fatalf("parity.csv was not a fresh generation: %q", csvData)
	}
	summary, err := os.ReadFile(filepath.Join(outDir, "parity_summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(summary), "stale-generation") || !strings.Contains(string(summary), "Total samples: 0") {
		t.Fatalf("parity_summary.md was not a fresh generation: %q", summary)
	}
	if _, err := os.Stat(filepath.Join(outDir, "obsolete.txt")); !os.IsNotExist(err) {
		t.Fatalf("obsolete prior-generation artifact survived whole-directory publication: %v", err)
	}
}

func TestRunParityRejectsOutputContainingSamplesDirectory(t *testing.T) {
	root := t.TempDir()
	samplesDir := filepath.Join(root, "samples")
	if err := os.MkdirAll(samplesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := RunParity(samplesDir, root); err == nil || !strings.Contains(err.Error(), "must not contain the samples directory") {
		t.Fatalf("destructive parity input/output overlap was not rejected: %v", err)
	}
}

func TestRequiredMetaRejectsX64FromGenerationTransactionally(t *testing.T) {
	src := t.TempDir()
	for _, name := range []string{"functions.jsonl", "call_edges.jsonl"} {
		if err := os.WriteFile(filepath.Join(src, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := output.WriteJSONFile(filepath.Join(src, ProvenanceFileName), auditFixtureProvenance(t, "x64", "3.12.2")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "flutter_meta.json"), []byte("stale-x64-meta"), 0o600); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "published")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(dst, "old-generation.txt")
	if err := os.WriteFile(sentinel, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Run(Opts{FromDir: src, OutDir: dst, Meta: MetaRequired, Quiet: true}); err == nil {
		t.Fatal("required x64 flutter_meta generation reported success")
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "old" {
		t.Fatalf("failed required-meta rerun changed previous generation: %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(src, "flutter_meta.json")); err != nil || string(got) != "stale-x64-meta" {
		t.Fatalf("failed rerun mutated --from source: %q, %v", got, err)
	}
}

func TestOptionalMetaDropsStaleX64ArtifactFromClonedGeneration(t *testing.T) {
	src := t.TempDir()
	for _, name := range []string{"functions.jsonl", "call_edges.jsonl"} {
		if err := os.WriteFile(filepath.Join(src, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := output.WriteJSONFile(filepath.Join(src, ProvenanceFileName), auditFixtureProvenance(t, "x64", "3.12.2")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "flutter_meta.json"), []byte("stale-x64-meta"), 0o600); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "published")
	var log bytes.Buffer
	if _, err := Run(Opts{FromDir: src, OutDir: dst, Meta: MetaIfSupported, Quiet: true, Log: &log}); err != nil {
		t.Fatalf("optional x64 meta rerun failed: %v", err)
	}
	if got := log.String(); !strings.Contains(got, "warning: flutter_meta.json generation skipped") {
		t.Fatalf("quiet mode hid optional-meta degradation warning: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dst, "flutter_meta.json")); !os.IsNotExist(err) {
		t.Fatalf("stale x64 flutter_meta survived optional rerun: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(src, "flutter_meta.json")); err != nil || string(got) != "stale-x64-meta" {
		t.Fatalf("optional rerun mutated --from source: %q, %v", got, err)
	}
}

func TestPrepareFuncSymbolsIsRangeBound(t *testing.T) {
	ranges := []cluster.CodeRange{{PCOffset: 0x20, Size: 4}}
	got := prepareFuncSymbols(map[uint64]string{
		0x1010: "container",
		0x1020: "real_function",
	}, ranges, 0x1000, 0)
	if len(got) != 1 || got[0x1020] != "real_function" {
		t.Fatalf("range-bound symbols = %#v", got)
	}
}

func TestLoadSnapshotKeepsMalformedELFAsOpenError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "malformed.so")
	b := make([]byte, 64)
	copy(b[:4], []byte{0x7f, 'E', 'L', 'F'})
	b[4], b[5], b[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(b[16:18], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(b[18:20], uint16(elf.EM_AARCH64))
	binary.LittleEndian.PutUint32(b[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint64(b[40:48], 64) // section table starts exactly at EOF
	binary.LittleEndian.PutUint16(b[52:54], 64)
	binary.LittleEndian.PutUint16(b[58:60], 64)
	binary.LittleEndian.PutUint16(b[60:62], 1)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadSnapshot(p, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
	if !errors.Is(err, elfx.ErrMalformed) {
		t.Fatalf("LoadSnapshot(malformed ELF) = %v, want ErrMalformed preserved", err)
	}
	if err != nil && strings.Contains(err.Error(), "HALT_UNSUPPORTED_VERSION") {
		t.Fatalf("malformed ELF was mislabeled as unsupported Dart version: %v", err)
	}
}

func TestFindLibappDoesNotDowngradeMalformedELFToMagic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "malformed.apk")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("lib/arm64-v8a/libapp.so")
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	copy(b[:4], []byte{0x7f, 'E', 'L', 'F'})
	b[4], b[5], b[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(b[16:18], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(b[18:20], uint16(elf.EM_AARCH64))
	binary.LittleEndian.PutUint32(b[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint64(b[40:48], 64) // section table is truncated
	binary.LittleEndian.PutUint16(b[52:54], 64)
	binary.LittleEndian.PutUint16(b[58:60], 64)
	binary.LittleEndian.PutUint16(b[60:62], 1)
	b = append(b, []byte{0xf5, 0xf5, 0xdc, 0xdc}...)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if result, err := FindLibappInZip(path); !errors.Is(err, elfx.ErrMalformed) {
		t.Fatalf("FindLibappInZip(malformed ELF + magic) = result=%+v err=%v, want ErrMalformed", result, err)
	}
}

func TestFindLibappDoesNotTrustMagicInNonELF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake.apk")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("lib/arm64-v8a/libapp.so")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte{0x00, 0xf5, 0xf5, 0xdc, 0xdc, 0x00}); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := FindLibappInZip(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Found || got.Reason != "NOT_FLUTTER" {
		t.Fatalf("non-ELF magic became a Dart hit: %+v", got)
	}
}

func TestFindLibappAcceptsX8664CandidateWithoutFabricatingHit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("lib/x86_64/libapp.so")
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	// A minimal valid x86_64 ET_DYN maps snapshot magic in PT_LOAD but has no
	// Dart snapshot symbols. ABI discovery must accept the candidate machine
	// without turning four magic bytes into a verified Dart hit.
	const (
		ehSize = 64
		phSize = 56
	)
	b := make([]byte, 0x100)
	copy(b[:4], []byte{0x7f, 'E', 'L', 'F'})
	b[4], b[5], b[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(b[16:18], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(b[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(b[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint64(b[32:40], ehSize)
	binary.LittleEndian.PutUint16(b[52:54], ehSize)
	binary.LittleEndian.PutUint16(b[54:56], phSize)
	binary.LittleEndian.PutUint16(b[56:58], 1)
	ph := b[ehSize : ehSize+phSize]
	binary.LittleEndian.PutUint32(ph[0:4], uint32(elf.PT_LOAD))
	binary.LittleEndian.PutUint32(ph[4:8], uint32(elf.PF_R))
	binary.LittleEndian.PutUint64(ph[32:40], uint64(len(b)))
	binary.LittleEndian.PutUint64(ph[40:48], uint64(len(b)))
	binary.LittleEndian.PutUint64(ph[48:56], 0x1000)
	copy(b[0xf0:], []byte{0xf5, 0xf5, 0xdc, 0xdc})
	if _, err := w.Write(b); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := FindLibappInZip(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Found || got.Reason != "NOT_FLUTTER" || got.Best != nil {
		t.Fatalf("x86_64 magic-only candidate became a verified Dart hit: %+v", got)
	}
	if len(got.Candidates) != 1 || got.Candidates[0].PathInAPK != "lib/x86_64/libapp.so" || !IsStandardLibappPath(got.Candidates[0].PathInAPK) {
		t.Fatalf("x86_64 standard path classification = %+v", got.Candidates)
	}
}

func TestRunFromExistingWritesSignalArtifactsOnlyToOutDir(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	for _, name := range []string{"functions.jsonl", "index.jsonl", "call_edges.jsonl", "string_refs.jsonl"} {
		if err := os.WriteFile(filepath.Join(src, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Run(Opts{FromDir: src, OutDir: dst, Signal: true, Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.OutDir != dst {
		t.Fatalf("result.OutDir=%q, want %q", result.OutDir, dst)
	}
	after, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("source directory was mutated: before=%d files after=%d", len(before), len(after))
	}
	if _, err := os.Stat(filepath.Join(dst, "signal_graph.json")); err != nil {
		t.Fatalf("signal output missing from destination: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "functions.jsonl")); err != nil {
		t.Fatalf("detached output is not reusable; cloned input missing: %v", err)
	}
}

func TestRunFromExistingCarriesProvenanceIdentityIntoResult(t *testing.T) {
	src := t.TempDir()
	for _, name := range []string{"functions.jsonl", "call_edges.jsonl"} {
		if err := os.WriteFile(filepath.Join(src, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := output.WriteJSONFile(filepath.Join(src, ProvenanceFileName), auditFixtureProvenance(t, "x64", "3.12.2")); err != nil {
		t.Fatal(err)
	}

	result, err := Run(Opts{FromDir: src, OutDir: filepath.Join(t.TempDir(), "out"), Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Arch != "x64" || result.DartVersion != "3.12.2" {
		t.Fatalf("reused result identity = arch %q Dart %q, want x64/3.12.2", result.Arch, result.DartVersion)
	}
}

func TestRunFromExistingWithoutSignalDropsStaleSignalGeneration(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "out")
	for _, name := range []string{"functions.jsonl", "call_edges.jsonl"} {
		if err := os.WriteFile(filepath.Join(src, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stale := append([]string{}, signalGenerationArtifacts...)
	stale = append(stale, signalDetectorArtifacts...)
	for _, name := range stale {
		if err := os.WriteFile(filepath.Join(src, name), []byte("stale generation\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := Run(Opts{FromDir: src, OutDir: dst, Quiet: true}); err != nil {
		t.Fatal(err)
	}
	for _, name := range stale {
		if _, err := os.Stat(filepath.Join(dst, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale signal artifact %s survived no-signal --from generation: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(src, name)); err != nil {
			t.Fatalf("source artifact %s was mutated while cleaning destination: %v", name, err)
		}
	}
}

func TestRunSignalStageLegacyArtifactsDoNotGuessArchitecture(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	asmDir := filepath.Join(src, "asm")
	if err := os.MkdirAll(asmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeLine := func(name string, v any) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, '\n')
		if err := os.WriteFile(filepath.Join(src, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeLine("functions.jsonl", disasm.FuncRecord{PC: "0x1000", RefID: 1, Size: 4, Name: "F"})
	writeLine("index.jsonl", strutil.DisasmIndexEntry{Name: "F", RefID: 1, Size: 4, File: "asm/F.txt"})
	if err := os.WriteFile(filepath.Join(src, "call_edges.jsonl"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	writeLine("string_refs.jsonl", disasm.StringRefRecord{Func: "F", PC: "0x1000", Value: "https://api.example.test/v1"})
	if err := os.WriteFile(filepath.Join(asmDir, "F.txt"), []byte("00001000: nop\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var log bytes.Buffer
	res, err := RunSignalStage(src, dst, 1, false, true, &log, false)
	if err != nil {
		t.Fatalf("legacy signal reuse failed without provenance: %v", err)
	}
	if got := log.String(); !strings.Contains(got, "warning: legacy analysis has no provenance architecture") {
		t.Fatalf("quiet mode hid missing-provenance warning: %q", got)
	}
	if res.SignalCount != 1 {
		t.Fatalf("signal count = %d, want 1", res.SignalCount)
	}
	if _, err := os.Stat(filepath.Join(dst, "signal_cfg.dot")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("architecture-dependent CFG should be omitted without provenance, stat err=%v", err)
	}
}

func TestRemoveSignalDetectorArtifactsClearsCompleteGeneration(t *testing.T) {
	dir := t.TempDir()
	for _, name := range signalDetectorArtifacts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("stale\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeSignalDetectorArtifacts(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range signalDetectorArtifacts {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale detector artifact %s survived cleanup: %v", name, err)
		}
	}
}

func TestDisasmArtifactFilesUsesProducerOwnedIndexPath(t *testing.T) {
	// The producer names this closure from its raw function name and PC offset;
	// the qualified display name cannot be inverted back to that filename.
	funcs := []disasm.FuncRecord{{
		PC:       "0x1000",
		PCOffset: 0xb1460,
		RefID:    77,
		Size:     4,
		Name:     "ShortcutManager.handleKeypress.#action#initializer_b1460",
		Owner:    "ShortcutManager",
	}}
	index := []strutil.DisasmIndexEntry{{
		Name:      "#action#initializer",
		OwnerName: "ShortcutManager",
		RefID:     77,
		PCOffset:  0xb1460,
		Size:      4,
		File:      "asm/ShortcutManager/#action#initializer_b1460.txt",
	}}

	got, err := DisasmArtifactFiles(funcs, index)
	if err != nil {
		t.Fatal(err)
	}
	if want := index[0].File; got[funcs[0].Name] != filepath.FromSlash(want) {
		t.Fatalf("artifact path = %q, want exact producer path %q", got[funcs[0].Name], filepath.FromSlash(want))
	}
}

func TestDisasmArtifactFilesRejectsCorruptParallelStreams(t *testing.T) {
	baseFunc := disasm.FuncRecord{PC: "0x1000", PCOffset: 0x10, RefID: 7, Size: 4, Name: "Owner.f_10", Owner: "Owner"}
	baseIndex := strutil.DisasmIndexEntry{Name: "f", OwnerName: "Owner", RefID: 7, PCOffset: 0x10, Size: 4, File: "asm/Owner/f_10.txt"}
	tests := []struct {
		name  string
		funcs []disasm.FuncRecord
		index []strutil.DisasmIndexEntry
	}{
		{"count", []disasm.FuncRecord{baseFunc}, nil},
		{"identity", []disasm.FuncRecord{baseFunc}, []strutil.DisasmIndexEntry{{Name: "f", OwnerName: "Owner", RefID: 8, PCOffset: 0x10, Size: 4, File: baseIndex.File}}},
		{"size", []disasm.FuncRecord{baseFunc}, []strutil.DisasmIndexEntry{{Name: "f", OwnerName: "Owner", RefID: 7, PCOffset: 0x10, Size: 8, File: baseIndex.File}}},
		{"traversal", []disasm.FuncRecord{baseFunc}, []strutil.DisasmIndexEntry{{Name: "f", OwnerName: "Owner", RefID: 7, PCOffset: 0x10, Size: 4, File: "../escape.txt"}}},
		{"not asm", []disasm.FuncRecord{baseFunc}, []strutil.DisasmIndexEntry{{Name: "f", OwnerName: "Owner", RefID: 7, PCOffset: 0x10, Size: 4, File: "cfg/Owner/f_10.txt"}}},
		{"duplicate function", []disasm.FuncRecord{baseFunc, baseFunc}, []strutil.DisasmIndexEntry{baseIndex, baseIndex}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DisasmArtifactFiles(tt.funcs, tt.index); err == nil {
				t.Fatal("corrupt functions/index streams were accepted")
			}
		})
	}
}

func TestDisasmArtifactFilesJoinsByIdentityNotRowOrder(t *testing.T) {
	funcs := []disasm.FuncRecord{
		{PCOffset: 0x20, RefID: 2, Size: 4, Name: "B"},
		{PCOffset: 0x10, RefID: 1, Size: 4, Name: "A"},
	}
	index := []strutil.DisasmIndexEntry{
		{RefID: 1, PCOffset: 0x10, Size: 4, File: "asm/A.txt"},
		{RefID: 2, PCOffset: 0x20, Size: 4, File: "asm/B.txt"},
	}
	got, err := DisasmArtifactFiles(funcs, index)
	if err != nil {
		t.Fatal(err)
	}
	if got["A"] != filepath.FromSlash("asm/A.txt") || got["B"] != filepath.FromSlash("asm/B.txt") {
		t.Fatalf("identity join = %#v", got)
	}
}

func TestDisasmArtifactFilesAllowsDeduplicatedCodeAliases(t *testing.T) {
	funcs := []disasm.FuncRecord{
		{PCOffset: 0x10, RefID: 1, Size: 4, Name: "Owner.same_10"},
		{PCOffset: 0x10, RefID: 2, Size: 4, Name: "Owner.same_10"},
	}
	index := []strutil.DisasmIndexEntry{
		{RefID: 1, PCOffset: 0x10, Size: 4, File: "asm/Owner/same_10.txt"},
		{RefID: 2, PCOffset: 0x10, Size: 4, File: "asm/Owner/same_10.txt"},
	}
	got, err := DisasmArtifactFiles(funcs, index)
	if err != nil {
		t.Fatalf("deduplicated Code aliases rejected: %v", err)
	}
	if got["Owner.same_10"] != filepath.FromSlash("asm/Owner/same_10.txt") {
		t.Fatalf("artifact alias = %q", got["Owner.same_10"])
	}

	index[1].File = "asm/Owner/other_10.txt"
	if _, err := DisasmArtifactFiles(funcs, index); err == nil {
		t.Fatal("same display name pointing at different artifacts was accepted")
	}
}

func TestRunFromExistingFailurePreservesPreviousDestination(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "dst")
	// Enough to pass runFromExisting's base validation, then fail inside the
	// signal stage because string_refs.jsonl is absent.
	for _, name := range []string{"functions.jsonl", "call_edges.jsonl"} {
		if err := os.WriteFile(filepath.Join(src, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Without the marker the transaction would refuse the destination before
	// the signal stage ran, and this test would pass for the wrong reason.
	publishAuditTestGeneration(t, dst, map[string][]byte{"sentinel.txt": []byte("previous generation")})
	sentinel := filepath.Join(dst, "sentinel.txt")
	_, err := Run(Opts{FromDir: src, OutDir: dst, Signal: true, Quiet: true})
	if err == nil {
		t.Fatal("expected signal regeneration to fail")
	}
	if strings.Contains(err.Error(), output.GenerationMarker) {
		t.Fatalf("failed on the ownership guard, not the signal stage: %v", err)
	}
	b, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("failed rerun destroyed previous destination: %v", err)
	}
	if string(b) != "previous generation" {
		t.Fatalf("previous destination changed after failed rerun: %q", b)
	}
}

func TestOutputTransactionCommitReplacesWholeGeneration(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "out")
	publishAuditTestGeneration(t, target, map[string][]byte{"stale.txt": []byte("stale")})
	tx, err := output.BeginDirTransaction(target)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Abort()
	if err := os.WriteFile(filepath.Join(tx.StageDir(), "fresh.txt"), []byte("fresh"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "stale.txt")); !os.IsNotExist(err) {
		t.Fatalf("stale artifact survived whole-generation commit: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(target, "fresh.txt")); err != nil || string(b) != "fresh" {
		t.Fatalf("fresh generation missing: %q, %v", b, err)
	}
}

// A directory generation is replaced wholesale, so `--out` at a directory that
// holds someone's own files must be refused before any analysis or deletion.
func TestRunRefusesForeignOutputDirectory(t *testing.T) {
	lib := filepath.Join(t.TempDir(), "libapp.so")
	if err := os.WriteFile(lib, []byte("not-an-elf"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "my-project")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	precious := filepath.Join(out, "notes.txt")
	if err := os.WriteFile(precious, []byte("irreplaceable"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Run(Opts{LibPath: lib, OutDir: out, Quiet: true})
	if err == nil || !strings.Contains(err.Error(), output.GenerationMarker) {
		t.Fatalf("Run did not refuse a foreign directory with the marker explanation: %v", err)
	}
	if b, readErr := os.ReadFile(precious); readErr != nil || string(b) != "irreplaceable" {
		t.Fatalf("user data destroyed by --out: %q, %v", b, readErr)
	}
}

func TestRunRejectsOutputDirectoryContainingSourceBinary(t *testing.T) {
	dir := t.TempDir()
	lib := filepath.Join(dir, "libapp.so")
	const original = "not-an-elf-but-must-survive"
	if err := os.WriteFile(lib, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(Opts{LibPath: lib, OutDir: dir, Quiet: true}); err == nil {
		t.Fatal("pipeline accepted an output directory containing its source binary")
	}
	b, err := os.ReadFile(lib)
	if err != nil || string(b) != original {
		t.Fatalf("source binary changed after rejected output path: %q, %v", b, err)
	}
}

func TestRunMetaStageRejectsMissingOrMalformedDartMeta(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"missing", ""},
		{"malformed", `{"arch":"arm64","dart_version":"3.9.2","compressed_pointers":true,"pointer_size":8,"thr_fields":[]}`},
		{"wrong-arch", `{"arch":"x64","dart_version":"3.9.2","compressed_pointers":true,"pointer_size":4,"thr_fields":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeAuditMetaProvenance(t, dir, "3.9.2", true)
			for _, name := range []string{"functions.jsonl", "classes.jsonl", "string_refs.jsonl"} {
				if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(filepath.Join(dir, "asm"), 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.body != "" {
				if err := os.WriteFile(filepath.Join(dir, "dart_meta.json"), []byte(tc.body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := RunMetaStage(dir, dir, "arm64", true, true, io.Discard); err == nil {
				t.Fatal("invalid dart_meta.json was silently accepted")
			}
		})
	}
}

func writeAuditMetaProvenance(t *testing.T, dir, version string, compressed bool) Provenance {
	t.Helper()
	prov := auditFixtureProvenance(t, "arm64", version)
	prov.CompressedPointers = compressed
	if err := output.WriteJSONFile(filepath.Join(dir, ProvenanceFileName), prov); err != nil {
		t.Fatal(err)
	}
	return prov
}

func writeExactAuditDartMeta(t *testing.T, dir string) strutil.DartMetaJSON {
	t.Helper()
	p := snapshot.ProfileForVersion("3.9.2")
	if p == nil {
		t.Fatal("missing 3.9.2 profile")
	}
	p.BuildMode = snapshot.BuildProduct
	p.CompressedPointers = true
	target, ok := vmtables.TargetProfileFromVersion(p, true)
	if !ok {
		t.Fatal("could not derive exact 3.9.2 ARM64 metadata target")
	}
	if err := strutil.WriteDartMeta(dir, target); err != nil {
		t.Fatal(err)
	}
	writeAuditMetaProvenance(t, dir, "3.9.2", true)
	meta, err := strutil.DartMetaForTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	return meta
}

func TestRunMetaStageWritesValidMetaAtomicallyAndPreservesUTF8(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "functions.jsonl"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "classes.jsonl"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	longValue := "🙂" + string(make([]rune, 0))
	for i := 0; i < 100; i++ {
		longValue += "界"
	}
	ref := disasm.StringRefRecord{PC: "0x1000", Value: longValue}
	refBytes, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "string_refs.jsonl"), append(refBytes, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "asm"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeExactAuditDartMeta(t, dir)
	path, err := RunMetaStage(dir, dir, "arm64", true, true, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(b) {
		t.Fatalf("flutter_meta.json is invalid JSON/UTF-8: %q", b)
	}
	var meta strutil.FlutterMetaJSON
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Version != "3" || meta.Architecture != "arm64" || len(meta.BinarySHA256) != 64 || meta.BinarySize <= 0 {
		t.Fatalf("flutter meta identity = version %q arch %q sha=%q size=%d, want version 3 arm64 with binary identity",
			meta.Version, meta.Architecture, meta.BinarySHA256, meta.BinarySize)
	}
}

func TestRunMetaStageIncludesNestedAsmComments(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"functions.jsonl", "classes.jsonl", "string_refs.jsonl"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeExactAuditDartMeta(t, dir)
	asmPath := filepath.Join(dir, "asm", "Owner", "method.txt")
	if err := os.MkdirAll(filepath.Dir(asmPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(asmPath, []byte("0x0010  ldr x0, [x1] ; nested annotation\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	path, err := RunMetaStage(dir, dir, "arm64", true, true, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var meta strutil.FlutterMetaJSON
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatal(err)
	}
	want := []strutil.FlutterMetaComment{{Addr: "0x10", Text: "nested annotation"}}
	if !reflect.DeepEqual(meta.Comments, want) {
		t.Fatalf("nested asm comments = %#v, want %#v", meta.Comments, want)
	}
}

func TestRunMetaStageRejectsControlBearingDartVersionWithoutLogInjection(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR", "")
	t.Setenv("CLICOLOR_FORCE", "1")
	dir := t.TempDir()
	for _, name := range []string{"functions.jsonl", "classes.jsonl", "string_refs.jsonl"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "asm"), 0o755); err != nil {
		t.Fatal(err)
	}
	meta := writeExactAuditDartMeta(t, dir)
	meta.DartVersion = "3.9.2\x1b[8mHIDDEN\x1b[0m\nFORGED"
	b, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dart_meta.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	_, err = RunMetaStage(dir, dir, "arm64", true, false, &log)
	if err == nil {
		t.Fatal("control-bearing unknown Dart version was accepted")
	}
	if got := log.String(); strings.Contains(got, "\x1b[8m") || strings.Contains(got, "\nFORGED") {
		t.Fatalf("rejected metadata still injected terminal controls/log lines: %q", got)
	}
	if strings.Contains(err.Error(), "\x1b[8m") || strings.Contains(err.Error(), "\nFORGED") {
		t.Fatalf("error exposed raw terminal control/newline: %q", err)
	}
}

func TestRunMetaStageRejectsAmbiguousAddressesAndIdentityMismatch(t *testing.T) {
	makeBase := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		for _, name := range []string{"classes.jsonl", "string_refs.jsonl"} {
			if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Mkdir(filepath.Join(dir, "asm"), 0o755); err != nil {
			t.Fatal(err)
		}
		writeExactAuditDartMeta(t, dir)
		return dir
	}

	t.Run("duplicate-normalized-function-address", func(t *testing.T) {
		dir := makeBase(t)
		rows := []disasm.FuncRecord{
			{PC: "0x0010", Size: 4, Name: "first"},
			{PC: "0X10", Size: 4, Name: "second"},
		}
		if _, err := jsonutil.WriteJSONLFile(filepath.Join(dir, "functions.jsonl"), rows); err != nil {
			t.Fatal(err)
		}
		if _, err := RunMetaStage(dir, dir, "arm64", true, true, io.Discard); err == nil || !strings.Contains(err.Error(), "duplicate function address") {
			t.Fatalf("duplicate normalized address error = %v", err)
		}
	})

	t.Run("oversized-function-range", func(t *testing.T) {
		dir := makeBase(t)
		rows := []disasm.FuncRecord{{PC: "0x10", Size: int(maxFunctionBinBytes + 1), Name: "too_large"}}
		if _, err := jsonutil.WriteJSONLFile(filepath.Join(dir, "functions.jsonl"), rows); err != nil {
			t.Fatal(err)
		}
		if _, err := RunMetaStage(dir, dir, "arm64", true, true, io.Discard); err == nil || !strings.Contains(err.Error(), "invalid size") {
			t.Fatalf("oversized function range error = %v", err)
		}
	})

	t.Run("dart-meta-provenance-mismatch", func(t *testing.T) {
		dir := makeBase(t)
		if err := os.WriteFile(filepath.Join(dir, "functions.jsonl"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		prov := writeAuditMetaProvenance(t, dir, "3.12.2", true)
		_ = prov
		if _, err := RunMetaStage(dir, dir, "arm64", true, true, io.Discard); err == nil || !strings.Contains(err.Error(), "identity disagrees with provenance") {
			t.Fatalf("metadata identity mismatch error = %v", err)
		}
	})

	t.Run("invalid-class-layout", func(t *testing.T) {
		dir := makeBase(t)
		if err := os.WriteFile(filepath.Join(dir, "functions.jsonl"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		rows := []strutil.FlutterMetaJSONClass{{
			ClassName:    "Bad",
			ClassID:      0,
			InstanceSize: 12,
			Fields: []strutil.FlutterMetaField{{
				Name:        "type_arguments_field",
				ByteOffset:  4,
				IsReference: false,
				SlotType:    "type_arguments_field",
			}},
		}}
		if _, err := jsonutil.WriteJSONLFile(filepath.Join(dir, "classes.jsonl"), rows); err != nil {
			t.Fatal(err)
		}
		if _, err := RunMetaStage(dir, dir, "arm64", true, true, io.Discard); err == nil || !strings.Contains(err.Error(), "invalid identity/layout") {
			t.Fatalf("invalid class layout error = %v", err)
		}
	})

	t.Run("invalid-class-slot-semantics", func(t *testing.T) {
		dir := makeBase(t)
		if err := os.WriteFile(filepath.Join(dir, "functions.jsonl"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		rows := []strutil.FlutterMetaJSONClass{{
			ClassName:    "BadSlot",
			ClassID:      42,
			InstanceSize: 16,
			Fields: []strutil.FlutterMetaField{{
				Name:        "type_arguments_field",
				ByteOffset:  8,
				IsReference: false,
				SlotType:    "type_arguments_field",
			}},
		}}
		if _, err := jsonutil.WriteJSONLFile(filepath.Join(dir, "classes.jsonl"), rows); err != nil {
			t.Fatal(err)
		}
		if _, err := RunMetaStage(dir, dir, "arm64", true, true, io.Discard); err == nil || !strings.Contains(err.Error(), "type_arguments_field as non-reference") {
			t.Fatalf("invalid class slot semantics error = %v", err)
		}
	})
}

func TestPipelineDiagnosticsRemainVisibleBoundedAndSanitizedInQuietMode(t *testing.T) {
	var log bytes.Buffer
	opts := Opts{Quiet: true, Log: &log}
	result := &Result{}
	diags := make([]dartfmt.Diag, maxReportedPipelineDiagnostics+3)
	for i := range diags {
		diags[i] = dartfmt.Diag{
			Offset: uint64(i),
			Kind:   dartfmt.DiagTruncated,
			Msg:    fmt.Sprintf("broken-%d\nFORGED\x1b[2J\u202etext", i),
		}
	}

	opts.reportDiagnostics(result, "snapshot", diags)
	got := log.String()
	if strings.Contains(got, "\nFORGED") || strings.Contains(got, "\x1b[") || strings.ContainsRune(got, '\u202e') {
		t.Fatalf("pipeline diagnostic injected terminal controls in quiet mode: %q", got)
	}
	if !strings.Contains(got, "warning: snapshot diagnostic:") {
		t.Fatalf("quiet mode hid pipeline diagnostic: %q", got)
	}
	if !strings.Contains(got, "3 additional issue(s) suppressed") {
		t.Fatalf("diagnostic cap was not reported: %q", got)
	}
	if want := maxReportedPipelineDiagnostics + 1; len(result.Diags) != want {
		t.Fatalf("Result.Diags length = %d, want %d bounded entries", len(result.Diags), want)
	}
}

func TestReadProvenanceRejectsMalformedReuseMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ProvenanceFileName)
	for _, body := range []string{
		`{"source_name":"libapp.so","arch":"arm64","unexpected":true}`,
		`{"source_name":`,
		`{"source":"/tmp/libapp.so"}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadProvenance(dir); err == nil {
			t.Fatalf("malformed provenance was silently accepted: %q", body)
		}
	}
}

func TestDecompileRuntimeLimitsAreRestored(t *testing.T) {
	origProcs := runtime.GOMAXPROCS(3)
	defer runtime.GOMAXPROCS(origProcs)
	origLimit := debug.SetMemoryLimit(777 << 20)
	defer debug.SetMemoryLimit(origLimit)

	if err := RunDecompileLoop(DecompLoopDeps{Pl: &naming.PoolLookups{}, W: bufio.NewWriter(io.Discard), StartTime: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if got := runtime.GOMAXPROCS(0); got != 3 {
		t.Fatalf("RunDecompileLoop leaked GOMAXPROCS=%d, want 3", got)
	}
	gotLimit := debug.SetMemoryLimit(-1)
	debug.SetMemoryLimit(gotLimit)
	if gotLimit != 777<<20 {
		t.Fatalf("RunDecompileLoop leaked memory limit=%d, want %d", gotLimit, 777<<20)
	}

	if err := RunFromMain(FromMainDeps{
		SymbolNames:  map[uint64]string{0x1000: "main"},
		W:            bufio.NewWriter(io.Discard),
		CombinedPath: "discard",
		StartTime:    time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if got := runtime.GOMAXPROCS(0); got != 3 {
		t.Fatalf("RunFromMain leaked GOMAXPROCS=%d, want 3", got)
	}
	gotLimit = debug.SetMemoryLimit(-1)
	debug.SetMemoryLimit(gotLimit)
	if gotLimit != 777<<20 {
		t.Fatalf("RunFromMain leaked memory limit=%d, want %d", gotLimit, 777<<20)
	}
}

// TestStrictBatchDecompilePropagatesFunctionBuildFailures pins the --strict
// contract: the first function that cannot be built aborts the batch and the
// cause stays reachable through errors.Is. Without Strict a failing function is
// skipped and listed instead; that default is covered by
// decompile_failures_test.go.
func TestStrictBatchDecompilePropagatesFunctionBuildFailures(t *testing.T) {
	wantErr := errors.New("synthetic IR failure")
	r := cluster.CodeRange{RefID: 1, PCOffset: 0, Size: 4}
	if err := RunDecompileLoop(DecompLoopDeps{
		Strict:      true,
		Ranges:      []cluster.CodeRange{r},
		CodeVA:      0x1000,
		SymbolNames: map[uint64]string{0x1000: "f"},
		Pl:          &naming.PoolLookups{},
		W:           bufio.NewWriter(io.Discard),
		StartTime:   time.Now(),
		DecompileRangeWithIR: func(cluster.CodeRange) (*decompiler.FuncIR, decompiler.Artifact, error) {
			return nil, decompiler.Artifact{}, wantErr
		},
	}); !errors.Is(err, wantErr) {
		t.Fatalf("RunDecompileLoop error = %v, want wrapped %v", err, wantErr)
	}

	if err := RunFromMain(FromMainDeps{
		Strict:       true,
		Ranges:       []cluster.CodeRange{r},
		CodeVA:       0x1000,
		SymbolNames:  map[uint64]string{0x1000: "main"},
		W:            bufio.NewWriter(io.Discard),
		CombinedPath: "discard",
		StartTime:    time.Now(),
		BuildFuncIR: func(cluster.CodeRange) (*decompiler.FuncIR, error) {
			return nil, wantErr
		},
		LibraryURLForCodeRef:  func(int) string { return "package:app/main.dart" },
		IsFrameworkLibraryURL: func(string) bool { return false },
	}); !errors.Is(err, wantErr) {
		t.Fatalf("RunFromMain error = %v, want wrapped %v", err, wantErr)
	}
}
