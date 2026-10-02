package fingerprint

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestVersionExtractionRequiresProvenanceBearingBanner(t *testing.T) {
	dart := `3.12.2 (stable) (Tue Sep 1 00:00:00 2026 +0000) on "linux_arm64"`
	if got, arch, ok := dartBannerEvidence(dart); !ok || got != "3.12.2" || arch != "arm64" {
		t.Fatalf("dartBannerEvidence() = (%q,%q,%v), want (3.12.2,arm64,true)", got, arch, ok)
	}
	if got, _, ok := dartBannerEvidence("Dart VM version: " + dart); !ok || got != "3.12.2" {
		t.Fatalf("wrapped dartBannerEvidence() = %q ok=%v, want 3.12.2", got, ok)
	}
	legacy := `2.12.0 (stable) (Mon Feb 22 10:35:18 2021 +0100)`
	if got, arch, ok := dartBannerEvidence(legacy); !ok || got != "2.12.0" || arch != "" {
		t.Fatalf("legacy Version::str_ = (%q,%q,%v), want (2.12.0,,true)", got, arch, ok)
	}
	pre := `3.13.0-70.0.dev (dev) (Tue Sep 1 00:00:00 2026 +0000) on "linux_x64"`
	if got, arch, ok := dartBannerEvidence(pre); !ok || got != "3.13.0-70.0.dev" || arch != "x64" {
		t.Fatalf("prerelease banner = (%q,%q,%v)", got, arch, ok)
	}
	producer := `Dart 3.12.2 (stable) (Tue Sep 1 00:00:00 2026 +0000) on "linux_simarm64"`
	if got, arch, ok := dartBannerEvidence(producer); !ok || got != "3.12.2" || arch != "arm64" {
		t.Fatalf("DWARF producer banner = (%q,%q,%v), want normalized arm64", got, arch, ok)
	}
	unknownTime := `3.12.2 (stable) (Unknown timestamp) on "linux_x64"`
	if got, arch, ok := dartBannerEvidence(unknownTime); !ok || got != "3.12.2" || arch != "x64" {
		t.Fatalf("Unknown timestamp banner = (%q,%q,%v)", got, arch, ok)
	}
	for _, bad := range []string{
		"dart:io connects to 127.0.0.1",
		"Dart SDK documentation 127.0.0",
		"Version 3.12.2",
		"3.12.2 stable linux_arm64",
	} {
		if got, _, ok := dartBannerEvidence(bad); ok || got != "" {
			t.Errorf("dartBannerEvidence(%q) = %q ok=%v; unproven semver must not become a Dart version", bad, got, ok)
		}
	}

	if got := flutterVersionFromBanner("Flutter Engine 3.24.1 (stable)"); got != "3.24.1" {
		t.Fatalf("flutterVersionFromBanner() = %q, want 3.24.1", got)
	}
	if got := flutterVersionFromBanner("engine docs 3.24.1"); got != "" {
		t.Fatalf("unlabelled engine text produced Flutter version %q", got)
	}
}

func TestScanEngineMarkersDoesNotPromoteGenericDartSemver(t *testing.T) {
	data := append(bytes.Repeat([]byte{0}, (64<<10)-5), []byte("dart:io endpoint 127.0.0.1\x00")...)
	data = append(data, []byte(`3.12.2 (stable) (Tue Sep 1 00:00:00 2026 +0000) on "linux_arm64"`)...)

	markers, err := scanEngineMarkers(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if markers.DartVersion != "3.12.2" {
		t.Fatalf("DartVersion = %q, want 3.12.2", markers.DartVersion)
	}
	if len(markers.DartMarkers) != 2 {
		t.Fatalf("DartMarkers = %q, want diagnostic URI + version banner", markers.DartMarkers)
	}
}

func TestConflictingBannerArchitectureDowngradesConfidence(t *testing.T) {
	note := buildIDNote([]byte{0xde, 0xad, 0xbe, 0xef})
	tail := []byte(`3.12.2 (stable) (Tue Sep 1 00:00:00 2026 +0000) on "linux_x64"` + "\x00")
	path := writeProgramNoteELF(t, note, tail) // helper emits EM_AARCH64
	rep, err := Run(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Confidence != ConfidenceLow || len(rep.EvidenceConflicts) == 0 {
		t.Fatalf("conflicting arch report = %+v, want low confidence + conflict", rep)
	}
}

func TestConflictingDartVersionsAreNotPromoted(t *testing.T) {
	data := []byte(
		`3.12.2 (stable) (Tue Sep 1 00:00:00 2026 +0000) on "linux_arm64"` + "\x00" +
			`3.13.0-1.0.dev (dev) (Wed Sep 2 00:00:00 2026 +0000) on "linux_arm64"` + "\x00")
	markers, err := scanEngineMarkers(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if markers.DartVersion != "" || len(markers.Conflicts) == 0 {
		t.Fatalf("conflicting versions = %+v, want no promoted version + conflict", markers)
	}
}

func TestRunBuildIDPlusGenericDartTextIsNotHighConfidenceVersion(t *testing.T) {
	note := buildIDNote([]byte{0xde, 0xad, 0xbe, 0xef})
	path := writeProgramNoteELF(t, note, []byte("dart:io endpoint 127.0.0.1\x00"))
	rep, err := Run(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.BuildID != "deadbeef" {
		t.Fatalf("BuildID = %q, want deadbeef", rep.BuildID)
	}
	if rep.DartVersion != "" {
		t.Fatalf("DartVersion = %q; generic dart: text must not produce a version", rep.DartVersion)
	}
	if rep.Confidence != ConfidenceLow {
		t.Fatalf("Confidence = %q, want %q with build-id only", rep.Confidence, ConfidenceLow)
	}
	if len(rep.FileSHA256) != 64 {
		t.Fatalf("FileSHA256 = %q, want SHA-256 hex", rep.FileSHA256)
	}
}

func TestBuildIDUsesSectionlessPTNote(t *testing.T) {
	path := writeProgramNoteELF(t, buildIDNote([]byte{1, 2, 3, 4}), nil)
	rep, err := Run(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.BuildID != "01020304" {
		t.Fatalf("BuildID = %q, want 01020304", rep.BuildID)
	}
}

func TestBuildIDUsesSHTNoteAndRejectsNamedPROGBITS(t *testing.T) {
	note := buildIDNote([]byte{0xaa, 0xbb})
	good := writeSectionELF(t, ".note.gnu.build-id", elf.SHT_NOTE, note)
	rep, err := Run(good)
	if err != nil {
		t.Fatal(err)
	}
	if rep.BuildID != "aabb" {
		t.Fatalf("SHT_NOTE BuildID = %q, want aabb", rep.BuildID)
	}

	bad := writeSectionELF(t, "denote", elf.SHT_PROGBITS, note)
	rep, err = Run(bad)
	if err != nil {
		t.Fatal(err)
	}
	if rep.BuildID != "" {
		t.Fatalf("PROGBITS section named denote fabricated BuildID %q", rep.BuildID)
	}
}

func TestConflictingBuildIDsAreReportedInsteadOfFirstWins(t *testing.T) {
	notes := append(buildIDNote([]byte{1, 2, 3, 4}), buildIDNote([]byte{5, 6, 7, 8})...)
	path := writeProgramNoteELF(t, notes, nil)
	rep, err := Run(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.BuildID != "" {
		t.Fatalf("conflicting notes promoted BuildID %q", rep.BuildID)
	}
	if len(rep.EvidenceConflicts) == 0 || !strings.Contains(rep.EvidenceConflicts[0], "build-id") {
		t.Fatalf("missing build-id conflict: %+v", rep.EvidenceConflicts)
	}
}

func TestBuildIDRequiresExactGNUOwnerEncoding(t *testing.T) {
	note := buildIDNote([]byte{1, 2, 3, 4})
	binary.LittleEndian.PutUint32(note[0:4], 3) // malformed: GNU owner size must include trailing NUL
	ids, err := parseBuildIDNotes(note, binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("malformed GNU owner produced build IDs %q", ids)
	}
}

func TestBuildIDNotesRejectMalformedRecordAfterValidID(t *testing.T) {
	note := append(buildIDNote([]byte{1, 2, 3, 4}), []byte{1, 2, 3}...)
	if ids, err := parseBuildIDNotes(note, binary.LittleEndian); err == nil {
		t.Fatalf("trailing malformed note was ignored after build-id %q", ids)
	}
}

func TestLegacyZdebugNoteIsNotDecompressedForBuildID(t *testing.T) {
	path := writeSectionELF(t, ".zdebug.note.gnu.build-id", elf.SHT_NOTE, buildIDNote([]byte{1, 2, 3, 4}))
	rep, err := Run(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.BuildID != "" {
		t.Fatalf("legacy .zdebug note produced BuildID %q", rep.BuildID)
	}
}

func TestRunIgnoresUnmappedAppendedVersionBanner(t *testing.T) {
	path := writeProgramNoteELF(t, buildIDNote([]byte{0xde, 0xad, 0xbe, 0xef}), nil)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.WriteString(`3.12.2 (stable) (Tue Sep 1 00:00:00 2026 +0000) on "linux_arm64"` + "\x00")
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("append fake banner: write=%v close=%v", writeErr, closeErr)
	}
	rep, err := Run(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.DartVersion != "" || rep.Confidence != ConfidenceLow {
		t.Fatalf("unmapped appended banner became trusted evidence: %+v", rep)
	}
}

func TestMappedDartProducerSimArchIsCompatible(t *testing.T) {
	tail := []byte(`Dart 3.12.2 (stable) (Tue Sep 1 00:00:00 2026 +0000) on "linux_simarm64"` + "\x00")
	path := writeProgramNoteELF(t, buildIDNote([]byte{1, 2, 3, 4}), tail)
	rep, err := Run(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.DartVersion != "3.12.2" || rep.DartArch != "arm64" || len(rep.EvidenceConflicts) != 0 {
		t.Fatalf("mapped simulator producer evidence = %+v", rep)
	}
	if rep.Confidence != ConfidenceMedium {
		t.Fatalf("single mapped Dart provenance confidence = %q, want medium", rep.Confidence)
	}
}

func TestMachineArchitectureMatchingIsFailClosed(t *testing.T) {
	if machineMatchesDartArch(elf.EM_PPC64, elf.ELFCLASS64, "x64") {
		t.Fatal("PPC64 accepted x64 Dart banner")
	}
	if machineMatchesDartArch(elf.EM_PPC64, elf.ELFCLASS64, "ppc64") {
		t.Fatal("unsupported PPC64 was accepted")
	}
	if machineMatchesDartArch(elf.EM_RISCV, elf.ELFCLASS32, "riscv32") {
		t.Fatal("unsupported ELF32 RISC-V was accepted")
	}
	if machineMatchesDartArch(elf.EM_RISCV, elf.ELFCLASS64, "riscv64") {
		t.Fatal("unsupported ELF64 RISC-V was accepted")
	}
	if machineMatchesDartArch(elf.EM_RISCV, elf.ELFCLASS32, "riscv64") {
		t.Fatal("ELF32 RISC-V accepted riscv64 Dart banner")
	}
	if machineMatchesDartArch(elf.EM_RISCV, elf.ELFCLASS64, "riscv32") {
		t.Fatal("ELF64 RISC-V accepted riscv32 Dart banner")
	}
	if machineMatchesDartArch(elf.EM_RISCV, elf.ELFCLASS64, "riscv") {
		t.Fatal("RISC-V accepted architecture label that Dart does not emit")
	}
	if machineMatchesDartArch(elf.EM_RISCV, elf.ELFCLASS64, "riscv_evil") {
		t.Fatal("RISC-V accepted arbitrary riscv prefix")
	}
	if machineMatchesDartArch(elf.EM_X86_64, elf.ELFCLASS32, "x64") {
		t.Fatal("ELF32 accepted x64 Dart banner")
	}
	if machineMatchesDartArch(elf.Machine(0xffff), elf.ELFCLASS64, "x64") {
		t.Fatal("unknown ELF machine accepted architecture evidence")
	}
}

func TestRunRejectsDartArchWithWrongELFClass(t *testing.T) {
	tail := []byte(`3.13.0 (stable) (Tue Sep 1 00:00:00 2026 +0000) on "linux_riscv64"` + "\x00")
	path := writeProgramLoadELF32(t, elf.EM_RISCV, tail)
	if rep, err := Run(path); err == nil {
		t.Fatalf("unsupported ELF32/RISC-V fingerprint succeeded: %+v", rep)
	}
}

func buildIDNote(desc []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(4))
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(desc)))
	_ = binary.Write(&b, binary.LittleEndian, uint32(3))
	b.WriteString("GNU\x00")
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
	b.Write(desc)
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
	return b.Bytes()
}

func writeProgramNoteELF(t *testing.T, note, tail []byte) string {
	t.Helper()
	const (
		ehSize = 64
		phSize = 56
	)
	phNum := 1
	if len(tail) > 0 {
		phNum = 2
	}
	noteOff := ehSize + phSize*phNum
	data := make([]byte, noteOff+len(note)+len(tail))
	writeELFIdentAndHeader(data[:ehSize], uint64(ehSize), 0, uint16(phNum), 0, 0)
	ph := data[ehSize : ehSize+phSize]
	binary.LittleEndian.PutUint32(ph[0:4], uint32(elf.PT_NOTE))
	binary.LittleEndian.PutUint64(ph[8:16], uint64(noteOff))
	binary.LittleEndian.PutUint64(ph[32:40], uint64(len(note)))
	binary.LittleEndian.PutUint64(ph[40:48], uint64(len(note)))
	binary.LittleEndian.PutUint64(ph[48:56], 4)
	if len(tail) > 0 {
		load := data[ehSize+phSize : ehSize+2*phSize]
		binary.LittleEndian.PutUint32(load[0:4], uint32(elf.PT_LOAD))
		binary.LittleEndian.PutUint32(load[4:8], uint32(elf.PF_R))
		binary.LittleEndian.PutUint64(load[8:16], uint64(noteOff+len(note)))
		binary.LittleEndian.PutUint64(load[32:40], uint64(len(tail)))
		binary.LittleEndian.PutUint64(load[40:48], uint64(len(tail)))
		binary.LittleEndian.PutUint64(load[48:56], 1)
	}
	copy(data[noteOff:], note)
	copy(data[noteOff+len(note):], tail)
	return writeTempELF(t, data)
}

func writeProgramLoadELF32(t *testing.T, machine elf.Machine, payload []byte) string {
	t.Helper()
	const (
		ehSize = 52
		phSize = 32
	)
	payloadOff := ehSize + phSize
	data := make([]byte, payloadOff+len(payload))
	copy(data[:4], []byte{0x7f, 'E', 'L', 'F'})
	data[4] = byte(elf.ELFCLASS32)
	data[5] = byte(elf.ELFDATA2LSB)
	data[6] = byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(data[16:18], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(data[18:20], uint16(machine))
	binary.LittleEndian.PutUint32(data[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint32(data[28:32], ehSize)
	binary.LittleEndian.PutUint16(data[40:42], ehSize)
	binary.LittleEndian.PutUint16(data[42:44], phSize)
	binary.LittleEndian.PutUint16(data[44:46], 1)

	ph := data[ehSize : ehSize+phSize]
	binary.LittleEndian.PutUint32(ph[0:4], uint32(elf.PT_LOAD))
	binary.LittleEndian.PutUint32(ph[4:8], uint32(payloadOff))
	binary.LittleEndian.PutUint32(ph[16:20], uint32(len(payload)))
	binary.LittleEndian.PutUint32(ph[20:24], uint32(len(payload)))
	binary.LittleEndian.PutUint32(ph[24:28], uint32(elf.PF_R))
	binary.LittleEndian.PutUint32(ph[28:32], 1)
	copy(data[payloadOff:], payload)
	return writeTempELF(t, data)
}

func writeSectionELF(t *testing.T, name string, typ elf.SectionType, payload []byte) string {
	t.Helper()
	const ehSize = 64
	shstr := []byte("\x00" + name + "\x00.shstrtab\x00")
	nameOff := uint32(1)
	shstrNameOff := uint32(1 + len(name) + 1)
	payloadOff := ehSize
	strOff := payloadOff + len(payload)
	shoff := (strOff + len(shstr) + 7) &^ 7
	data := make([]byte, shoff+3*64)
	writeELFIdentAndHeader(data[:ehSize], 0, uint64(shoff), 0, 3, 2)
	copy(data[payloadOff:], payload)
	copy(data[strOff:], shstr)

	writeSectionHeader(data[shoff+64:shoff+128], nameOff, typ, uint64(payloadOff), uint64(len(payload)), 4)
	writeSectionHeader(data[shoff+128:shoff+192], shstrNameOff, elf.SHT_STRTAB, uint64(strOff), uint64(len(shstr)), 1)
	return writeTempELF(t, data)
}

func writeELFIdentAndHeader(h []byte, phoff, shoff uint64, phnum, shnum, shstrndx uint16) {
	copy(h[:4], []byte{0x7f, 'E', 'L', 'F'})
	h[4] = byte(elf.ELFCLASS64)
	h[5] = byte(elf.ELFDATA2LSB)
	h[6] = byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(h[16:18], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(h[18:20], uint16(elf.EM_AARCH64))
	binary.LittleEndian.PutUint32(h[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint64(h[32:40], phoff)
	binary.LittleEndian.PutUint64(h[40:48], shoff)
	binary.LittleEndian.PutUint16(h[52:54], 64)
	binary.LittleEndian.PutUint16(h[54:56], 56)
	binary.LittleEndian.PutUint16(h[56:58], phnum)
	binary.LittleEndian.PutUint16(h[58:60], 64)
	binary.LittleEndian.PutUint16(h[60:62], shnum)
	binary.LittleEndian.PutUint16(h[62:64], shstrndx)
}

func writeSectionHeader(h []byte, name uint32, typ elf.SectionType, off, size, align uint64) {
	binary.LittleEndian.PutUint32(h[0:4], name)
	binary.LittleEndian.PutUint32(h[4:8], uint32(typ))
	binary.LittleEndian.PutUint64(h[24:32], off)
	binary.LittleEndian.PutUint64(h[32:40], size)
	binary.LittleEndian.PutUint64(h[48:56], align)
}

func writeTempELF(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sample.so")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScannerDropsHugePrintableRunsInsteadOfRetainingThem(t *testing.T) {
	data := strings.Repeat("A", 16<<20) + "\x00dart:io marker\x00"
	markers, err := scanEngineMarkers(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(markers.DartMarkers) != 1 || markers.DartMarkers[0] != "dart:io marker" {
		t.Fatalf("markers = %q", markers.DartMarkers)
	}
}

func TestScannerCapsDiagnosticMarkerCardinality(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxMarkersPerFamily+500; i++ {
		fmt.Fprintf(&b, "dart:marker_%04d_unique\x00", i)
	}
	markers, err := scanEngineMarkers(strings.NewReader(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(markers.DartMarkers) != maxMarkersPerFamily {
		t.Fatalf("marker count = %d, want cap %d", len(markers.DartMarkers), maxMarkersPerFamily)
	}
}
