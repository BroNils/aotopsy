package analysis

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"aotopsy/internal/output"
)

func writeMinimalSharedELF(t *testing.T, machine elf.Machine) string {
	t.Helper()
	b := make([]byte, 64)
	copy(b[:4], []byte{0x7f, 'E', 'L', 'F'})
	b[4], b[5], b[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1
	binary.LittleEndian.PutUint16(b[16:], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(b[18:], uint16(machine))
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint16(b[52:], 64)
	p := filepath.Join(t.TempDir(), "libapp.so")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVerifyProvenanceBinaryRejectsDifferentBytes(t *testing.T) {
	lib := writeMinimalSharedELF(t, elf.EM_AARCH64)
	b, err := os.ReadFile(lib)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	dir := t.TempDir()
	p := Provenance{
		Source:      lib,
		SourceName:  "libapp.so",
		SHA256:      hex.EncodeToString(sum[:]),
		Size:        int64(len(b)),
		Arch:        "arm64",
		DartVersion: "3.12.2",
	}
	if err := output.WriteJSONFile(filepath.Join(dir, ProvenanceFileName), p); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyProvenanceBinary(dir, lib); err != nil {
		t.Fatalf("matching binary rejected: %v", err)
	}

	other := writeMinimalSharedELF(t, elf.EM_X86_64)
	if _, err := VerifyProvenanceBinary(dir, other); err == nil {
		t.Fatal("different binary/architecture accepted against static provenance")
	}
}

func TestVerifyProvenanceBinaryRequiresCompleteIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := output.WriteJSONFile(filepath.Join(dir, ProvenanceFileName), Provenance{SourceName: "libapp.so"}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyProvenanceBinary(dir, "unused.so"); err == nil {
		t.Fatal("incomplete provenance was accepted")
	}
}
