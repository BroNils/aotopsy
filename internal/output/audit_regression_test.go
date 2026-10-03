package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type badJSON struct{}

func (badJSON) MarshalJSON() ([]byte, error) { return nil, errors.New("encode failed") }

func TestWriteSARIFEmptyReplacesStaleReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aotopsy.sarif")
	if err := os.WriteFile(path, []byte("STALE-SARIF"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteSARIF(dir, nil, "dev", ArtifactIdentity{URI: "app.so"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("STALE-SARIF")) {
		t.Fatal("zero-finding rerun preserved stale SARIF")
	}
	var log sarifLog
	if err := json.Unmarshal(b, &log); err != nil {
		t.Fatalf("replacement is not valid SARIF JSON: %v", err)
	}
	if got := len(log.Runs[0].Results); got != 0 {
		t.Fatalf("zero-finding report has %d results", got)
	}
}

func TestWriteJSONFileFailurePreservesOldArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSONFile(path, badJSON{}); err == nil {
		t.Fatal("expected JSON encoding error")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "old\n" {
		t.Fatalf("failed transactional write changed old artifact: %q", b)
	}
}

func TestWriteAtomicDoesNotDeleteSubstitutedTempOnFailure(t *testing.T) {
	target := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected writer failure")
	err := WriteAtomic(target, 0o600, func(w io.Writer) error {
		if _, err := io.WriteString(w, "new-partial"); err != nil {
			return err
		}
		return injected
	})
	if !errors.Is(err, injected) {
		t.Fatalf("WriteAtomic error = %v, want injected failure", err)
	}
	b, readErr := os.ReadFile(target)
	if readErr != nil || string(b) != "old" {
		t.Fatalf("failed write changed current artifact: %q, %v", b, readErr)
	}
}

func TestArtifactWritersRejectTraversal(t *testing.T) {
	for _, name := range []string{"../escape", `..\escape`, "/absolute", "a/../escape", "a//escape"} {
		if err := WriteBin(t.TempDir(), name, []byte{1}); err == nil {
			t.Errorf("WriteBin(%q) accepted unsafe path", name)
		}
	}
}

func TestArtifactWriterRejectsDotSegmentsForAllCallers(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{".", "..", "./f.dart", "../f.dart", `..\f.dart`, "Owner/../f.dart"} {
		if err := WriteArtifactFile(base, name, []byte("x"), 0o644); err == nil {
			t.Errorf("WriteArtifactFile(%q) accepted unsafe path", name)
		}
	}
	if err := WriteArtifactFile(base, "Owner/f_1000.dart", []byte("safe"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(base, "Owner", "f_1000.dart"))
	if err != nil || string(b) != "safe" {
		t.Fatalf("safe grouped artifact = %q, %v", b, err)
	}
}

func TestArtifactWriterRejectsPortableWindowsSpecialNames(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{
		`file.txt:stream`,
		`C:drive-relative`,
		`NUL`,
		`Owner/CON`,
		`Owner/COM1`,
		`Owner/LPT²`,
		`Owner/CONIN$`,
		`Owner/trailing.`,
		`Owner/trailing `,
	} {
		if err := WriteArtifactFile(base, name, []byte("x"), 0o644); err == nil {
			t.Errorf("WriteArtifactFile(%q) accepted Windows-unsafe name", name)
		}
	}
}

func TestArtifactWriterAllowsIntentionalGrouping(t *testing.T) {
	dir := t.TempDir()
	if err := WriteBin(dir, "Owner/method_1234", []byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "asm", "Owner", "method_1234.bin")); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactWriterRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation may require elevated privileges")
	}
	base := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(base, "Owner")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := WriteArtifactFile(base, "Owner/f.dart", []byte("escape"), 0o644); err == nil {
		t.Fatal("WriteArtifactFile followed child symlink outside root")
	}
	if _, err := os.Stat(filepath.Join(outside, "f.dart")); !os.IsNotExist(err) {
		t.Fatalf("outside target was modified: %v", err)
	}
}

func TestArtifactWriterRejectsDanglingSymlinkAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation may require elevated privileges")
	}
	base := t.TempDir()
	target := filepath.Join(t.TempDir(), "not-created")
	link := filepath.Join(base, "Owner")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := WriteArtifactFile(base, "Owner/f.dart", []byte("x"), 0o644); err == nil {
		t.Fatal("WriteArtifactFile accepted dangling symlink ancestor")
	}
}

func TestParseAddressAcceptsFullUint64VA(t *testing.T) {
	const pc = "0xfffffffffffffff0"
	got, ok := parseAddress(pc)
	if !ok || got != 0xfffffffffffffff0 {
		t.Fatalf("parseAddress(%q) = %#x,%v", pc, got, ok)
	}
}

func TestFindingFingerprintIsFieldBoundarySafe(t *testing.T) {
	a := SignalFinding{Category: "a:b", Function: "c", PC: "d", StringValue: "e"}
	b := SignalFinding{Category: "a", Function: "b:c", PC: "d", StringValue: "e"}
	if findingFingerprint(a) == findingFingerprint(b) {
		t.Fatal("distinct field tuples collide")
	}
}

func TestFindingFingerprintNormalizesEmittedAddressIdentity(t *testing.T) {
	a := SignalFinding{Category: "url", Function: "f", PC: " 0X001000 ", StringValue: "x"}
	b := SignalFinding{Category: "url", Function: "f", PC: "0x1000", StringValue: "x", AddressKind: "instruction"}
	if findingFingerprint(a) != findingFingerprint(b) {
		t.Fatal("equivalent emitted instruction addresses have different fingerprints")
	}
	withoutAddressKind := SignalFinding{Category: "entropy", StringValue: "x"}
	ignoredAddressKind := withoutAddressKind
	ignoredAddressKind.AddressKind = "function"
	if findingFingerprint(withoutAddressKind) != findingFingerprint(ignoredAddressKind) {
		t.Fatal("ignored address kind perturbs a binary-level finding fingerprint")
	}
}

func TestWriteSARIFRejectsMalformedIdentityAndAddressWithoutReplacingReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aotopsy.sarif")
	const old = "old-report\n"
	if err := os.WriteFile(path, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteSARIF(dir, nil, "dev", ArtifactIdentity{SHA256: "not-a-sha256"}); err == nil {
		t.Fatal("malformed artifact hash was accepted")
	}
	if err := WriteSARIF(dir, []SignalFinding{{Category: "url", PC: "not-an-address"}}, "dev", ArtifactIdentity{}); err == nil {
		t.Fatal("malformed non-empty finding address was accepted")
	}
	if err := WriteSARIF(dir, []SignalFinding{{Category: "url", PC: "4096"}}, "dev", ArtifactIdentity{}); err == nil {
		t.Fatal("ambiguous unprefixed finding address was accepted as hexadecimal")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != old {
		t.Fatalf("rejected SARIF input replaced old report: %q", b)
	}
}

func TestSignalCategorySARIFLevelsTrackSignalSeverity(t *testing.T) {
	want := map[string]string{
		"url": "warning", "host": "warning", "file": "note", "cloaking": "error",
		"thr": "note", "async": "note", "generator": "note", "encryption": "error", "auth": "error",
		"sim": "error", "sms": "error", "contacts": "error", "data": "error",
		"webview": "error", "blockchain": "error", "gambling": "error",
	}
	for category, level := range want {
		if got := sarifLevel(category); got != level {
			t.Errorf("sarifLevel(%q) = %q, want %q", category, got, level)
		}
		if strings.TrimSpace(ruleDescription[category]) == "" {
			t.Errorf("ruleDescription[%q] is empty", category)
		}
	}
}
