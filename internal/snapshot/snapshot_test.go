package snapshot

import (
	"os"
	"path/filepath"
	"testing"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
)

func findSample(t *testing.T, name string) string {
	t.Helper()
	dir, _ := os.Getwd()
	for {
		p := filepath.Join(dir, "samples", name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skipf("sample %s not found", name)
		}
		dir = parent
	}
}

func openSample(t *testing.T, name string) *elfx.File {
	t.Helper()
	path := findSample(t, name)
	ef, err := elfx.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ef.Close() })
	return ef
}

func TestExtractBlutterLCE(t *testing.T) {
	ef := openSample(t, "blutter-lce.so")
	info, err := Extract(ef, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
	if err != nil {
		t.Fatal(err)
	}

	// Verify all four regions found.
	if info.VmData.VA == 0 {
		t.Error("VmData VA is 0")
	}
	if info.VmInstructions.VA == 0 {
		t.Error("VmInstructions VA is 0")
	}
	if info.IsolateData.VA == 0 {
		t.Error("IsolateData VA is 0")
	}
	if info.IsolateInstructions.VA == 0 {
		t.Error("IsolateInstructions VA is 0")
	}

	// Verify headers parsed.
	if info.VmHeader == nil {
		t.Fatal("VmHeader is nil")
	}
	if info.VmHeader.SnapshotHash == "" {
		t.Error("VmHeader hash is empty")
	}
	if info.VmHeader.SnapshotHash != "1441d6b13b8623fa7fbf61433abebd31" {
		t.Errorf("unexpected hash: %s", info.VmHeader.SnapshotHash)
	}
	if info.VmHeader.Features == "" {
		t.Error("VmHeader features is empty")
	}

	// Verify SHA256 computed.
	if info.VmData.SHA256 == "" {
		t.Error("VmData SHA256 is empty")
	}
}

func TestExtractNewandromo(t *testing.T) {
	ef := openSample(t, "newandromo.so")
	info, err := Extract(ef, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
	if err != nil {
		t.Fatal(err)
	}

	if info.VmHeader == nil {
		t.Fatal("VmHeader is nil")
	}
	if info.VmHeader.SnapshotHash != "7dbbeeb8ef7b91338640dca3927636de" {
		t.Errorf("unexpected hash: %s", info.VmHeader.SnapshotHash)
	}
	if !info.VmHeader.HasFeature("null-safety") {
		t.Error("expected null-safety feature")
	}
	if !info.VmHeader.HasFeature("compressed-pointers") {
		t.Error("expected compressed-pointers feature")
	}
}

func TestExtractEvilPatched(t *testing.T) {
	ef := openSample(t, "evil-patched.so")
	info, err := Extract(ef, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
	if err != nil {
		t.Fatal(err)
	}

	if info.VmHeader == nil {
		t.Fatal("VmHeader is nil")
	}
	if info.VmHeader.SnapshotHash != "1ce86630892e2dca9a8543fdb8ed8e22" {
		t.Errorf("unexpected hash: %s", info.VmHeader.SnapshotHash)
	}
}

// TestVersionProfileFlags pins the format flag cross-product per sample.
// If a hash→profile mapping changes or flags are swapped, this fails.
func TestVersionProfileFlags(t *testing.T) {
	tests := []struct {
		sample         string
		wantVersion    string
		wantHeaderFlds int
		wantFillRefUns bool
		wantPreV32     bool
	}{
		{"blutter-lce.so", "2.17.6", 6, true, true},
		{"newandromo.so", "3.1.0", 5, false, true},
		{"evil-patched.so", "3.10.7", 5, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.sample, func(t *testing.T) {
			ef := openSample(t, tt.sample)
			info, err := Extract(ef, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
			if err != nil {
				t.Fatal(err)
			}
			if info.Version.DartVersion != tt.wantVersion {
				t.Errorf("DartVersion = %q, want %q", info.Version.DartVersion, tt.wantVersion)
			}
			if info.Version.HeaderFields != tt.wantHeaderFlds {
				t.Errorf("HeaderFields = %d, want %d", info.Version.HeaderFields, tt.wantHeaderFlds)
			}
			if info.Version.FillRefUnsigned != tt.wantFillRefUns {
				t.Errorf("FillRefUnsigned = %v, want %v", info.Version.FillRefUnsigned, tt.wantFillRefUns)
			}
			if info.Version.PreV32Format != tt.wantPreV32 {
				t.Errorf("PreV32Format = %v, want %v", info.Version.PreV32Format, tt.wantPreV32)
			}
		})
	}
}

func TestParseHeader(t *testing.T) {
	// Construct a minimal valid header.
	data := make([]byte, 256)
	copy(data[0:4], []byte{0xf5, 0xf5, 0xdc, 0xdc})
	data[4] = 0x10 // size = 16
	copy(data[0x14:0x34], []byte("abcdef0123456789abcdef0123456789"))
	copy(data[0x34:], []byte("arm64 android compressed-pointers\x00"))

	h, err := parseHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	if h.SnapshotHash != "abcdef0123456789abcdef0123456789" {
		t.Errorf("hash: %s", h.SnapshotHash)
	}
	if h.Features != "arm64 android compressed-pointers" {
		t.Errorf("features: %s", h.Features)
	}
}

func TestParseHeaderBadMagic(t *testing.T) {
	data := make([]byte, 64)
	_, err := parseHeader(data)
	if err == nil {
		t.Fatal("expected error for bad magic")
	}
}

func TestParseHeaderTooShort(t *testing.T) {
	_, err := parseHeader([]byte{0xf5, 0xf5, 0xdc, 0xdc})
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func FuzzExtract(f *testing.F) {
	f.Add([]byte("\x7fELF\x02\x01\x01\x00"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		tmp := filepath.Join(t.TempDir(), "fuzz.so")
		if err := os.WriteFile(tmp, data, 0644); err != nil {
			t.Fatal(err)
		}
		ef, err := elfx.Open(tmp)
		if err != nil {
			return
		}
		defer ef.Close()
		// Must not panic.
		Extract(ef, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
	})
}
