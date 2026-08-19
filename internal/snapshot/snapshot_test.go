package snapshot

import (
	"os"
	"path/filepath"
	"testing"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
)

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
