package snapshot

import (
	"encoding/binary"
	"math"
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
	binary.LittleEndian.PutUint64(data[4:12], uint64(len(data)-4))
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

func TestParseHeaderRejectsOverflowAndTruncation(t *testing.T) {
	makeHeader := func(length uint64) []byte {
		data := make([]byte, 64)
		copy(data[0:4], snapshotMagic[:])
		binary.LittleEndian.PutUint64(data[4:12], length)
		copy(data[0x14:0x34], []byte("abcdef0123456789abcdef0123456789"))
		data[0x34] = 0
		return data
	}
	for _, length := range []uint64{math.MaxUint64, math.MaxInt64} {
		if _, err := parseHeader(makeHeader(length)); err == nil {
			t.Fatalf("length %#x accepted", length)
		}
	}
	if _, err := parseHeader(makeHeader(1000)); err == nil {
		t.Fatal("declared snapshot larger than backing data was accepted")
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

func TestSegmentRemainingAvoidsAddressOverflow(t *testing.T) {
	vaddr := uint64(math.MaxUint64 - 0xf)
	filesz := uint64(0x20)
	va := uint64(math.MaxUint64 - 8)
	got, ok := segmentRemaining(vaddr, filesz, va)
	if !ok || got != 0x19 {
		t.Fatalf("segmentRemaining overflow case = %#x,%v; want 0x19,true", got, ok)
	}
	if _, ok := segmentRemaining(vaddr, filesz, vaddr-1); ok {
		t.Fatal("VA below segment accepted")
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
