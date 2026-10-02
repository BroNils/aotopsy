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

func TestParseIdentityHashIsBoundedAndStrict(t *testing.T) {
	data := make([]byte, hashOffset+hashLen)
	copy(data[0:4], snapshotMagic[:])
	binary.LittleEndian.PutUint64(data[4:12], 60) // total size 64 bytes
	copy(data[hashOffset:hashOffset+hashLen], []byte("abcdef0123456789abcdef0123456789"))

	got, err := parseIdentityHash(data, 64, 64)
	if err != nil {
		t.Fatal(err)
	}
	if got != "abcdef0123456789abcdef0123456789" {
		t.Fatalf("identity hash = %q", got)
	}

	badHash := append([]byte(nil), data...)
	badHash[hashOffset] = 'G'
	if _, err := parseIdentityHash(badHash, 64, 64); err == nil {
		t.Fatal("non-hex snapshot hash was accepted")
	}
	if _, err := parseIdentityHash(data, 63, 64); err == nil {
		t.Fatal("declared snapshot larger than symbol was accepted")
	}
	if _, err := parseIdentityHash(data, 64, 63); err == nil {
		t.Fatal("declared snapshot larger than mapped extent was accepted")
	}
}

func TestConsistentSnapshotHashRejectsLegacyConflict(t *testing.T) {
	const (
		vmHash      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		isolateHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	if got, err := consistentSnapshotHash(vmHash, isolateHash); err == nil || got != "" {
		t.Fatalf("conflicting snapshot hashes = %q,%v; want empty + error", got, err)
	}
	if got, err := consistentSnapshotHash(vmHash, vmHash); err != nil || got != vmHash {
		t.Fatalf("matching snapshot hashes = %q,%v; want %q,nil", got, err, vmHash)
	}
	if got, err := consistentSnapshotHash("", isolateHash); err != nil || got != isolateHash {
		t.Fatalf("single surviving snapshot hash = %q,%v; want %q,nil", got, err, isolateHash)
	}
}

func TestCapRegionSizePropagatesELFMappingError(t *testing.T) {
	if size, err := capRegionSize(nil, 0); err == nil || size != 0 {
		t.Fatalf("capRegionSize(nil) = %#x,%v; want zero + error", size, err)
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
