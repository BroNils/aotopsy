package snapshot

import (
	"encoding/binary"
	"math"
	"testing"
)

func buildInstructionImage(t *testing.T, version string, payload []byte) ([]byte, uint64) {
	t.Helper()
	profile := ProfileForVersion(version)
	if profile == nil {
		t.Fatalf("missing profile %s", version)
	}
	headerSize, err := InstructionsSectionHeaderSize(profile)
	if err != nil {
		t.Fatal(err)
	}
	const sectionOff = uint64(0x40)
	codeOff := sectionOff + headerSize
	data := make([]byte, int(codeOff)+len(payload))
	binary.LittleEndian.PutUint64(data[0:8], uint64(len(data)))
	binary.LittleEndian.PutUint64(data[8:16], sectionOff)
	binary.LittleEndian.PutUint64(data[sectionOff+8:sectionOff+16], uint64(len(payload)))
	copy(data[codeOff:], payload)
	return data, codeOff
}

func TestCodeRegionUsesVersionedInstructionsSectionHeader(t *testing.T) {
	payload := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	for _, tc := range []struct {
		version string
		wantOff uint64
	}{
		{"3.4.3", 0x68},
		{"3.5.0", 0x80},
		{"3.13.0", 0x80},
	} {
		data, builtOff := buildInstructionImage(t, tc.version, payload)
		if builtOff != tc.wantOff {
			t.Fatalf("fixture %s code offset %#x, want %#x", tc.version, builtOff, tc.wantOff)
		}
		code, off, n, err := CodeRegion(data, ProfileForVersion(tc.version))
		if err != nil {
			t.Fatalf("%s: %v", tc.version, err)
		}
		if off != tc.wantOff || n != uint64(len(payload)) || string(code) != string(payload) {
			t.Fatalf("%s: off=%#x n=%d code=%x", tc.version, off, n, code)
		}
	}
}

func TestParseInstructionsSectionRejectsWraparoundOffset(t *testing.T) {
	if _, err := ParseInstructionsSection(make([]byte, 64), math.MaxUint64-20, instructionsSectionFields); err == nil {
		t.Fatal("wraparound offset accepted")
	}
}

func TestCodeRegionDoesNotDowngradeCorruptModernImageTo210(t *testing.T) {
	data := make([]byte, 64)
	binary.LittleEndian.PutUint64(data[0:8], uint64(len(data)))
	binary.LittleEndian.PutUint64(data[8:16], 0x1000)
	if _, _, _, err := CodeRegion(data, ProfileForVersion("3.9.2")); err == nil {
		t.Fatal("out-of-range modern InstructionsSection offset was treated as legacy code")
	}
}

func TestCodeRegion210LegacyLayoutIsExplicit(t *testing.T) {
	payload := []byte("12345678")
	data := make([]byte, 32+len(payload))
	binary.LittleEndian.PutUint64(data[0:8], uint64(len(data)))
	binary.LittleEndian.PutUint64(data[8:16], math.MaxUint64) // bss_offset, not an InstructionsSection offset
	// Dart 2.10 bare AOT writes InstructionsSection at Image::kHeaderSize:
	// tags at +16, payload_length at +24, then machine code at +32.
	binary.LittleEndian.PutUint64(data[24:32], uint64(len(payload)))
	copy(data[32:], payload)
	code, off, n, err := CodeRegion(data, ProfileForVersion("2.10.0"))
	if err != nil {
		t.Fatal(err)
	}
	if off != 32 || n != 8 || string(code) != "12345678" {
		t.Fatalf("legacy code region off=%d n=%d code=%q", off, n, code)
	}
}

func TestCodeRegion210RejectsTruncatedInstructionsSection(t *testing.T) {
	data := make([]byte, 24)
	binary.LittleEndian.PutUint64(data[0:8], uint64(len(data)))
	if _, _, _, err := CodeRegion(data, ProfileForVersion("2.10.0")); err == nil {
		t.Fatal("truncated Dart 2.10 InstructionsSection header was accepted")
	}
}

func TestProbeTagStyleNeverPromotesUnknownHashToSupported(t *testing.T) {
	// Five one-byte VLE header fields followed by an ObjectHeader-style CID 5.
	// The exact release is still ambiguous across the whole 3.4+ family.
	data := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xd0, 0x00, 0x80}
	p := ProbeTagStyle(data, 0)
	if p == nil {
		t.Fatal("nil profile")
	}
	if p.Supported {
		t.Fatalf("family-only probe promoted unknown release to supported: %+v", *p)
	}
	if p.DartVersion != "" {
		t.Fatalf("probe invented exact Dart version %q", p.DartVersion)
	}
}
