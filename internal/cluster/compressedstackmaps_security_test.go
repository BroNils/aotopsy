package cluster

import "testing"

func TestDecodeCompressedStackMapsRejectsTruncatedULEB128(t *testing.T) {
	// flags_and_size = 4 means one byte of standalone payload. 0x80 starts a
	// ULEB128 but requires another byte; this used to decode as a zero entry.
	if entries, err := DecodeCompressedStackMaps([]byte{4, 0, 0, 0, 0x80}, nil); err == nil {
		t.Fatalf("truncated ULEB128 accepted with entries=%+v", entries)
	}
}

func TestDecodeCompressedStackMapsRejectsOverflowingULEB128(t *testing.T) {
	// Ten continuation/final bytes that overflow uint64. Keep the check at the
	// real CSM caller as well as dartfmt's primitive regression so a future
	// decoder bypass cannot reintroduce truncation.
	data := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02}
	payload := append([]byte{byte(len(data) << 2), 0, 0, 0}, data...)
	if entries, err := DecodeCompressedStackMaps(payload, nil); err == nil {
		t.Fatalf("overflowing ULEB128 accepted with entries=%+v", entries)
	}
}
