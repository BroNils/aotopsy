package cluster

import "testing"

func TestDecodeCompressedStackMapsRejectsTruncatedULEB128(t *testing.T) {
	// flags_and_size = 4 means one byte of standalone payload. 0x80 starts a
	// ULEB128 but requires another byte; this used to decode as a zero entry.
	if entries, err := DecodeCompressedStackMaps([]byte{4, 0, 0, 0, 0x80}, nil); err == nil {
		t.Fatalf("truncated ULEB128 accepted with entries=%+v", entries)
	}
}

func TestReadLEB128RejectsOverflow(t *testing.T) {
	data := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02}
	if _, _, err := readLEB128(data, 0); err == nil {
		t.Fatal("overflowing ULEB128 was accepted")
	}
}
