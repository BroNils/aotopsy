package cluster

import "testing"

func TestDecodeCompressedStackMapsRejectsTruncatedULEB128(t *testing.T) {
	// flags_and_size = 4 means one byte of standalone payload. 0x80 starts a
	// ULEB128 but requires another byte; this used to decode as a zero entry.
	if entries, err := DecodeCompressedStackMaps([]byte{4, 0, 0, 0, 0x80}, nil); err == nil {
		t.Fatalf("truncated ULEB128 accepted with entries=%+v", entries)
	}
}

// csmTableFixture builds a table-referencing CSM with n entries that all point
// at one bitmap body in the global table (spill=8, saved=8, two bitmap bytes).
func csmTableFixture(n int) (payload, globalTable []byte) {
	gtData := []byte{8, 8, 0xAA, 0xBB}
	globalTable = append([]byte{byte(len(gtData)<<2) | 1, 0, 0, 0}, gtData...)
	entries := make([]byte, 0, 2*n)
	for i := 0; i < n; i++ {
		entries = append(entries, 1, 0) // pc delta 1, global table offset 0
	}
	size := uint32(len(entries))<<2 | 2 // UsesTableBit
	payload = append([]byte{byte(size), byte(size >> 8), byte(size >> 16), byte(size >> 24)}, entries...)
	return payload, globalTable
}

func TestDecodeCompressedStackMapsResolvesGlobalTableEntries(t *testing.T) {
	payload, gt := csmTableFixture(3)
	got, err := DecodeCompressedStackMaps(payload, gt)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("entries = %d, want 3", len(got))
	}
	for i, e := range got {
		if e.PCOffset != uint32(i+1) || e.SpillSlotCount != 8 || e.SavedSlotCount != 8 || len(e.Bits) != 2 || e.Bits[0] != 0xAA {
			t.Fatalf("entry %d = %+v", i, e)
		}
	}
	// An offset past the table is rejected, not read from a clamped position.
	bad := append([]byte(nil), payload...)
	bad[5] = 4 // first entry's global-table offset == len(table body)
	if _, err := DecodeCompressedStackMaps(bad, gt); err == nil {
		t.Fatal("global table offset at the end of the table was accepted")
	}
}

// The entries of a table-referencing CSM are random-access offsets into one
// table, so the decoder must reposition a single stream instead of building a
// new one per entry. Measured before the change: 2.01 allocations per entry
// (a Stream plus the bitmap copy); after: 1.01.
func TestDecodeCompressedStackMapsGlobalTableAllocatesOncePerEntry(t *testing.T) {
	const n = 500
	payload, gt := csmTableFixture(n)
	allocs := testing.AllocsPerRun(10, func() {
		if _, err := DecodeCompressedStackMaps(payload, gt); err != nil {
			t.Fatal(err)
		}
	})
	if perEntry := allocs / n; perEntry > 1.5 {
		t.Fatalf("%.2f allocations per global-table entry, want about 1 (the bitmap copy)", perEntry)
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
