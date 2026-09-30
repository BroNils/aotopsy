package cluster

import (
	"strings"
	"testing"
)

// TestDecodeKindAndMetadata pins the bit layout of
// UntaggedPcDescriptors::KindAndMetadata.
//
// kLastKind == kOther == 128, so ShiftForPowerOfTwo(128) == 7 and
// BitLength(7) == 3: KindShiftBits occupies bits [0,3), TryIndexBits the next
// 10 bits [3,13), YieldIndexBits the remainder. try_index and yield_index are
// stored biased by +1 so their -1 sentinels encode as 0.
func TestDecodeKindAndMetadata(t *testing.T) {
	// encode mirrors KindAndMetadata::Encode for test construction.
	encode := func(kindShift, tryIndex, yieldIndex int) int64 {
		return int64(uint32(kindShift) | uint32(tryIndex+1)<<3 | uint32(yieldIndex+1)<<13)
	}

	cases := []struct {
		name       string
		kindShift  int
		tryIndex   int
		yieldIndex int
		wantKind   PcDescriptorKind
	}{
		{"deopt, no try", 0, InvalidTryIndex, InvalidYieldIndex, PcDeopt},
		{"iccall, try 0", 1, 0, InvalidYieldIndex, PcIcCall},
		{"unopt static, try 3", 2, 3, InvalidYieldIndex, PcUnoptStaticCall},
		{"runtime call, try 1", 3, 1, InvalidYieldIndex, PcRuntimeCall},
		{"osr entry", 4, InvalidTryIndex, InvalidYieldIndex, PcOsrEntry},
		{"rewind", 5, InvalidTryIndex, InvalidYieldIndex, PcRewind},
		{"bss relocation", 6, InvalidTryIndex, InvalidYieldIndex, PcBSSRelocation},
		{"other, try 1022 max", 7, 1022, InvalidYieldIndex, PcOther},
		{"other with yield 5", 7, 2, 5, PcOther},
	}
	for _, c := range cases {
		kind, tryIdx, yieldIdx := decodeKindAndMetadata(encode(c.kindShift, c.tryIndex, c.yieldIndex))
		if kind != c.wantKind {
			t.Errorf("%s: kind = %v, want %v", c.name, kind, c.wantKind)
		}
		if tryIdx != c.tryIndex {
			t.Errorf("%s: tryIndex = %d, want %d", c.name, tryIdx, c.tryIndex)
		}
		if yieldIdx != c.yieldIndex {
			t.Errorf("%s: yieldIndex = %d, want %d", c.name, yieldIdx, c.yieldIndex)
		}
	}

	// TryIndexBits is 10 bits wide holding try_index+1, so 1022 is the largest
	// representable index and must not bleed into YieldIndexBits.
	_, tryIdx, yieldIdx := decodeKindAndMetadata(encode(0, 1022, InvalidYieldIndex))
	if tryIdx != 1022 {
		t.Errorf("max try index: got %d, want 1022", tryIdx)
	}
	if yieldIdx != InvalidYieldIndex {
		t.Errorf("max try index bled into yield index: got %d", yieldIdx)
	}
}

// TestDecodePcDescriptors checks the two-SLEB128-per-record AOT stream shape,
// including that pc_offset accumulates deltas rather than being absolute.
func TestDecodePcDescriptors(t *testing.T) {
	enc := func(kindShift, tryIndex int) byte {
		return byte(uint32(kindShift) | uint32(tryIndex+1)<<3)
	}
	// Three records. try_index -1 fits in one byte (bias makes it 0); try_index
	// 0 encodes as 1<<3 = 8, which also fits.
	payload := []byte{
		enc(1, -1), 0x10, // IcCall  at pc 0x10, no try
		enc(3, 0), 0x08, // RuntimeCall at pc 0x18, try 0
		enc(1, 0), 0x08, // IcCall  at pc 0x20, try 0
	}
	entries, err := DecodePcDescriptors(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	wantPC := []uint32{0x10, 0x18, 0x20}
	for i, w := range wantPC {
		if entries[i].PCOffset != w {
			t.Errorf("entry %d pc = 0x%x, want 0x%x (deltas must accumulate)", i, entries[i].PCOffset, w)
		}
	}
	if entries[0].TryIndex != InvalidTryIndex {
		t.Errorf("entry 0 try = %d, want %d", entries[0].TryIndex, InvalidTryIndex)
	}
	if entries[1].Kind != PcRuntimeCall {
		t.Errorf("entry 1 kind = %v, want RuntimeCall", entries[1].Kind)
	}

	if _, err := DecodePcDescriptors(nil); err != nil {
		t.Errorf("empty payload should decode to no entries, got %v", err)
	}
	// A record missing its delta must be reported, not silently dropped.
	if _, err := DecodePcDescriptors([]byte{enc(1, 0)}); err == nil {
		t.Error("truncated record did not error")
	} else if !strings.Contains(err.Error(), "pc_offset delta at 1") {
		t.Fatalf("truncated record diagnostic = %q, want field start offset 1", err)
	}
	// A large positive delta must not wrap through uint32 into a plausible PC.
	// 2^32 as canonical SLEB128: four zero data groups followed by 0x10.
	oversizedDelta := []byte{enc(1, -1), 0x80, 0x80, 0x80, 0x80, 0x10}
	if _, err := DecodePcDescriptors(oversizedDelta); err == nil {
		t.Error("pc offset beyond uint32 was accepted")
	}
}

// TestBuildTryRegions checks that point annotations become ranges correctly:
// a try index holds from the descriptor that introduces it until the next
// descriptor with a different index, and the final region is closed by endPC.
func TestBuildTryRegions(t *testing.T) {
	entries := []PcDescriptorEntry{
		{PCOffset: 0x00, TryIndex: InvalidTryIndex},
		{PCOffset: 0x10, TryIndex: 0},
		{PCOffset: 0x18, TryIndex: 0},
		{PCOffset: 0x30, TryIndex: InvalidTryIndex},
		{PCOffset: 0x40, TryIndex: 1},
	}
	got := BuildTryRegions(entries, 0x60)
	if len(got) != 2 {
		t.Fatalf("got %d regions, want 2: %+v", len(got), got)
	}
	// try 0 runs from its first descriptor to the next differing one.
	if got[0] != (TryRegion{StartPC: 0x10, EndPC: 0x30, TryIndex: 0}) {
		t.Errorf("region 0 = %+v, want {0x10 0x30 0}", got[0])
	}
	// try 1 is closed by endPC because no descriptor follows it.
	if got[1] != (TryRegion{StartPC: 0x40, EndPC: 0x60, TryIndex: 1}) {
		t.Errorf("region 1 = %+v, want {0x40 0x60 1}", got[1])
	}

	// Unsorted input must give the same answer.
	shuffled := []PcDescriptorEntry{entries[4], entries[1], entries[3], entries[0], entries[2]}
	if got2 := BuildTryRegions(shuffled, 0x60); len(got2) != 2 || got2[0] != got[0] || got2[1] != got[1] {
		t.Errorf("unsorted input gave %+v, want %+v", got2, got)
	}

	// No try blocks at all -> no regions.
	if r := BuildTryRegions([]PcDescriptorEntry{{PCOffset: 0, TryIndex: InvalidTryIndex}}, 0x10); len(r) != 0 {
		t.Errorf("expected no regions, got %+v", r)
	}
	if r := BuildTryRegions(nil, 0x10); r != nil {
		t.Errorf("expected nil for no entries, got %+v", r)
	}
}
