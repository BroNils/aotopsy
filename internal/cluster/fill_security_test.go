package cluster

import (
	"bytes"
	"testing"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

func TestReadFillArrayHugeDeclaredLengthDoesNotPreallocateDeclaredSize(t *testing.T) {
	// The fill claims one array contains 1<<30 elements but provides no element
	// refs. The parser must reach EOF without trying to reserve ~8 GiB first.
	data := append(encUnsigned(1<<30), encUnsigned(0)...)
	s := dartfmt.NewStream(data)
	cm := &ClusterMeta{Count: 1, StartRef: 1, Lengths: []int64{0}}
	profile := snapshot.DetectVersion("97ff04a728735e6b6b098bdf983faaba")
	if _, err := readFillArray(s, cm, true, profile); err == nil {
		t.Fatal("readFillArray accepted truncated huge array")
	}
}

func TestInitialCaptureCapBoundsUntrustedCount(t *testing.T) {
	if got := initialCaptureCap(10_000_000, 8); got != 8 {
		t.Fatalf("small remaining stream cap = %d, want 8", got)
	}
	if got := initialCaptureCap(10_000_000, 10_000_000); got != 4096 {
		t.Fatalf("large speculative cap = %d, want 4096", got)
	}
}

func TestReadFillStringsRejectsLengthMismatch(t *testing.T) {
	for _, tc := range []struct {
		name      string
		oldFormat bool
		allocLen  int64
		fillLen   int64
	}{
		{name: "old plain length", oldFormat: true, allocLen: 1, fillLen: 5},
		{name: "encoded length and cid", oldFormat: false, allocLen: 2, fillLen: 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cm := &ClusterMeta{Count: 1, StartRef: 1, Lengths: []int64{tc.allocLen}}
			s := dartfmt.NewStream(encUnsigned(tc.fillLen))
			if _, err := readFillStrings(s, cm, tc.oldFormat, nil); err == nil {
				t.Fatal("string fill accepted a length that differs from alloc")
			}
		})
	}
}

func TestDebugFillPositionsInstanceDoesNotPanic(t *testing.T) {
	profile := snapshot.DetectVersion("97ff04a728735e6b6b098bdf983faaba") // Dart 3.9.2
	headerWords := int32(1)
	if profile.CompressedPointers {
		headerWords = 2
	}
	cm := ClusterMeta{
		CID:                    profile.CIDs.NumPredefinedCids + 1,
		Count:                  1,
		StartRef:               1,
		NextFieldOffsetInWords: headerWords,
		InstanceSizeInWords:    headerWords,
	}
	// >=2.12 Instance fill starts with the per-cluster unboxed bitmap. There
	// are no field slots in this synthetic instance, so that is the whole fill.
	data := append([]byte{0}, encUnsigned(0)...)
	result := &Result{FillStart: 1, Clusters: []ClusterMeta{cm}}
	var out bytes.Buffer
	if err := DebugFillPositions(data, result, profile, false, &out); err != nil {
		t.Fatalf("DebugFillPositions: %v", err)
	}
}

func TestRODataOffsetArithmeticRejectsShiftOverflow(t *testing.T) {
	if _, ok := advanceRODataOffset(0, 1<<59, 4); ok {
		t.Fatal("advanceRODataOffset accepted overflowing delta shift")
	}
	if _, ok := checkedAddNonnegativeInt64(int64(^uint64(0)>>1), 1); ok {
		t.Fatal("checkedAddNonnegativeInt64 accepted overflowing addition")
	}
}

func TestExtractRODataStringsHugeDeltaDoesNotPanic(t *testing.T) {
	profile := snapshot.DetectVersion("5b97292b25f0a715613b7a28e0734f77")
	cm := &ClusterMeta{Count: 1, StartRef: 1, Lengths: []int64{1 << 59}}
	if got := extractRODataStrings(make([]byte, 128), cm, profile.CIDs, 16, profile, false); len(got) != 0 {
		t.Fatalf("overflowing ROData delta produced %d strings", len(got))
	}
}

func TestReadFillTypedDataRejectsByteCountOverflowOrTruncation(t *testing.T) {
	profile := snapshot.DetectVersion("5b97292b25f0a715613b7a28e0734f77")
	ct := profile.CIDs
	const length = int64(1 << 60)
	cm := &ClusterMeta{
		CID:      typedDataInt32ArrayCid(ct),
		Count:    1,
		StartRef: 1,
		Lengths:  []int64{length},
	}
	s := dartfmt.NewStream(encUnsigned(length))
	if err := readFillTypedData(s, cm, ct, false, map[int][]byte{}); err == nil {
		t.Fatal("typed data accepted enormous length with no payload")
	}
}

func TestInstanceAllocRejectsImpossibleLayout(t *testing.T) {
	data := encUnsigned(1)
	data = append(data, encTagged64(5)...)
	data = append(data, encTagged64(4)...)
	cm := &ClusterMeta{CID: 123}
	if _, err := skipInstanceAllocV(dartfmt.NewStream(data), cm, 100); err == nil {
		t.Fatal("instance alloc accepted next_field_offset greater than instance_size")
	}
}
