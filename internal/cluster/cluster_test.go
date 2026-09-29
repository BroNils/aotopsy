package cluster

import (
	"math"
	"testing"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

func TestClassifyAlloc_TypedDataInternal(t *testing.T) {
	ct := &snapshot.CIDTable{
		TypedDataInt8ArrayCid: 112,
		ByteDataViewCid:       168,
		TypedDataCidStride:    4,
		NativePointerCid:      1,
		Instance:              45,
	}

	// TypedData internal CIDs should classify as AllocTypedData.
	for cid := 112; cid < 168; cid += 4 {
		kind := ClassifyAlloc(cid, ct)
		if kind != AllocTypedData {
			t.Errorf("CID %d: got %d, want AllocTypedData", cid, kind)
		}
	}

	// View CIDs (remainder 1) should NOT match TypedData, should fall to Instance.
	kind := ClassifyAlloc(113, ct)
	if kind != AllocInstance {
		t.Errorf("CID 113 (view): got %d, want AllocInstance", kind)
	}

	// DeltaEncodedTypedData (CID 1) should classify as AllocTypedData.
	kind = ClassifyAlloc(1, ct)
	if kind != AllocTypedData {
		t.Errorf("CID 1 (DeltaEncodedTypedData): got %d, want AllocTypedData", kind)
	}
}

func TestCidNameV_TypedDataInternal(t *testing.T) {
	ct := &snapshot.CIDTable{
		TypedDataInt8ArrayCid: 112,
		ByteDataViewCid:       168,
		TypedDataCidStride:    4,
		NativePointerCid:      1,
	}

	tests := []struct {
		cid  int
		want string
	}{
		{112, "TypedDataInt8Array"},
		{116, "TypedDataUint8Array"},
		{113, "TypedDataInt8ArrayView"},
		{114, "ExternalTypedDataInt8Array"},
		{115, "UnmodifiableTypedDataInt8ArrayView"},
		{1, "DeltaEncodedTypedData"},
	}

	for _, tt := range tests {
		got := CidNameV(tt.cid, ct)
		if got != tt.want {
			t.Errorf("CidNameV(%d) = %q, want %q", tt.cid, got, tt.want)
		}
	}
}

func TestScanClustersRejectsSplitCountOverflowBeforeAllocation(t *testing.T) {
	profile := snapshot.DetectVersion("e4a09dbf2bb120fe4674e0576617a0dc")
	var data []byte
	for _, v := range []int64{0, 0, math.MaxInt64, math.MaxInt64, 0} {
		data = append(data, encUnsigned(v)...)
	}
	if _, err := ScanClusters(data, 0, profile, false, dartfmt.Options{}); err == nil {
		t.Fatal("ScanClusters accepted overflowing canonical+noncanonical cluster counts")
	}
}

func TestScanClustersStrictVsBestEffortMalformedTag(t *testing.T) {
	profile := snapshot.DetectVersion("e4a09dbf2bb120fe4674e0576617a0dc")
	// 2.13 split-canonical header: base, objects, canonical clusters,
	// noncanonical clusters, field-table length. The trailing 0x01 starts a
	// tagged integer but never supplies its terminator.
	var data []byte
	for _, v := range []int64{0, 0, 0, 1, 0} {
		data = append(data, encUnsigned(v)...)
	}
	data = append(data, 0x01)

	if _, err := ScanClusters(data, 0, profile, false, dartfmt.Options{Mode: dartfmt.ModeStrict}); err == nil {
		t.Fatal("strict mode returned nil error for truncated cluster tag")
	}
	got, err := ScanClusters(data, 0, profile, false, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
	if err != nil {
		t.Fatalf("best-effort mode returned error: %v", err)
	}
	if got == nil || len(got.Diags) == 0 {
		t.Fatal("best-effort mode did not preserve a diagnostic for truncated tag")
	}
}
