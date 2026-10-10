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

	// View and external CIDs use fixed-size alloc clusters (count only).
	kind := ClassifyAlloc(113, ct)
	if kind != AllocSimple {
		t.Errorf("CID 113 (view): got %d, want AllocSimple", kind)
	}
	kind = ClassifyAlloc(114, ct)
	if kind != AllocSimple {
		t.Errorf("CID 114 (external): got %d, want AllocSimple", kind)
	}
	// Remainder 3 is an unmodifiable view in 4-stride SDKs. The Full-AOT
	// cluster factory does not route it through the typed-data/view/external
	// clusters, so a synthetic cluster must fail closed.
	kind = ClassifyAlloc(115, ct)
	if kind != AllocUnknown {
		t.Errorf("CID 115 (unmodifiable view): got %d, want AllocUnknown", kind)
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
	if got.AllocComplete {
		t.Fatal("best-effort truncated alloc phase was marked complete")
	}
	if err := ReadFill(data, got, profile, false, 0, dartfmt.Options{}); err == nil {
		t.Fatal("ReadFill accepted a partial best-effort alloc result")
	}
}

func TestScanClustersRejectsHeaderObjectCountMismatch(t *testing.T) {
	profile := snapshot.ProfileForVersion("2.13.0")
	// 2.13 split-canonical header: base=0, num_objects=1, zero clusters,
	// field_table_len=0. With no cluster alloc records the SDK's invariant is
	// next_ref_index-kFirstReference == 0, not 1.
	var data []byte
	for _, v := range []int64{0, 1, 0, 0, 0} {
		data = append(data, encUnsigned(v)...)
	}
	if _, err := ScanClusters(data, 0, profile, false, dartfmt.Options{}); err == nil {
		t.Fatal("ScanClusters accepted num_objects inconsistent with allocated refs")
	}
}
