package cluster

import (
	"testing"

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
