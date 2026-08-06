package cluster

import (
	"os"
	"path/filepath"
	"testing"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/snapshot"
)

func findSample(t *testing.T, name string) string {
	t.Helper()
	dir, _ := os.Getwd()
	for {
		p := filepath.Join(dir, "samples", name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skipf("sample %s not found", name)
		}
		dir = parent
	}
}

func extractSnapshot(t *testing.T, name string) *snapshot.Info {
	t.Helper()
	path := findSample(t, name)
	ef, err := elfx.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ef.Close() })

	info, err := snapshot.Extract(ef, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func scanSnapshot(t *testing.T, info *snapshot.Info, data []byte, isVM bool) *Result {
	t.Helper()
	if len(data) < 64 {
		t.Fatal("data too short")
	}
	cs, err := FindClusterDataStart(data)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ScanClusters(data, cs, info.Version, isVM, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestScanClusters_EvilPatched_VM(t *testing.T) {
	info := extractSnapshot(t, "evil-patched.so")
	result := scanSnapshot(t, info, info.VmData.Data, true)

	if int64(len(result.Clusters)) != result.Header.NumClusters {
		t.Errorf("decoded %d clusters, want %d", len(result.Clusters), result.Header.NumClusters)
	}
	if result.Header.NumClusters != 6 {
		t.Errorf("NumClusters = %d, want 6", result.Header.NumClusters)
	}
}

func TestScanClusters_EvilPatched_Isolate(t *testing.T) {
	info := extractSnapshot(t, "evil-patched.so")
	result := scanSnapshot(t, info, info.IsolateData.Data, false)

	if int64(len(result.Clusters)) != result.Header.NumClusters {
		t.Errorf("decoded %d clusters, want %d", len(result.Clusters), result.Header.NumClusters)
	}
	if result.Header.NumClusters != 56 {
		t.Errorf("NumClusters = %d, want 56", result.Header.NumClusters)
	}

	// First cluster should be String (kStringCid, used for canonical string clusters).
	if result.Clusters[0].CID != info.Version.CIDs.String {
		t.Errorf("first cluster CID = %d, want String (%d)", result.Clusters[0].CID, info.Version.CIDs.String)
	}
}

func TestScanClusters_BlutterLce_VM(t *testing.T) {
	info := extractSnapshot(t, "blutter-lce.so")
	if info.Version == nil || info.Version.DartVersion != "2.17.6" {
		t.Fatalf("expected version 2.17.6, got %v", info.Version)
	}
	result := scanSnapshot(t, info, info.VmData.Data, true)

	if int64(len(result.Clusters)) != result.Header.NumClusters {
		t.Errorf("decoded %d clusters, want %d", len(result.Clusters), result.Header.NumClusters)
	}
	if result.Header.NumClusters != 6 {
		t.Errorf("NumClusters = %d, want 6", result.Header.NumClusters)
	}
}

func TestScanClusters_BlutterLce_Isolate(t *testing.T) {
	info := extractSnapshot(t, "blutter-lce.so")
	result := scanSnapshot(t, info, info.IsolateData.Data, false)

	if int64(len(result.Clusters)) != result.Header.NumClusters {
		t.Errorf("decoded %d clusters, want %d", len(result.Clusters), result.Header.NumClusters)
	}
	if result.Header.NumClusters != 341 {
		t.Errorf("NumClusters = %d, want 341", result.Header.NumClusters)
	}
}

func TestScanClusters_Newandromo_VM(t *testing.T) {
	info := extractSnapshot(t, "newandromo.so")
	result := scanSnapshot(t, info, info.VmData.Data, true)

	if int64(len(result.Clusters)) != result.Header.NumClusters {
		t.Errorf("decoded %d clusters, want %d", len(result.Clusters), result.Header.NumClusters)
	}
	if result.Header.NumClusters != 7 {
		t.Errorf("NumClusters = %d, want 7", result.Header.NumClusters)
	}
}

func TestScanClusters_Newandromo_Isolate(t *testing.T) {
	info := extractSnapshot(t, "newandromo.so")
	result := scanSnapshot(t, info, info.IsolateData.Data, false)

	if int64(len(result.Clusters)) != result.Header.NumClusters {
		t.Errorf("decoded %d clusters, want %d", len(result.Clusters), result.Header.NumClusters)
	}
	if result.Header.NumClusters != 655 {
		t.Errorf("NumClusters = %d, want 655", result.Header.NumClusters)
	}
}

func TestHeaderFieldCount_V2(t *testing.T) {
	info := extractSnapshot(t, "blutter-lce.so")
	if info.Version.HeaderFields != 6 {
		t.Errorf("HeaderFields = %d, want 6 for v2.17.6", info.Version.HeaderFields)
	}

	result := scanSnapshot(t, info, info.IsolateData.Data, false)
	if result.Header.InitialFieldTableLen == 0 {
		t.Error("InitialFieldTableLen should be nonzero for v2.17.6")
	}
}

func TestHeaderFieldCount_V3(t *testing.T) {
	info := extractSnapshot(t, "evil-patched.so")
	if info.Version.HeaderFields != 5 {
		t.Errorf("HeaderFields = %d, want 5 for v3.10.7", info.Version.HeaderFields)
	}

	result := scanSnapshot(t, info, info.IsolateData.Data, false)
	if result.Header.InitialFieldTableLen != 0 {
		t.Errorf("InitialFieldTableLen = %d, want 0 for v3.x", result.Header.InitialFieldTableLen)
	}
}

// TestPatchClassRefCount is a drift sentinel: pins the PatchClass ref count
// per format boundary. If the PreV32Format flag or specPatchClass logic changes,
// this fails before stream corruption can propagate to downstream clusters.
func TestPatchClassRefCount(t *testing.T) {
	tests := []struct {
		sample   string
		wantRefs int
	}{
		{"blutter-lce.so", 3},  // v2.17.6: PreV32Format=true → 3 refs
		{"newandromo.so", 3},   // v3.1.0:  PreV32Format=true → 3 refs
		{"evil-patched.so", 2}, // v3.10.7: PreV32Format=false → 2 refs
	}
	for _, tt := range tests {
		t.Run(tt.sample, func(t *testing.T) {
			info := extractSnapshot(t, tt.sample)
			patchCID := info.Version.CIDs.PatchClass
			spec := GetFillSpec(patchCID, &ClusterMeta{CID: patchCID}, info.Version)
			if spec.NumRefs != tt.wantRefs {
				t.Errorf("PatchClass NumRefs = %d, want %d (PreV32Format=%v)",
					spec.NumRefs, tt.wantRefs, info.Version.PreV32Format)
			}
		})
	}
}

// TestReadFill_AllSamples is the integration drift sentinel: full fill parsing
// must complete without error and produce exact string/named counts. Any ref
// count mismatch in ANY cluster propagates as stream drift and fails here.
func TestReadFill_AllSamples(t *testing.T) {
	tests := []struct {
		sample      string
		wantStrings int
		wantNamed   int
		wantCodes   int
	}{
		{"evil-patched.so", 2352, 2367, 1465},
		{"blutter-lce.so", 12314, 14883, 10113},
		{"newandromo.so", 24019, 12912, 4152},
	}
	for _, tt := range tests {
		t.Run(tt.sample, func(t *testing.T) {
			info := extractSnapshot(t, tt.sample)
			data := info.IsolateData.Data
			result := scanSnapshot(t, info, data, false)
			if err := ReadFill(data, result, info.Version, false, 0); err != nil {
				t.Fatalf("ReadFill: %v", err)
			}
			if len(result.Strings) != tt.wantStrings {
				t.Errorf("Strings = %d, want %d", len(result.Strings), tt.wantStrings)
			}
			if len(result.Named) != tt.wantNamed {
				t.Errorf("Named = %d, want %d", len(result.Named), tt.wantNamed)
			}
			if len(result.Codes) != tt.wantCodes {
				t.Errorf("Codes = %d, want %d", len(result.Codes), tt.wantCodes)
			}
		})
	}
}

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
