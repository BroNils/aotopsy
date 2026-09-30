package cluster

import (
	"strings"
	"testing"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

func TestClassAllocRejectsUnsupportedExtraCountPrefix(t *testing.T) {
	ct := &snapshot.CIDTable{NumPredefinedCids: 176}
	// Exact supported SDKs write predefined_count first. A first value above
	// kNumPredefinedCids is malformed; it must not be reinterpreted as a private
	// fork's total-count prefix and consume the next field as a plausible count.
	data := append(encUnsigned(500), encUnsigned(1)...)
	s := dartfmt.NewStream(data)
	if _, err := skipClassAlloc(s, &ClusterMeta{}, ct, false, 10_000); err == nil ||
		!strings.Contains(err.Error(), "exceeds SDK kNumPredefinedCids") {
		t.Fatalf("oversized predefined class count error = %v", err)
	}
}

func TestContextScopeRefCountTracksSDKLayout(t *testing.T) {
	for _, tc := range []struct {
		version string
		refs    int
	}{
		{"2.19.0", 8},
		{"3.0.5", 9},
		{"3.2.5", 10},
		{"3.13.0", 10},
	} {
		t.Run(tc.version, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(tc.version)
			if profile == nil {
				t.Fatalf("missing profile %s", tc.version)
			}
			data := append(encUnsigned(1), 0) // length=1, is_implicit=false
			for i := 0; i < tc.refs; i++ {
				data = append(data, encUnsigned(0)...)
			}
			data = append(data, 0x5a)
			s := dartfmt.NewStream(data)
			cm := &ClusterMeta{Count: 1, Lengths: []int64{1}}
			if err := skipFillContextScope(s, cm, true, profile); err != nil {
				t.Fatalf("skipFillContextScope: %v", err)
			}
			marker, err := s.ReadByte()
			if err != nil || marker != 0x5a {
				t.Fatalf("stream position after ContextScope = marker %#x err=%v, want 0x5a", marker, err)
			}
		})
	}
}

func TestContextScopeRejectsFillLengthMismatch(t *testing.T) {
	profile := snapshot.ProfileForVersion("3.13.0")
	s := dartfmt.NewStream(append(encUnsigned(2), 0))
	cm := &ClusterMeta{Count: 1, Lengths: []int64{1}}
	if err := skipFillContextScope(s, cm, true, profile); err == nil ||
		!strings.Contains(err.Error(), "differs from alloc length") {
		t.Fatalf("ContextScope mismatched length error = %v", err)
	}
}

func TestExternalTypedDataUsesLengthAlignmentAndRawPayload(t *testing.T) {
	profile := snapshot.ProfileForVersion("3.12.2")
	ct := profile.CIDs
	externalInt8CID := ct.TypedDataInt8ArrayCid + 2
	if got := ClassifyAlloc(externalInt8CID, ct); got != AllocSimple {
		t.Fatalf("external typed data alloc kind = %d, want AllocSimple", got)
	}
	if got := GetFillSpec(externalInt8CID, &ClusterMeta{CID: externalInt8CID}, profile).Kind; got != FillExternalTypedData {
		t.Fatalf("external typed data fill kind = %d, want FillExternalTypedData", got)
	}

	// One-byte unsigned length leaves the stream at offset 1; SDK then aligns
	// to 8 before copying three raw Int8 bytes.
	data := append([]byte{}, encUnsigned(3)...)
	data = append(data, make([]byte, 7)...)
	data = append(data, 0x11, 0x22, 0x33, 0x5a)
	s := dartfmt.NewStream(data)
	cm := &ClusterMeta{CID: externalInt8CID, Count: 1}
	if err := skipFillExternalTypedData(s, cm, ct); err != nil {
		t.Fatalf("skipFillExternalTypedData: %v", err)
	}
	marker, err := s.ReadByte()
	if err != nil || marker != 0x5a {
		t.Fatalf("stream position after external typed data = marker %#x err=%v, want 0x5a", marker, err)
	}
}

func TestExternalTypedDataRejectsPaddingPastTheInput(t *testing.T) {
	profile := snapshot.ProfileForVersion("3.12.2")
	ct := profile.CIDs
	cid := ct.TypedDataInt8ArrayCid + 2
	// length=3 leaves the stream at offset 1, so 7 padding bytes are needed
	// before the payload; only 3 bytes exist. Align must fail, not clamp to the
	// end and let a truncated blob look like an empty payload.
	data := append(encUnsigned(3), 0, 0, 0)
	err := skipFillExternalTypedData(dartfmt.NewStream(data), &ClusterMeta{CID: cid, Count: 1}, ct)
	if err == nil || !strings.Contains(err.Error(), "alignment") {
		t.Fatalf("padding past the input error = %v", err)
	}
}

// A stream start outside the data is malformed input. It used to be clamped, so
// a negative or oversized offset silently became "parse from byte 0 / from EOF".
func TestStreamStartOffsetsAreValidated(t *testing.T) {
	profile := snapshot.ProfileForVersion("3.9.2")
	data := make([]byte, 64)

	if _, err := ScanClusters(data, -1, profile, false, dartfmt.Options{}); err == nil {
		t.Fatal("ScanClusters accepted a negative cluster start")
	}
	if _, err := ScanClusters(data, len(data), profile, false, dartfmt.Options{}); err == nil {
		t.Fatal("ScanClusters accepted a cluster start at the end of the data")
	}

	res := &Result{FillEnd: len(data) + 1}
	err := ReadObjectStoreRefs(data, res, profile)
	if err == nil || !strings.Contains(err.Error(), "stream start") {
		t.Fatalf("ReadObjectStoreRefs with FillEnd past the data error = %v", err)
	}
	if res.ObjectStoreRefs != nil {
		t.Fatal("rejected ReadObjectStoreRefs still recorded refs")
	}
}

func TestByteDataViewUsesTypedDataViewClusterShape(t *testing.T) {
	for _, version := range []string{"2.10.0", "3.2.5", "3.12.2", "3.13.0"} {
		t.Run(version, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(version)
			if profile == nil || profile.CIDs == nil || profile.CIDs.ByteDataViewCid == 0 {
				t.Fatalf("%s profile lacks ByteDataViewCid", version)
			}
			cid := profile.CIDs.ByteDataViewCid
			if got := ClassifyAlloc(cid, profile.CIDs); got != AllocSimple {
				t.Fatalf("ByteDataView alloc kind = %d, want AllocSimple", got)
			}
			spec := GetFillSpec(cid, &ClusterMeta{CID: cid}, profile)
			if spec.Kind != FillRefs || spec.NumRefs != 3 {
				t.Fatalf("ByteDataView spec = kind %d refs %d, want FillRefs/3", spec.Kind, spec.NumRefs)
			}
			if got, want := spec.LeadingBool, version == "2.10.0"; got != want {
				t.Fatalf("ByteDataView LeadingBool = %v, want %v", got, want)
			}
		})
	}
}

func TestDart210ConcreteTypedDataViewReadsCanonicalByte(t *testing.T) {
	profile := snapshot.ProfileForVersion("2.10.0")
	if profile == nil || profile.CIDs == nil {
		t.Fatal("missing Dart 2.10.0 profile")
	}
	cid := profile.CIDs.TypedDataInt8ArrayCid + 1
	spec := GetFillSpec(cid, &ClusterMeta{CID: cid}, profile)
	if !spec.LeadingBool || spec.NumRefs != 3 {
		t.Fatalf("2.10 typed-data view spec = %+v", spec)
	}
	data := []byte{1} // is_canonical
	for i := 0; i < 3; i++ {
		data = append(data, encUnsigned(0)...)
	}
	data = append(data, 0x5a)
	s := dartfmt.NewStream(data)
	cm := &ClusterMeta{CID: cid, Count: 1, StartRef: 1}
	if _, _, _, _, _, _, _, _, _, _, _, err := readFillRefs(s, cm, &spec, true, profile); err != nil {
		t.Fatal(err)
	}
	marker, err := s.ReadByte()
	if err != nil || marker != 0x5a {
		t.Fatalf("stream position after 2.10 typed-data view marker=%#x err=%v, want 0x5a", marker, err)
	}
}

func TestLegacyMapCompactFillBoundary(t *testing.T) {
	for _, tc := range []struct {
		version     string
		leadingBool bool
		legacy      bool
		invalid     bool
	}{
		{version: "2.10.0", leadingBool: true, legacy: true},
		{version: "2.12.0", legacy: true},
		{version: "2.13.0", legacy: true},
		{version: "2.14.0", invalid: true},
	} {
		t.Run(tc.version, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(tc.version)
			if profile == nil || profile.CIDs == nil || profile.CIDs.Map == 0 {
				t.Fatalf("missing Map CID for %s", tc.version)
			}
			spec := GetFillSpec(profile.CIDs.Map, &ClusterMeta{CID: profile.CIDs.Map}, profile)
			if tc.invalid {
				if spec.Kind != FillUnknown {
					t.Fatalf("invalid map spec kind=%d, want FillUnknown", spec.Kind)
				}
				return
			}
			if tc.legacy {
				if spec.Kind != FillLegacyMap || spec.LeadingBool != tc.leadingBool {
					t.Fatalf("legacy map spec = kind %d leadingBool=%v", spec.Kind, spec.LeadingBool)
				}
				data := make([]byte, 0, 8)
				if tc.leadingBool {
					data = append(data, 1)
				}
				data = append(data, encUnsigned(0)...) // type_arguments
				data = append(data, byte(2+192))       // Read<int32_t>(pairs=2)
				for i := 0; i < 4; i++ {
					data = append(data, encUnsigned(int64(i))...)
				}
				data = append(data, 0x5a)
				s := dartfmt.NewStream(data)
				if err := skipFillLegacyMap(s, &ClusterMeta{Count: 1}, true, tc.leadingBool, 100); err != nil {
					t.Fatal(err)
				}
				marker, err := s.ReadByte()
				if err != nil || marker != 0x5a {
					t.Fatalf("legacy map stream marker=%#x err=%v, want 0x5a", marker, err)
				}
				return
			}
			t.Fatalf("unexpected non-legacy/non-invalid case")
		})
	}
}

func TestAbstractTypedDataBaseCIDsFailClosed(t *testing.T) {
	for _, version := range []string{"2.10.0", "2.14.0", "3.12.2", "3.13.0"} {
		t.Run(version, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(version)
			if profile == nil || profile.CIDs == nil {
				t.Fatalf("missing profile %s", version)
			}
			for name, cid := range map[string]int{
				"TypedData":         profile.CIDs.TypedData,
				"ExternalTypedData": profile.CIDs.ExternalTypedData,
				"TypedDataView":     profile.CIDs.TypedDataView,
			} {
				if cid == 0 {
					continue
				}
				if got := ClassifyAlloc(cid, profile.CIDs); got != AllocUnknown {
					t.Errorf("%s alloc kind = %d, want AllocUnknown", name, got)
				}
				if got := GetFillSpec(cid, &ClusterMeta{CID: cid}, profile).Kind; got != FillUnknown {
					t.Errorf("%s fill kind = %d, want FillUnknown", name, got)
				}
			}
		})
	}
}

func TestTransferableTypedDataClusterFailsClosed(t *testing.T) {
	profile := snapshot.ProfileForVersion("3.12.2")
	if profile == nil || profile.CIDs == nil || profile.CIDs.TransferableTypedData == 0 {
		t.Fatal("3.12.2 profile lacks TransferableTypedData CID")
	}
	cid := profile.CIDs.TransferableTypedData
	if got := ClassifyAlloc(cid, profile.CIDs); got != AllocUnknown {
		t.Fatalf("TransferableTypedData alloc kind = %d, want AllocUnknown", got)
	}
	if got := GetFillSpec(cid, &ClusterMeta{CID: cid}, profile).Kind; got != FillUnknown {
		t.Fatalf("TransferableTypedData fill kind = %d, want FillUnknown", got)
	}
}

func TestKernelProgramInfoFailsClosedInFullAOT(t *testing.T) {
	for _, version := range []string{"2.10.0", "2.18.0", "2.19.0", "3.13.0"} {
		t.Run(version, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(version)
			if profile == nil || profile.CIDs == nil || profile.CIDs.KernelProgramInfo == 0 {
				t.Fatalf("missing KernelProgramInfo CID for %s", version)
			}
			cid := profile.CIDs.KernelProgramInfo
			if got := ClassifyAlloc(cid, profile.CIDs); got != AllocUnknown {
				t.Fatalf("KernelProgramInfo alloc kind = %d, want AllocUnknown", got)
			}
			if got := GetFillSpec(cid, &ClusterMeta{CID: cid}, profile).Kind; got != FillUnknown {
				t.Fatalf("KernelProgramInfo fill kind = %d, want FillUnknown", got)
			}
		})
	}
}

func TestDart210LegacyClustersUseExactFillOrder(t *testing.T) {
	profile := snapshot.ProfileForVersion("2.10.0")
	if profile == nil || profile.CIDs == nil {
		t.Fatal("missing Dart 2.10.0 profile")
	}

	t.Run("RedirectionData", func(t *testing.T) {
		cid := profile.CIDs.RedirectionData
		if cid == 0 || ClassifyAlloc(cid, profile.CIDs) != AllocSimple {
			t.Fatalf("RedirectionData CID/alloc not wired: cid=%d kind=%d", cid, ClassifyAlloc(cid, profile.CIDs))
		}
		spec := GetFillSpec(cid, &ClusterMeta{CID: cid}, profile)
		if spec.Kind != FillRefs || spec.NumRefs != 3 {
			t.Fatalf("RedirectionData spec = kind %d refs %d, want FillRefs/3", spec.Kind, spec.NumRefs)
		}
		data := append(encUnsigned(0), encUnsigned(0)...)
		data = append(data, encUnsigned(0)...)
		data = append(data, 0x5a)
		s := dartfmt.NewStream(data)
		cm := &ClusterMeta{CID: cid, Count: 1, StartRef: 1}
		if _, _, _, _, _, _, _, _, _, _, _, err := readFillRefs(s, cm, &spec, true, profile); err != nil {
			t.Fatal(err)
		}
		marker, err := s.ReadByte()
		if err != nil || marker != 0x5a {
			t.Fatalf("RedirectionData stream position marker=%#x err=%v, want 0x5a", marker, err)
		}
	})

	t.Run("ParameterTypeCheck", func(t *testing.T) {
		cid := profile.CIDs.ParameterTypeCheck
		if cid == 0 || ClassifyAlloc(cid, profile.CIDs) != AllocSimple {
			t.Fatalf("ParameterTypeCheck CID/alloc not wired: cid=%d kind=%d", cid, ClassifyAlloc(cid, profile.CIDs))
		}
		spec := GetFillSpec(cid, &ClusterMeta{CID: cid}, profile)
		if spec.Kind != FillRefs || spec.NumRefs != 4 || len(spec.LeadingScalars) != 1 || spec.LeadingScalars[0] != OpTagged64 {
			t.Fatalf("ParameterTypeCheck spec = %+v", spec)
		}
		data := append([]byte{}, encTagged64(7)...)
		for i := 0; i < 4; i++ {
			data = append(data, encUnsigned(0)...)
		}
		data = append(data, 0x5a)
		s := dartfmt.NewStream(data)
		cm := &ClusterMeta{CID: cid, Count: 1, StartRef: 1}
		if _, _, _, _, _, _, _, _, _, _, _, err := readFillRefs(s, cm, &spec, true, profile); err != nil {
			t.Fatal(err)
		}
		marker, err := s.ReadByte()
		if err != nil || marker != 0x5a {
			t.Fatalf("ParameterTypeCheck stream position marker=%#x err=%v, want 0x5a", marker, err)
		}
	})
}

func TestClosureDataLayoutAcrossLegacyBoundaries(t *testing.T) {
	for _, tc := range []struct {
		version    string
		refs       int
		scalars    int
		closureIdx int
	}{
		{"2.10.0", 3, 0, 2},
		{"2.12.0", 4, 0, 1},
		{"2.13.0", 3, 1, 1},
		{"2.14.0", 2, 1, 1},
	} {
		t.Run(tc.version, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(tc.version)
			if profile == nil || profile.CIDs == nil {
				t.Fatalf("missing profile %s", tc.version)
			}
			cid := profile.CIDs.ClosureData
			spec := GetFillSpec(cid, &ClusterMeta{CID: cid}, profile)
			if spec.Kind != FillRefs || spec.NumRefs != tc.refs || len(spec.Scalars) != tc.scalars {
				t.Fatalf("ClosureData spec refs=%d scalars=%d, want %d/%d", spec.NumRefs, len(spec.Scalars), tc.refs, tc.scalars)
			}
			data := make([]byte, 0, 16)
			for i := 0; i < tc.refs; i++ {
				data = append(data, encUnsigned(int64(10+i))...)
			}
			if tc.scalars != 0 {
				data = append(data, encUnsigned(0)...)
			}
			data = append(data, 0x5a)
			s := dartfmt.NewStream(data)
			cm := &ClusterMeta{CID: cid, Count: 1, StartRef: 100}
			_, _, _, _, _, _, _, cds, _, _, _, err := readFillRefs(s, cm, &spec, true, profile)
			if err != nil {
				t.Fatal(err)
			}
			if len(cds) != 1 || cds[0].ClosureRef != 10+tc.closureIdx {
				t.Fatalf("ClosureData capture = %+v, want closure ref %d", cds, 10+tc.closureIdx)
			}
			marker, err := s.ReadByte()
			if err != nil || marker != 0x5a {
				t.Fatalf("stream marker=%#x err=%v, want 0x5a", marker, err)
			}
		})
	}
}

func TestLoadingUnitIDWidthBoundary(t *testing.T) {
	for _, tc := range []struct {
		version string
		op      ScalarOp
	}{
		{"3.4.3", OpTagged32},
		{"3.5.0", OpTagged64},
		{"3.13.0", OpTagged64},
	} {
		t.Run(tc.version, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(tc.version)
			if profile == nil || profile.CIDs == nil {
				t.Fatalf("missing profile %s", tc.version)
			}
			spec := GetFillSpec(profile.CIDs.LoadingUnit, &ClusterMeta{CID: profile.CIDs.LoadingUnit}, profile)
			if len(spec.Scalars) != 1 || spec.Scalars[0] != tc.op {
				t.Fatalf("LoadingUnit scalar = %v, want %v", spec.Scalars, tc.op)
			}
		})
	}

	// A value above int32 demonstrates that the >=3.5 path is not merely using
	// a wider reader and then truncating the captured id again.
	const want = int64(1) << 40
	s := dartfmt.NewStream(encTagged64(want))
	var state scalarState
	if err := readLoadingUnitScalar(s, &state, 0, 1, OpTagged64); err != nil {
		t.Fatal(err)
	}
	if state.loadingUnitID != want {
		t.Fatalf("LoadingUnit id = %d, want %d", state.loadingUnitID, want)
	}
}

func TestSimd128ClusterBoundaryAndRawPayload(t *testing.T) {
	old := snapshot.ProfileForVersion("3.3.0")
	if old == nil || old.CIDs == nil {
		t.Fatal("missing 3.3.0 profile")
	}
	oldCID := old.CIDs.Int32x4
	if spec := GetFillSpec(oldCID, &ClusterMeta{CID: oldCID}, old); spec.Kind != FillUnknown {
		t.Fatalf("3.3 SIMD fill kind=%d, want FillUnknown", spec.Kind)
	}
	if _, err := skipAllocV(dartfmt.NewStream(encUnsigned(1)), &ClusterMeta{CID: oldCID}, false, old.CIDs, false, old, nil, 100); err == nil {
		t.Fatal("3.3 SIMD alloc accepted despite no SDK serialization cluster")
	}

	modern := snapshot.ProfileForVersion("3.4.3")
	if modern == nil || modern.CIDs == nil {
		t.Fatal("missing 3.4.3 profile")
	}
	cid := modern.CIDs.Float64x2
	if spec := GetFillSpec(cid, &ClusterMeta{CID: cid}, modern); spec.Kind != FillSimd128 {
		t.Fatalf("3.4.3 SIMD fill kind=%d, want FillSimd128", spec.Kind)
	}
	data := append(make([]byte, 16), 0x5a)
	s := dartfmt.NewStream(data)
	if err := skipFillSimd128(s, &ClusterMeta{CID: cid, Count: 1}); err != nil {
		t.Fatal(err)
	}
	marker, err := s.ReadByte()
	if err != nil || marker != 0x5a {
		t.Fatalf("SIMD stream marker=%#x err=%v, want 0x5a", marker, err)
	}
}

func TestGenericInstanceFallbackRejectsUnknownPredefinedCIDs(t *testing.T) {
	for _, version := range []string{"2.10.0", "2.15.0", "2.16.0", "2.18.0", "3.13.0"} {
		t.Run(version, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(version)
			if profile == nil || profile.CIDs == nil {
				t.Fatalf("missing profile %s", version)
			}
			ct := profile.CIDs

			// Smi is immediately before Mint throughout the supported range. It is
			// a predefined/root value and has no serialization cluster of its own.
			smiCID := ct.Mint - 1
			if got := ClassifyAlloc(smiCID, ct); got != AllocUnknown {
				t.Fatalf("Smi CID %d alloc kind=%d, want AllocUnknown", smiCID, got)
			}
			if got := GetFillSpec(smiCID, &ClusterMeta{CID: smiCID}, profile).Kind; got != FillUnknown {
				t.Fatalf("Smi CID %d fill kind=%d, want FillUnknown", smiCID, got)
			}

			if !snapshot.VersionAtLeast(version, "2.16.0") {
				// NewClusterForClass only gains the CLASS_LIST_FFI_TYPE_MARKER case
				// in 2.16.0, so before it there is no FFI range to accept.
				if ct.FfiMarkerFirstCid != 0 || ct.FfiMarkerLastCid != 0 {
					t.Fatalf("pre-2.16 FFI marker range = %d..%d, want 0..0", ct.FfiMarkerFirstCid, ct.FfiMarkerLastCid)
				}
			} else {
				if ct.FfiMarkerFirstCid == 0 || ct.FfiMarkerLastCid < ct.FfiMarkerFirstCid {
					t.Fatalf("invalid FFI marker range %d..%d", ct.FfiMarkerFirstCid, ct.FfiMarkerLastCid)
				}
				ffiCID := ct.FfiMarkerFirstCid
				if got := ClassifyAlloc(ffiCID, ct); got != AllocInstance {
					t.Fatalf("FFI marker CID %d alloc kind=%d, want AllocInstance", ffiCID, got)
				}
				if got := GetFillSpec(ffiCID, &ClusterMeta{CID: ffiCID}, profile).Kind; got != FillInstance {
					t.Fatalf("FFI marker CID %d fill kind=%d, want FillInstance", ffiCID, got)
				}
			}

			appCID := ct.NumPredefinedCids
			if got := ClassifyAlloc(appCID, ct); got != AllocInstance {
				t.Fatalf("first app CID %d alloc kind=%d, want AllocInstance", appCID, got)
			}
			if got := GetFillSpec(appCID, &ClusterMeta{CID: appCID}, profile).Kind; got != FillInstance {
				t.Fatalf("first app CID %d fill kind=%d, want FillInstance", appCID, got)
			}
		})
	}
}

func TestInstanceAllocBoundsFieldLoopByMaxSteps(t *testing.T) {
	// Uncompressed object header is one word, so nfo=102 means 101 field slots.
	data := append(encUnsigned(1), encTagged64(102)...)
	data = append(data, encTagged64(102)...)
	cm := &ClusterMeta{CID: 999}
	if _, err := skipInstanceAllocV(dartfmt.NewStream(data), cm, 100, false); err == nil ||
		!strings.Contains(err.Error(), "field slot count 101 exceeds max_steps 100") {
		t.Fatalf("unbounded instance layout error = %v", err)
	}

	// With compressed pointers the header is two words; the same nfo has 100
	// field slots and is therefore exactly at the limit.
	cm = &ClusterMeta{CID: 999}
	if _, err := skipInstanceAllocV(dartfmt.NewStream(data), cm, 100, true); err != nil {
		t.Fatalf("compressed layout at max_steps rejected: %v", err)
	}
}

func TestObjectPoolType4Boundary(t *testing.T) {
	for _, tc := range []struct {
		version string
		payload []byte
		wantErr bool
	}{
		// 2.10 type 4 is kNativeEntryData and carries one ref.
		{version: "2.10.0", payload: encUnsigned(7)},
		// 2.12-2.14 have no type 4 at all.
		{version: "2.14.0", wantErr: true},
		// 2.15+ old-format type 4 is kMegamorphicCallEntryPoint and has no payload.
		{version: "2.15.0"},
		{version: "3.2.5"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(tc.version)
			data := append(encUnsigned(1), byte(4)) // fill length=1, entry_bits type=4
			data = append(data, tc.payload...)
			data = append(data, 0x5a)
			s := dartfmt.NewStream(data)
			cm := &ClusterMeta{Count: 1, Lengths: []int64{1}}
			_, err := readFillObjectPool(s, cm, profile, profile.FillRefUnsigned)
			if tc.wantErr {
				if err == nil {
					t.Fatal("type-4 pool entry unexpectedly accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			marker, err := s.ReadByte()
			if err != nil || marker != 0x5a {
				t.Fatalf("pool marker=%#x err=%v, want 0x5a", marker, err)
			}
		})
	}
}

func TestObjectPoolModernRejectsNotSnapshotable(t *testing.T) {
	profile := snapshot.ProfileForVersion("3.3.0")
	// behavior=1 occupies bits 5..7; type=0 is otherwise a valid immediate.
	data := append(encUnsigned(1), byte(0x20))
	cm := &ClusterMeta{Count: 1, Lengths: []int64{1}}
	if _, err := readFillObjectPool(dartfmt.NewStream(data), cm, profile, profile.FillRefUnsigned); err == nil ||
		!strings.Contains(err.Error(), "kNotSnapshotable") {
		t.Fatalf("modern not-snapshotable pool error=%v", err)
	}
}

func TestRegExpFlagsWidthChangesAt312(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    ScalarOp
	}{
		{version: "3.11.0", want: OpInt8},
		{version: "3.12.2", want: OpTagged32},
		{version: "3.13.0", want: OpTagged32},
	} {
		t.Run(tc.version, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(tc.version)
			spec := GetFillSpec(profile.CIDs.RegExp, &ClusterMeta{CID: profile.CIDs.RegExp}, profile)
			if len(spec.Scalars) != 3 || spec.Scalars[2] != tc.want {
				t.Fatalf("regexp scalar ops=%v, want trailing %v", spec.Scalars, tc.want)
			}
		})
	}

	// A 3.12 flags value above the single-byte immediate range must consume the
	// entire tagged uint32, not leave its continuation bytes in the stream.
	profile := snapshot.ProfileForVersion("3.12.2")
	spec := GetFillSpec(profile.CIDs.RegExp, &ClusterMeta{CID: profile.CIDs.RegExp}, profile)
	data := make([]byte, 0, 32)
	for i := 0; i < spec.NumRefs; i++ {
		data = append(data, encUnsigned(0)...)
	}
	data = append(data, encTagged64(1)...)
	data = append(data, encTagged64(2)...)
	data = append(data, encTagged64(0x1ff)...)
	data = append(data, 0x5a)
	s := dartfmt.NewStream(data)
	cm := &ClusterMeta{CID: profile.CIDs.RegExp, Count: 1, StartRef: 1}
	if _, _, _, _, _, _, _, _, _, _, _, err := readFillRefs(s, cm, &spec, profile.FillRefUnsigned, profile); err != nil {
		t.Fatal(err)
	}
	marker, err := s.ReadByte()
	if err != nil || marker != 0x5a {
		t.Fatalf("regexp marker=%#x err=%v, want 0x5a", marker, err)
	}
}

func TestFieldKindBitsWidthChangesAt310(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    ScalarOp
	}{
		{version: "2.18.0", want: OpUint16},
		{version: "3.9.2", want: OpUint16},
		{version: "3.10.7", want: OpTagged32},
		{version: "3.13.0", want: OpTagged32},
	} {
		t.Run(tc.version, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(tc.version)
			spec := GetFillSpec(profile.CIDs.Field, &ClusterMeta{CID: profile.CIDs.Field}, profile)
			if len(spec.Scalars) != 2 || spec.Scalars[0] != tc.want || spec.Scalars[1] != OpRefId {
				t.Fatalf("field scalar ops=%v, want [%v %v]", spec.Scalars, tc.want, OpRefId)
			}
		})
	}
}

func TestDeltaEncodedTypedDataExactShape(t *testing.T) {
	old := snapshot.ProfileForVersion("2.18.0")
	if old == nil || old.CIDs == nil || old.CIDs.NativePointerCid == 0 {
		t.Fatal("missing 2.18 NativePointer CID")
	}
	cid := old.CIDs.NativePointerCid
	if got := GetFillSpec(cid, &ClusterMeta{CID: cid}, old).Kind; got != FillUnknown {
		t.Fatalf("2.18 CID-1 fill kind=%d, want FillUnknown", got)
	}
	if _, err := skipAllocV(dartfmt.NewStream(encUnsigned(1)), &ClusterMeta{CID: cid}, false, old.CIDs, false, old, nil, 100); err == nil {
		t.Fatal("2.18 CID-1 cluster accepted before DeltaEncodedTypedData existed")
	}

	modern := snapshot.ProfileForVersion("2.19.0")
	if modern == nil || modern.CIDs == nil {
		t.Fatal("missing 2.19 profile")
	}
	cid = modern.CIDs.NativePointerCid
	if got := GetFillSpec(cid, &ClusterMeta{CID: cid}, modern).Kind; got != FillDeltaEncodedTypedData {
		t.Fatalf("2.19 delta fill kind=%d", got)
	}
	// Uint16, 3 elements => alloc length_in_bytes=6; fill encoded length=6
	// (3<<1|0), then three monotonic deltas.
	data := append(encUnsigned(6), encUnsigned(1)...)
	data = append(data, encUnsigned(2)...)
	data = append(data, encUnsigned(3)...)
	data = append(data, 0x5a)
	s := dartfmt.NewStream(data)
	cm := &ClusterMeta{CID: cid, Count: 1, Lengths: []int64{6}}
	if err := skipFillDeltaEncodedTypedData(s, cm, 100); err != nil {
		t.Fatal(err)
	}
	marker, err := s.ReadByte()
	if err != nil || marker != 0x5a {
		t.Fatalf("delta stream marker=%#x err=%v, want 0x5a", marker, err)
	}
}

func TestLocalVarDescriptorsExact313Shape(t *testing.T) {
	profile := snapshot.ProfileForVersion("3.13.0")
	if profile == nil || profile.CIDs == nil || profile.CIDs.LocalVarDescriptors == 0 {
		t.Fatal("missing 3.13 LocalVarDescriptors CID")
	}
	cid := profile.CIDs.LocalVarDescriptors
	if got := ClassifyAlloc(cid, profile.CIDs); got != AllocLocalVarDescriptors {
		t.Fatalf("LocalVarDescriptors alloc kind=%d", got)
	}
	if got := GetFillSpec(cid, &ClusterMeta{CID: cid}, profile).Kind; got != FillLocalVarDescriptors {
		t.Fatalf("LocalVarDescriptors fill kind=%d", got)
	}
	data := append(encUnsigned(1), encUnsigned(0)...) // length=1, name ref
	data = append(data, byte(7+192))
	for _, v := range []int64{10, 20, 30} {
		data = append(data, byte(v+192))
	}
	data = append(data, encTagged64(40)...)
	data = append(data, 0x5a)
	s := dartfmt.NewStream(data)
	cm := &ClusterMeta{CID: cid, Count: 1, Lengths: []int64{1}}
	if err := skipFillLocalVarDescriptors(s, cm, profile.FillRefUnsigned, 100); err != nil {
		t.Fatal(err)
	}
	marker, err := s.ReadByte()
	if err != nil || marker != 0x5a {
		t.Fatalf("LocalVarDescriptors stream marker=%#x err=%v, want 0x5a", marker, err)
	}
}

func TestClosureVarLenFillMustMatchAllocLength(t *testing.T) {
	profile := snapshot.ProfileForVersion("3.13.0")
	cm := &ClusterMeta{
		CID:      profile.CIDs.Closure,
		Count:    1,
		StartRef: 1,
		Lengths:  []int64{2},
	}
	spec := GetFillSpec(cm.CID, cm, profile)
	if !spec.VarLenRefs {
		t.Fatal("3.13 Closure spec is not variable-length")
	}
	// Fill claims one tail ref while alloc declared two. Reject before reading
	// the fixed/tail refs, otherwise all later objects shift by one ref.
	s := dartfmt.NewStream(encUnsigned(1))
	_, _, _, _, _, _, _, _, _, _, _, err := readFillRefs(s, cm, &spec, true, profile)
	if err == nil || !strings.Contains(err.Error(), "differs from alloc length") {
		t.Fatalf("Closure mismatched length error = %v", err)
	}
}

func TestClosureVarLenTailCountsTowardCaptureBudget(t *testing.T) {
	profile := snapshot.ProfileForVersion("3.13.0")
	result := &Result{
		AllocComplete: true,
		FillStart:     1,
		Clusters: []ClusterMeta{{
			CID:      profile.CIDs.Closure,
			Count:    1,
			StartRef: 1,
			StopRef:  2,
			Lengths:  []int64{1000},
		}},
	}
	err := ReadFill([]byte{0, 0x80}, result, profile, false, 0, dartfmt.Options{MaxBytes: 1024})
	if err == nil || !strings.Contains(err.Error(), "exceeds max_bytes") {
		t.Fatalf("Closure tail capture budget error = %v", err)
	}
}

func TestAllocLengthMaxStepsOnlyBoundsLoopFamilies(t *testing.T) {
	const maxSteps = 10

	// Array length becomes a per-element ReadRef loop in fill, so it obeys
	// MaxSteps even though the cluster object count itself is only one.
	arrayData := append(encUnsigned(1), encUnsigned(maxSteps+1)...)
	if _, err := skipCountedLengthAlloc(dartfmt.NewStream(arrayData), &ClusterMeta{}, maxSteps, "array", true); err == nil ||
		!strings.Contains(err.Error(), "exceeds max_steps") {
		t.Fatalf("array oversized loop length error = %v", err)
	}

	// TypedData length is consumed as a checked raw byte extent, not one parser
	// iteration per element. A large but representable payload must therefore not
	// be rejected merely because its length exceeds MaxSteps.
	typedData := append(encUnsigned(1), encUnsigned(maxSteps+1)...)
	cm := &ClusterMeta{}
	if count, err := skipCountedLengthAlloc(dartfmt.NewStream(typedData), cm, maxSteps, "typed_data", false); err != nil || count != 1 {
		t.Fatalf("typed_data raw length rejected: count=%d err=%v", count, err)
	}
	if len(cm.Lengths) != 1 || cm.Lengths[0] != maxSteps+1 {
		t.Fatalf("typed_data length capture = %v, want [%d]", cm.Lengths, maxSteps+1)
	}
}

func TestRuntimeOnlyPredefinedFamiliesFailClosed(t *testing.T) {
	for _, version := range []string{"2.10.0", "2.17.6", "3.9.2", "3.13.0"} {
		t.Run(version, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(version)
			if profile == nil || profile.CIDs == nil {
				t.Fatalf("missing profile %s", version)
			}
			families := map[string]int{
				"Capability":             profile.CIDs.Capability,
				"ReceivePort":            profile.CIDs.ReceivePort,
				"SendPort":               profile.CIDs.SendPort,
				"SuspendState":           profile.CIDs.SuspendState,
				"WeakReference":          profile.CIDs.WeakReference,
				"FutureOr":               profile.CIDs.FutureOr,
				"UserTag":                profile.CIDs.UserTag,
				"TransferableTypedData":  profile.CIDs.TransferableTypedData,
				"SingleTargetCache":      profile.CIDs.SingleTargetCache,
				"MonomorphicSmiableCall": profile.CIDs.MonomorphicSmiableCall,
				"CallSiteData":           profile.CIDs.CallSiteData,
			}
			for name, cid := range families {
				if cid == 0 {
					continue
				}
				if got := ClassifyAlloc(cid, profile.CIDs); got != AllocUnknown {
					t.Errorf("%s alloc kind=%d, want AllocUnknown", name, got)
				}
				if got := GetFillSpec(cid, &ClusterMeta{CID: cid}, profile).Kind; got != FillUnknown {
					t.Errorf("%s fill kind=%d, want FillUnknown", name, got)
				}
			}
		})
	}
}

func TestRecordShapeMustMatchAllocFieldCount(t *testing.T) {
	profile := snapshot.ProfileForVersion("3.13.0")
	if profile == nil || profile.CIDs == nil || profile.CIDs.Record == 0 {
		t.Fatal("missing Record CID")
	}
	cm := &ClusterMeta{CID: profile.CIDs.Record, Count: 1, Lengths: []int64{2}}
	// Low 16 bits of shape encode num_fields. Claiming three fields after alloc
	// reserved two must be rejected before consuming any field refs.
	s := dartfmt.NewStream(encUnsigned(3))
	if err := skipFillRecord(s, cm, profile.FillRefUnsigned, profile); err == nil || !strings.Contains(err.Error(), "differs from alloc length") {
		t.Fatalf("Record mismatched shape error=%v", err)
	}
}

func TestRecord219ConsumesFieldNamesRef(t *testing.T) {
	profile := snapshot.ProfileForVersion("2.19.0")
	if profile == nil || profile.CIDs == nil || profile.CIDs.Record == 0 {
		t.Fatal("missing Dart 2.19 Record profile")
	}
	// num_fields=2, then field_names ref and two field refs. ReadRefId encodes
	// small refs 0/1/2 as the single signed terminators 0x80/0x81/0x82.
	data := append(encUnsigned(2), 0x80, 0x81, 0x82, 0x5a)
	s := dartfmt.NewStream(data)
	cm := &ClusterMeta{CID: profile.CIDs.Record, Count: 1, Lengths: []int64{2}}
	if err := skipFillRecord(s, cm, profile.FillRefUnsigned, profile); err != nil {
		t.Fatal(err)
	}
	marker, err := s.ReadByte()
	if err != nil || marker != 0x5a {
		t.Fatalf("2.19 Record marker=%#x err=%v, want 0x5a", marker, err)
	}
}

func TestRecord30PackedShapeHasNoFieldNamesRef(t *testing.T) {
	profile := snapshot.ProfileForVersion("3.0.5")
	if profile == nil || profile.CIDs == nil || profile.CIDs.Record == 0 {
		t.Fatal("missing Dart 3.0 Record profile")
	}
	// shape low 16 bits says two fields; only those two refs follow.
	data := append(encUnsigned(2), 0x80, 0x81, 0x5a)
	s := dartfmt.NewStream(data)
	cm := &ClusterMeta{CID: profile.CIDs.Record, Count: 1, Lengths: []int64{2}}
	if err := skipFillRecord(s, cm, profile.FillRefUnsigned, profile); err != nil {
		t.Fatal(err)
	}
	marker, err := s.ReadByte()
	if err != nil || marker != 0x5a {
		t.Fatalf("3.0 Record marker=%#x err=%v, want 0x5a", marker, err)
	}
}

func TestMapSetSerializationBoundaries(t *testing.T) {
	for _, tc := range []struct {
		version      string
		mapKind      FillKind
		constMapKind FillKind
		setKind      FillKind
		constSetKind FillKind
	}{
		{version: "2.13.0", mapKind: FillLegacyMap, constMapKind: FillUnknown, setKind: FillUnknown, constSetKind: FillUnknown},
		{version: "2.14.0", mapKind: FillUnknown, constMapKind: FillUnknown, setKind: FillUnknown, constSetKind: FillUnknown},
		{version: "2.15.0", mapKind: FillUnknown, constMapKind: FillRefs, setKind: FillUnknown, constSetKind: FillRefs},
		{version: "2.19.0", mapKind: FillUnknown, constMapKind: FillRefs, setKind: FillUnknown, constSetKind: FillRefs},
		{version: "3.13.0", mapKind: FillUnknown, constMapKind: FillRefs, setKind: FillUnknown, constSetKind: FillRefs},
	} {
		t.Run(tc.version, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(tc.version)
			if profile == nil || profile.CIDs == nil {
				t.Fatalf("missing profile %s", tc.version)
			}
			ct := profile.CIDs
			checks := []struct {
				name string
				cid  int
				kind FillKind
			}{
				{"Map", ct.Map, tc.mapKind},
				{"ConstMap", ct.ConstMap, tc.constMapKind},
				{"Set", ct.Set, tc.setKind},
				{"ConstSet", ct.ConstSet, tc.constSetKind},
			}
			for _, check := range checks {
				if check.cid == 0 {
					continue
				}
				if got := GetFillSpec(check.cid, &ClusterMeta{CID: check.cid}, profile).Kind; got != check.kind {
					t.Errorf("%s fill kind=%d, want %d", check.name, got, check.kind)
				}
				wantAlloc := AllocSimple
				if check.kind == FillUnknown {
					wantAlloc = AllocUnknown
				}
				if got := ClassifyAlloc(check.cid, ct); got != wantAlloc {
					t.Errorf("%s alloc kind=%d, want %d", check.name, got, wantAlloc)
				}
			}
		})
	}
}

func TestFfiTrampolineScalarEncodingBoundaries(t *testing.T) {
	for _, tc := range []struct {
		version string
		ops     []ScalarOp
	}{
		{"2.17.6", []ScalarOp{OpUnsigned}},
		{"2.18.0", []ScalarOp{OpUnsigned}},
		{"2.19.0", []ScalarOp{OpTagged32}},
		{"3.0.5", []ScalarOp{OpTagged32}},
		{"3.1.0", []ScalarOp{OpTagged32, OpUint8}},
		{"3.13.0", []ScalarOp{OpTagged32, OpUint8}},
	} {
		t.Run(tc.version, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(tc.version)
			if profile == nil || profile.CIDs == nil || profile.CIDs.FfiTrampolineData == 0 {
				t.Fatalf("missing FfiTrampolineData profile for %s", tc.version)
			}
			spec := GetFillSpec(profile.CIDs.FfiTrampolineData, &ClusterMeta{CID: profile.CIDs.FfiTrampolineData}, profile)
			if len(spec.Scalars) != len(tc.ops) {
				t.Fatalf("scalar count=%d, want %d (%v)", len(spec.Scalars), len(tc.ops), spec.Scalars)
			}
			for i := range tc.ops {
				if spec.Scalars[i] != tc.ops[i] {
					t.Fatalf("scalar[%d]=%d, want %d", i, spec.Scalars[i], tc.ops[i])
				}
			}
		})
	}
}

func TestStackTraceAndRegExpRefCountBoundaries(t *testing.T) {
	for _, tc := range []struct {
		version    string
		regexpRefs int
	}{
		{"2.10.0", 11},
		{"2.12.0", 11},
		{"2.13.0", 10},
		{"3.3.0", 10},
		{"3.4.3", 6},
		{"3.13.0", 6},
	} {
		t.Run(tc.version, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(tc.version)
			if profile == nil || profile.CIDs == nil {
				t.Fatalf("missing profile %s", tc.version)
			}
			stack := GetFillSpec(profile.CIDs.StackTrace, &ClusterMeta{CID: profile.CIDs.StackTrace}, profile)
			if stack.Kind != FillRefs || stack.NumRefs != 3 {
				t.Fatalf("StackTrace spec kind=%d refs=%d, want FillRefs/3", stack.Kind, stack.NumRefs)
			}
			re := GetFillSpec(profile.CIDs.RegExp, &ClusterMeta{CID: profile.CIDs.RegExp}, profile)
			if re.Kind != FillRefs || re.NumRefs != tc.regexpRefs {
				t.Fatalf("RegExp spec kind=%d refs=%d, want FillRefs/%d", re.Kind, re.NumRefs, tc.regexpRefs)
			}
			wantFlags := OpInt8
			if snapshot.VersionAtLeast(tc.version, "3.12.2") {
				wantFlags = OpTagged32
			}
			if len(re.Scalars) != 3 || re.Scalars[0] != OpTagged32 || re.Scalars[1] != OpTagged32 || re.Scalars[2] != wantFlags {
				t.Fatalf("RegExp scalars=%v", re.Scalars)
			}
		})
	}
}

func TestWeakSerializationReferenceBoundary(t *testing.T) {
	for _, tc := range []struct {
		version   string
		allocKind AllocKind
		fillKind  FillKind
		scalars   []ScalarOp
	}{
		{"2.10.0", AllocEmpty, FillRefs, []ScalarOp{OpTagged32}},
		{"2.12.0", AllocEmpty, FillRefs, []ScalarOp{OpTagged32}},
		{"2.13.0", AllocEmpty, FillNone, nil},
		{"3.13.0", AllocEmpty, FillNone, nil},
	} {
		t.Run(tc.version, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(tc.version)
			if profile == nil || profile.CIDs == nil || profile.CIDs.WeakSerializationReference == 0 {
				t.Fatalf("missing WSR CID for %s", tc.version)
			}
			cid := profile.CIDs.WeakSerializationReference
			if got := ClassifyAlloc(cid, profile.CIDs); got != tc.allocKind {
				t.Fatalf("alloc kind=%d, want %d", got, tc.allocKind)
			}
			spec := GetFillSpec(cid, &ClusterMeta{CID: cid}, profile)
			if spec.Kind != tc.fillKind || len(spec.Scalars) != len(tc.scalars) {
				t.Fatalf("fill spec kind=%d scalars=%v, want kind=%d scalars=%v", spec.Kind, spec.Scalars, tc.fillKind, tc.scalars)
			}
			for i := range tc.scalars {
				if spec.Scalars[i] != tc.scalars[i] {
					t.Fatalf("scalar[%d]=%d, want %d", i, spec.Scalars[i], tc.scalars[i])
				}
			}

			// Pin the version-dependent alloc payload independently of ClassifyAlloc.
			stream := dartfmt.NewStream(encUnsigned(1))
			cm := &ClusterMeta{CID: cid}
			count, err := skipAllocV(stream, cm, false, profile.CIDs, false, profile, nil, 100)
			if !snapshot.VersionAtLeast(tc.version, "2.13.0") {
				if err != nil || count != 1 || stream.Position() == 0 {
					t.Fatalf("legacy WSR alloc count=%d pos=%d err=%v", count, stream.Position(), err)
				}
			} else if err != nil || count != 0 || stream.Position() != 0 {
				t.Fatalf("modern WSR alloc count=%d pos=%d err=%v", count, stream.Position(), err)
			}
		})
	}
}

func TestUnknownPredefinedCIDsFailClosed(t *testing.T) {
	profile := snapshot.ProfileForVersion("2.10.0")
	if profile == nil || profile.CIDs == nil {
		t.Fatal("missing 2.10.0 profile")
	}
	// 2.10 class_id.h: Code=16, then Bytecode=17, Instructions=18,
	// InstructionsSection=19, ObjectPool=20. Bytecode's WriteFill explicitly
	// asserts kind != FullAOT; Instructions/InstructionsSection likewise have no
	// ordinary Full-AOT cluster path. None may be guessed as count-only.
	for _, cid := range []int{17, 18, 19} {
		if got := ClassifyAlloc(cid, profile.CIDs); got != AllocUnknown {
			t.Errorf("CID %d alloc kind=%d, want AllocUnknown", cid, got)
		}
		if got := GetFillSpec(cid, &ClusterMeta{CID: cid}, profile).Kind; got != FillUnknown {
			t.Errorf("CID %d fill kind=%d, want FillUnknown", cid, got)
		}
	}
}

func TestNamespaceFullAOTRefBoundary(t *testing.T) {
	for _, tc := range []struct {
		version string
		refs    int
	}{
		{"2.10.0", 4},
		{"2.12.0", 4},
		{"2.13.0", 1},
		{"3.13.0", 1},
	} {
		t.Run(tc.version, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(tc.version)
			if profile == nil || profile.CIDs == nil {
				t.Fatalf("missing profile %s", tc.version)
			}
			spec := GetFillSpec(profile.CIDs.Namespace, &ClusterMeta{CID: profile.CIDs.Namespace}, profile)
			if spec.Kind != FillRefs || spec.NumRefs != tc.refs {
				t.Fatalf("Namespace spec kind=%d refs=%d, want FillRefs/%d", spec.Kind, spec.NumRefs, tc.refs)
			}
		})
	}
}

func TestApiErrors313AllocAndSentinelFailClosed(t *testing.T) {
	profile := snapshot.ProfileForVersion("3.13.0")
	if profile == nil || profile.CIDs == nil {
		t.Fatal("missing 3.13.0 profile")
	}
	for name, cid := range map[string]int{
		"ApiError":    profile.CIDs.ApiError,
		"UnwindError": profile.CIDs.UnwindError,
	} {
		if cid == 0 {
			t.Fatalf("%s CID is zero", name)
		}
		if got := ClassifyAlloc(cid, profile.CIDs); got != AllocSimple {
			t.Errorf("%s alloc kind=%d, want AllocSimple", name, got)
		}
		if got := GetFillSpec(cid, &ClusterMeta{CID: cid}, profile).Kind; got != FillRefs {
			t.Errorf("%s fill kind=%d, want FillRefs", name, got)
		}
	}
	if profile.CIDs.Sentinel != 0 {
		cid := profile.CIDs.Sentinel
		if got := ClassifyAlloc(cid, profile.CIDs); got != AllocUnknown {
			t.Errorf("Sentinel alloc kind=%d, want AllocUnknown", got)
		}
		if got := GetFillSpec(cid, &ClusterMeta{CID: cid}, profile).Kind; got != FillUnknown {
			t.Errorf("Sentinel fill kind=%d, want FillUnknown", got)
		}
	}
}
