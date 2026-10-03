package cluster

import (
	"testing"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

// Type cluster capture across the three UntaggedType layouts.
//
// TypeDeserializationCluster::ReadFill has had three shapes, and getting the
// version boundary wrong does not desynchronise the stream -- the scalars are
// the right size either way -- so nothing crashes. It just produces class ids
// that are silently wrong, or none at all:
//
//	2.10-2.15  type_class_id is a REF inside ReadFromTo (captured from
//	           allRefs in readFillRefs, not here)
//	2.16-2.18  type_class_id_ = d.ReadUnsigned(); combined = d.Read<uint8_t>()
//	2.19.0+    set_flags(d.ReadUnsigned()), type_class_id packed inside
//
// and within the packed era the shift moved:
//
//	2.19.0-3.4.3  NullabilityBits is 2 bits -> TypeState 2..3 -> shift 4
//	3.5.0+        NullabilityBit  is 1 bit  -> TypeState 1..2 -> shift 3
//
// Verified in raw_object.h / app_snapshot.cc at 2.14.0, 2.16.0, 2.17.6,
// 2.18.0, 2.19.0, 3.0.5, 3.1.0, 3.2.5, 3.3.0, 3.4.3, 3.5.0, 3.6.2, 3.7.0,
// 3.9.2 and 3.13.0.

func TestTypeClassIDShiftBoundary(t *testing.T) {
	// The boundary is 3.5.0, and it is worth naming the versions either side
	// rather than testing only the two adjacent ones: every version in the
	// lower group decoded its class ids one bit off.
	cases := []struct {
		version string
		want    uint
	}{
		{"2.19.0", 4},
		{"3.0.5", 4},
		{"3.1.0", 4},
		{"3.2.5", 4},
		{"3.3.0", 4},
		{"3.4.3", 4},
		{"3.5.0", 3},
		{"3.6.2", 3},
		{"3.7.0", 3},
		{"3.9.2", 3},
		{"3.12.2", 3},
		{"3.13.0", 3},
	}
	for _, c := range cases {
		if got := typeClassIDShift(c.version); got != c.want {
			t.Errorf("typeClassIDShift(%s) = %d, want %d", c.version, got, c.want)
		}
	}
}

// TestTypeClassIDDecode checks the two packed-era shifts decode a known class
// id out of a flags word built the way the SDK builds it.
func TestTypeClassIDDecode(t *testing.T) {
	const classID = 1234

	// pack builds a flags word: nullability in the low bits, then TypeState
	// (2 bits), then the 20-bit class id.
	pack := func(shift uint, nullability, typeState uint32) uint64 {
		return uint64(nullability) |
			uint64(typeState)<<(shift-2) |
			uint64(classID)<<shift
	}

	for _, c := range []struct {
		name  string
		shift uint
		null  uint32
	}{
		{"2.19.0-3.4.3 (nullability 2 bits)", 4, 0b11},
		{"3.5.0+ (nullability 1 bit)", 3, 0b1},
	} {
		flags := pack(c.shift, c.null, 0b10)
		got := int32((flags >> c.shift) & 0xFFFFF)
		if got != classID {
			t.Errorf("%s: decoded %d, want %d", c.name, got, classID)
		}
		// Decoding with the OTHER era's shift must NOT accidentally agree --
		// otherwise this whole boundary would be untestable, and the bug it
		// describes would have been invisible.
		other := uint(3)
		if c.shift == 3 {
			other = 4
		}
		if wrong := int32((flags >> other) & 0xFFFFF); wrong == classID {
			t.Errorf("%s: shift %d also yields %d, so the shifts are indistinguishable",
				c.name, other, classID)
		}
	}
}

func TestDecodeTypeNullabilityAcrossPackedLayouts(t *testing.T) {
	cases := []struct {
		name  string
		shift uint
		raw   uint64
		want  TypeNullability
	}{
		{"pre-3.5 nullable", 4, 0, TypeNullabilityNullable},
		{"pre-3.5 non-nullable", 4, 1, TypeNullabilityNonNullable},
		{"pre-3.5 legacy", 4, 2, TypeNullabilityLegacy},
		{"pre-3.5 invalid", 4, 3, TypeNullabilityUnknown},
		{"3.5+ nullable", 3, 0, TypeNullabilityNullable},
		{"3.5+ non-nullable", 3, 1, TypeNullabilityNonNullable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := decodeTypeNullability(c.raw, c.shift); got != c.want {
				t.Fatalf("decodeTypeNullability(raw=%d, shift=%d) = %v, want %v", c.raw, c.shift, got, c.want)
			}
		})
	}
}

func TestReadTypeParameterScalarVersionedLayouts(t *testing.T) {
	t.Run("2.10 token position and implicit base zero", func(t *testing.T) {
		profile := &snapshot.VersionProfile{
			DartVersion:         "2.10.0",
			CIDs:                &snapshot.CIDTable{Function: 6},
			HasTypeParamClassId: true,
			TypeHasTokenPos:     true,
		}
		// class-id 6, token_pos 0, index 2, nullable combined byte 0.
		s := dartfmt.NewStream([]byte{198, 192, 194, 0})
		var state scalarState
		ops := []ScalarOp{OpTagged32, OpTagged32, OpInt16, OpUint8}
		for i, op := range ops {
			if err := readTypeParameterScalar(s, i, &state, profile, op); err != nil {
				t.Fatalf("scalar %d: %v", i, err)
			}
		}
		if !state.typeParamCaptured || !state.typeParamIsFunction || state.typeParamBase != 0 || state.typeParamIndex != 2 {
			t.Fatalf("2.10 metadata = %+v", state)
		}
		if state.typeParamNullability != TypeNullabilityNullable {
			t.Fatalf("2.10 nullability = %v, want nullable", state.typeParamNullability)
		}
	})

	t.Run("2.13 wide base/index with class id", func(t *testing.T) {
		profile := &snapshot.VersionProfile{
			DartVersion:          "2.13.0",
			CIDs:                 &snapshot.CIDTable{Function: 6},
			HasTypeParamClassId:  true,
			TypeParamByteScalars: true,
			TypeParamWideScalars: true,
		}
		// Small signed VLEs encode as endByteMarker(192)+value. The final
		// flags byte is raw: class-id 6, base 2, index 3, non-nullable flags 1.
		s := dartfmt.NewStream([]byte{198, 194, 195, 1})
		var state scalarState
		ops := []ScalarOp{OpTagged32, OpUint16, OpUint16, OpUint8}
		for i, op := range ops {
			if err := readTypeParameterScalar(s, i, &state, profile, op); err != nil {
				t.Fatalf("scalar %d: %v", i, err)
			}
		}
		if !state.typeParamCaptured || !state.typeParamIsFunction || state.typeParamBase != 2 || state.typeParamIndex != 3 {
			t.Fatalf("2.13 metadata = %+v", state)
		}
		if state.typeParamNullability != TypeNullabilityNonNullable {
			t.Fatalf("2.13 nullability = %v, want non-nullable", state.typeParamNullability)
		}
	})

	t.Run("3.1 kind moved into flags", func(t *testing.T) {
		profile := &snapshot.VersionProfile{
			DartVersion: "3.1.0",
			CIDs:        &snapshot.CIDTable{Function: 6},
		}
		// base=0, index=1 as uint16 VLEs; bit 4 marks a function type
		// parameter and low bits 0 encode nullable.
		s := dartfmt.NewStream([]byte{192, 193, 0x10})
		var state scalarState
		ops := []ScalarOp{OpUint16, OpUint16, OpUint8}
		for i, op := range ops {
			if err := readTypeParameterScalar(s, i, &state, profile, op); err != nil {
				t.Fatalf("scalar %d: %v", i, err)
			}
		}
		if !state.typeParamCaptured || !state.typeParamIsFunction || state.typeParamBase != 0 || state.typeParamIndex != 1 {
			t.Fatalf("3.1 metadata = %+v", state)
		}
		if state.typeParamNullability != TypeNullabilityNullable {
			t.Fatalf("3.1 nullability = %v, want nullable", state.typeParamNullability)
		}
	})

	t.Run("3.5 one-bit nullability moves function bit", func(t *testing.T) {
		profile := &snapshot.VersionProfile{
			DartVersion: "3.5.0",
			CIDs:        &snapshot.CIDTable{Function: 6},
		}
		// TypeStateBits::kNextBit is 3 from Dart 3.5 onward. Bit 3 marks
		// a function type parameter; low bit 1 is non-nullable.
		s := dartfmt.NewStream([]byte{192, 193, 0x09})
		var state scalarState
		ops := []ScalarOp{OpUint16, OpUint16, OpUint8}
		for i, op := range ops {
			if err := readTypeParameterScalar(s, i, &state, profile, op); err != nil {
				t.Fatalf("scalar %d: %v", i, err)
			}
		}
		if !state.typeParamCaptured || !state.typeParamIsFunction || state.typeParamIndex != 1 {
			t.Fatalf("3.5 metadata = %+v", state)
		}
		if state.typeParamNullability != TypeNullabilityNonNullable {
			t.Fatalf("3.5 nullability = %v, want non-nullable", state.typeParamNullability)
		}
	})
}

func TestTypeParameterSerializedNameBoundary(t *testing.T) {
	legacy := snapshot.ProfileForVersion("2.13.0")
	if legacy == nil || legacy.CIDs == nil {
		t.Fatal("missing Dart 2.13.0 profile")
	}
	legacySpec := GetFillSpec(legacy.CIDs.TypeParameter, &ClusterMeta{CID: legacy.CIDs.TypeParameter}, legacy)
	if legacySpec.NumRefs != 5 || legacySpec.NameIdx != 1 {
		t.Fatalf("2.13 TypeParameter spec = refs=%d nameIdx=%d, want 5/1", legacySpec.NumRefs, legacySpec.NameIdx)
	}

	modern := snapshot.ProfileForVersion("2.14.0")
	if modern == nil || modern.CIDs == nil {
		t.Fatal("missing Dart 2.14.0 profile")
	}
	modernSpec := GetFillSpec(modern.CIDs.TypeParameter, &ClusterMeta{CID: modern.CIDs.TypeParameter}, modern)
	if modernSpec.NumRefs != 3 || modernSpec.NameIdx != -1 {
		t.Fatalf("2.14 TypeParameter spec = refs=%d nameIdx=%d, want 3/-1", modernSpec.NumRefs, modernSpec.NameIdx)
	}
}

// TestSpecTypeCapturesEveryEra pins which layouts produce a capturable
// TypeInfo. Result.Types being empty is not a loud failure -- it makes every
// declared field type unresolvable and leaves the analyser quietly weaker --
// so the era flags are worth asserting directly.
func TestSpecTypeCapturesEveryEra(t *testing.T) {
	cases := []struct {
		name             string
		profile          snapshot.VersionProfile
		wantIsType       bool
		wantScalar0IsCID bool
	}{
		{
			// 2.10-2.15: type_class_id is a ref, captured from allRefs.
			name:       "type_class_id as ref",
			profile:    snapshot.VersionProfile{DartVersion: "2.12.0", TypeClassIdIsRef: true, OldTypeScalars: true},
			wantIsType: false,
		},
		{
			// 2.16-2.18: separate ReadUnsigned scalar. This era captured
			// nothing at all before -- 0 Types on a 2.17.6 build whose 3.9.2
			// sibling yielded 2506.
			name:             "type_class_id as scalar 0",
			profile:          snapshot.VersionProfile{DartVersion: "2.17.6", OldTypeScalars: true},
			wantIsType:       true,
			wantScalar0IsCID: true,
		},
		{
			name:       "packed flags, pre-3.5.0 shift",
			profile:    snapshot.VersionProfile{DartVersion: "3.1.0"},
			wantIsType: true,
		},
		{
			name:       "packed flags, 3.5.0+ shift",
			profile:    snapshot.VersionProfile{DartVersion: "3.9.2"},
			wantIsType: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := c.profile
			spec := specType(p.FillRefUnsigned, p.OldTypeScalars, p.TypeClassIdIsRef,
				p.TypeHasTokenPos, p.TypeNumRefs, typeClassIDShift(p.DartVersion))
			if spec.IsType != c.wantIsType {
				t.Errorf("IsType = %v, want %v", spec.IsType, c.wantIsType)
			}
			if spec.TypeClassIDIsScalar0 != c.wantScalar0IsCID {
				t.Errorf("TypeClassIDIsScalar0 = %v, want %v",
					spec.TypeClassIDIsScalar0, c.wantScalar0IsCID)
			}
		})
	}
}
