package cluster

import (
	"testing"

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
