package cluster

import (
	"testing"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

func TestReadFunctionScalarCapturesVersionedKindTagFlags(t *testing.T) {
	for _, tc := range []struct {
		version    string
		scalarIdx  int
		numScalars int
	}{
		{version: "2.10.0", scalarIdx: 2, numScalars: 3},
		{version: "2.12.0", scalarIdx: 2, numScalars: 3},
		{version: "2.13.0", scalarIdx: 2, numScalars: 3},
		{version: "3.13.0", scalarIdx: 1, numScalars: 2},
	} {
		t.Run(tc.version, func(t *testing.T) {
			profile := &snapshot.VersionProfile{DartVersion: tc.version}
			flags, ok := functionKindTagFlagLayoutFor(profile)
			if !ok {
				t.Fatal("missing kind_tag flag layout")
			}
			raw := uint32(1)<<flags.staticBit | uint32(1)<<flags.nativeBit | uint32(1)<<flags.externalBit
			s := dartfmt.NewStream(encTagged64(int64(raw)))
			var state scalarState
			if err := readFunctionScalar(s, tc.scalarIdx, tc.numScalars, &state, 0, 1, profile, OpTagged32, FuncPackedFieldsLayout{}); err != nil {
				t.Fatalf("readFunctionScalar: %v", err)
			}
			if !state.hasKindTag || !state.isStatic || !state.isNative || !state.isExternal {
				t.Fatalf("captured flags = kind:%v static:%v native:%v external:%v", state.hasKindTag, state.isStatic, state.isNative, state.isExternal)
			}
		})
	}
}
