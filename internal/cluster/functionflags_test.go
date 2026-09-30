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

func TestFunctionModifierDecodesExactSDKValues(t *testing.T) {
	tests := []struct {
		raw  uint32
		want FunctionModifier
	}{
		{0 << 14, FunctionModifierNone},
		{1 << 14, FunctionModifierAsync},
		{2 << 14, FunctionModifierSyncStar},
		{3 << 14, FunctionModifierAsyncStar},
	}
	for _, tt := range tests {
		if got := decodeFunctionModifier(tt.raw); got != tt.want {
			t.Errorf("decodeFunctionModifier(%#x) = %v, want %v", tt.raw, got, tt.want)
		}
	}

	// Neighbouring kind/flag bits must not contaminate the modifier field.
	raw := uint32(3<<14) | 0x1f | (1 << 24)
	if got := decodeFunctionModifier(raw); got != FunctionModifierAsyncStar {
		t.Fatalf("modifier with neighbouring bits = %v, want async*", got)
	}
}
