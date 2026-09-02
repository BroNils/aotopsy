package cluster

import (
	"math/bits"
	"sort"
	"testing"

	"aotopsy/internal/cmacro"
	"aotopsy/internal/sdktest"
	"aotopsy/internal/snapshot"
)

// TestFunctionKindLayoutsMatchSDK re-derives every row of funcKindLayouts
// from dart-lang/sdk's FOR_EACH_RAW_FUNCTION_KIND and fails on any drift.
//
// This table cannot be validated locally, and both ways of getting it wrong
// are silent:
//
//   - too wide a mask folds the low bit of RecognizedBits into the kind, so
//     a constructor with that bit set reads as some other kind and is missed;
//   - too narrow a mask aliases the highest kind onto RegularFunction;
//   - a wrong ordinal labels a DIFFERENT kind as constructor. On 2.10 that is
//     SetterFunction, so every setter would be emitted as `new X`.
//
// The third is what the previous table actually did, because it picked the
// mask off VersionProfile.FillRefUnsigned -- which describes the Function
// fill's scalar layout, a different axis entirely. The corpus has no 2.10 or
// 2.18 sample, so nothing local could have caught it. This gate did, before
// it was even finished.
//
// Network- and gh-dependent, so it is opt-in:
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/cluster/ -run FunctionKindLayoutsMatchSDK
func TestFunctionKindLayoutsMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	// Every version the table claims, not a sample of them: a row nobody
	// checked is exactly how 2.10 and 2.18 went wrong.
	versions := make([]string, 0, len(funcKindLayouts))
	for v := range funcKindLayouts {
		versions = append(versions, v)
	}
	sort.Strings(versions)

	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			kinds, err := sdkFunctionKinds(v)
			if err != nil {
				t.Fatalf("could not read FOR_EACH_RAW_FUNCTION_KIND at %s: %v", v, err)
			}
			if len(kinds) == 0 {
				t.Fatalf("no kinds parsed at %s", v)
			}
			layout := funcKindLayouts[v]

			// KindBits width is BitLength(last ordinal).
			wantMask := uint32(1)<<bits.Len(uint(len(kinds)-1)) - 1
			if layout.mask != wantMask {
				t.Errorf("mask = 0x%02X, SDK has %d kinds (last %q) so it must be 0x%02X",
					layout.mask, len(kinds), kinds[len(kinds)-1], wantMask)
			}

			// Every ordinal the table claims must name the kind the SDK has
			// at that index.
			for i, want := range layout.order {
				if i >= len(kinds) {
					t.Errorf("table claims ordinal %d but the SDK only has %d kinds", i, len(kinds))
					break
				}
				if got := sdkKindName(want); got != kinds[i] {
					t.Errorf("ordinal %d: table says %s (%q), SDK says %q\nfull SDK list: %v",
						i, want, got, kinds[i], kinds)
					break
				}
			}
		})
	}
}

// TestFunctionKindRefusesUnknownVersions guards the deliberate nil. Borrowing
// a neighbouring version's numbering is what made 2.10 label setters as
// constructors.
func TestFunctionKindRefusesUnknownVersions(t *testing.T) {
	for _, v := range []string{"", "2.11.0", "3.14.0", "4.0.0", "nonsense"} {
		if got := decodeFunctionKind(5, &snapshot.VersionProfile{DartVersion: v}); got != FunctionKindUnknown {
			t.Errorf("decodeFunctionKind at %q = %v, want FunctionKindUnknown", v, got)
		}
	}
	if got := decodeFunctionKind(5, nil); got != FunctionKindUnknown {
		t.Errorf("nil profile = %v, want FunctionKindUnknown", got)
	}
}

// The ordinal of Constructor is NOT stable across versions, which is the
// whole reason the kind is normalised at parse time.
func TestConstructorOrdinalMovedIn212(t *testing.T) {
	// 2.10 numbers it 6 (SignatureFunction occupies index 3).
	if got := decodeFunctionKind(6, &snapshot.VersionProfile{DartVersion: "2.10.0"}); got != FunctionKindConstructor {
		t.Errorf("2.10.0 ordinal 6 = %v, want FunctionKindConstructor", got)
	}
	if got := decodeFunctionKind(5, &snapshot.VersionProfile{DartVersion: "2.10.0"}); got != FunctionKindSetter {
		t.Errorf("2.10.0 ordinal 5 = %v, want FunctionKindSetter -- labelling it a constructor "+
			"is the bug this table exists to prevent", got)
	}
	// 2.12 onward numbers it 5.
	for _, v := range []string{"2.12.0", "2.18.0", "2.19.0", "3.9.2", "3.12.2"} {
		if got := decodeFunctionKind(5, &snapshot.VersionProfile{DartVersion: v}); got != FunctionKindConstructor {
			t.Errorf("%s ordinal 5 = %v, want FunctionKindConstructor", v, got)
		}
	}
}

// A 4-bit field must not have a 5th bit read out of it. 2.18 has 16 kinds, so
// ordinal 5 with bit 4 set (21) is a constructor whose RecognizedBits leaked
// in -- masking correctly at 4 bits recovers it.
func TestFunctionKindMaskWidthIsPerVersion(t *testing.T) {
	if got := decodeFunctionKind(0x15, &snapshot.VersionProfile{DartVersion: "2.18.0"}); got != FunctionKindConstructor {
		t.Errorf("2.18.0 raw 0x15 = %v, want FunctionKindConstructor (4-bit field)", got)
	}
	// 2.19 really is 5 bits, so the same raw value is NOT a constructor.
	if got := decodeFunctionKind(0x15, &snapshot.VersionProfile{DartVersion: "2.19.0"}); got == FunctionKindConstructor {
		t.Error("2.19.0 raw 0x15 must not read as a constructor; the field is 5 bits there")
	}
}

// sdkKindName maps a canonical kind back to its FOR_EACH_RAW_FUNCTION_KIND
// spelling, for comparison against the SDK list.
func sdkKindName(k FunctionKind) string {
	switch k {
	case FunctionKindRegular:
		return "RegularFunction"
	case FunctionKindClosure:
		return "ClosureFunction"
	case FunctionKindImplicitClosure:
		return "ImplicitClosureFunction"
	case FunctionKindSignature:
		return "SignatureFunction"
	case FunctionKindGetter:
		return "GetterFunction"
	case FunctionKindSetter:
		return "SetterFunction"
	case FunctionKindConstructor:
		return "Constructor"
	case FunctionKindImplicitGetter:
		return "ImplicitGetter"
	case FunctionKindImplicitSetter:
		return "ImplicitSetter"
	}
	return "<unmapped>"
}

// sdkFunctionKinds returns FOR_EACH_RAW_FUNCTION_KIND's entries in order.
//
// The line-oriented scan this used to do stopped at the first line that
// was not a V(...) entry, so a list with a blank line or a wrapped
// comment inside it was silently truncated -- and a short list reads as
// "narrower mask", which is one of the two silent failure modes this
// gate exists to catch. It goes through the shared macro expander now.
func sdkFunctionKinds(tag string) ([]string, error) {
	src, err := sdktest.GHFileAtTag("runtime/vm/raw_object.h", tag)
	if err != nil {
		return nil, err
	}
	return cmacro.Expand(cmacro.ParseMacros(src), "FOR_EACH_RAW_FUNCTION_KIND")
}
