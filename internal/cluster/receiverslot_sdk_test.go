package cluster

import (
	"math/bits"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"aotopsy/internal/cmacro"
	"aotopsy/internal/sdktest"
)

// TestKindTagModifierPositionMatchesSDK re-derives kindTagModifierMask from
// the SDK at EVERY supported version.
//
// The modifier decides two things. Below 3.4.3 it decides whether a receiver
// has a static frame slot at all (Function::MakesCopyOfParameters); at every
// version it is how a Function is recognised as async, sync* or async*
// (FunctionModifier). Nothing local can catch drift: a wrong ModifierBits
// position reads some other field as the modifier, which mislabels a function
// as async or makes ReceiverFrameSlot decline or accept wrongly -- a plausible
// wrong answer, never an error.
//
// The layout is two different things in the SDK, and both are handled:
//   - through 3.5.0, object.h hardcodes kKindTagSize=5, kRecognizedTagSize=9,
//     kModifierPos/kModifierSize=2;
//   - from 3.6.0 it is computed: KindBits at 0 of width BitLength(last Kind),
//     RecognizedBits after it of width BitLength(kNumRecognizedMethods - 1), and
//     ModifierBits after that of width BitLength(kAsyncGen). The widths are
//     re-derived from FOR_EACH_RAW_FUNCTION_KIND and RECOGNIZED_LIST, so a
//     method added to the recognized list past 512 (which would shift the
//     modifier to bit 15) fails here instead of silently mislabelling async.
//
// The AsyncModifier ordinals (kNoModifier=0, kAsync, kSyncGen, kAsyncGen) that
// decodeFunctionModifier relies on are checked at every version too, and so is
// the fact that the single-bit flags start right after the modifier (bit 16),
// which functionKindTagFlagLayoutFor assumes.
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/cluster/ -run KindTagModifier
func TestKindTagModifierPositionMatchesSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	num := regexp.MustCompile(`=\s*(\d+)`)
	field := func(src, name string) (int, bool) {
		for _, line := range strings.Split(src, "\n") {
			if !strings.Contains(line, name) {
				continue
			}
			if m := num.FindStringSubmatch(line); m != nil {
				v, err := strconv.Atoi(m[1])
				return v, err == nil
			}
		}
		return 0, false
	}
	// Chain of BitField declarations that the computed layout is built from.
	chain := []*regexp.Regexp{
		regexp.MustCompile(`(?s)using KindBits = BitField<[^;]*?,\s*0,\s*UntaggedFunction::kKindBitSize>;`),
		regexp.MustCompile(`(?s)using RecognizedBits = BitField<[^;]*?KindBits::kNextBit,\s*MethodRecognizer::kKindBitSize>;`),
		regexp.MustCompile(`(?s)using ModifierBits = BitField<[^;]*?RecognizedBits::kNextBit,\s*UntaggedFunction::kAsyncModifierBitSize>;`),
	}
	// The enum is spelled with bit flags; kNoModifier=0, kAsync=1, kSyncGen=2 and
	// kAsyncGen=1|2=3 are the values decodeFunctionModifier assumes.
	asyncEnum := regexp.MustCompile(`enum AsyncModifier\s*\{\s*kNoModifier\s*=\s*0x0,\s*kAsyncBit\s*=\s*0x1,\s*kGeneratorBit\s*=\s*0x2,\s*` +
		`kAsync\s*=\s*kAsyncBit,\s*kSyncGen\s*=\s*kGeneratorBit,\s*kAsyncGen\s*=\s*kAsyncBit\s*\|\s*kGeneratorBit,`)
	asyncBitSize := regexp.MustCompile(`kAsyncModifierBitSize\s*=\s*Utils::BitLength\(kAsyncGen\)`)

	for _, v := range fillLayoutTags {
		t.Run(v, func(t *testing.T) {
			obj, err := sdktest.SDKFileAtTag("runtime/vm/object.h", v)
			if err != nil {
				t.Fatalf("fetch object.h: %v", err)
			}
			raw, err := sdktest.SDKFileAtTag("runtime/vm/raw_object.h", v)
			if err != nil {
				t.Fatalf("fetch raw_object.h: %v", err)
			}
			if !asyncEnum.MatchString(raw) {
				t.Fatalf("AsyncModifier is no longer kNoModifier=0, kAsync, kSyncGen, kAsyncGen: decodeFunctionModifier is wrong")
			}

			// Widths derived from the two lists (valid wherever they exist).
			kinds, err := sdkFunctionKinds(v)
			if err != nil {
				t.Fatalf("FOR_EACH_RAW_FUNCTION_KIND: %v", err)
			}
			list, err := sdktest.SDKFileAtTag("runtime/vm/compiler/recognized_methods_list.h", v)
			if err != nil {
				t.Fatalf("fetch recognized_methods_list.h: %v", err)
			}
			macros, err := cmacro.ParseMacros(list)
			if err != nil {
				t.Fatalf("parse recognized_methods_list.h: %v", err)
			}
			rows, err := cmacro.ExpandRaw(macros, "RECOGNIZED_LIST")
			if err != nil {
				t.Fatalf("expand RECOGNIZED_LIST: %v", err)
			}
			derivedKind := bits.Len(uint(len(kinds) - 1)) // BitLength(last Kind ordinal)
			derivedRec := bits.Len(uint(len(rows)))       // BitLength(kNumRecognizedMethods - 1), kUnknown + rows
			derivedMod := bits.Len(3)                     // BitLength(kAsyncGen)

			kindSize, ok1 := field(obj, "kKindTagSize")
			recSize, ok2 := field(obj, "kRecognizedTagSize")
			modSize, ok3 := field(obj, "kModifierSize")
			switch {
			case ok1 && ok2 && ok3:
				// Hardcoded layout: it must agree with what the lists imply.
				if recSize != derivedRec || modSize != derivedMod {
					t.Errorf("hardcoded kRecognizedTagSize=%d kModifierSize=%d, lists imply %d and %d",
						recSize, modSize, derivedRec, derivedMod)
				}
			case !ok1 && !ok2 && !ok3:
				for _, re := range chain {
					if !re.MatchString(obj) {
						t.Fatalf("computed KindTagBits chain changed (%s missing): this gate needs rewriting", re)
					}
				}
				if !asyncBitSize.MatchString(raw) {
					t.Fatalf("kAsyncModifierBitSize is no longer BitLength(kAsyncGen)")
				}
				kindSize, recSize, modSize = derivedKind, derivedRec, derivedMod
			default:
				t.Fatalf("KindTagBits partly hardcoded (kind=%v recognized=%v modifier=%v): unexpected layout", ok1, ok2, ok3)
			}

			wantPos := uint(kindSize + recSize)
			wantMask := uint32((1<<uint(modSize) - 1)) << wantPos
			if wantMask != kindTagModifierMask {
				t.Errorf("SDK ModifierBits at pos %d width %d -> mask %#x, kindTagModifierMask = %#x",
					wantPos, modSize, wantMask, kindTagModifierMask)
			}
			if first := wantPos + uint(modSize); first != 16 {
				t.Errorf("single-bit flags start at bit %d, functionKindTagFlagLayoutFor assumes 16", first)
			}
		})
	}
}

// TestReceiverFrameSlotDeclinesWithoutStaticSlot pins the two cases where
// there is nothing to return, because both used to return a number.
func TestReceiverFrameSlotDeclinesWithoutStaticSlot(t *testing.T) {
	// No optional parameters: a static slot exists, one past the last
	// parameter. Confirmed on a real 2.12.0 arm64 binary -- a two-parameter
	// operator+ loads its receiver with `ldr x3, [x29, #24]`.
	if got, ok := ReceiverFrameSlot(2, 0, false, 8); !ok || got != 24 {
		t.Errorf("fixed arity: got (%d, %v), want (24, true)", got, ok)
	}
	// Optional parameters: addressed off ArgumentsDescriptor.count at
	// runtime, so no static slot exists.
	if got, ok := ReceiverFrameSlot(2, 1, false, 8); ok {
		t.Errorf("optional params: got (%d, true), want no slot", got)
	}
	// Suspendable: same, via the other half of MakesCopyOfParameters.
	if got, ok := ReceiverFrameSlot(2, 0, true, 8); ok {
		t.Errorf("suspendable: got (%d, true), want no slot", got)
	}
	// Arity unknown -- the common case on 2.14..3.3.0, where the signature
	// is behind a WeakSerializationReference the AOT serializer drops.
	if got, ok := ReceiverFrameSlot(0, 0, false, 8); ok {
		t.Errorf("unknown arity: got (%d, true), want no slot", got)
	}
}
