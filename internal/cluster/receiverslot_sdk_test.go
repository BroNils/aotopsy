package cluster

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
)

// TestKindTagModifierPositionMatchesSDK re-derives kindTagModifierMask from
// object.h's KindTagBits enum at every version AOTopsy supports below 3.4.3 --
// the range where the modifier decides whether a receiver has a static frame
// slot at all (Function::MakesCopyOfParameters).
//
// Nothing local can catch drift here. A wrong ModifierBits position reads some
// other field as the async modifier, which makes ReceiverFrameSlot decline for
// functions that do have a slot and accept for ones that do not -- in both
// directions a silently missing or fabricated receiver type, never an error.
//
// The position has been constant (kKindTagSize=5, kRecognizedTagSize=9,
// kModifierPos=14, kModifierSize=2) at every version read so far, which is
// exactly why a gate is worth more than a comment: a constant nobody rechecks
// is a constant that drifts unnoticed.
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/cluster/ -run KindTagModifier
func TestKindTagModifierPositionMatchesSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	// Every version in scope below 3.4.3, plus 3.4.3 itself as the boundary.
	versions := []string{
		"2.10.0", "2.12.0", "2.13.0", "2.14.0", "2.15.0", "2.16.0",
		"2.17.6", "2.18.0", "2.19.0", "3.0.5", "3.1.0", "3.2.5", "3.3.0",
		"3.4.3",
	}
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

	for _, v := range versions {
		src, err := sdktest.GHFileAtTag("runtime/vm/object.h", v)
		if err != nil {
			t.Fatalf("%s: fetch object.h: %v", v, err)
		}
		kindSize, ok1 := field(src, "kKindTagSize")
		recSize, ok2 := field(src, "kRecognizedTagSize")
		modSize, ok3 := field(src, "kModifierSize")
		if !ok1 || !ok2 || !ok3 {
			t.Fatalf("%s: KindTagBits sizes not found (kind=%v recognized=%v modifier=%v) -- "+
				"the enum became computed rather than hardcoded, so this gate needs rewriting "+
				"rather than deleting", v, ok1, ok2, ok3)
		}
		wantPos := uint(kindSize + recSize)
		wantMask := uint32((1<<uint(modSize) - 1)) << wantPos
		if wantMask != kindTagModifierMask {
			t.Errorf("%s: SDK ModifierBits at pos %d width %d -> mask %#x, kindTagModifierMask = %#x",
				v, wantPos, modSize, wantMask, kindTagModifierMask)
		}
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
