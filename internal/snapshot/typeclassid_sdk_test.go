package snapshot

import (
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
)

// TestTypeClassIdIsRefMatchesSDK re-derives, per version, whether
// UntaggedType.type_class_id is a pointer inside the visited range or a scalar
// written after it, and diffs that against VersionProfile.TypeClassIdIsRef.
//
// The two shapes are:
//
//	<= 2.14   COMPRESSED_POINTER_FIELD(SmiPtr, type_class_id)   -- a ref
//	>= 2.15   ClassIdTagType type_class_id_;                    -- a scalar
//
// This boundary was off by one version and nothing local could catch it. A
// wrong answer does not error: the ref-era path captures whichever ref happens
// to sit at the guessed index, that ref is not a Smi, MintValues has no entry
// for it, and every Type silently ends up with class id 0. Measured before the
// fix: 0 of 2228 Types resolved on 2.15.0, against 2254 of 2255 on 2.14.0, and
// the field-type map was empty on 2.13.0, 2.14.0 and 2.15.0 alike.
//
// That is the same failure shape as the four boundary bugs AGENTS-local's
// cross-version table records, which is why this gets a gate rather than a
// comment.
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/snapshot/ -run TypeClassIdIsRef
func TestTypeClassIdIsRefMatchesSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	for _, v := range SupportedVersions() {
		p := versionProfiles[v]
		if p == nil {
			continue
		}
		src, err := sdktest.GHFileAtTag("runtime/vm/raw_object.h", v)
		if err != nil {
			t.Fatalf("%s: fetch raw_object.h: %v", v, err)
		}
		// The class was renamed at 2.12 (TypeLayout -> UntaggedType), and the
		// field's spelling changed again at 2.12 (bare member -> macro), so
		// match on neither. The discriminator that holds across all three
		// eras is the field's TYPE:
		//
		//	2.10   SmiPtr type_class_id_;                          ref
		//	2.12   COMPRESSED_POINTER_FIELD(SmiPtr, type_class_id) ref
		//	2.15   ClassIdTagType type_class_id_;                  scalar
		//	2.19   packed into flags_, accessors only             scalar
		//
		// Only ref-ness is asserted. The two non-ref shapes differ from each
		// other in ways this profile field does not describe (that is
		// OldTypeScalars' and TypeClassIDShift's job), so folding them
		// together here is the honest scope.
		body, ok := classBody(src, "class UntaggedType :")
		if !ok {
			body, ok = classBody(src, "class TypeLayout :")
		}
		if !ok {
			t.Fatalf("%s: neither UntaggedType nor TypeLayout found in raw_object.h", v)
		}
		if !strings.Contains(body, "type_class_id") {
			t.Fatalf("%s: the Type class no longer mentions type_class_id at all -- "+
				"this gate has gone blind and needs rewriting, not deleting:\n%s", v, body)
		}
		wantRef := strings.Contains(body, "SmiPtr, type_class_id)") ||
			strings.Contains(body, "SmiPtr type_class_id_;")
		if wantRef != p.TypeClassIdIsRef {
			t.Errorf("%s: SDK says type_class_id is a %s, profile says TypeClassIdIsRef=%v",
				v, map[bool]string{true: "ref", false: "scalar"}[wantRef], p.TypeClassIdIsRef)
		}
	}
}

// classBody returns the text of a C++ class declaration, from its header line
// to the closing "};" at column 0.
func classBody(src, header string) (string, bool) {
	i := strings.Index(src, header)
	if i < 0 {
		return "", false
	}
	rest := src[i:]
	j := strings.Index(rest, "\n};")
	if j < 0 {
		return "", false
	}
	return rest[:j], true
}
