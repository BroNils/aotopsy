package cluster

import (
	"regexp"
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
	"aotopsy/internal/snapshot"
)

// TestTypeRefsAfterArgumentsMatchesSDK re-derives how many refs follow
// UntaggedType.arguments inside the visited range, and checks it against the
// table typeArgumentsRef uses.
//
// Getting this wrong captures the wrong ref -- a Smi hash, or the signature --
// as the type-arguments ref, which then fails every TypeArguments lookup in
// SILENCE: no type-testing stub gets its type arguments and nothing errors.
// Measured before the fix, 0 of 2146 Types on dart-2.16.0-gt-arm64 resolved,
// against 745 of 2447 on 3.3.0, which read as a property of the sample rather
// than as a bug.
//
// The count moved twice and in both directions, which is why it is derived
// here rather than asserted as one boundary: 2.10.0 carries `signature` after
// `hash`, 2.12.0 drops it, and 3.1.0 drops `hash` too.
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/cluster/ -run TypeRefsAfterArguments
func TestTypeRefsAfterArgumentsMatchesSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	// A pointer field inside the visited range, in either spelling: the
	// macro form used from 2.12, and the bare `XPtr name_;` of 2.10.
	reField := regexp.MustCompile(`(?m)^\s*(?:COMPRESSED_)?POINTER_FIELD\(\s*\w+,\s*(\w+)\s*\)|^\s*\w+Ptr\s+(\w+)_;`)
	reVisitTo := regexp.MustCompile(`VISIT_TO\((?:\w+,\s*)?(\w+?)_?\)`)

	for _, v := range snapshot.SupportedVersions() {
		src, err := sdktest.GHFileAtTag("runtime/vm/raw_object.h", v)
		if err != nil {
			t.Fatalf("%s: fetch raw_object.h: %v", v, err)
		}
		body, ok := typeClassBody(src)
		if !ok {
			t.Fatalf("%s: neither UntaggedType nor TypeLayout found", v)
		}
		vt := reVisitTo.FindStringSubmatch(body)
		if vt == nil {
			t.Fatalf("%s: no VISIT_TO in the Type class:\n%s", v, body)
		}
		last := vt[1]

		var fields []string
		for _, m := range reField.FindAllStringSubmatch(body, -1) {
			name := m[1]
			if name == "" {
				name = m[2]
			}
			fields = append(fields, name)
		}
		argIdx, lastIdx := -1, -1
		for i, f := range fields {
			if f == "arguments" {
				argIdx = i
			}
			if f == last {
				lastIdx = i
			}
		}
		if argIdx < 0 {
			t.Fatalf("%s: no `arguments` field in the Type class:\n%s", v, body)
		}
		if lastIdx < argIdx {
			t.Fatalf("%s: VISIT_TO(%s) precedes `arguments`; this gate's model is wrong:\n%s", v, last, body)
		}
		if want, got := lastIdx-argIdx, typeRefsAfterArguments(v); got != want {
			t.Errorf("%s: SDK has %d ref(s) after `arguments` (VISIT_TO(%s)), typeArgumentsRef assumes %d",
				v, want, last, got)
		}
	}
}

// typeClassBody returns the Type class declaration, under either the modern
// name or the 2.10 one.
func typeClassBody(src string) (string, bool) {
	for _, header := range []string{"class UntaggedType :", "class TypeLayout :"} {
		i := strings.Index(src, header)
		if i < 0 {
			continue
		}
		rest := src[i:]
		if j := strings.Index(rest, "\n};"); j >= 0 {
			return rest[:j], true
		}
	}
	return "", false
}
