package sdk

import (
	"sort"
	"strings"
	"testing"

	"aotopsy/internal/cmacro"
	"aotopsy/internal/sdktest"
	"aotopsy/internal/snapshot"
)

// SDK drift gate for the VM native namespace table.
//
// The table classifies by namespace, so the failure mode is a namespace
// that does not exist -- a typo, or one the SDK renamed. Nothing would
// report that: the classifier would simply never match, and the natives
// it was meant to cover would go back to being unclassified strings.
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/sdk/ -run DartNative

// sdkNativeNamespaces returns every native namespace the SDK declares at a
// tag. Historical SDKs (including 2.12.0) keep Ffi_* entries directly inside
// BOOTSTRAP_NATIVE_LIST; newer SDKs split some entries into
// BOOTSTRAP_FFI_NATIVE_LIST. The gate follows the declarations that actually
// exist at each exact tag instead of imposing the current header shape on old
// releases.
func sdkNativeNamespaces(t *testing.T, tag string) map[string]bool {
	t.Helper()
	out := map[string]bool{}

	add := func(name string) {
		if i := strings.IndexByte(name, '_'); i > 0 {
			out[name[:i]] = true
		}
	}

	bn, err := sdktest.SDKFileAtTag("runtime/vm/bootstrap_natives.h", tag)
	if err != nil {
		t.Fatalf("verify bootstrap_natives.h@%s: %v", tag, err)
	}
	for _, n := range expandDeclaredNativeLists(t, bn, tag,
		"BOOTSTRAP_NATIVE_LIST", "BOOTSTRAP_FFI_NATIVE_LIST") {
		add(n)
	}

	io, err := sdktest.SDKFileAtTag("runtime/bin/io_natives.cc", tag)
	if err != nil {
		t.Fatalf("verify io_natives.cc@%s: %v", tag, err)
	}
	for _, n := range expandDeclaredNativeLists(t, io, tag, "IO_NATIVE_LIST") {
		add(n)
	}

	if len(out) < 40 {
		t.Fatalf("%s: only %d native namespaces parsed; the sources moved", tag, len(out))
	}
	return out
}

func TestDartNativeNamespacesMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	// Namespaces come and go: check the full supported release set so a namespace
	// that existed only in an unsampled boundary release cannot be mistaken for a
	// typo (or vice versa).
	tags := snapshot.SupportedVersions()
	seen := map[string][]string{}
	for _, tag := range tags {
		sdkNS := sdkNativeNamespaces(t, tag)
		for _, ns := range DartNativeNamespaces() {
			if sdkNS[ns] {
				seen[ns] = append(seen[ns], tag)
			}
		}
		t.Logf("%s: %d namespaces in the SDK", tag, len(sdkNS))
	}

	ours := DartNativeNamespaces()
	sort.Strings(ours)
	for _, ns := range ours {
		if len(seen[ns]) == 0 {
			t.Errorf("namespace %q is classified but no native of that name exists at any of %v.\n"+
				"  Nothing reports this at runtime -- the classifier just never matches.", ns, tags)
			continue
		}
		if len(seen[ns]) < len(tags) {
			t.Logf("  %-24s only at %v (renamed or removed upstream)", ns, seen[ns])
		}
	}
}

// TestDartNativeCategoryIsExact guards the property that makes this table
// worth having: it must not substring-match. SecurityContext_UsePrivateKeyBytes
// was read as a blockchain signal by the heuristics it replaces.
func TestDartNativeCategoryIsExact(t *testing.T) {
	cases := []struct{ version, name, want string }{
		{"3.12.2", "SecurityContext_UsePrivateKeyBytes", NativeCatTLS},
		{"3.12.2", "X509_Subject", NativeCatTLS},
		{"3.12.2", "SecureSocket_Connect", NativeCatTLS},
		{"3.12.2", "Socket_CreateConnect", NativeCatNet},
		{"3.12.2", "File_Open", NativeCatFile},
		{"3.12.2", "Isolate_spawnUri", NativeCatIsolate},
		{"3.12.2", "Process_Start", NativeCatProcess},
		{"3.12.2", "Crypto_GetRandomBytes", NativeCatEncryption},
		{"3.12.2", "Filter_CreateZLibInflate", NativeCatCompression},
		{"3.12.2", "Ffi_dl_open", NativeCatDynamicLoad},
		// Removed after 3.2.5; category lookup must respect exact membership.
		{"3.2.5", "Ffi_asFunctionInternal", NativeCatFFI},
	}
	for _, c := range cases {
		got, ok := DartNativeCategory(c.version, c.name)
		if !ok || got != c.want {
			t.Errorf("DartNativeCategory(%s, %q) = (%q, %v), want (%q, true)", c.version, c.name, got, ok, c.want)
		}
	}
	if cat, ok := DartNativeCategory("3.12.2", "Ffi_asFunctionInternal"); ok {
		t.Errorf("removed native classified at 3.12.2 as %q", cat)
	}

	// Names that merely contain a classified namespace must NOT match:
	// the namespace is a prefix up to the first underscore, not a
	// substring anywhere.
	for _, n := range []string{
		"MySocket_Connect",          // namespace is MySocket
		"reopenFile_something",      // namespace is reopenFile
		"Socket_NotARealNative",     // real namespace, fabricated member
		"File_DefinitelyNotSDK",     // real namespace, fabricated member
		"Ffi_CustomApplicationHook", // real namespace, fabricated member
		"Socket",                    // no underscore at all
		"Socket_",                   // no member
		"_Socket_Connect",           // empty namespace
	} {
		if cat, ok := DartNativeCategory("3.12.2", n); ok {
			t.Errorf("DartNativeCategory(%q) = %q, want no match", n, cat)
		}
	}

	// Namespaces every Dart program touches carry no signal and must stay
	// unclassified, or they drown the ones that matter.
	for _, n := range []string{"Object_toString", "Double_add", "List_getIndexed", "String_charAt"} {
		if cat, ok := DartNativeCategory("3.12.2", n); ok {
			t.Errorf("DartNativeCategory(%q) = %q, want no match: it appears in every program", n, cat)
		}
	}
}

func TestKnownNativeMembershipIsSDKBacked(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	for _, tag := range snapshot.SupportedVersions() {
		bn, err := sdktest.SDKFileAtTag("runtime/vm/bootstrap_natives.h", tag)
		if err != nil {
			t.Fatalf("verify bootstrap natives @%s: %v", tag, err)
		}
		ioSrc, err := sdktest.SDKFileAtTag("runtime/bin/io_natives.cc", tag)
		if err != nil {
			t.Fatalf("verify io natives @%s: %v", tag, err)
		}
		actual := map[string]bool{}
		for _, name := range expandDeclaredNativeLists(t, bn, tag,
			"BOOTSTRAP_NATIVE_LIST", "BOOTSTRAP_FFI_NATIVE_LIST") {
			actual[name] = true
		}
		for _, name := range expandDeclaredNativeLists(t, ioSrc, tag, "IO_NATIVE_LIST") {
			actual[name] = true
		}
		for name := range dartNativeKnown {
			if got, want := dartNativeExistsAtVersion(tag, name), actual[name]; got != want {
				t.Errorf("%s native membership for %s = %v, SDK = %v", tag, name, got, want)
			}
		}
		// Reverse direction matters just as much. The old test only iterated the
		// committed union, so a newly-added SDK native in a behavioral namespace
		// omitted from dartnatives_known.txt was invisible and the gate still
		// passed. Mundane namespaces (Object_*, Double_*, List_*...) are excluded
		// from the classifier by design and therefore are not members of this
		// committed union.
		for name := range actual {
			classified := false
			if _, ok := dartNativeExact[name]; ok {
				classified = true
			} else if i := strings.IndexByte(name, '_'); i > 0 {
				_, classified = dartNativeNamespaces[name[:i]]
			}
			if !classified {
				continue
			}
			if _, ok := dartNativeKnown[name]; !ok {
				t.Errorf("%s classified SDK native %s is absent from the committed native union", tag, name)
			}
		}
	}
	for name := range dartNativeKnown {
		if _, ok := dartNativeExact[name]; ok {
			continue
		}
		i := strings.IndexByte(name, '_')
		if i <= 0 {
			t.Errorf("committed native %s has no namespace separator", name)
			continue
		}
		if _, ok := dartNativeNamespaces[name[:i]]; !ok {
			t.Errorf("committed native %s belongs to intentionally-unclassified namespace %s", name, name[:i])
		}
	}
	for _, tag := range snapshot.SupportedVersions() {
		if _, ok := dartNativeVersionBit[tag]; !ok {
			t.Errorf("supported version %s has no native membership bit", tag)
		}
	}
}

func TestDartNativeVersionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		version, name string
		want          bool
	}{
		{"2.10.0", "Ffi_sizeOf", true},
		{"2.12.0", "Ffi_sizeOf", true},
		{"2.13.0", "Ffi_sizeOf", false},
		{"3.0.5", "Ffi_dl_close", false},
		{"3.1.0", "Ffi_dl_close", true},
		{"2.18.0", "SendPortImpl_get_id", true},
		{"2.19.0", "SendPortImpl_get_id", false},
		{"2.18.0", "SendPort_get_id", false},
		{"2.19.0", "SendPort_get_id", true},
		{"3.99.0", "Ffi_dl_close", false},
	} {
		if got := dartNativeExistsAtVersion(tc.version, tc.name); got != tc.want {
			t.Errorf("native %s at %s = %v, want %v", tc.name, tc.version, got, tc.want)
		}
	}
}

// expandDeclaredNativeLists requires the first macro and expands each optional
// macro only when that exact SDK header declares it. This is deliberately not
// "ignore any missing macro": the canonical list must exist, while known
// version-evolution splits are optional.
func expandDeclaredNativeLists(t *testing.T, body, tag, required string, optional ...string) []string {
	t.Helper()
	macros, err := cmacro.ParseMacros(body)
	if err != nil {
		t.Fatalf("parse native macros@%s: %v", tag, err)
	}
	names, err := cmacro.Expand(macros, required)
	if err != nil {
		t.Fatalf("expand required %s@%s: %v", required, tag, err)
	}
	for _, list := range optional {
		if _, ok := macros[list]; !ok {
			continue
		}
		more, err := cmacro.Expand(macros, list)
		if err != nil {
			t.Fatalf("expand optional %s@%s: %v", list, tag, err)
		}
		names = append(names, more...)
	}
	return names
}

func TestExpandDeclaredNativeListsHandlesHistoricalFFISplit(t *testing.T) {
	inline := "#define BOOTSTRAP_NATIVE_LIST(V) V(Object_toString, 1) V(Ffi_dl_open, 1)\n"
	split := "#define BOOTSTRAP_NATIVE_LIST(V) V(Object_toString, 1)\n" +
		"#define BOOTSTRAP_FFI_NATIVE_LIST(V) V(Ffi_dl_open, 1)\n"
	for name, src := range map[string]string{"inline": inline, "split": split} {
		t.Run(name, func(t *testing.T) {
			got := expandDeclaredNativeLists(t, src, "fixture",
				"BOOTSTRAP_NATIVE_LIST", "BOOTSTRAP_FFI_NATIVE_LIST")
			if len(got) != 2 || got[0] != "Object_toString" || got[1] != "Ffi_dl_open" {
				t.Fatalf("got %v, want [Object_toString Ffi_dl_open]", got)
			}
		})
	}
}
