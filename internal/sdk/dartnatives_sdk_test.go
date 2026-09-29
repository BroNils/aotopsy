package sdk

import (
	"sort"
	"strings"
	"testing"

	"aotopsy/internal/cmacro"
	"aotopsy/internal/sdktest"
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

	// Namespaces come and go: SendPortImpl lost its suffix in the 3.x
	// cycle, NetworkInterface was removed after 2.x. So a namespace
	// absent from ONE tag is version evolution and the table keeps both
	// spellings on purpose; a namespace absent from EVERY tag is a typo,
	// and nothing at runtime would report it -- the classifier would just
	// never match.
	tags := []string{"2.17.6", "3.12.2"}
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
	cases := []struct{ name, want string }{
		{"SecurityContext_UsePrivateKeyBytes", NativeCatTLS},
		{"X509_Subject", NativeCatTLS},
		{"SecureSocket_Connect", NativeCatTLS},
		{"Socket_CreateConnect", NativeCatNet},
		{"File_Open", NativeCatFile},
		{"Isolate_spawnUri", NativeCatIsolate},
		{"Process_Start", NativeCatProcess},
		{"Crypto_GetRandomBytes", NativeCatEncryption},
		{"Filter_CreateZLibInflate", NativeCatCompression},
		{"Ffi_dl_open", NativeCatDynamicLoad},
		{"Ffi_asFunctionInternal", NativeCatFFI},
	}
	for _, c := range cases {
		got, ok := DartNativeCategory(c.name)
		if !ok || got != c.want {
			t.Errorf("DartNativeCategory(%q) = (%q, %v), want (%q, true)", c.name, got, ok, c.want)
		}
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
		if cat, ok := DartNativeCategory(n); ok {
			t.Errorf("DartNativeCategory(%q) = %q, want no match", n, cat)
		}
	}

	// Namespaces every Dart program touches carry no signal and must stay
	// unclassified, or they drown the ones that matter.
	for _, n := range []string{"Object_toString", "Double_add", "List_getIndexed", "String_charAt"} {
		if cat, ok := DartNativeCategory(n); ok {
			t.Errorf("DartNativeCategory(%q) = %q, want no match: it appears in every program", n, cat)
		}
	}
}

func TestKnownNativeMembershipIsSDKBacked(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	seen := map[string]bool{}
	// This is a provenance coverage set, not a version sample: every committed
	// known native must occur in at least one exact tag below. If a future table
	// update needs a name that only exists at another supported release, add that
	// exact release here. Missing membership is always an error.
	tags := []string{"2.12.0", "2.17.6", "3.12.2", "3.13.0"}
	for _, tag := range tags {
		bn, err := sdktest.SDKFileAtTag("runtime/vm/bootstrap_natives.h", tag)
		if err != nil {
			t.Fatalf("verify bootstrap natives @%s: %v", tag, err)
		}
		ioSrc, err := sdktest.SDKFileAtTag("runtime/bin/io_natives.cc", tag)
		if err != nil {
			t.Fatalf("verify io natives @%s: %v", tag, err)
		}
		for _, name := range expandDeclaredNativeLists(t, bn, tag,
			"BOOTSTRAP_NATIVE_LIST", "BOOTSTRAP_FFI_NATIVE_LIST") {
			seen[name] = true
		}
		for _, name := range expandDeclaredNativeLists(t, ioSrc, tag, "IO_NATIVE_LIST") {
			seen[name] = true
		}
	}
	for name := range dartNativeKnown {
		if seen[name] {
			continue
		}
		t.Errorf("known native %s is absent from every exact SDK provenance tag (%v)", name, tags)
	}
}

// expandDeclaredNativeLists requires the first macro and expands each optional
// macro only when that exact SDK header declares it. This is deliberately not
// "ignore any missing macro": the canonical list must exist, while known
// version-evolution splits are optional.
func expandDeclaredNativeLists(t *testing.T, body, tag, required string, optional ...string) []string {
	t.Helper()
	macros := cmacro.ParseMacros(body)
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
