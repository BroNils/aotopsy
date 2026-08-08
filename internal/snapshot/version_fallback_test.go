package snapshot

import "testing"

// TestDetectVersionUnknownHashIsUsable guards the regression where
// DetectVersion("") returned a zero-valued &VersionProfile{}: CIDs was nil and
// HeaderFields was 0.
//
// Two crashes followed from that:
//
//   - cmd/aotopsy/clusters.go:109 calls DetectVersion("").CIDs and passes it to
//     cluster.CidNameV, which dereferences ct.Class. Reached when
//     info.Version is nil (no VM header) -- note an unknown *hash* halts
//     earlier on !Supported, so this is the narrower nil-Version path.
//   - cluster.ScanClusters substitutes DetectVersion("") for a nil profile and
//     would then read 0 snapshot header words.
//
// The panic that was actually reproduced end-to-end on a real binary is the
// sibling one in cluster.readFillRefs (nil profile.CIDs), fixed separately.
//
// The contract is: an unknown hash yields a placeholder that is safe to USE
// (populated CIDs / HeaderFields / Tags) but is flagged Supported=false with an
// empty DartVersion so callers can tell it is a guess. ProbeTagStyle is what
// refines it once actual snapshot bytes are available.
func TestDetectVersionUnknownHashIsUsable(t *testing.T) {
	p := DetectVersion("")
	if p == nil {
		t.Fatal("DetectVersion(\"\") returned nil")
	}
	if p.CIDs == nil {
		t.Error("CIDs is nil: every caller reading a CID field will panic")
	}
	if p.HeaderFields == 0 {
		t.Error("HeaderFields is 0: ScanClusters would read the wrong header size")
	}
	if p.DartVersion != "" {
		t.Errorf("DartVersion = %q, want \"\" so callers can detect the guess", p.DartVersion)
	}
	if p.Supported {
		t.Error("Supported = true for an unknown hash")
	}
}

// TestDetectVersionKnownButUnprofiled covers the other early-return: a hash we
// recognise but have no profile for. It is allowed to have nil CIDs (callers
// gate on Supported), but must still not be nil itself.
func TestDetectVersionKnownButUnprofiled(t *testing.T) {
	for hash, version := range knownHashes {
		if _, ok := versionProfiles[version]; ok {
			continue
		}
		p := DetectVersion(hash)
		if p == nil {
			t.Fatalf("DetectVersion(%q) returned nil", hash)
		}
		if p.Supported {
			t.Errorf("hash %q -> version %q has no profile but Supported=true", hash, version)
		}
		return
	}
}

// TestBuildModeFromFeatures pins the features-string tokens that
// Dart::FeaturesString actually writes (runtime/vm/dart.cc):
//
//	#if defined(DEBUG)     -> "debug"
//	#elif defined(PRODUCT) -> "product"
//	#else                  -> "release"
//
// The regression: BuildMode was matched against a "profile" token that Dart
// never emits, so BuildProfile was unreachable and a Flutter profile build
// (which reports "release") was classified as debug. A real release APK's
// string is asserted verbatim below.
func TestBuildModeFromFeatures(t *testing.T) {
	// Verbatim from compare_sample's Dart 3.9.2 arm64 libapp.so.
	const releaseAPK = "product no-code_comments no-dwarf_stack_traces_mode " +
		"dedup_instructions no-tsan no-msan no-shared_data arm64 android compressed-pointers"

	cases := []struct {
		features string
		want     BuildMode
	}{
		{releaseAPK, BuildProduct},
		{"product arm64 android compressed-pointers", BuildProduct},
		{"release arm64 android compressed-pointers", BuildRelease},
		{"debug arm64 android compressed-pointers", BuildDebug},
		// No token at all: keep the BuildProduct default rather than guessing
		// debug, which is what the old "not product => debug" branch did.
		{"", BuildProduct},
		{"arm64 android", BuildProduct},
		// "profile" is not a Dart feature token; it must not be honoured.
		{"profile arm64 android", BuildProduct},
	}
	for _, c := range cases {
		got := buildModeFromFeatures(c.features)
		if got != c.want {
			t.Errorf("features %q: got %v, want %v", c.features, got, c.want)
		}
	}

	if !BuildProduct.IsProduct() {
		t.Error("BuildProduct.IsProduct() = false")
	}
	for _, m := range []BuildMode{BuildRelease, BuildDebug} {
		if m.IsProduct() {
			t.Errorf("%v.IsProduct() = true", m)
		}
	}
}

// TestHasFeatureExactTokens ensures hasFeature matches whole tokens, so that
// e.g. "no-product" never satisfies a lookup for "product".
func TestHasFeatureExactTokens(t *testing.T) {
	const f = "release no-product no-code_comments arm64"
	if !hasFeature(f, "release") {
		t.Error("hasFeature missed a present token")
	}
	if hasFeature(f, "product") {
		t.Error("hasFeature matched \"product\" inside \"no-product\"")
	}
	if hasFeature(f, "arm") {
		t.Error("hasFeature matched a prefix of \"arm64\"")
	}
}
