package snapshot

import "testing"

// TestDetectVersionUnknownHashRefusesNearestProfile guards the fail-closed
// contract. A first-cluster tag can identify a broad family, but cannot prove
// that family's CID/root/fill dimensions.
func TestDetectVersionUnknownHashRefusesNearestProfile(t *testing.T) {
	if p := DetectVersion(""); p != nil {
		t.Fatalf("unknown hash inherited parser profile: %+v", *p)
	}
	if p := DetectVersion("ffffffffffffffffffffffffffffffff"); p != nil {
		t.Fatalf("future hash inherited parser profile: %+v", *p)
	}
}

// Every hash in the supported identity table must map to a concrete profile.
func TestKnownHashesHaveConcreteProfiles(t *testing.T) {
	for hash, version := range knownHashes {
		p := DetectVersion(hash)
		if p == nil {
			t.Errorf("hash %q -> %q has no parser profile", hash, version)
			continue
		}
		if !p.Supported || p.CIDs == nil {
			t.Errorf("hash %q -> %q returned incomplete profile: %+v", hash, version, *p)
		}
	}
}

func TestSpeculativeCompatibilityHashesAreNotParserOracles(t *testing.T) {
	for _, hash := range []string{
		"aa64af18e7d086041ac127cc4bc50c5e", // previously labelled "approximate"
		"2858c2c0920495f00b9bce9edf6a8cd9", // previously labelled "likely"
	} {
		if p := DetectVersion(hash); p != nil {
			t.Errorf("speculative hash %s inherited parser profile %+v", hash, *p)
		}
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
		{"", BuildUnknown},
		{"arm64 android", BuildUnknown},
		{"arm64 product", BuildUnknown},
		{" product arm64", BuildUnknown},
		// "profile" is not a Dart feature token; it must not be honoured.
		{"profile arm64 android", BuildUnknown},
		// Contradictory mode tokens are corruption, not a priority rule.
		{"product release arm64", BuildUnknown},
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
	for _, m := range []BuildMode{BuildUnknown, BuildRelease, BuildDebug} {
		if m.IsProduct() {
			t.Errorf("%v.IsProduct() = true", m)
		}
	}
}

func TestCompressionFeatureVocabularyByProfile(t *testing.T) {
	for _, tc := range []struct {
		version  string
		features string
		want     bool
		wantErr  bool
	}{
		{"2.12.0", "product arm64", false, false},
		{"2.12.0", "product arm64 compressed", false, true},
		{"2.14.0", "product arm64 compressed", true, false},
		{"2.14.0", "product arm64", false, false},
		{"2.14.0", "product arm64 compressed-pointers", false, true},
		{"2.15.0", "product arm64 compressed-pointers", true, false},
		{"2.15.0", "product arm64 no-compressed-pointers", false, false},
		{"2.15.0", "product arm64", false, true},
		{"3.13.0", "product arm64 compressed-pointers no-compressed-pointers", false, true},
	} {
		p := ProfileForVersion(tc.version)
		if p == nil {
			t.Fatalf("missing profile %s", tc.version)
		}
		got, err := compressedPointersFromFeatures(p.CompressionFeatures, tc.features)
		if (err != nil) != tc.wantErr || (!tc.wantErr && got != tc.want) {
			t.Errorf("%s features %q => compressed=%v err=%v, want compressed=%v err=%v",
				tc.version, tc.features, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestSupportedProfilesCarryVerifiedWireDimensions(t *testing.T) {
	for _, version := range SupportedVersions() {
		p := ProfileForVersion(version)
		if p == nil || !p.Supported {
			t.Fatalf("supported version %s has no supported profile", version)
		}
		if p.SnapshotSymbols == SnapshotSymbolsUnknown ||
			p.CompressionFeatures == CompressionFeatureUnknown ||
			p.InstructionsImage == InstructionsImageUnknown ||
			p.DataImageAlignment == 0 || p.ImageHeaderSize == 0 ||
			p.ClassIdTagPos == 0 || p.ClassIdTagSize == 0 {
			t.Errorf("%s has unverified wire dimensions: %+v", version, *p)
		}
		if p.FullAOTKind != KindFullAOT && p.FullAOTKind != KindFullAOTV210 {
			t.Errorf("%s has invalid Full-AOT kind %d", version, p.FullAOTKind)
		}
		if p.RootsHasSharedInitialFieldTable && !p.RootsHasInitialFieldTable {
			t.Errorf("%s claims shared field table without initial field table", version)
		}
	}
}

func TestProfileForVersionReturnsPerBinaryCopy(t *testing.T) {
	a := ProfileForVersion("3.12.2")
	b := ProfileForVersion("3.12.2")
	if a == nil || b == nil || a == b {
		t.Fatalf("ProfileForVersion did not return independent copies: a=%p b=%p", a, b)
	}
	a.BuildMode = BuildProduct
	a.CompressedPointers = true
	if b.BuildMode != BuildUnknown || b.CompressedPointers {
		t.Fatalf("per-binary feature state leaked through shared profile: a=%+v b=%+v", *a, *b)
	}
}

func TestIsExactSupportedProfileAllowsOnlyPerBinaryFeatureState(t *testing.T) {
	p := ProfileForVersion("3.12.2")
	if p == nil || !IsExactSupportedProfile(p) {
		t.Fatal("canonical exact profile was not accepted")
	}
	p.BuildMode = BuildProduct
	p.CompressedPointers = true
	if !IsExactSupportedProfile(p) {
		t.Fatal("per-binary build/compression state made exact profile invalid")
	}

	mutated := *p
	mutated.DataImageAlignment++
	if IsExactSupportedProfile(&mutated) {
		t.Fatal("profile with mutated static wire dimension was accepted")
	}

	future := *p
	future.DartVersion = "3.12.99"
	if IsExactSupportedProfile(&future) {
		t.Fatal("future/unknown Dart version with copied profile facts was accepted")
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
