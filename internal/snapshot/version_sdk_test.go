package snapshot

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
)

var (
	vmSnapshotFilesRE = regexp.MustCompile(`(?s)VM_SNAPSHOT_FILES\s*=\s*\[(.*?)\]`)
	quotedPythonRE    = regexp.MustCompile(`['"]([^'"]+)['"]`)
	fullAOTEnumRE     = regexp.MustCompile(`(?s)enum\s+Kind\s*\{(.*?)\}`)
	constantRE        = regexp.MustCompile(`(?m)\b(kMaxObjectAlignment|kObjectStartAlignment)\s*=\s*([0-9]+)\s*;`)
	imageHeaderRE     = regexp.MustCompile(`(?m)\bkHeaderSize\s*=\s*(kMaxObjectAlignment|kObjectStartAlignment)\s*;`)
	dataImageAlignRE  = regexp.MustCompile(`RoundUp\s*\(\s*length\(\)\s*,\s*(kMaxObjectAlignment|kObjectStartAlignment)\s*\)`)
)

// TestKnownHashesContainSDKCanonicalHash re-runs the exact algorithm used by
// tools/make_version.py at every supported SDK tag. This is the parser-identity
// drift gate: a profile is not allowed to survive after its SDK's canonical
// VM_SNAPSHOT_FILES hash stops mapping back to that same profile.
func TestKnownHashesContainSDKCanonicalHash(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	for _, tag := range SupportedVersions() {
		tag := tag
		t.Run(tag, func(t *testing.T) {
			makeVersion, err := sdktest.SDKFileAtTag("tools/make_version.py", tag)
			if err != nil {
				t.Fatal(err)
			}
			m := vmSnapshotFilesRE.FindStringSubmatch(makeVersion)
			if m == nil {
				t.Fatalf("%s: VM_SNAPSHOT_FILES not found in tools/make_version.py", tag)
			}
			matches := quotedPythonRE.FindAllStringSubmatch(m[1], -1)
			if len(matches) == 0 {
				t.Fatalf("%s: VM_SNAPSHOT_FILES was empty", tag)
			}
			h := md5.New() // The SDK itself uses MD5 for snapshot format identity.
			for _, match := range matches {
				src, err := sdktest.SDKFileAtTag("runtime/vm/"+match[1], tag)
				if err != nil {
					t.Fatalf("%s: read VM_SNAPSHOT_FILES member %s: %v", tag, match[1], err)
				}
				_, _ = h.Write([]byte(src))
			}
			hash := hex.EncodeToString(h.Sum(nil))
			if got, ok := knownHashes[hash]; !ok || got != tag {
				t.Fatalf("SDK-derived snapshot hash %s maps to %q, want %q", hash, got, tag)
			}
		})
	}
}

// TestWireDimensionsMatchSDK derives the profile fields that live outside the
// clustered object stream directly from exact SDK sources. It intentionally
// does not check ClassIdTagPos/ClassIdTagSize: classidtag_sdk_test.go already
// has the generator-backed source gate for that independent bitfield.
func TestWireDimensionsMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	for _, tag := range SupportedVersions() {
		tag := tag
		t.Run(tag, func(t *testing.T) {
			profile := ProfileForVersion(tag)
			if profile == nil {
				t.Fatalf("missing profile for %s", tag)
			}
			got, err := wireDimensionsFromSDK(tag)
			if err != nil {
				t.Fatal(err)
			}
			if profile.SnapshotSymbols != got.symbols ||
				profile.CompressionFeatures != got.compression ||
				profile.TargetFeatures != got.targetFeatures ||
				profile.InstructionsImage != got.instructionsImage ||
				profile.FullAOTKind != got.fullAOTKind ||
				profile.DataImageAlignment != got.dataImageAlignment ||
				profile.ImageHeaderSize != got.imageHeaderSize ||
				profile.RootsHasInitialFieldTable != got.initialFieldTable ||
				profile.RootsHasSharedInitialFieldTable != got.sharedInitialFieldTable {
				t.Fatalf("wire profile disagrees with SDK\n got profile: symbols=%d compression=%d target=%d instructions=%d kind=%d align=%d imageHeader=%d initial=%v shared=%v\nwant SDK:     symbols=%d compression=%d target=%d instructions=%d kind=%d align=%d imageHeader=%d initial=%v shared=%v",
					profile.SnapshotSymbols, profile.CompressionFeatures, profile.TargetFeatures, profile.InstructionsImage, profile.FullAOTKind,
					profile.DataImageAlignment, profile.ImageHeaderSize, profile.RootsHasInitialFieldTable, profile.RootsHasSharedInitialFieldTable,
					got.symbols, got.compression, got.targetFeatures, got.instructionsImage, got.fullAOTKind,
					got.dataImageAlignment, got.imageHeaderSize, got.initialFieldTable, got.sharedInitialFieldTable)
			}
		})
	}
}

func wireDimensionsFromSDK(tag string) (wireDimensions, error) {
	var out wireDimensions

	dartAPI, err := sdktest.SDKFileAtTag("runtime/include/dart_api.h", tag)
	if err != nil {
		return out, err
	}
	legacySymbols := strings.Contains(dartAPI, `kVmSnapshotDataCSymbol "kDartVmSnapshotData"`) &&
		strings.Contains(dartAPI, `kIsolateSnapshotDataCSymbol "kDartIsolateSnapshotData"`)
	unifiedSymbols := strings.Contains(dartAPI, `kSnapshotDataCSymbol "kDartSnapshotData"`) &&
		strings.Contains(dartAPI, `kSnapshotTextCSymbol "kDartSnapshotText"`)
	switch {
	case legacySymbols && !unifiedSymbols:
		out.symbols = SnapshotSymbolsLegacy
	case unifiedSymbols && !legacySymbols:
		out.symbols = SnapshotSymbolsUnified
	default:
		return out, fmt.Errorf("%s: ambiguous snapshot symbol macros (legacy=%v unified=%v)", tag, legacySymbols, unifiedSymbols)
	}
	dartCC, err := sdktest.SDKFileAtTag("runtime/vm/dart.cc", tag)
	if err != nil {
		return out, err
	}
	legacyTargetVocabulary := strings.Contains(dartCC, `buffer.AddString(" arm64-sysv")`) &&
		strings.Contains(dartCC, `buffer.AddString(" x64-sysv")`)
	modernTargetVocabulary := strings.Contains(dartCC, `buffer.AddString(" arm64")`) &&
		strings.Contains(dartCC, `buffer.AddString(" x64")`) &&
		strings.Contains(dartCC, `buffer.AddString(" android")`) &&
		strings.Contains(dartCC, `buffer.AddString(" linux")`)
	switch {
	case legacyTargetVocabulary && !modernTargetVocabulary:
		out.targetFeatures = TargetFeatureLegacyABI
	case modernTargetVocabulary && !legacyTargetVocabulary:
		out.targetFeatures = TargetFeatureArchAndOS
	default:
		return out, fmt.Errorf("%s: ambiguous FeaturesString target vocabulary", tag)
	}
	hasPositive := strings.Contains(dartCC, `buffer.AddString(" compressed-pointers")`)
	hasNegative := strings.Contains(dartCC, `buffer.AddString(" no-compressed-pointers")`)
	hasLegacyPositive := strings.Contains(dartCC, `buffer.AddString(" compressed")`)
	switch {
	case hasPositive && hasNegative && !hasLegacyPositive:
		out.compression = CompressionFeatureExplicit
	case !hasPositive && !hasNegative && hasLegacyPositive:
		out.compression = CompressionFeatureLegacyPositiveOnly
	case !hasPositive && !hasNegative && !hasLegacyPositive:
		out.compression = CompressionFeatureFixedUncompressed
	default:
		return out, fmt.Errorf("%s: ambiguous FeaturesString compression vocabulary", tag)
	}

	snapshotH, err := sdktest.SDKFileAtTag("runtime/vm/snapshot.h", tag)
	if err != nil {
		return out, err
	}
	kindBody := fullAOTEnumRE.FindStringSubmatch(snapshotH)
	if kindBody == nil {
		return out, fmt.Errorf("%s: Snapshot::Kind enum not found", tag)
	}
	kinds := regexp.MustCompile(`\bk[A-Za-z0-9_]+\b`).FindAllString(kindBody[1], -1)
	fullAOTOrdinal := -1
	for i, kind := range kinds {
		if kind == "kFullAOT" {
			fullAOTOrdinal = i
			break
		}
	}
	if fullAOTOrdinal < 0 {
		return out, fmt.Errorf("%s: kFullAOT missing from Snapshot::Kind", tag)
	}
	out.fullAOTKind = SnapshotKind(fullAOTOrdinal)

	alignName := dataImageAlignRE.FindStringSubmatch(snapshotH)
	if alignName == nil {
		return out, fmt.Errorf("%s: Snapshot::DataImage alignment expression not found", tag)
	}
	pointerTagging, err := sdktest.SDKFileAtTag("runtime/vm/pointer_tagging.h", tag)
	if err != nil {
		return out, err
	}
	constants := map[string]int64{}
	for _, m := range constantRE.FindAllStringSubmatch(pointerTagging, -1) {
		v, err := strconv.ParseInt(m[2], 10, 64)
		if err != nil {
			return out, fmt.Errorf("%s: parse %s: %w", tag, m[1], err)
		}
		constants[m[1]] = v
	}
	align, ok := constants[alignName[1]]
	if !ok {
		return out, fmt.Errorf("%s: %s has no numeric definition in pointer_tagging.h", tag, alignName[1])
	}
	out.dataImageAlignment = align

	imageH, err := sdktest.SDKFileAtTag("runtime/vm/image_snapshot.h", tag)
	if err != nil {
		return out, err
	}
	headerName := imageHeaderRE.FindStringSubmatch(imageH)
	if headerName == nil {
		return out, fmt.Errorf("%s: Image::kHeaderSize expression not found", tag)
	}
	headerSize, ok := constants[headerName[1]]
	if !ok {
		return out, fmt.Errorf("%s: %s has no numeric definition for Image::kHeaderSize", tag, headerName[1])
	}
	out.imageHeaderSize = uint64(headerSize)

	if !strings.Contains(imageH, "InstructionsSectionOffset") {
		out.instructionsImage = InstructionsImageLegacy210
	} else {
		objectH, err := sdktest.SDKFileAtTag("runtime/vm/object.h", tag)
		if err != nil {
			return out, err
		}
		section := sdkClassBody(objectH, "class InstructionsSection : public Object")
		if section == "" {
			return out, fmt.Errorf("%s: InstructionsSection class not found", tag)
		}
		if strings.Contains(section, "kPayloadAlignment = 32") {
			out.instructionsImage = InstructionsImageSection64
		} else if strings.Contains(section, "Instructions::kBarePayloadAlignment") {
			out.instructionsImage = InstructionsImageSection40
		} else {
			return out, fmt.Errorf("%s: unrecognized InstructionsSection::HeaderSize layout", tag)
		}
	}

	appSnapshot, err := sdktest.SDKFileAtTagAny(tag,
		"runtime/vm/app_snapshot.cc",
		"runtime/vm/clustered_snapshot.cc",
	)
	if err != nil {
		return out, err
	}
	roots := sdkClassBody(appSnapshot, "class ProgramSerializationRoots : public SerializationRoots")
	if roots == "" {
		return out, fmt.Errorf("%s: ProgramSerializationRoots class not found", tag)
	}
	writeRoots := sdkMethodBody(roots, "void WriteRoots(Serializer* s)")
	if writeRoots == "" {
		return out, fmt.Errorf("%s: ProgramSerializationRoots::WriteRoots not found", tag)
	}
	out.initialFieldTable = strings.Contains(writeRoots, "initial_field_table")
	out.sharedInitialFieldTable = strings.Contains(writeRoots, "shared_initial_field_table")
	return out, nil
}

func sdkClassBody(src, marker string) string {
	start := strings.Index(src, marker)
	if start < 0 {
		return ""
	}
	open := strings.Index(src[start:], "{")
	if open < 0 {
		return ""
	}
	open += start
	return balancedBraces(src, open)
}

func sdkMethodBody(src, signature string) string {
	start := strings.Index(src, signature)
	if start < 0 {
		return ""
	}
	open := strings.Index(src[start:], "{")
	if open < 0 {
		return ""
	}
	return balancedBraces(src, start+open)
}

func balancedBraces(src string, open int) string {
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open : i+1]
			}
		}
	}
	return ""
}
