// Package snapshot locates and extracts Dart snapshot regions from libapp.so.
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
)

// Well-known symbol names for Dart AOT snapshots.
const (
	SymVmSnapshotData              = "_kDartVmSnapshotData"
	SymVmSnapshotInstructions      = "_kDartVmSnapshotInstructions"
	SymIsolateSnapshotData         = "_kDartIsolateSnapshotData"
	SymIsolateSnapshotInstructions = "_kDartIsolateSnapshotInstructions"
	SymSnapshotBuildID             = "_kDartSnapshotBuildId"

	// Dart 3.13.0+ replaced all four symbols above with these two, and merged
	// the VM and isolate snapshots into a single one.
	//
	// SDK-verified via gh api on runtime/include/dart_api.h at both tags:
	// 3.12.2 defines kVmSnapshotDataCSymbol / kIsolateSnapshotDataCSymbol and
	// their Instructions counterparts; 3.13.0 defines only kSnapshotDataCSymbol
	// and kSnapshotTextCSymbol. That this is deliberate is visible in the SDK
	// itself: pkg/native_stack_traces/lib/src/constants.dart@3.13.0 keeps the
	// old four as oldVmSymbolName / oldIsolateSymbolName for reading older
	// snapshots, and ImageWriter::SectionSymbol lost its `bool vm` parameter,
	// so there is no VM-vs-isolate distinction at the image level any more.
	SymUnifiedSnapshotData = "_kDartSnapshotData"
	SymUnifiedSnapshotText = "_kDartSnapshotText"
)

// snapshotMagic is the 4-byte magic at the start of a Dart snapshot data blob.
var snapshotMagic = [4]byte{0xf5, 0xf5, 0xdc, 0xdc}

// Region describes one snapshot region extracted from libapp.so.
type Region struct {
	Name       string `json:"name"`
	VA         uint64 `json:"va"`
	FileOffset uint64 `json:"file_offset"`
	SymSize    uint64 `json:"sym_size"`  // from ELF symbol; 0 if unknown
	DataSize   uint64 `json:"data_size"` // from snapshot header; 0 if not parsed
	SHA256     string `json:"sha256"`    // hex; empty if data not extracted
	Data       []byte `json:"-"`         // raw bytes; not serialized
}

// SnapshotKind identifies the snapshot type.
type SnapshotKind int64

const (
	KindFull    SnapshotKind = 0
	KindCore    SnapshotKind = 1
	KindFullJIT SnapshotKind = 2
	KindFullAOT SnapshotKind = 3
)

func (k SnapshotKind) String() string {
	switch k {
	case KindFull:
		return "Full"
	case KindCore:
		return "FullCore"
	case KindFullJIT:
		return "FullJIT"
	case KindFullAOT:
		return "FullAOT"
	default:
		return fmt.Sprintf("Unknown(%d)", k)
	}
}

// Header holds parsed fields from a Dart snapshot data header.
// Layout:
//
//	+0x00: magic   int32  (0xdcdcf5f5)
//	+0x04: length  int64  (excludes magic; total = stored + 4)
//	+0x0c: kind    int64  (0=Full, 1=Core, 2=FullJIT, 3=FullAOT)
//	+0x14: version hash (32 ASCII hex chars)
//	+0x34: features (null-terminated string)
type Header struct {
	Magic        [4]byte      `json:"-"`
	Length       int64        `json:"length"` // stored length (excludes magic)
	TotalSize    int64        `json:"size"`   // length + 4
	Kind         SnapshotKind `json:"kind"`
	SnapshotHash string       `json:"snapshot_hash"` // 32 hex chars at offset 0x14
	Features     string       `json:"features"`      // null-terminated at offset 0x34
}

// FeatureList returns the features as a sorted slice.
func (h *Header) FeatureList() []string {
	if h.Features == "" {
		return nil
	}
	return strings.Split(h.Features, " ")
}

// HasFeature checks if a specific feature is present.
func (h *Header) HasFeature(name string) bool {
	for _, f := range h.FeatureList() {
		if f == name {
			return true
		}
	}
	return false
}

// hasFeature checks if a feature string contains the given feature name.
// Works on the raw features string (space-separated). Matches whole tokens
// only, so "product" does not match Dart's "no-product" spelling.
func hasFeature(features, name string) bool {
	for _, f := range strings.Split(features, " ") {
		if f == name {
			return true
		}
	}
	return false
}

// buildModeFromFeatures maps a snapshot features string to a BuildMode.
//
// Split out of Extract so it is unit-testable: see
// TestBuildModeFromFeatures, which pins the exact token set Dart emits.
// Unrecognised or empty input keeps the BuildProduct default.
func buildModeFromFeatures(features string) BuildMode {
	switch {
	case hasFeature(features, "product"):
		return BuildProduct
	case hasFeature(features, "release"):
		return BuildRelease
	case hasFeature(features, "debug"):
		return BuildDebug
	}
	return BuildProduct
}

// Info aggregates all extracted snapshot information.
type Info struct {
	VmData              Region          `json:"vm_data"`
	VmInstructions      Region          `json:"vm_instructions"`
	IsolateData         Region          `json:"isolate_data"`
	IsolateInstructions Region          `json:"isolate_instructions"`
	UnifiedSnapshot     bool            `json:"unified_snapshot,omitempty"`
	VmHeader            *Header         `json:"vm_header,omitempty"`
	IsolateHeader       *Header         `json:"isolate_header,omitempty"`
	Version             *VersionProfile `json:"version,omitempty"`
	Diags               []dartfmt.Diag  `json:"diagnostics,omitempty"`
}

// Extract locates and reads snapshot regions from an opened ELF file.
func Extract(ef *elfx.File, opts dartfmt.Options) (*Info, error) {
	var diags dartfmt.Diags
	info := &Info{}

	// Resolve all four snapshot symbols.
	type symTarget struct {
		name   string
		region *Region
	}
	targets := []symTarget{
		{SymVmSnapshotData, &info.VmData},
		{SymVmSnapshotInstructions, &info.VmInstructions},
		{SymIsolateSnapshotData, &info.IsolateData},
		{SymIsolateSnapshotInstructions, &info.IsolateInstructions},
	}

	// Dart 3.13.0+ unified layout: one data blob and one text blob holding a
	// SINGLE snapshot that serves as both VM and isolate.
	//
	// The blob is mapped onto IsolateData/IsolateInstructions and the VM
	// regions are left empty. That is not a shortcut for "we did not find it":
	// there is exactly one snapshot in there, verified on a real 3.13.0
	// libapp.so by scanning for the 0xdcdcf5f5 magic, which occurs once, at
	// offset 0. Downstream code already guards VM parsing with
	// `len(VmData) >= 64`, so it skips cleanly instead of inventing a second
	// snapshot. UnifiedSnapshot lets callers tell "no VM snapshot exists" from
	// "VM snapshot extraction failed".
	if _, _, err := ef.Symbol(SymUnifiedSnapshotData); err == nil {
		info.UnifiedSnapshot = true
		targets = []symTarget{
			{SymUnifiedSnapshotData, &info.IsolateData},
			{SymUnifiedSnapshotText, &info.IsolateInstructions},
		}
	}

	for _, t := range targets {
		t.region.Name = t.name
		va, size, err := ef.Symbol(t.name)
		if err != nil {
			if opts.Mode == dartfmt.ModeStrict {
				return nil, fmt.Errorf("snapshot: %w", err)
			}
			diags.Add(0, dartfmt.DiagInvalid, fmt.Sprintf("symbol %s not found: %v", t.name, err))
			continue
		}
		t.region.VA = va
		t.region.SymSize = size

		off, err := ef.VAToFileOffset(va)
		if err != nil {
			if opts.Mode == dartfmt.ModeStrict {
				return nil, fmt.Errorf("snapshot: VA mapping for %s: %w", t.name, err)
			}
			diags.Add(va, dartfmt.DiagInvalid, fmt.Sprintf("VA 0x%x for %s: %v", va, t.name, err))
			continue
		}
		t.region.FileOffset = off

		// Read region data. Use symbol size if available, else cap at a reasonable max.
		readSize := size
		if readSize == 0 {
			// For instruction regions, symbol size is often 0. We'll read a
			// capped amount; the actual size comes from header parsing or
			// region boundary analysis later.
			readSize = capRegionSize(ef, va)
		}
		if readSize > 0 {
			data, err := ef.ReadBytesAtVA(va, int(readSize))
			if err != nil {
				if opts.Mode == dartfmt.ModeStrict {
					return nil, fmt.Errorf("snapshot: read %s: %w", t.name, err)
				}
				diags.Add(va, dartfmt.DiagTruncated, fmt.Sprintf("read %s: %v", t.name, err))
			} else {
				t.region.Data = data
				t.region.DataSize = uint64(len(data))
				h := sha256.Sum256(data)
				t.region.SHA256 = hex.EncodeToString(h[:])
			}
		}
	}

	// Parse headers from snapshot data regions.
	if len(info.VmData.Data) >= 64 {
		hdr, err := parseHeader(info.VmData.Data)
		if err != nil {
			diags.Add(info.VmData.VA, dartfmt.DiagInvalid, fmt.Sprintf("vm header: %v", err))
		} else {
			info.VmHeader = hdr
		}
	}
	if len(info.IsolateData.Data) >= 64 {
		hdr, err := parseHeader(info.IsolateData.Data)
		if err != nil {
			diags.Add(info.IsolateData.VA, dartfmt.DiagInvalid, fmt.Sprintf("isolate header: %v", err))
		} else {
			info.IsolateHeader = hdr
		}
	}

	// Detect Dart SDK version from snapshot hash.
	//
	// The hash normally comes from the VM snapshot header. Under the 3.13.0+
	// unified layout there is no VM snapshot, so the single header carries it.
	// Both headers hold the same version hash by construction, so preferring
	// the VM one and falling back to the isolate one is version-agnostic
	// rather than a special case.
	hashRegion, hashHeader := info.VmData, info.VmHeader
	if hashHeader == nil || hashHeader.SnapshotHash == "" {
		hashRegion, hashHeader = info.IsolateData, info.IsolateHeader
	}
	if hashHeader != nil && hashHeader.SnapshotHash != "" {
		info.Version = DetectVersion(hashHeader.SnapshotHash)

		// For unknown hashes, probe the data to determine tag style.
		if info.Version != nil && info.Version.DartVersion == "" && hashRegion.Data != nil {
			if cs, err := findClusterDataStart(hashRegion.Data); err == nil {
				info.Version = ProbeTagStyle(hashRegion.Data, cs)
			}
		}
	}

	// Propagate compressed pointers flag from features to version profile.
	// Also detect build mode (PRODUCT vs Debug/Profile) from features.
	if info.Version != nil {
		if (info.IsolateHeader != nil && info.IsolateHeader.HasFeature("compressed-pointers")) ||
			(info.VmHeader != nil && info.VmHeader.HasFeature("compressed-pointers")) {
			info.Version.CompressedPointers = true
		}

		// Detect build mode from the features string. Dart::FeaturesString
		// writes exactly one of "debug" / "product" / "release" as the FIRST
		// token; there is no "profile" token (see BuildMode's doc comment).
		//
		// Absence of all three means we could not read a features string at
		// all, in which case we keep the BuildProduct default rather than
		// guessing debug -- a release APK is overwhelmingly the common case,
		// and the previous "anything that isn't product is debug" fallback
		// mislabelled both "release" builds and unreadable headers.
		features := ""
		if info.IsolateHeader != nil {
			features = info.IsolateHeader.Features
		} else if info.VmHeader != nil {
			features = info.VmHeader.Features
		}
		info.Version.BuildMode = buildModeFromFeatures(features)

		// Warn loudly on non-PRODUCT: this is not a "reduced fidelity" mode,
		// it is unsupported. Code objects gain return_address_metadata_ and
		// comments_ refs that CodeNumRefs does not model, which desyncs the
		// fill stream at the first Code cluster.
		if !info.Version.BuildMode.IsProduct() {
			diags.Addf(0, dartfmt.DiagInvalid,
				"non-PRODUCT build detected (features mode %q); only PRODUCT "+
					"snapshots are supported -- Code fill has 2 extra refs in "+
					"!defined(PRODUCT) builds and will desync",
				info.Version.BuildMode.String())
		}
	}

	info.Diags = diags.Items()
	return info, nil
}

// findClusterDataStart returns the byte offset where clustered data begins
// within a snapshot data region. Duplicated from cluster package to avoid
// circular imports.
func findClusterDataStart(data []byte) (int, error) {
	const minHeader = 0x35
	if len(data) < minHeader {
		return 0, fmt.Errorf("data too short (%d < %d)", len(data), minHeader)
	}
	featStart := 0x34
	for i := featStart; i < len(data); i++ {
		if data[i] == 0 {
			return i + 1, nil
		}
		if i-featStart > 1024 {
			return 0, fmt.Errorf("features string too long")
		}
	}
	return 0, fmt.Errorf("unterminated features string")
}

// capRegionSize computes a bounded read size for a region whose symbol has size 0.
// Uses the gap to the next known VA or the segment end.
func capRegionSize(ef *elfx.File, va uint64) uint64 {
	const maxCap = 256 * 1024 * 1024 // 256 MiB hard cap

	// Find the PT_LOAD segment containing this VA and use its end as bound.
	for _, seg := range ef.LoadSegments() {
		if va >= seg.Vaddr && va < seg.Vaddr+seg.Filesz {
			remaining := seg.Vaddr + seg.Filesz - va
			if remaining > maxCap {
				remaining = maxCap
			}
			return remaining
		}
	}
	return 0
}

// Snapshot data header layout (observed from Dart AOT snapshots):
//
//	+0x00: magic       [4]byte  {0xf5, 0xf5, 0xdc, 0xdc}
//	+0x04: size        uint32   (little-endian, blob size)
//	+0x08: padding     [8]byte  (zeros + kind field)
//	+0x10: padding     [4]byte  (zeros)
//	+0x14: hash        [32]byte (ASCII hex, snapshot version hash)
//	+0x34: features    []byte   (null-terminated, space-separated)
const (
	headerMinSize  = 0x35 // minimum to read magic + size + hash
	hashOffset     = 0x14
	hashLen        = 32
	featuresOffset = 0x34
)

// parseHeader extracts structured fields from a Dart snapshot data blob header.
func parseHeader(data []byte) (*Header, error) {
	if len(data) < headerMinSize {
		return nil, errors.New("header too short")
	}
	var h Header
	copy(h.Magic[:], data[:4])
	if h.Magic != snapshotMagic {
		return nil, fmt.Errorf("bad magic: %x (want %x)", h.Magic, snapshotMagic)
	}

	// Bytes 4-11: length (int64 LE, excludes magic).
	h.Length = int64(data[4]) | int64(data[5])<<8 | int64(data[6])<<16 | int64(data[7])<<24 |
		int64(data[8])<<32 | int64(data[9])<<40 | int64(data[10])<<48 | int64(data[11])<<56
	h.TotalSize = h.Length + 4 // add magic size

	// Bytes 12-19: kind (int64 LE).
	kind := int64(data[12]) | int64(data[13])<<8 | int64(data[14])<<16 | int64(data[15])<<24 |
		int64(data[16])<<32 | int64(data[17])<<40 | int64(data[18])<<48 | int64(data[19])<<56
	h.Kind = SnapshotKind(kind)

	// Offset 0x14: 32-char hex snapshot version hash.
	if len(data) >= hashOffset+hashLen {
		hashBytes := data[hashOffset : hashOffset+hashLen]
		validHex := true
		for _, b := range hashBytes {
			if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
				validHex = false
				break
			}
		}
		if validHex {
			h.SnapshotHash = string(hashBytes)
		}
	}

	// Offset 0x34: null-terminated features string.
	if len(data) > featuresOffset {
		featEnd := featuresOffset
		for featEnd < len(data) && data[featEnd] != 0 {
			featEnd++
			if featEnd-featuresOffset > 1024 { // sanity cap
				break
			}
		}
		if featEnd > featuresOffset {
			h.Features = string(data[featuresOffset:featEnd])
		}
	}

	return &h, nil
}
