// Package snapshot locates and extracts Dart snapshot regions from libapp.so.
package snapshot

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
)

var (
	// ErrNoSnapshotSymbols means the ELF is structurally valid but does not
	// expose either supported Dart AOT snapshot symbol layout.
	ErrNoSnapshotSymbols = errors.New("snapshot: no supported snapshot symbols")
	// ErrMalformedSymbolLayout means the ELF exposes only part of a supported
	// layout, or mixes the mutually-exclusive legacy and unified layouts.
	ErrMalformedSymbolLayout = errors.New("snapshot: malformed snapshot symbol layout")
	// ErrConflictingSnapshotIdentity means a legacy VM/isolate pair carries
	// different version hashes. The Dart VM writes Version::SnapshotString() to
	// both snapshot headers, so choosing either value would hide corrupted or
	// attacker-controlled identity evidence.
	ErrConflictingSnapshotIdentity = errors.New("snapshot: conflicting snapshot identity")
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
	// Verified against the exact local 3.12.2 and 3.13.0 SDK working trees:
	// runtime/include/dart_api.h in 3.12.2 defines kVmSnapshotDataCSymbol /
	// kIsolateSnapshotDataCSymbol and their Instructions counterparts, while
	// 3.13.0 defines only kSnapshotDataCSymbol and kSnapshotTextCSymbol. That
	// this is deliberate is visible in the SDK itself:
	// pkg/native_stack_traces/lib/src/constants.dart@3.13.0 keeps the
	// old four as oldVmSymbolName / oldIsolateSymbolName for reading older
	// snapshots, and ImageWriter::SectionSymbol lost its `bool vm` parameter,
	// so there is no VM-vs-isolate distinction at the image level any more.
	SymUnifiedSnapshotData = "_kDartSnapshotData"
	SymUnifiedSnapshotText = "_kDartSnapshotText"
)

type resolvedSnapshotSymbol struct {
	name string
	va   uint64
	size uint64
}

// resolveSnapshotSymbols validates the mutually-exclusive snapshot symbol
// layouts without reading snapshot payloads. Supported root AOT ELFs expose
// either the four legacy VM/isolate symbols (through Dart 3.12) or the unified
// data/text pair (Dart 3.13+). Partial or mixed layouts are structural errors.
func resolveSnapshotSymbols(ef *elfx.File) ([]resolvedSnapshotSymbol, bool, error) {
	if ef == nil {
		return nil, false, fmt.Errorf("snapshot: nil ELF")
	}
	resolve := func(names []string) ([]resolvedSnapshotSymbol, error) {
		out := make([]resolvedSnapshotSymbol, 0, len(names))
		for _, name := range names {
			va, size, err := ef.DynamicSnapshotSymbol(name)
			if errors.Is(err, elfx.ErrNoSymbol) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("snapshot: symbol %s: %w", name, err)
			}
			out = append(out, resolvedSnapshotSymbol{name: name, va: va, size: size})
		}
		return out, nil
	}
	legacyNames := []string{
		SymVmSnapshotData,
		SymVmSnapshotInstructions,
		SymIsolateSnapshotData,
		SymIsolateSnapshotInstructions,
	}
	unifiedNames := []string{SymUnifiedSnapshotData, SymUnifiedSnapshotText}
	legacy, err := resolve(legacyNames)
	if err != nil {
		return nil, false, err
	}
	unified, err := resolve(unifiedNames)
	if err != nil {
		return nil, false, err
	}
	switch {
	case len(legacy) == 0 && len(unified) == 0:
		return nil, false, ErrNoSnapshotSymbols
	case len(legacy) == len(legacyNames) && len(unified) == 0:
		return legacy, false, nil
	case len(legacy) == 0 && len(unified) == len(unifiedNames):
		return unified, true, nil
	default:
		return nil, false, fmt.Errorf("%w: legacy=%d/%d unified=%d/%d",
			ErrMalformedSymbolLayout, len(legacy), len(legacyNames), len(unified), len(unifiedNames))
	}
}

// Identity is the small, structured identity portion of an AOT snapshot. It
// deliberately reports the version hash as a fact and does not translate it to
// a Dart SDK version: snapshot/version.go maps hashes to parser profiles, and
// those profiles are not an exact-version identity oracle.
type Identity struct {
	SnapshotHash string `json:"snapshot_hash"`
	Unified      bool   `json:"unified_snapshot,omitempty"`
}

// ExtractIdentity reads only the fixed snapshot identity header from mapped
// data symbols. It never materializes instructions or full snapshot regions.
// Legacy VM and isolate headers must carry the same version hash; a mismatch is
// returned as an explicit error instead of silently preferring one side.
func ExtractIdentity(ef *elfx.File) (*Identity, error) {
	symbols, unified, err := resolveSnapshotSymbols(ef)
	if err != nil {
		return nil, err
	}
	var hashes []string
	for _, sym := range symbols {
		if sym.name != SymVmSnapshotData && sym.name != SymIsolateSnapshotData && sym.name != SymUnifiedSnapshotData {
			continue
		}
		hash, err := readIdentityHash(ef, sym)
		if err != nil {
			return nil, fmt.Errorf("snapshot: identity %s: %w", sym.name, err)
		}
		hashes = append(hashes, hash)
	}
	if unified {
		if len(hashes) != 1 {
			return nil, fmt.Errorf("%w: unified snapshot has %d data identities", ErrMalformedSymbolLayout, len(hashes))
		}
		return &Identity{SnapshotHash: hashes[0], Unified: true}, nil
	}
	if len(hashes) != 2 {
		return nil, fmt.Errorf("%w: legacy snapshot has %d data identities", ErrMalformedSymbolLayout, len(hashes))
	}
	hash, err := consistentSnapshotHash(hashes[0], hashes[1])
	if err != nil {
		return nil, err
	}
	return &Identity{SnapshotHash: hash}, nil
}

// consistentSnapshotHash enforces the legacy Full-AOT identity invariant.
// Both the VM and isolate serializers write Version::SnapshotString():
// SDK @2.10.0 runtime/vm/clustered_snapshot.cc:5970-5982 and
// @3.6.2 runtime/vm/app_snapshot.cc:8518-8531. Therefore two non-empty,
// different hashes are contradictory evidence, never a "prefer VM" choice.
// One side may be empty in best-effort full parsing when its header is damaged;
// in that case the surviving structured hash remains usable but the header
// diagnostic is preserved separately by Extract.
func consistentSnapshotHash(vmHash, isolateHash string) (string, error) {
	if vmHash != "" && isolateHash != "" && vmHash != isolateHash {
		return "", fmt.Errorf("%w: VM=%s isolate=%s", ErrConflictingSnapshotIdentity, vmHash, isolateHash)
	}
	if vmHash != "" {
		return vmHash, nil
	}
	return isolateHash, nil
}

func readIdentityHash(ef *elfx.File, sym resolvedSnapshotSymbol) (string, error) {
	const identityBytes = hashOffset + hashLen
	if sym.size != 0 && sym.size < identityBytes {
		return "", fmt.Errorf("symbol size %d is smaller than identity header %d", sym.size, identityBytes)
	}
	remaining, err := ef.FileBackedRemaining(sym.va)
	if err != nil {
		return "", err
	}
	if remaining < identityBytes {
		return "", fmt.Errorf("mapped extent %d is smaller than identity header %d", remaining, identityBytes)
	}
	data, err := ef.ReadBytesAtVA(sym.va, identityBytes)
	if err != nil {
		return "", err
	}
	return parseIdentityHash(data, sym.size, remaining)
}

func parseIdentityHash(data []byte, symSize, mappedRemaining uint64) (string, error) {
	const identityBytes = hashOffset + hashLen
	if len(data) < identityBytes {
		return "", fmt.Errorf("identity header has %d bytes, want at least %d", len(data), identityBytes)
	}
	var magic [4]byte
	copy(magic[:], data[:4])
	if magic != snapshotMagic {
		return "", fmt.Errorf("bad magic: %x (want %x)", magic, snapshotMagic)
	}
	rawLength := binary.LittleEndian.Uint64(data[4:12])
	if rawLength > uint64(math.MaxInt64-4) {
		return "", fmt.Errorf("snapshot length 0x%x overflows signed size", rawLength)
	}
	total := rawLength + 4
	if total < headerMinSize {
		return "", fmt.Errorf("snapshot total size %d is smaller than minimum header %d", total, headerMinSize)
	}
	if symSize != 0 && total > symSize {
		return "", fmt.Errorf("snapshot declares %d bytes, symbol contains %d", total, symSize)
	}
	if total > mappedRemaining {
		return "", fmt.Errorf("snapshot declares %d bytes, mapped extent contains %d", total, mappedRemaining)
	}
	hashBytes := data[hashOffset : hashOffset+hashLen]
	for _, b := range hashBytes {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
			return "", fmt.Errorf("snapshot version hash is not 32 lowercase hex characters")
		}
	}
	return string(hashBytes), nil
}

// snapshotMagic is the 4-byte magic at the start of a Dart snapshot data blob.
var snapshotMagic = [4]byte{0xf5, 0xf5, 0xdc, 0xdc}

// Region describes one snapshot region extracted from libapp.so.
type Region struct {
	Name         string `json:"name"`
	VA           uint64 `json:"va"`
	FileOffset   uint64 `json:"file_offset"`
	SymSize      uint64 `json:"sym_size"`                         // from ELF symbol; 0 if unknown
	DataSize     uint64 `json:"data_size"`                        // materialized file-backed bytes
	DeclaredSize uint64 `json:"declared_snapshot_size,omitempty"` // data-header size; data symbols only
	SHA256       string `json:"sha256"`                           // hex; empty if data not extracted
	Data         []byte `json:"-"`                                // raw bytes; not serialized
}

// SnapshotKind identifies the snapshot type.
type SnapshotKind int64

const (
	// Dart 2.12.0 through 3.12.x Snapshot::Kind (runtime/vm/snapshot.h).
	// Dart 2.10 predates kFullCore, so kFullAOT is still ordinal 2 there.
	KindFull        SnapshotKind = 0
	KindCore        SnapshotKind = 1
	KindFullJIT     SnapshotKind = 2
	KindFullAOT     SnapshotKind = 3
	KindFullAOTV210 SnapshotKind = 2

	// Dart 3.13.0+ Snapshot::Kind (kFullCore and kNone removed)
	// 0=kFull, 1=kFullJIT, 2=kFullAOT, 3=kModule
	KindFullAOTV313 SnapshotKind = 2
	KindModuleV313  SnapshotKind = 3
)

func (k SnapshotKind) String() string {
	switch k {
	case KindFull:
		return "Full"
	case KindCore:
		return "FullCore"
	case KindFullJIT: // Also FullAOT on Dart 2.10 and 3.13+.
		return "FullJIT/FullAOT(v2.10/v3.13+)"
	case KindFullAOT: // Also Module on 3.13.0+
		return "FullAOT/Module(v3.13+)"
	default:
		return fmt.Sprintf("Unknown(%d)", k)
	}
}

// Header holds parsed fields from a Dart snapshot data header.
// Layout:
//
//	+0x00: magic   int32  (0xdcdcf5f5)
//	+0x04: length  int64  (excludes magic; total = stored + 4)
//	+0x0c: kind    int64  (versioned Snapshot::Kind enum; validate via VersionProfile)
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
// Missing, contradictory, or unrecognised input is BuildUnknown: PRODUCT is a
// wire-format fact and must never be inferred from popularity.
func buildModeFromFeatures(features string) BuildMode {
	tokens := strings.Split(features, " ")
	if len(tokens) == 0 {
		return BuildUnknown
	}
	var mode BuildMode
	switch tokens[0] {
	case "product":
		mode = BuildProduct
	case "release":
		mode = BuildRelease
	case "debug":
		mode = BuildDebug
	default:
		return BuildUnknown
	}
	// Dart::FeaturesString writes the build token exactly once, first. A second
	// mode token later in the string is contradictory evidence, not another flag.
	for _, token := range tokens[1:] {
		if token == "product" || token == "release" || token == "debug" {
			return BuildUnknown
		}
	}
	return mode
}

func compressedPointersFromFeatures(style CompressionFeatureStyle, features string) (bool, error) {
	switch style {
	case CompressionFeatureFixedUncompressed:
		if hasFeature(features, "compressed") || hasFeature(features, "compressed-pointers") || hasFeature(features, "no-compressed-pointers") {
			return false, fmt.Errorf("compression token present before compressed-pointer build support")
		}
		return false, nil
	case CompressionFeatureLegacyPositiveOnly:
		// SDK <=2.14 emits only "compressed" under DART_COMPRESSED_POINTERS.
		// Absence is therefore the old uncompressed encoding.
		if hasFeature(features, "compressed-pointers") || hasFeature(features, "no-compressed-pointers") {
			return false, fmt.Errorf("legacy compression feature vocabulary mixed with modern token")
		}
		return hasFeature(features, "compressed"), nil
	case CompressionFeatureExplicit:
		positive := hasFeature(features, "compressed-pointers")
		negative := hasFeature(features, "no-compressed-pointers")
		if positive == negative {
			return false, fmt.Errorf("expected exactly one of compressed-pointers/no-compressed-pointers")
		}
		return positive, nil
	default:
		return false, fmt.Errorf("unverified compression feature vocabulary")
	}
}

func targetFeaturesCompatible(style TargetFeatureStyle, features string, isARM64 bool) error {
	tokens := strings.Fields(features)
	has := func(want string) bool {
		for _, token := range tokens {
			if token == want {
				return true
			}
		}
		return false
	}
	count := func(vocabulary []string) (int, string) {
		n, found := 0, ""
		for _, token := range vocabulary {
			if has(token) {
				n++
				found = token
			}
		}
		return n, found
	}

	switch style {
	case TargetFeatureLegacyABI:
		// SDK @2.10.0..2.18.0 runtime/vm/dart.cc FeaturesString uses these
		// architecture/ABI tokens and has no separate OS token.
		n, target := count([]string{
			"arm64-sysv", "arm64-fuchsia", "x64-sysv", "x64-win",
			"ia32", "arm-eabi", "arm-ios", "riscv32", "riscv64",
		})
		if n != 1 {
			return fmt.Errorf("expected exactly one legacy architecture/ABI token")
		}
		want := "x64-sysv"
		if isARM64 {
			want = "arm64-sysv"
		}
		if target != want {
			return fmt.Errorf("snapshot target %q is incompatible with ELF machine (want %s)", target, want)
		}
		return nil

	case TargetFeatureArchAndOS:
		// SDK @2.19.0+ runtime/vm/dart.cc emits a bare architecture followed by
		// exactly one OS token. The pipeline implements ELF SysV semantics only,
		// so Windows/Fuchsia/iOS/macOS snapshots are unsupported even when their
		// CPU family matches.
		archCount, arch := count([]string{"arm64", "x64", "ia32", "arm", "riscv32", "riscv64"})
		if archCount != 1 {
			return fmt.Errorf("expected exactly one architecture token")
		}
		wantArch := "x64"
		if isARM64 {
			wantArch = "arm64"
		}
		if arch != wantArch {
			return fmt.Errorf("snapshot architecture %q is incompatible with ELF machine (want %s)", arch, wantArch)
		}
		osCount, targetOS := count([]string{"android", "fuchsia", "ios", "macos", "linux", "windows"})
		if osCount != 1 {
			return fmt.Errorf("expected exactly one target OS token")
		}
		if targetOS != "android" && targetOS != "linux" {
			return fmt.Errorf("snapshot target OS %q is unsupported for ELF analysis", targetOS)
		}
		return nil

	default:
		return fmt.Errorf("unverified target feature vocabulary")
	}
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
	FormatProbe         *FormatProbe    `json:"format_probe,omitempty"`
	Diags               []dartfmt.Diag  `json:"diagnostics,omitempty"`
}

// PrimaryHeader returns the header that identifies the snapshot carried by
// this binary. Legacy AOT ELFs have a VM snapshot and an isolate snapshot; the
// VM header is the version/build identity source there. Dart 3.13+ unified
// snapshots deliberately have no VM header, so the isolate-mapped unified
// header is the only header and must be used instead.
func (i *Info) PrimaryHeader() *Header {
	if i == nil {
		return nil
	}
	if i.UnifiedSnapshot {
		return i.IsolateHeader
	}
	if i.VmHeader != nil {
		return i.VmHeader
	}
	return i.IsolateHeader
}

// SnapshotHash returns the version hash from PrimaryHeader, or an empty string
// when no snapshot header was parsed. Callers should use this instead of
// directly dereferencing VmHeader: unified snapshots intentionally leave it nil.
func (i *Info) SnapshotHash() string {
	if h := i.PrimaryHeader(); h != nil {
		return h.SnapshotHash
	}
	return ""
}

// Extract locates and reads snapshot regions from an opened ELF file.
func Extract(ef *elfx.File, opts dartfmt.Options) (*Info, error) {
	var diags dartfmt.Diags
	info := &Info{}
	const maxSnapshotRegionBytes = uint64(256 << 20)
	const maxSnapshotAggregateBytes = uint64(512 << 20)
	type loadedRegion struct {
		name      string
		off, size uint64
	}
	var loaded []loadedRegion
	var aggregateBytes uint64
	overlaps := func(aOff, aSize, bOff, bSize uint64) bool {
		if aSize == 0 || bSize == 0 {
			return false
		}
		if aOff <= bOff {
			return bOff-aOff < aSize
		}
		return aOff-bOff < bSize
	}

	// Resolve the snapshot symbol layout before reading any region. The same
	// resolver also drives ExtractIdentity so format boundaries cannot drift
	// between full parsing and identity-only fingerprinting.
	resolved, unified, err := resolveSnapshotSymbols(ef)
	if err != nil {
		return nil, err
	}
	info.UnifiedSnapshot = unified
	for _, t := range resolved {
		var region *Region
		switch t.name {
		case SymVmSnapshotData:
			region = &info.VmData
		case SymVmSnapshotInstructions:
			region = &info.VmInstructions
		case SymIsolateSnapshotData, SymUnifiedSnapshotData:
			region = &info.IsolateData
		case SymIsolateSnapshotInstructions, SymUnifiedSnapshotText:
			region = &info.IsolateInstructions
		default:
			return nil, fmt.Errorf("snapshot: unexpected resolved symbol %s", t.name)
		}
		region.Name = t.name
		va, size := t.va, t.size
		region.VA = va
		region.SymSize = size

		off, err := ef.VAToFileOffset(va)
		if err != nil {
			return nil, fmt.Errorf("snapshot: VA mapping for %s: %w", t.name, err)
		}
		region.FileOffset = off

		// Read region data. A non-zero ELF symbol size is authoritative. A zero-size
		// snapshot symbol is resolved from the snapshot/image wire format itself;
		// never retain an arbitrary PT_LOAD remainder as if it were one region.
		readSize := size
		if readSize == 0 {
			readSize, err = zeroSizeSnapshotRegionSize(ef, t, resolved)
			if err != nil {
				return nil, fmt.Errorf("snapshot: size zero-size symbol %s: %w", t.name, err)
			}
		}
		if readSize > 0 {
			if readSize > maxSnapshotRegionBytes {
				return nil, fmt.Errorf("snapshot: symbol %s size 0x%x exceeds per-region limit 0x%x", t.name, readSize, maxSnapshotRegionBytes)
			}

			// Dart's ImageWriter gives each logical snapshot region its own section
			// symbol/label (legacy VM vs isolate data/text, or unified data vs text).
			// Therefore exact aliases are just as malformed as partial overlaps:
			// accepting one would let two identities/images claim the same bytes and
			// would also evade the aggregate materialization budget.
			for _, lr := range loaded {
				if off == lr.off && readSize == lr.size {
					return nil, fmt.Errorf("snapshot: regions %s and %s alias the same backing range", lr.name, t.name)
				}
				if overlaps(off, readSize, lr.off, lr.size) {
					return nil, fmt.Errorf("snapshot: regions %s and %s overlap", lr.name, t.name)
				}
			}
			if aggregateBytes > maxSnapshotAggregateBytes-readSize {
				return nil, fmt.Errorf("snapshot: aggregate region budget exceeds 0x%x bytes", maxSnapshotAggregateBytes)
			}
			maxInt := uint64(^uint(0) >> 1)
			if readSize > maxInt {
				return nil, fmt.Errorf("snapshot: symbol %s size 0x%x exceeds addressable read size", t.name, readSize)
			}
			data, err := ef.ReadBytesAtVA(va, int(readSize))
			if err != nil {
				return nil, fmt.Errorf("snapshot: read %s: %w", t.name, err)
			} else {
				region.Data = data
				region.DataSize = uint64(len(data))
				h := sha256.Sum256(data)
				region.SHA256 = hex.EncodeToString(h[:])
				aggregateBytes += readSize
				loaded = append(loaded, loadedRegion{name: t.name, off: off, size: readSize})
			}
		}
	}

	// Parse headers from snapshot data regions. The serialized minimum is 0x35,
	// not 64; refusing a valid short header here made the extractor and
	// parseHeader disagree about the wire minimum.
	if len(info.VmData.Data) >= headerMinSize {
		hdr, err := parseHeader(info.VmData.Data)
		if err != nil {
			if opts.Mode == dartfmt.ModeStrict {
				return nil, fmt.Errorf("snapshot: vm header: %w", err)
			}
			diags.Add(info.VmData.VA, dartfmt.DiagInvalid, fmt.Sprintf("vm header: %v", err))
		} else {
			info.VmHeader = hdr
			info.VmData.DeclaredSize = uint64(hdr.TotalSize)
		}
	}
	if len(info.IsolateData.Data) >= headerMinSize {
		hdr, err := parseHeader(info.IsolateData.Data)
		if err != nil {
			if opts.Mode == dartfmt.ModeStrict {
				return nil, fmt.Errorf("snapshot: isolate header: %w", err)
			}
			diags.Add(info.IsolateData.VA, dartfmt.DiagInvalid, fmt.Sprintf("isolate header: %v", err))
		} else {
			info.IsolateHeader = hdr
			info.IsolateData.DeclaredSize = uint64(hdr.TotalSize)
		}
	}

	// Detect the parser profile from the snapshot compatibility hash. This is
	// deliberately not an exact-version identity claim: make_version.py derives
	// the hash from snapshot-format source files, so releases can share a format.
	//
	// The hash normally comes from the VM snapshot header. Under the 3.13.0+
	// unified layout there is no VM snapshot, so the single header carries it.
	vmHash, isolateHash := "", ""
	if info.VmHeader != nil {
		vmHash = info.VmHeader.SnapshotHash
	}
	if info.IsolateHeader != nil {
		isolateHash = info.IsolateHeader.SnapshotHash
	}
	snapshotHash := isolateHash
	hashRegion := info.IsolateData
	if !info.UnifiedSnapshot {
		var err error
		snapshotHash, err = consistentSnapshotHash(vmHash, isolateHash)
		if err != nil {
			return nil, err
		}
		if vmHash != "" {
			hashRegion = info.VmData
		}
	}
	if snapshotHash != "" {
		info.Version = DetectVersion(snapshotHash)
		// An unknown compatibility hash may still be classified into a coarse
		// header/tag family for diagnostics. It must not become a parser profile.
		if info.Version == nil && hashRegion.Data != nil {
			if cs, err := FindClusterDataStart(hashRegion.Data); err == nil {
				info.FormatProbe = ProbeTagStyle(hashRegion.Data, cs)
			}
			msg := fmt.Sprintf("unknown snapshot compatibility hash %s; refusing version-specific parse", snapshotHash)
			if info.FormatProbe != nil {
				msg += fmt.Sprintf(" (coarse family %s)", info.FormatProbe.Family)
			}
			diags.Add(0, dartfmt.DiagInvalid, msg)
		}
	}

	// Validate dimensions that are carried outside the clustered stream itself.
	// A known hash is not enough: a corrupt/fabricated binary can combine that
	// hash with the wrong symbol era, Snapshot::Kind, or feature vocabulary.
	if info.Version != nil {
		// Preserve the exact static profile before unsupported() can mark the live
		// per-binary copy unsupported. Best-effort mode should still validate all
		// remaining image dimensions against the canonical SDK profile after an
		// earlier independent symbol/kind mismatch has already been diagnosed.
		imageProfile := *info.Version
		unsupported := func(format string, args ...any) error {
			msg := fmt.Sprintf(format, args...)
			diags.Add(0, dartfmt.DiagInvalid, msg)
			info.Version.Supported = false
			if opts.Mode == dartfmt.ModeStrict {
				return fmt.Errorf("snapshot: %s", msg)
			}
			return nil
		}

		wantUnified := info.Version.SnapshotSymbols == SnapshotSymbolsUnified
		if info.Version.SnapshotSymbols == SnapshotSymbolsUnknown || wantUnified != info.UnifiedSnapshot {
			if err := unsupported("snapshot symbol layout disagrees with format profile %s", info.Version.DartVersion); err != nil {
				return nil, err
			}
		}

		headers := []struct {
			label string
			hdr   *Header
		}{
			{"vm", info.VmHeader},
			{"isolate", info.IsolateHeader},
		}
		for _, item := range headers {
			if item.hdr == nil {
				continue
			}
			if item.hdr.Kind != info.Version.FullAOTKind {
				if err := unsupported("%s header kind %d is not FullAOT kind %d for format profile %s",
					item.label, item.hdr.Kind, info.Version.FullAOTKind, info.Version.DartVersion); err != nil {
					return nil, err
				}
			}
		}

		// Validate image extents at the extraction boundary, not only when a
		// downstream consumer happens to ask for code/ROData. This catches a
		// known hash paired with a truncated or wrong-era Image before any
		// cluster-derived offset can depend on it. Keep an immutable supported
		// copy for validation because unsupported() deliberately flips the live
		// profile after the first wire-format error in best-effort mode.
		dataImages := []struct {
			label  string
			region Region
			hdr    *Header
		}{
			{"vm", info.VmData, info.VmHeader},
			{"isolate", info.IsolateData, info.IsolateHeader},
		}
		for _, item := range dataImages {
			if item.hdr == nil || len(item.region.Data) == 0 {
				continue
			}
			if err := validateDataImageRegion(item.region.Data, item.hdr, &imageProfile); err != nil {
				if err2 := unsupported("%s data image is incompatible with format profile %s: %v",
					item.label, info.Version.DartVersion, err); err2 != nil {
					return nil, err2
				}
			}
		}
		instructionImages := []struct {
			label  string
			region Region
		}{
			{"vm", info.VmInstructions},
			{"isolate", info.IsolateInstructions},
		}
		for _, item := range instructionImages {
			if len(item.region.Data) == 0 {
				continue
			}
			if _, _, _, err := CodeRegion(item.region.Data, &imageProfile); err != nil {
				if err2 := unsupported("%s instructions image is incompatible with format profile %s: %v",
					item.label, info.Version.DartVersion, err); err2 != nil {
					return nil, err2
				}
			}
		}

		type featureState struct {
			mode       BuildMode
			compressed bool
		}
		var states []featureState
		for _, item := range headers {
			if item.hdr == nil {
				continue
			}
			mode := buildModeFromFeatures(item.hdr.Features)
			if mode == BuildUnknown {
				if err := unsupported("%s features do not prove exactly one SDK build mode", item.label); err != nil {
					return nil, err
				}
			}
			if err := targetFeaturesCompatible(info.Version.TargetFeatures, item.hdr.Features, ef.IsARM64()); err != nil {
				if err2 := unsupported("%s target features are incompatible with format profile %s: %v",
					item.label, info.Version.DartVersion, err); err2 != nil {
					return nil, err2
				}
			}
			compressed, err := compressedPointersFromFeatures(info.Version.CompressionFeatures, item.hdr.Features)
			if err != nil {
				if err2 := unsupported("%s compression features are incompatible with format profile %s: %v",
					item.label, info.Version.DartVersion, err); err2 != nil {
					return nil, err2
				}
			}
			states = append(states, featureState{mode: mode, compressed: compressed})
		}
		if len(states) == 0 {
			if err := unsupported("no valid snapshot features available for format profile %s", info.Version.DartVersion); err != nil {
				return nil, err
			}
		} else {
			info.Version.BuildMode = states[0].mode
			info.Version.CompressedPointers = states[0].compressed
			for _, st := range states[1:] {
				if st != states[0] {
					if err := unsupported("VM/isolate feature dimensions disagree for format profile %s", info.Version.DartVersion); err != nil {
						return nil, err
					}
					break
				}
			}
		}

		// Non-PRODUCT is not a reduced-fidelity mode. Code objects gain extra
		// refs and the PRODUCT cluster reader would desynchronise.
		if !info.Version.BuildMode.IsProduct() {
			if err := unsupported("non-PRODUCT %s build is unsupported; PRODUCT Code layout cannot be used",
				info.Version.BuildMode.String()); err != nil {
				return nil, err
			}
		}
	}
	if opts.Mode == dartfmt.ModeStrict && info.Version == nil {
		return nil, fmt.Errorf("snapshot: no valid snapshot header/version profile")
	}

	info.Diags = diags.Items()
	return info, nil
}

// FindClusterDataStart returns the byte offset where clustered data
// begins within a snapshot data region: past the header and past the
// null-terminated features string that starts at 0x34.
//
// This existed twice, here and as cluster.FindClusterDataStart, with a
// comment here saying it was "duplicated from cluster package to avoid
// circular imports". There was no cycle to avoid: cluster imports
// snapshot and snapshot does not import cluster, so the shared copy can
// only live here, which is also where it belongs -- this parses the
// snapshot header, not a cluster.
//
// Two copies of a header layout is the shape of bug this project has
// already paid for elsewhere: a correction to the 0x34 offset or the
// 1024-byte bound would have had to land in both, and nothing would have
// reported it if only one were updated.
func FindClusterDataStart(data []byte) (int, error) {
	h, err := parseHeader(data)
	if err != nil {
		return 0, err
	}
	// parseHeader has already proved the terminator exists inside the declared
	// snapshot length and inside the 1024-byte feature budget.
	return featuresOffset + len(h.Features) + 1, nil
}

func nextSnapshotSymbolDelta(va uint64, resolved []resolvedSnapshotSymbol) (uint64, bool) {
	var best uint64
	found := false
	for _, other := range resolved {
		if other.va <= va {
			continue
		}
		delta := other.va - va
		if !found || delta < best {
			best, found = delta, true
		}
	}
	return best, found
}

func checkedAddUint64(a, b uint64) (uint64, bool) {
	if b > math.MaxUint64-a {
		return 0, false
	}
	return a + b, true
}

func roundUpUint64(value, alignment uint64) (uint64, bool) {
	if alignment == 0 || alignment&(alignment-1) != 0 {
		return 0, false
	}
	mask := alignment - 1
	if value > math.MaxUint64-mask {
		return 0, false
	}
	return (value + mask) &^ mask, true
}

func isSnapshotDataSymbol(name string) bool {
	return name == SymVmSnapshotData || name == SymIsolateSnapshotData || name == SymUnifiedSnapshotData
}

func isSnapshotInstructionsSymbol(name string) bool {
	return name == SymVmSnapshotInstructions || name == SymIsolateSnapshotInstructions || name == SymUnifiedSnapshotText
}

func validateDataImageRegion(data []byte, hdr *Header, profile *VersionProfile) error {
	if hdr == nil || hdr.TotalSize <= 0 {
		return fmt.Errorf("valid snapshot header required")
	}
	if !IsExactSupportedProfile(profile) || profile.DataImageAlignment <= 0 || profile.ImageHeaderSize == 0 {
		return fmt.Errorf("exact supported image profile required")
	}
	start, ok := roundUpUint64(uint64(hdr.TotalSize), uint64(profile.DataImageAlignment))
	if !ok {
		return fmt.Errorf("snapshot size %d cannot be aligned to %d", hdr.TotalSize, profile.DataImageAlignment)
	}
	if start > uint64(len(data)) || uint64(len(data))-start < 8 {
		return fmt.Errorf("DataImage header at 0x%x exceeds region size 0x%x", start, len(data))
	}
	imageSize := binary.LittleEndian.Uint64(data[start : start+8])
	if imageSize < profile.ImageHeaderSize {
		return fmt.Errorf("DataImage size %d is smaller than verified Image header %d", imageSize, profile.ImageHeaderSize)
	}
	if imageSize > uint64(len(data))-start {
		return fmt.Errorf("DataImage size 0x%x at 0x%x exceeds region size 0x%x", imageSize, start, len(data))
	}
	return nil
}

// zeroSizeSnapshotRegionSize derives an exact/bounded extent without treating
// unrelated PT_LOAD bytes as snapshot data. Text images are self-sized by the
// first Image word. Data regions contain the clustered snapshot followed by a
// profile-aligned DataImage, whose first word is another exact ImageSize.
//
// For an unknown compatibility hash we deliberately refuse to invent the
// alignment needed to locate DataImage. Such a region is only materializable
// when the next snapshot symbol provides an unambiguous structural boundary;
// semantic parsing will still halt because DetectVersion remains nil.
func zeroSizeSnapshotRegionSize(ef *elfx.File, sym resolvedSnapshotSymbol, resolved []resolvedSnapshotSymbol) (uint64, error) {
	if ef == nil {
		return 0, fmt.Errorf("nil ELF")
	}
	remaining, err := ef.FileBackedRemaining(sym.va)
	if err != nil {
		return 0, err
	}
	limit := remaining
	nextDelta, hasNext := nextSnapshotSymbolDelta(sym.va, resolved)
	if hasNext && nextDelta < limit {
		limit = nextDelta
	}

	if isSnapshotInstructionsSymbol(sym.name) {
		if limit < imageHeaderSize {
			return 0, fmt.Errorf("mapped/bounded extent %d is smaller than Image header %d", limit, imageHeaderSize)
		}
		prefix, err := ef.ReadBytesAtVA(sym.va, imageHeaderSize)
		if err != nil {
			return 0, err
		}
		imageSize := binary.LittleEndian.Uint64(prefix[:8])
		if imageSize < imageHeaderSize {
			return 0, fmt.Errorf("declared Image size %d is smaller than header %d", imageSize, imageHeaderSize)
		}
		if imageSize > limit {
			return 0, fmt.Errorf("declared Image size %d exceeds bounded extent %d", imageSize, limit)
		}
		return imageSize, nil
	}

	if !isSnapshotDataSymbol(sym.name) {
		return 0, fmt.Errorf("unrecognised snapshot region %q", sym.name)
	}
	const identityBytes = hashOffset + hashLen
	if limit < identityBytes {
		return 0, fmt.Errorf("bounded extent %d is smaller than identity header %d", limit, identityBytes)
	}
	prefix, err := ef.ReadBytesAtVA(sym.va, identityBytes)
	if err != nil {
		return 0, err
	}
	hash, err := parseIdentityHash(prefix, 0, limit)
	if err != nil {
		return 0, err
	}
	profile := DetectVersion(hash)
	if profile == nil {
		if hasNext {
			return nextDelta, nil
		}
		return 0, fmt.Errorf("unknown snapshot hash %s has no verified DataImage alignment and no following snapshot-symbol boundary", hash)
	}

	clusteredSize := binary.LittleEndian.Uint64(prefix[4:12]) + 4 // parseIdentityHash validated overflow.
	dataImageStart, ok := roundUpUint64(clusteredSize, uint64(profile.DataImageAlignment))
	if !ok {
		return 0, fmt.Errorf("clustered size %d cannot be aligned to %d", clusteredSize, profile.DataImageAlignment)
	}
	if dataImageStart > limit || limit-dataImageStart < 8 {
		return 0, fmt.Errorf("DataImage header at 0x%x exceeds bounded extent 0x%x", dataImageStart, limit)
	}
	imageVA, ok := checkedAddUint64(sym.va, dataImageStart)
	if !ok {
		return 0, fmt.Errorf("DataImage virtual address overflows uint64")
	}
	imagePrefix, err := ef.ReadBytesAtVA(imageVA, 8)
	if err != nil {
		return 0, err
	}
	imageSize := binary.LittleEndian.Uint64(imagePrefix)
	minImageSize := profile.ImageHeaderSize
	if imageSize < minImageSize {
		return 0, fmt.Errorf("DataImage size %d is smaller than verified Image header %d", imageSize, minImageSize)
	}
	extent, ok := checkedAddUint64(dataImageStart, imageSize)
	if !ok {
		return 0, fmt.Errorf("DataImage extent overflows uint64")
	}
	if extent > limit {
		return 0, fmt.Errorf("DataImage extent 0x%x exceeds bounded region 0x%x", extent, limit)
	}
	return extent, nil
}

// Snapshot data header layout. SDK @2.10.0 runtime/vm/snapshot.h:105-112 and
// @3.13.0:35-42 define the same magic/length/kind prefix with an int64 length.
//
//	+0x00: magic       [4]byte  {0xf5, 0xf5, 0xdc, 0xdc}
//	+0x04: size        int64    (little-endian, excludes magic)
//	+0x0c: kind        int64
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

	// Bytes 4-11: length (uint64 on disk, excludes magic). Validate before
	// converting to the signed public fields; MaxUint64 used to become -1 and
	// then TotalSize=3, which downstream offset arithmetic trusted.
	rawLength := binary.LittleEndian.Uint64(data[4:12])
	if rawLength > uint64(math.MaxInt64-4) {
		return nil, fmt.Errorf("snapshot length 0x%x overflows signed size", rawLength)
	}
	total := rawLength + 4
	if total < headerMinSize {
		return nil, fmt.Errorf("snapshot total size %d is smaller than minimum header %d", total, headerMinSize)
	}
	if total > uint64(len(data)) {
		return nil, fmt.Errorf("snapshot declares %d bytes, only %d available", total, len(data))
	}
	h.Length = int64(rawLength)
	h.TotalSize = int64(total)

	// Bytes 12-19: kind (int64 LE).
	rawKind := binary.LittleEndian.Uint64(data[12:20])
	if rawKind > math.MaxInt64 {
		return nil, fmt.Errorf("snapshot kind 0x%x overflows signed representation", rawKind)
	}
	h.Kind = SnapshotKind(int64(rawKind))

	// Offset 0x14: 32-char lowercase hex snapshot version hash. Identity-only
	// parsing enforces the same invariant; full parsing must not silently turn a
	// malformed hash into "unknown" and then continue with weaker evidence.
	hashBytes := data[hashOffset : hashOffset+hashLen]
	for _, b := range hashBytes {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
			return nil, fmt.Errorf("snapshot version hash is not 32 lowercase hex characters")
		}
	}
	h.SnapshotHash = string(hashBytes)

	// Offset 0x34: null-terminated features string.
	declaredData := data[:int(total)]
	if len(declaredData) > featuresOffset {
		featEnd := featuresOffset
		for featEnd < len(declaredData) && declaredData[featEnd] != 0 {
			featEnd++
			if featEnd-featuresOffset > 1024 {
				return nil, fmt.Errorf("snapshot features string exceeds 1024 bytes")
			}
		}
		if featEnd == len(declaredData) {
			return nil, fmt.Errorf("snapshot features string is unterminated")
		}
		if featEnd > featuresOffset {
			featureBytes := declaredData[featuresOffset:featEnd]
			for _, b := range featureBytes {
				// Dart::FeaturesString is plain printable ASCII. Reject controls
				// (especially CR/LF/tab) so malformed headers cannot become log
				// injection while still satisfying build/compression token checks.
				if b < 0x20 || b > 0x7e {
					return nil, fmt.Errorf("snapshot features string contains non-printable byte 0x%02x", b)
				}
			}
			h.Features = string(featureBytes)
		}
	}

	return &h, nil
}
