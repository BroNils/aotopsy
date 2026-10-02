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
	// Pre-3.13.0 Snapshot::Kind (runtime/vm/snapshot.h)
	KindFull    SnapshotKind = 0
	KindCore    SnapshotKind = 1
	KindFullJIT SnapshotKind = 2
	KindFullAOT SnapshotKind = 3

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
	case KindFullJIT: // Also FullAOT on 3.13.0+
		return "FullJIT/FullAOT(v3.13+)"
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
		off, size uint64
		data      []byte
		hash      string
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

		// Read region data. Use symbol size if available, else cap at a reasonable max.
		readSize := size
		if readSize == 0 {
			// For instruction regions, symbol size is often 0. We'll read a
			// capped amount; the actual size comes from header parsing or
			// region boundary analysis later.
			readSize, err = capRegionSize(ef, va)
			if err != nil {
				return nil, fmt.Errorf("snapshot: bound zero-size symbol %s: %w", t.name, err)
			}
		}
		if readSize > 0 {
			if readSize > maxSnapshotRegionBytes {
				return nil, fmt.Errorf("snapshot: symbol %s size 0x%x exceeds per-region limit 0x%x", t.name, readSize, maxSnapshotRegionBytes)
			}

			// Exact aliases share one backing slice. Partial overlaps are not a
			// valid way to describe independent snapshot regions and previously
			// let a tiny ELF retain the same bytes several times.
			reused := false
			for _, lr := range loaded {
				if off == lr.off && readSize == lr.size {
					region.Data = lr.data
					region.DataSize = uint64(len(lr.data))
					region.SHA256 = lr.hash
					reused = true
					break
				}
				if overlaps(off, readSize, lr.off, lr.size) {
					return nil, fmt.Errorf("snapshot: symbol %s partially overlaps another snapshot region", t.name)
				}
			}
			if reused {
				continue
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
				loaded = append(loaded, loadedRegion{off: off, size: readSize, data: data, hash: region.SHA256})
			}
		}
	}

	// Parse headers from snapshot data regions.
	if len(info.VmData.Data) >= 64 {
		hdr, err := parseHeader(info.VmData.Data)
		if err != nil {
			if opts.Mode == dartfmt.ModeStrict {
				return nil, fmt.Errorf("snapshot: vm header: %w", err)
			}
			diags.Add(info.VmData.VA, dartfmt.DiagInvalid, fmt.Sprintf("vm header: %v", err))
		} else {
			info.VmHeader = hdr
		}
	}
	if len(info.IsolateData.Data) >= 64 {
		hdr, err := parseHeader(info.IsolateData.Data)
		if err != nil {
			if opts.Mode == dartfmt.ModeStrict {
				return nil, fmt.Errorf("snapshot: isolate header: %w", err)
			}
			diags.Add(info.IsolateData.VA, dartfmt.DiagInvalid, fmt.Sprintf("isolate header: %v", err))
		} else {
			info.IsolateHeader = hdr
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

		// For unknown hashes, probe the data to determine tag style.
		if info.Version != nil && info.Version.DartVersion == "" && hashRegion.Data != nil {
			if cs, err := FindClusterDataStart(hashRegion.Data); err == nil {
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
			// This is a wire-format incompatibility, not a fidelity downgrade.
			// Mark the profile unsupported even in best-effort mode so callers
			// cannot proceed into PRODUCT cluster layouts after seeing the
			// diagnostic. Strict mode fails immediately with the same reason.
			info.Version.Supported = false
			if opts.Mode == dartfmt.ModeStrict {
				return nil, fmt.Errorf("snapshot: non-PRODUCT %s build is unsupported", info.Version.BuildMode.String())
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
	const minHeader = 0x35 // magic + length + kind + hash
	if len(data) < minHeader {
		return 0, fmt.Errorf("snapshot: data too short (%d < %d)", len(data), minHeader)
	}
	// Features string starts at offset 0x34, null-terminated.
	const featStart = 0x34
	for i := featStart; i < len(data); i++ {
		if data[i] == 0 {
			return i + 1, nil // byte after null terminator
		}
		if i-featStart > 1024 {
			return 0, fmt.Errorf("snapshot: features string too long (no null terminator within 1024 bytes)")
		}
	}
	return 0, fmt.Errorf("snapshot: unterminated features string")
}

// capRegionSize computes a bounded read size for a region whose symbol has size
// 0, using only the remaining bytes in its validated file-backed PT_LOAD.
func capRegionSize(ef *elfx.File, va uint64) (uint64, error) {
	const maxCap = 256 * 1024 * 1024 // 256 MiB hard cap
	remaining, err := ef.FileBackedRemaining(va)
	if err != nil {
		return 0, err
	}
	if remaining > maxCap {
		remaining = maxCap
	}
	return remaining, nil
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
			h.Features = string(declaredData[featuresOffset:featEnd])
		}
	}

	return &h, nil
}
