// Package fingerprint reports bounded, source-grounded identity evidence from
// a Dart AOT ELF. Exact file/build/snapshot identities are kept separate from
// heuristic Dart version banners so repeated copies of Version::String() cannot
// manufacture high-confidence SDK identity.
package fingerprint

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"aotopsy/internal/elfx"
	"aotopsy/internal/snapshot"
)

// VersionConfidence describes only the inferred Dart SDK version. Snapshot
// hashes and build IDs are exact identities but are deliberately not translated
// into an exact Dart version here: snapshot.DetectVersion selects parser
// profiles and is not an identity oracle for every hash.
const (
	VersionConfidenceUnknown    = "unknown"
	VersionConfidenceHeuristic  = "heuristic"
	VersionConfidenceConflicted = "conflicted"
)

// VersionEvidence is one source that produced a Dart Version::String()-shaped
// version. Both supported sources are heuristic for application identity: a
// mapped printable string can be application data, while DW_AT_producer is
// structured but is generated from the same Version::String() value and is not
// independent corroboration.
type VersionEvidence struct {
	Source  string `json:"source"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
}

// Report is the fingerprint result for a single ELF file.
type Report struct {
	Path                 string            `json:"path"`
	Machine              string            `json:"machine"`
	ELFClass             string            `json:"elf_class"`
	FileSHA256           string            `json:"file_sha256"`
	BuildID              string            `json:"build_id,omitempty"`
	BuildIDSource        string            `json:"build_id_source,omitempty"`
	SnapshotHash         string            `json:"snapshot_hash,omitempty"`
	SnapshotLayout       string            `json:"snapshot_layout,omitempty"`
	DartVersion          string            `json:"dart_version,omitempty"`
	DartArch             string            `json:"dart_arch,omitempty"`
	VersionEvidence      []VersionEvidence `json:"version_evidence,omitempty"`
	DartMarkers          []string          `json:"dart_markers,omitempty"`
	FlutterMarkers       []string          `json:"flutter_markers,omitempty"` // diagnostic only; never version evidence
	EvidenceConflicts    []string          `json:"evidence_conflicts,omitempty"`
	EvidenceLimitations  []string          `json:"evidence_limitations,omitempty"`
	VersionConfidence    string            `json:"version_confidence"`
	FileSize             int64             `json:"file_size"`
	MappedExecutableSize uint64            `json:"mapped_executable_size"`
	MarkerScanBytes      uint64            `json:"marker_scan_bytes"`
	MarkerScanComplete   bool              `json:"marker_scan_complete"`
	DWARFLogicalBytes    uint64            `json:"dwarf_logical_bytes"`
	DWARFScanComplete    bool              `json:"dwarf_scan_complete"`
}

// Run fingerprints the ELF file at path.
func Run(path string) (*Report, error) {
	ef, err := elfx.Open(path)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: open supported AOT ELF: %w", err)
	}
	defer func() { _ = ef.Close() }()

	rep := &Report{
		Path:     path,
		Machine:  machineName(ef.Machine()),
		ELFClass: className(ef.Class()),
		FileSize: ef.FileSize(),
	}
	rep.FileSHA256, err = ef.SHA256()
	if err != nil {
		return nil, fmt.Errorf("fingerprint: hash file: %w", err)
	}

	var buildConflicts []string
	rep.BuildID, rep.BuildIDSource, buildConflicts, err = extractBuildID(ef)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: build-id: %w", err)
	}
	rep.EvidenceConflicts = append(rep.EvidenceConflicts, buildConflicts...)

	identity, identityErr := snapshot.ExtractIdentity(ef)
	switch {
	case identityErr == nil:
		rep.SnapshotHash = identity.SnapshotHash
		if identity.Unified {
			rep.SnapshotLayout = "unified"
		} else {
			rep.SnapshotLayout = "legacy"
		}
	case errors.Is(identityErr, snapshot.ErrNoSnapshotSymbols):
		rep.EvidenceLimitations = append(rep.EvidenceLimitations, "snapshot identity unavailable: no supported snapshot symbols")
	default:
		return nil, fmt.Errorf("fingerprint: snapshot identity: %w", identityErr)
	}

	for _, p := range ef.LoadSegments() {
		if p.Flags&elf.PF_X == 0 || p.Filesz == 0 {
			continue
		}
		if rep.MappedExecutableSize > ^uint64(0)-p.Filesz {
			return nil, fmt.Errorf("fingerprint: mapped executable size overflow")
		}
		rep.MappedExecutableSize += p.Filesz
	}

	loadSegments := ef.LoadSegments()
	markerBytes, markerComplete, err := mappedScanExtent(ef, maxMarkerScanBytes)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: mapped scan extent: %w", err)
	}
	rep.MarkerScanBytes = markerBytes
	rep.MarkerScanComplete = markerComplete
	if !markerComplete {
		if len(loadSegments) == 0 {
			rep.EvidenceLimitations = append(rep.EvidenceLimitations,
				"mapped marker scan unavailable: ELF has no file-backed PT_LOAD segments")
		} else {
			rep.EvidenceLimitations = append(rep.EvidenceLimitations,
				fmt.Sprintf("mapped marker scan truncated at %d bytes", maxMarkerScanBytes))
		}
	}

	// Provenance banners are runtime data. Scan only file-backed PT_LOAD bytes,
	// never arbitrary appended bytes or section-table-only SHF_ALLOC fallbacks.
	// elfx.MappedReader has a useful no-PT_LOAD fallback for other callers, so
	// fingerprint explicitly disables that fallback here.
	markerReader := io.Reader(bytes.NewReader(nil))
	if len(loadSegments) != 0 {
		markerReader = ef.MappedReader(maxMarkerScanBytes)
	}
	markers, err := scanEngineMarkers(markerReader)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: scan markers: %w", err)
	}
	// Modern Dart puts `Dart <Version::String()>` in DW_AT_producer. Debug
	// sections are not mapped, so they cannot be included in the PT_LOAD trust
	// boundary above; parse that one structured field through debug/dwarf rather
	// than falling back to arbitrary raw-file strings.
	producerEvidence, producerMarkers, dwarfStatus, err := scanDartDWARFProducers(ef)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: structured DWARF evidence: %w", err)
	}
	rep.DWARFLogicalBytes = dwarfStatus.LogicalBytes
	rep.DWARFScanComplete = dwarfStatus.Complete
	if dwarfStatus.Limitation != "" {
		rep.EvidenceLimitations = append(rep.EvidenceLimitations, dwarfStatus.Limitation)
	}
	mergeDiagnosticMarkers(&markers, producerMarkers)
	rep.FlutterMarkers = markers.FlutterMarkers
	rep.DartMarkers = markers.DartMarkers
	rep.VersionEvidence = append(rep.VersionEvidence, markers.VersionEvidence...)
	rep.VersionEvidence = append(rep.VersionEvidence, producerEvidence...)
	rep.VersionEvidence = normalizeVersionEvidence(rep.VersionEvidence)
	var versionConflicts []string
	rep.DartVersion, rep.DartArch, versionConflicts = consensusVersionEvidence(rep.VersionEvidence, nil)
	rep.EvidenceConflicts = append(rep.EvidenceConflicts, versionConflicts...)
	if rep.DartArch != "" && !machineMatchesDartArch(ef.Machine(), ef.Class(), rep.DartArch) {
		conflict := fmt.Sprintf("Dart banner architecture %q contradicts ELF machine %s/%s", rep.DartArch, ef.Machine(), ef.Class())
		rep.EvidenceConflicts = append(rep.EvidenceConflicts, conflict)
		versionConflicts = append(versionConflicts, conflict)
	}
	sort.Strings(rep.EvidenceConflicts)
	rep.EvidenceConflicts = dedupeStrings(rep.EvidenceConflicts)
	sort.Strings(rep.EvidenceLimitations)
	rep.EvidenceLimitations = dedupeStrings(rep.EvidenceLimitations)
	rep.VersionConfidence = versionConfidence(rep.DartVersion != "", len(versionConflicts) != 0)

	return rep, nil
}

const (
	maxDWARFBytes   = 64 << 20
	maxDWARFEntries = 200000
)

type dwarfScanStatus struct {
	LogicalBytes uint64
	Complete     bool
	Limitation   string
}

// scanDartDWARFProducers extracts only structured DW_AT_producer strings. It
// refuses legacy .zdebug sections (whose compressed size is not a trustworthy
// bound) and caps aggregate uncompressed modern DWARF size before asking the Go
// DWARF decoder to materialize it. SDK @3.5.0 runtime/vm/dwarf.cc:276 writes
// only "Dart VM"; @3.6.2:281-282 and @3.13.0:258-259 write
// `Dart <Version::String()>`, so only the latter shape carries version evidence.
func scanDartDWARFProducers(ef *elfx.File) (evidence []VersionEvidence, markers []string, status dwarfScanStatus, err error) {
	status.Complete = true
	var total uint64
	hasInfo := false
	for _, s := range ef.Sections() {
		if strings.HasPrefix(s.Name, ".zdebug_") {
			status.Complete = false
			status.LogicalBytes = total
			status.Limitation = "DWARF producer scan skipped: legacy .zdebug_* compression has no trusted uncompressed-size bound"
			return nil, nil, status, nil
		}
		if !strings.HasPrefix(s.Name, ".debug_") {
			continue
		}
		if s.Size > maxDWARFBytes || total > maxDWARFBytes-s.Size {
			status.Complete = false
			status.LogicalBytes = total
			status.Limitation = fmt.Sprintf("DWARF producer scan skipped: logical debug data exceeds %d-byte budget", maxDWARFBytes)
			return nil, nil, status, nil
		}
		total += s.Size
		if s.Name == ".debug_info" {
			hasInfo = true
		}
	}
	status.LogicalBytes = total
	if !hasInfo || total == 0 {
		return nil, nil, status, nil
	}

	d, err := ef.DWARF()
	if err != nil {
		return nil, nil, status, err
	}
	r := d.Reader()
	seenMarkers := make(map[string]bool)
	seenEvidence := make(map[string]bool, 2)
	entries := 0
	for ; entries < maxDWARFEntries; entries++ {
		entry, err := r.Next()
		if err != nil {
			return nil, nil, status, err
		}
		if entry == nil {
			break
		}
		producer, ok := entry.Val(dwarf.AttrProducer).(string)
		if !ok || producer == "" {
			continue
		}
		v, arch, ok := dartBannerEvidence(producer)
		if !ok {
			continue
		}
		key := v + "\x00" + arch
		if !seenEvidence[key] && len(seenEvidence) < 2 {
			seenEvidence[key] = true
			evidence = append(evidence, VersionEvidence{Source: "dwarf_producer", Version: v, Arch: arch})
		}
		if !seenMarkers[producer] && len(markers) < 2 {
			seenMarkers[producer] = true
			markers = append(markers, producer)
		}
	}
	if entries == maxDWARFEntries {
		entry, err := r.Next()
		if err != nil {
			return nil, nil, status, err
		}
		if entry != nil {
			return nil, nil, status, fmt.Errorf("DWARF entry count exceeds limit %d", maxDWARFEntries)
		}
	}
	sort.Strings(markers)
	return evidence, markers, status, nil
}

func mergeDiagnosticMarkers(result *markerScanResult, markers []string) {
	if result == nil {
		return
	}
	for _, marker := range markers {
		found := false
		for _, existing := range result.DartMarkers {
			if existing == marker {
				found = true
				break
			}
		}
		if !found && len(result.DartMarkers) < maxMarkersPerFamily {
			result.DartMarkers = append(result.DartMarkers, marker)
		}
	}
	sort.Strings(result.DartMarkers)
}

func machineName(m elf.Machine) string {
	switch m {
	case elf.EM_AARCH64:
		return "aarch64"
	case elf.EM_X86_64:
		return "x86_64"
	default:
		return fmt.Sprintf("unknown(0x%x)", uint16(m))
	}
}

func className(c elf.Class) string {
	switch c {
	case elf.ELFCLASS64:
		return "ELF64"
	case elf.ELFCLASS32:
		return "ELF32"
	default:
		return fmt.Sprintf("unknown(0x%x)", uint8(c))
	}
}

// extractBuildID hand-parses the ELF note format looking for NT_GNU_BUILD_ID
// (type 3, owner "GNU"). PT_NOTE is the primary ET_DYN source. A SHT_NOTE
// corroborator/fallback is accepted only when SHF_ALLOC metadata and the
// section's VA/offset/size agree with a unique file-backed PT_LOAD mapping.
// Conflicting primary/corroborating IDs are reported instead of choosing one.
// Dead section-table bytes are never identity evidence.
//
// Dart emits this exact GNU-note shape and exposes the same allocated note as
// _kDartSnapshotBuildId: SDK @2.10.0 runtime/vm/elf.cc:1183-1197,
// 1246-1264,1294-1324; @3.13.0 runtime/vm/elf.cc:1525-1529,
// 1696-1758. Descriptor length is intentionally not fixed here because the SDK
// has changed the build-id hash composition while retaining valid GNU-note
// framing.

const (
	maxNoteBytes        = 1 << 20
	maxNoteRegions      = 128
	maxMarkersPerFamily = 4096
	maxMarkerScanBytes  = 512 << 20
)

func extractBuildID(ef *elfx.File) (id, source string, conflicts []string, err error) {
	ptIDs := make(map[string]bool, 2)
	mappedSectionIDs := make(map[string]bool, 2)
	addIDs := func(dst map[string]bool, found []string) {
		for _, id := range found {
			if id == "" || dst[id] {
				continue
			}
			if len(dst) < 2 {
				dst[id] = true
			}
		}
	}
	progRegions := 0
	for _, p := range ef.Programs() {
		if p.Type != elf.PT_NOTE || p.Filesz == 0 {
			continue
		}
		progRegions++
		if progRegions > maxNoteRegions {
			return "", "", nil, fmt.Errorf("PT_NOTE count exceeds limit %d", maxNoteRegions)
		}
		if p.Filesz > maxNoteBytes {
			return "", "", nil, fmt.Errorf("PT_NOTE %d size %d exceeds limit %d", p.Index, p.Filesz, maxNoteBytes)
		}
		data, err := ef.ReadProgram(p.Index, maxNoteBytes)
		if err != nil {
			return "", "", nil, fmt.Errorf("read PT_NOTE %d: %w", p.Index, err)
		}
		found, err := parseBuildIDNotes(data, binary.LittleEndian)
		if err != nil {
			return "", "", nil, fmt.Errorf("parse PT_NOTE %d: %w", p.Index, err)
		}
		addIDs(ptIDs, found)
	}

	// Corroborate PT_NOTE with only note sections that are themselves
	// runtime-mapped. If PT_NOTE is absent this also serves as the bounded
	// fallback. Arbitrary section-table-only notes are an attacker-controlled
	// append surface and are intentionally ignored.
	sectionRegions := 0
	for _, s := range ef.Sections() {
		if s.Type != elf.SHT_NOTE || s.Size == 0 || strings.HasPrefix(s.Name, ".zdebug_") {
			continue
		}
		if !sectionIsMappedFileBacked(ef, s) {
			continue
		}
		sectionRegions++
		if sectionRegions > maxNoteRegions {
			return "", "", nil, fmt.Errorf("mapped SHT_NOTE count exceeds limit %d", maxNoteRegions)
		}
		if s.Size > maxNoteBytes {
			return "", "", nil, fmt.Errorf("mapped SHT_NOTE %q size %d exceeds limit %d", s.Name, s.Size, maxNoteBytes)
		}
		data, err := ef.ReadSection(s.Index, maxNoteBytes)
		if err != nil {
			return "", "", nil, fmt.Errorf("read mapped SHT_NOTE %q: %w", s.Name, err)
		}
		found, err := parseBuildIDNotes(data, binary.LittleEndian)
		if err != nil {
			return "", "", nil, fmt.Errorf("parse mapped SHT_NOTE %q: %w", s.Name, err)
		}
		addIDs(mappedSectionIDs, found)
	}
	return resolveBuildIDEvidence(ptIDs, mappedSectionIDs)
}

func sectionIsMappedFileBacked(ef *elfx.File, s elfx.SectionInfo) bool {
	if ef == nil || s.Flags&elf.SHF_ALLOC == 0 || s.Type == elf.SHT_NOBITS || s.Size == 0 {
		return false
	}
	off, err := ef.VAToFileOffset(s.Addr)
	if err != nil || off != s.Offset {
		return false
	}
	remaining, err := ef.FileBackedRemaining(s.Addr)
	return err == nil && s.Size <= remaining
}

func sortedBuildIDs(ids map[string]bool) []string {
	keys := make([]string, 0, len(ids))
	for id := range ids {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	return keys

}

func resolveBuildIDEvidence(ptIDs, mappedSectionIDs map[string]bool) (string, string, []string, error) {
	pt := sortedBuildIDs(ptIDs)
	sht := sortedBuildIDs(mappedSectionIDs)
	var conflicts []string
	if len(pt) > 1 {
		conflicts = append(conflicts, fmt.Sprintf("conflicting GNU build-id notes from pt_note: %s", strings.Join(pt, ", ")))
	}
	if len(sht) > 1 {
		conflicts = append(conflicts, fmt.Sprintf("conflicting GNU build-id notes from mapped_sht_note: %s", strings.Join(sht, ", ")))
	}
	if len(conflicts) != 0 {
		return "", "", conflicts, nil
	}
	switch {
	case len(pt) == 1 && len(sht) == 1:
		if pt[0] != sht[0] {
			return "", "", []string{fmt.Sprintf("conflicting GNU build-id evidence: pt_note=%s mapped_sht_note=%s", pt[0], sht[0])}, nil
		}
		return pt[0], "pt_note+mapped_sht_note", nil, nil
	case len(pt) == 1:
		return pt[0], "pt_note", nil, nil
	case len(sht) == 1:
		return sht[0], "mapped_sht_note", nil, nil
	default:
		return "", "", nil, nil
	}
}

// parseBuildIDNotes walks a raw ELF note-section byte stream (repeated
// namesz/descsz/type u32 triples, name padded to 4-byte alignment,
// descriptor padded to 4-byte alignment) looking for name=="GNU" type==3.
// The caller supplies byte order explicitly. AOTopsy's trust boundary accepts
// only little-endian ELF, so production calls use binary.LittleEndian.
func parseBuildIDNotes(data []byte, bo binary.ByteOrder) ([]string, error) {
	off := 0
	var ids []string
	for off < len(data) {
		if len(data)-off < 12 {
			if allZeroBytes(data[off:]) {
				return ids, nil
			}
			return nil, fmt.Errorf("truncated ELF note header at offset %d", off)
		}
		namesz := bo.Uint32(data[off:])
		descsz := bo.Uint32(data[off+4:])
		ntype := bo.Uint32(data[off+8:])
		off += 12

		if uint64(namesz) > uint64(len(data)-off) {
			return nil, fmt.Errorf("ELF note name at offset %d exceeds region", off)
		}
		nameEnd := off + int(namesz)
		name := ""
		exactGNUOwner := false
		if namesz > 0 {
			// namesz includes the trailing NUL.
			raw := data[off:nameEnd]
			exactGNUOwner = namesz == 4 && bytes.Equal(raw, []byte{'G', 'N', 'U', 0})
			if i := bytes.IndexByte(raw, 0); i >= 0 {
				name = string(raw[:i])
			} else {
				name = string(raw)
			}
		}
		off = align4(nameEnd)

		if off > len(data) {
			return nil, fmt.Errorf("ELF note name padding exceeds region")
		}
		if uint64(descsz) > uint64(len(data)-off) {
			return nil, fmt.Errorf("ELF note descriptor at offset %d exceeds region", off)
		}
		descEnd := off + int(descsz)
		desc := data[off:descEnd]
		off = align4(descEnd)
		if off > len(data) {
			return nil, fmt.Errorf("ELF note descriptor padding exceeds region")
		}

		if exactGNUOwner && name == "GNU" && ntype == 3 { // NT_GNU_BUILD_ID
			id := hex.EncodeToString(desc)
			if id != "" && !slicesContains(ids, id) && len(ids) < 2 {
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}

func allZeroBytes(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func slicesContains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func align4(n int) int {
	return (n + 3) &^ 3
}

// scanEngineMarkers streams printable-ASCII runs from r. Generic Dart strings
// (dart: URIs, "Dart SDK", snapshot labels) are retained as diagnostic markers,
// but VERSION FIELDS are populated only from evidence-specific banner shapes.
// This prevents an unrelated semver/IP such as 127.0.0 inside a dart: string
// from being promoted to Dart version evidence.
type markerScanResult struct {
	FlutterMarkers  []string
	DartMarkers     []string
	VersionEvidence []VersionEvidence
}

func scanEngineMarkers(r io.Reader) (markerScanResult, error) {
	seenFlutter := make(map[string]bool)
	seenDart := make(map[string]bool)
	seenEvidence := make(map[string]bool, 2)
	var result markerScanResult

	consume := func(s string) {
		lower := strings.ToLower(s)
		isFlutter := strings.Contains(lower, "flutter engine")
		isDart := strings.Contains(lower, "dart vm") || strings.Contains(lower, "dart sdk") ||
			strings.Contains(lower, "dart:") || strings.Contains(lower, "isolate snapshot") ||
			strings.Contains(lower, "vm snapshot")

		if v, arch, ok := dartBannerEvidence(s); ok {
			key := v + "\x00" + arch
			if !seenEvidence[key] && len(seenEvidence) < 2 {
				seenEvidence[key] = true
				result.VersionEvidence = append(result.VersionEvidence, VersionEvidence{
					Source: "mapped_dart_banner", Version: v, Arch: arch,
				})
			}
			isDart = true
		}
		if isFlutter && !seenFlutter[s] && len(seenFlutter) < maxMarkersPerFamily {
			seenFlutter[s] = true
			result.FlutterMarkers = append(result.FlutterMarkers, s)
		}
		if isDart && !seenDart[s] && len(seenDart) < maxMarkersPerFamily {
			seenDart[s] = true
			result.DartMarkers = append(result.DartMarkers, s)
		}
	}

	const (
		minRun = 10
		maxRun = 240
	)
	buf := make([]byte, 64<<10)
	run := make([]byte, 0, maxRun)
	tooLong := false
	flush := func() {
		if !tooLong && len(run) >= minRun {
			consume(string(run))
		}
		run = run[:0]
		tooLong = false
	}
	for {
		n, readErr := r.Read(buf)
		for _, b := range buf[:n] {
			if b >= 0x20 && b < 0x7f {
				if !tooLong {
					if len(run) < maxRun {
						run = append(run, b)
					} else {
						tooLong = true
						run = run[:0]
					}
				}
				continue
			}
			flush()
		}
		if readErr != nil {
			if readErr != io.EOF {
				return markerScanResult{}, readErr
			}
			break
		}
	}
	flush()
	sort.Strings(result.FlutterMarkers)
	sort.Strings(result.DartMarkers)
	return result, nil
}

// dartBannerEvidence recognizes both exact SDK-generated shapes. Dart 2.10
// through 2.14 keep only
//
//	<version> (<channel>) (<commit time>)
//
// in str_, while Version::String() appends `on "<os>_<arch>"` dynamically
// (SDK @2.10.0 runtime/vm/version_in.cc:15-20; @2.14.0:17-29). Starting at
// Dart 2.15 the suffix is embedded directly in str_ (version_in.cc:11-12,
// 28-63). Both shapes can therefore be present in mapped runtime data; a
// generic semver, or the unsupported literal prefix "Dart VM version:", is not
// SDK-generated provenance for any supported release.
func dartBannerEvidence(s string) (version, arch string, ok bool) {
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "dart ") {
		// runtime/vm/dwarf.cc @3.6.2:281-282 writes producer="Dart %s" where %s is
		// Version::String(); @3.5.0:276 still writes the non-versioned "Dart VM".
		s = strings.TrimSpace(s[len("Dart "):])
	}
	v := versionPrefix(s)
	if v == "" || len(s) <= len(v) || !strings.HasPrefix(s[len(v):], " (") {
		return "", "", false
	}
	rest := s[len(v):]
	firstEnd := strings.Index(rest, ") (")
	if firstEnd < 2 {
		return "", "", false
	}
	channel := rest[2:firstEnd]
	if channel == "" {
		return "", "", false
	}
	commitStart := firstEnd + len(") (")
	commitEndRel := strings.IndexByte(rest[commitStart:], ')')
	if commitEndRel < 0 {
		return "", "", false
	}
	commitEnd := commitStart + commitEndRel
	commitTime := rest[commitStart:commitEnd]
	// Generated COMMIT_TIME values are timestamps. Requiring a clock separator
	// keeps arbitrary `1.2.3 (foo) (bar)` application text out of version truth.
	if !strings.Contains(commitTime, ":") && commitTime != "Unknown timestamp" {
		return "", "", false
	}
	tail := strings.TrimSpace(rest[commitEnd+1:])
	if tail == "" {
		return v, "", true // legacy Version::str_ form
	}
	if !strings.HasPrefix(tail, `on "`) || !strings.HasSuffix(tail, `"`) {
		return "", "", false
	}
	target := strings.TrimSuffix(strings.TrimPrefix(tail, `on "`), `"`)
	underscore := strings.LastIndexByte(target, '_')
	if underscore < 0 || underscore == len(target)-1 {
		return "", "", false
	}
	return v, canonicalDartArch(target[underscore+1:]), true
}

func canonicalDartArch(arch string) string {
	switch arch {
	case "simarm64":
		return "arm64"
	case "simarm":
		return "arm"
	case "simx64":
		return "x64"
	case "simia32":
		return "ia32"
	case "simriscv32":
		return "riscv32"
	case "simriscv64":
		return "riscv64"
	default:
		return arch
	}
}

// versionPrefix parses the SDK VERSION_STR token at the start of s while
// preserving prerelease/build suffixes such as `3.13.0-70.0.dev`.
func versionPrefix(s string) string {
	if s == "" || !isDigit(s[0]) {
		return ""
	}
	i := 0
	for seg := 0; seg < 3; seg++ {
		start := i
		for i < len(s) && isDigit(s[i]) {
			i++
		}
		if i == start {
			return ""
		}
		if seg < 2 {
			if i >= len(s) || s[i] != '.' {
				return ""
			}
			i++
		}
	}
	if i < len(s) && (s[i] == '-' || s[i] == '+') {
		i++
		start := i
		for i < len(s) {
			c := s[i]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || isDigit(c) || c == '.' || c == '-' || c == '+' {
				i++
				continue
			}
			break
		}
		if i == start {
			return ""
		}
	}
	return s[:i]
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func machineMatchesDartArch(machine elf.Machine, class elf.Class, arch string) bool {
	arch = canonicalDartArch(arch)
	switch machine {
	case elf.EM_AARCH64:
		return class == elf.ELFCLASS64 && arch == "arm64"
	case elf.EM_X86_64:
		return class == elf.ELFCLASS64 && (arch == "x64" || arch == "x86_64")
	default:
		return false
	}
}

func normalizeVersionEvidence(in []VersionEvidence) []VersionEvidence {
	seen := make(map[string]bool, len(in))
	out := make([]VersionEvidence, 0, len(in))
	for _, ev := range in {
		if ev.Version == "" || ev.Source == "" {
			continue
		}
		key := ev.Source + "\x00" + ev.Version + "\x00" + ev.Arch
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ev)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].Arch < out[j].Arch
	})
	return out
}

func consensusVersionEvidence(evidence []VersionEvidence, conflicts []string) (version, arch string, outConflicts []string) {
	versions := make(map[string]bool, 2)
	archs := make(map[string]bool, 2)
	for _, ev := range evidence {
		if ev.Version != "" && len(versions) < 2 {
			versions[ev.Version] = true
		}
		if ev.Arch != "" && len(archs) < 2 {
			archs[ev.Arch] = true
		}
	}
	outConflicts = append(outConflicts, conflicts...)
	version, outConflicts = oneConsensus("Dart version", versions, outConflicts)
	arch, outConflicts = oneConsensus("Dart architecture", archs, outConflicts)
	return version, arch, outConflicts
}

func oneConsensus(label string, values map[string]bool, conflicts []string) (string, []string) {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	switch len(keys) {
	case 0:
		return "", conflicts
	case 1:
		return keys[0], conflicts
	default:
		return "", append(conflicts, fmt.Sprintf("conflicting %s evidence: %s", label, strings.Join(keys, ", ")))
	}
}

func versionConfidence(hasVersion, hasConflict bool) string {
	if hasConflict {
		return VersionConfidenceConflicted
	}
	if hasVersion {
		return VersionConfidenceHeuristic
	}
	return VersionConfidenceUnknown
}

func dedupeStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}

func mappedScanExtent(ef *elfx.File, limit uint64) (bytesScanned uint64, complete bool, err error) {
	if ef == nil || limit == 0 {
		return 0, true, nil
	}
	var total uint64
	hasLoad := false
	add := func(size uint64) error {
		if total > ^uint64(0)-size {
			return fmt.Errorf("mapped evidence size overflow")
		}
		total += size
		return nil
	}
	for _, p := range ef.LoadSegments() {
		if p.Filesz == 0 {
			continue
		}
		hasLoad = true
		if err := add(p.Filesz); err != nil {
			return 0, false, err
		}
	}
	if !hasLoad {
		return 0, false, nil
	}
	if total > limit {
		return limit, false, nil
	}
	return total, true, nil
}
