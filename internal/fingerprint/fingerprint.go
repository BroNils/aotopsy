// Package fingerprint identifies the build-id, target architecture, and
// Flutter/Dart engine version markers embedded in a native library, without
// needing any Dart-snapshot-aware parsing. Ported from flutterdec's
// engine_fingerprint.rs (Rust), generalized to work for any ELF machine
// type aotopsy's elfx package accepts (ARM64, x86_64), not just ARM64.
package fingerprint

import (
	"bytes"
	"crypto/sha256"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Confidence levels for the detected version/build markers.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// Report is the fingerprint result for a single ELF file.
type Report struct {
	Path              string   `json:"path"`
	Machine           string   `json:"machine"`
	FileSHA256        string   `json:"file_sha256"`
	BuildID           string   `json:"build_id,omitempty"`
	FlutterVersion    string   `json:"flutter_version,omitempty"`
	DartVersion       string   `json:"dart_version,omitempty"`
	DartArch          string   `json:"dart_arch,omitempty"`
	FlutterMarkers    []string `json:"flutter_markers,omitempty"`
	DartMarkers       []string `json:"dart_markers,omitempty"`
	EvidenceConflicts []string `json:"evidence_conflicts,omitempty"`
	Confidence        string   `json:"confidence"`
	FileSize          int64    `json:"file_size"`
	ExecSectionSize   uint64   `json:"exec_section_size"`
}

// Run fingerprints the ELF file at path.
func Run(path string) (*Report, error) {
	f, err := os.Open(path) //nolint:gosec // path is an explicit CLI-provided target, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("fingerprint: open: %w", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("fingerprint: stat: %w", err)
	}

	ef, err := elf.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: not an ELF file: %w", err)
	}
	defer func() { _ = ef.Close() }()

	rep := &Report{
		Path:     path,
		Machine:  machineName(ef.Machine),
		FileSize: info.Size(),
	}
	rep.FileSHA256, err = hashOpenedFile(f, info.Size())
	if err != nil {
		return nil, fmt.Errorf("fingerprint: hash file: %w", err)
	}

	var buildConflicts []string
	rep.BuildID, buildConflicts = extractBuildID(ef)
	rep.EvidenceConflicts = append(rep.EvidenceConflicts, buildConflicts...)

	for _, s := range ef.Sections {
		if s.Flags&elf.SHF_EXECINSTR != 0 {
			rep.ExecSectionSize += s.Size
		}
	}

	// Provenance banners are runtime data. Scan only file-backed bytes that the
	// ELF maps into memory, never arbitrary appended bytes after the last segment.
	// ET_REL/debug artifacts without PT_LOAD use SHF_ALLOC sections as the same
	// trust boundary. The reader is streaming and aggregate-capped.
	markers, err := scanEngineMarkers(mappedMarkerReader(f, ef, info.Size()))
	if err != nil {
		return nil, fmt.Errorf("fingerprint: scan markers: %w", err)
	}
	// Modern Dart puts `Dart <Version::String()>` in DW_AT_producer. Debug
	// sections are not mapped, so they cannot be included in the PT_LOAD trust
	// boundary above; parse that one structured field through debug/dwarf rather
	// than falling back to arbitrary raw-file strings.
	producerVersions, producerArchs, producerMarkers := scanDartDWARFProducers(ef)
	mergeStructuredDartEvidence(&markers, producerVersions, producerArchs, producerMarkers)
	rep.FlutterMarkers = markers.FlutterMarkers
	rep.DartMarkers = markers.DartMarkers
	rep.FlutterVersion = markers.FlutterVersion
	rep.DartVersion = markers.DartVersion
	rep.DartArch = markers.DartArch
	rep.EvidenceConflicts = append(rep.EvidenceConflicts, markers.Conflicts...)
	if rep.DartArch != "" && !machineMatchesDartArch(ef.Machine, ef.Class, rep.DartArch) {
		rep.EvidenceConflicts = append(rep.EvidenceConflicts,
			fmt.Sprintf("Dart banner architecture %q contradicts ELF machine %s", rep.DartArch, ef.Machine))
	}

	rep.Confidence = confidenceLevel(rep.DartVersion != "", rep.FlutterVersion != "", len(rep.EvidenceConflicts) != 0)

	return rep, nil
}

const (
	maxDWARFBytes   = 64 << 20
	maxDWARFEntries = 200000
)

// scanDartDWARFProducers extracts only structured DW_AT_producer strings. It
// refuses legacy .zdebug sections (whose compressed size is not a trustworthy
// bound) and caps aggregate uncompressed modern DWARF size before asking the Go
// DWARF decoder to materialize it.
func scanDartDWARFProducers(ef *elf.File) (versions, archs map[string]bool, markers []string) {
	versions = make(map[string]bool, 2)
	archs = make(map[string]bool, 2)
	var total uint64
	hasInfo := false
	for _, s := range ef.Sections {
		if strings.HasPrefix(s.Name, ".zdebug") {
			return versions, archs, nil
		}
		if !strings.HasPrefix(s.Name, ".debug_") {
			continue
		}
		if s.Size > maxDWARFBytes || total > maxDWARFBytes-s.Size {
			return versions, archs, nil
		}
		total += s.Size
		if s.Name == ".debug_info" {
			hasInfo = true
		}
	}
	if !hasInfo || total == 0 {
		return versions, archs, nil
	}

	d, err := ef.DWARF()
	if err != nil {
		return versions, archs, nil
	}
	r := d.Reader()
	seenMarkers := make(map[string]bool)
	for entries := 0; entries < maxDWARFEntries; entries++ {
		entry, err := r.Next()
		if err != nil || entry == nil {
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
		addEvidenceValue(versions, v)
		addEvidenceValue(archs, arch)
		if !seenMarkers[producer] && len(markers) < 2 {
			seenMarkers[producer] = true
			markers = append(markers, producer)
		}
	}
	sort.Strings(markers)
	return versions, archs, markers
}

func mergeStructuredDartEvidence(result *markerScanResult, versions, archs map[string]bool, markers []string) {
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

	result.DartVersion, result.Conflicts = mergeSingleEvidence(
		"Dart version", result.DartVersion, versions, result.Conflicts)
	result.DartArch, result.Conflicts = mergeSingleEvidence(
		"Dart architecture", result.DartArch, archs, result.Conflicts)
}

func mergeSingleEvidence(label, current string, extra map[string]bool, conflicts []string) (string, []string) {
	value, extraConflicts := singleEvidenceValue(label, extra, nil)
	for _, c := range extraConflicts {
		conflicts = appendUniqueString(conflicts, c)
	}
	if value == "" {
		return current, conflicts
	}
	// If the raw/mapped evidence was already internally contradictory, a
	// structured producer cannot make that contradiction disappear.
	conflictPrefix := "conflicting " + label + " markers:"
	for _, c := range conflicts {
		if strings.HasPrefix(c, conflictPrefix) {
			return "", conflicts
		}
	}
	if current == "" {
		return value, conflicts
	}
	if current == value {
		return current, conflicts
	}
	values := []string{current, value}
	sort.Strings(values)
	conflicts = appendUniqueString(conflicts,
		fmt.Sprintf("conflicting %s markers: %s", label, strings.Join(values, ", ")))
	return "", conflicts
}

func appendUniqueString(values []string, value string) []string {
	for _, v := range values {
		if v == value {
			return values
		}
	}
	return append(values, value)
}

func hashOpenedFile(f *os.File, size int64) (string, error) {
	if f == nil || size < 0 {
		return "", fmt.Errorf("invalid opened file")
	}
	h := sha256.New()
	if _, err := io.CopyN(h, io.NewSectionReader(f, 0, size), size); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func machineName(m elf.Machine) string {
	switch m {
	case elf.EM_AARCH64:
		return "aarch64"
	case elf.EM_X86_64:
		return "x86_64"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_386:
		return "x86"
	case elf.EM_RISCV:
		return "riscv"
	case elf.EM_PPC64:
		return "ppc64"
	default:
		return fmt.Sprintf("unknown(0x%x)", uint16(m))
	}
}

// extractBuildID hand-parses the ELF note format looking for NT_GNU_BUILD_ID
// (type 3, owner "GNU"). Program headers are authoritative for runtime ELF
// notes and survive section stripping, so PT_NOTE is checked first. SHT_NOTE is
// a fallback for relocatable/debug artifacts that retain sections. Section
// *names* are deliberately irrelevant: a PROGBITS section called "denote" is
// not an ELF note and must never be trusted as a build-id source.

const (
	maxNoteBytes        = 1 << 20
	maxNoteRegions      = 128
	maxMarkersPerFamily = 4096
	maxMarkerScanBytes  = 512 << 20
)

func extractBuildID(ef *elf.File) (string, []string) {
	ids := make(map[string]bool, 2)
	addIDs := func(found []string) {
		for _, id := range found {
			if id == "" || ids[id] {
				continue
			}
			if len(ids) < 2 {
				ids[id] = true
			}
		}
	}
	progRegions := 0
	for _, p := range ef.Progs {
		if p.Type != elf.PT_NOTE || p.Filesz == 0 {
			continue
		}
		progRegions++
		if progRegions > maxNoteRegions || p.Filesz > maxNoteBytes {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(p.Open(), int64(p.Filesz)))
		if err != nil {
			continue
		}
		addIDs(parseBuildIDNotes(data, ef.ByteOrder))
	}
	sectionRegions := 0
	for _, s := range ef.Sections {
		if s.Type != elf.SHT_NOTE {
			continue
		}
		sectionRegions++
		if sectionRegions > maxNoteRegions || s.Size > maxNoteBytes || strings.HasPrefix(s.Name, ".zdebug") {
			continue
		}
		// Section.Open streams both modern SHF_COMPRESSED and ordinary note
		// sections. LimitReader prevents a legacy/hostile decompressor from using
		// an advertised uncompressed size to make Data() allocate arbitrarily.
		data, err := io.ReadAll(io.LimitReader(s.Open(), maxNoteBytes+1))
		if err != nil {
			continue
		}
		if len(data) > maxNoteBytes {
			continue
		}
		addIDs(parseBuildIDNotes(data, ef.ByteOrder))
	}
	keys := make([]string, 0, len(ids))
	for id := range ids {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	switch len(keys) {
	case 0:
		return "", nil
	case 1:
		return keys[0], nil
	default:
		return "", []string{fmt.Sprintf("conflicting GNU build-id notes: %s", strings.Join(keys, ", "))}
	}
}

// parseBuildIDNotes walks a raw ELF note-section byte stream (repeated
// namesz/descsz/type u32 triples, name padded to 4-byte alignment,
// descriptor padded to 4-byte alignment) looking for name=="GNU" type==3.
// The u32 fields are read using the ELF's native byte order (bo), which is
// ef.ByteOrder from the caller -- not hardcoded little-endian, so big-endian
// ELFs are handled correctly.
func parseBuildIDNotes(data []byte, bo binary.ByteOrder) []string {
	off := 0
	var ids []string
	for off+12 <= len(data) {
		namesz := bo.Uint32(data[off:])
		descsz := bo.Uint32(data[off+4:])
		ntype := bo.Uint32(data[off+8:])
		off += 12

		if uint64(namesz) > uint64(len(data)-off) {
			return ids
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

		if off > len(data) || uint64(descsz) > uint64(len(data)-off) {
			return ids
		}
		descEnd := off + int(descsz)
		desc := data[off:descEnd]
		off = align4(descEnd)

		if exactGNUOwner && name == "GNU" && ntype == 3 { // NT_GNU_BUILD_ID
			id := hex.EncodeToString(desc)
			if id != "" && !slicesContains(ids, id) && len(ids) < 2 {
				ids = append(ids, id)
			}
		}
	}
	return ids
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

// mappedMarkerReader returns a bounded concatenation of bytes the ELF loader
// actually maps. A NUL separator prevents a printable run from being fabricated
// by concatenating the end of one region with the start of another.
func mappedMarkerReader(f *os.File, ef *elf.File, fileSize int64) io.Reader {
	var readers []io.Reader
	remaining := int64(maxMarkerScanBytes)
	addFileRange := func(off, size uint64) {
		if remaining <= 0 || fileSize <= 0 || off >= uint64(fileSize) {
			return
		}
		available := uint64(fileSize) - off
		if size > available {
			size = available
		}
		if size > uint64(remaining) {
			size = uint64(remaining)
		}
		if size == 0 {
			return
		}
		readers = append(readers, io.NewSectionReader(f, int64(off), int64(size)), bytes.NewReader([]byte{0}))
		remaining -= int64(size)
	}

	hasLoad := false
	for _, p := range ef.Progs {
		if p.Type == elf.PT_LOAD && p.Filesz > 0 {
			hasLoad = true
			addFileRange(p.Off, p.Filesz)
		}
	}
	if !hasLoad {
		for _, s := range ef.Sections {
			if remaining <= 0 {
				break
			}
			if s.Flags&elf.SHF_ALLOC == 0 || s.Type == elf.SHT_NOBITS || s.Size == 0 {
				continue
			}
			limit := int64(s.Size)
			if limit > remaining {
				limit = remaining
			}
			readers = append(readers, io.LimitReader(s.Open(), limit), bytes.NewReader([]byte{0}))
			remaining -= limit
		}
	}
	return io.MultiReader(readers...)
}

// scanEngineMarkers streams printable-ASCII runs from r. Generic Dart strings
// (dart: URIs, "Dart SDK", snapshot labels) are retained as diagnostic markers,
// but VERSION FIELDS are populated only from evidence-specific banner shapes.
// This prevents an unrelated semver/IP such as 127.0.0 inside a dart: string
// from being promoted to a high-confidence Dart version.
type markerScanResult struct {
	FlutterMarkers []string
	DartMarkers    []string
	FlutterVersion string
	DartVersion    string
	DartArch       string
	Conflicts      []string
}

func scanEngineMarkers(r io.Reader) (markerScanResult, error) {
	seenFlutter := make(map[string]bool)
	seenDart := make(map[string]bool)
	flutterVersions := make(map[string]bool)
	dartVersions := make(map[string]bool)
	dartArchs := make(map[string]bool)
	var result markerScanResult

	consume := func(s string) {
		lower := strings.ToLower(s)
		isFlutter := strings.Contains(lower, "flutter engine")
		isDart := strings.Contains(lower, "dart vm") || strings.Contains(lower, "dart sdk") ||
			strings.Contains(lower, "dart:") || strings.Contains(lower, "isolate snapshot") ||
			strings.Contains(lower, "vm snapshot")

		if v, arch, ok := dartBannerEvidence(s); ok {
			addEvidenceValue(dartVersions, v)
			if arch != "" {
				addEvidenceValue(dartArchs, arch)
			}
			isDart = true
		}
		if v := flutterVersionFromBanner(s); v != "" {
			addEvidenceValue(flutterVersions, v)
			isFlutter = true
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
	result.FlutterVersion, result.Conflicts = singleEvidenceValue("Flutter version", flutterVersions, result.Conflicts)
	result.DartVersion, result.Conflicts = singleEvidenceValue("Dart version", dartVersions, result.Conflicts)
	result.DartArch, result.Conflicts = singleEvidenceValue("Dart architecture", dartArchs, result.Conflicts)
	return result, nil
}

func addEvidenceValue(values map[string]bool, value string) {
	if value == "" || values[value] {
		return
	}
	// Two distinct values are sufficient to prove a conflict. Keeping an
	// attacker-controlled third, fourth, ... value only amplifies memory/sort
	// work and conflict-string size without adding information.
	if len(values) < 2 {
		values[value] = true
	}
}

func singleEvidenceValue(label string, values map[string]bool, conflicts []string) (string, []string) {
	if len(values) == 0 {
		return "", conflicts
	}
	keys := make([]string, 0, len(values))
	for v := range values {
		keys = append(keys, v)
	}
	sort.Strings(keys)
	if len(keys) > 1 {
		return "", append(conflicts, fmt.Sprintf("conflicting %s markers: %s", label, strings.Join(keys, ", ")))
	}
	return keys[0], conflicts
}

// extractSemverToken finds the first "digits.digits.digits" pattern in s
// (e.g. "Flutter Engine 3.24.1 (stable)" -> "3.24.1"), a hand-rolled
// state-machine scanner mirroring flutterdec's extract_semver_token.
func extractSemverToken(s string) string {
	n := len(s)
	for i := 0; i < n; i++ {
		if !isDigit(s[i]) {
			continue
		}
		j := i
		seg := 0
		var lastDigitEnd int
		for seg < 3 {
			k := j
			for k < n && isDigit(s[k]) {
				k++
			}
			if k == j {
				break // no digits in this segment
			}
			lastDigitEnd = k
			seg++
			if seg == 3 {
				return s[i:lastDigitEnd]
			}
			if k >= n || s[k] != '.' {
				break
			}
			j = k + 1
		}
		// Advance i past this failed attempt's first digit run to avoid
		// re-scanning the same digits repeatedly. The outer loop's i++ only
		// advances by 1, so without this a string with many digit runs is
		// O(n^2). Skip to lastDigitEnd (the end of the digit run we just
		// examined) so the next iteration starts after it.
		if lastDigitEnd > i+1 {
			i = lastDigitEnd
			continue
		}
	}
	return ""
}

// flutterVersionFromBanner accepts only a Flutter-engine-labelled version.
// Arbitrary semantic versions elsewhere in a printable run are not evidence.
func flutterVersionFromBanner(s string) string {
	lower := strings.ToLower(s)
	i := strings.Index(lower, "flutter engine")
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(s[i+len("flutter engine"):])
	return versionPrefix(rest)
}

// dartBannerEvidence recognizes both exact SDK-generated shapes. Older SDKs
// such as Dart 2.10 and 2.12 keep only
//
//	<version> (<channel>) (<commit time>)
//
// and Version::String() appends `on "<os>_<arch>"` dynamically. Starting with
// Dart 2.15 among the supported profiles, the suffix is embedded directly into
// str_. Both forms can therefore be
// present in a compiled image and both are provenance-bearing; a generic
// semver is not.
func dartBannerEvidence(s string) (version, arch string, ok bool) {
	const prefix = "Dart VM version:"
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, strings.ToLower(prefix)) {
		s = strings.TrimSpace(s[len(prefix):])
	} else if strings.HasPrefix(lower, "dart ") {
		// runtime/vm/dwarf.cc writes producer="Dart %s" where %s is
		// Version::String() starting with the supported Dart 3.6 line.
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
	case elf.EM_ARM:
		return class == elf.ELFCLASS32 && arch == "arm"
	case elf.EM_386:
		return class == elf.ELFCLASS32 && (arch == "ia32" || arch == "x86")
	case elf.EM_RISCV:
		switch class {
		case elf.ELFCLASS32:
			return arch == "riscv32"
		case elf.ELFCLASS64:
			return arch == "riscv64"
		default:
			return false
		}
	case elf.EM_PPC64:
		return class == elf.ELFCLASS64 && (arch == "ppc64" || arch == "ppc64le")
	default:
		return false
	}
}

func confidenceLevel(hasDartVersion, hasFlutterVersion, hasConflict bool) string {
	if hasConflict {
		return ConfidenceLow
	}
	switch {
	case hasDartVersion && hasFlutterVersion:
		return ConfidenceHigh
	case hasDartVersion || hasFlutterVersion:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}
