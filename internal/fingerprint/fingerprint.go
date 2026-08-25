// Package fingerprint identifies the build-id, target architecture, and
// Flutter/Dart engine version markers embedded in a native library, without
// needing any Dart-snapshot-aware parsing. Ported from flutterdec's
// engine_fingerprint.rs (Rust), generalized to work for any ELF machine
// type aotopsy's elfx package accepts (ARM64, x86_64), not just ARM64.
package fingerprint

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
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
	Path            string   `json:"path"`
	Machine         string   `json:"machine"`
	BuildID         string   `json:"build_id,omitempty"`
	FlutterVersion  string   `json:"flutter_version,omitempty"`
	DartVersion     string   `json:"dart_version,omitempty"`
	FlutterMarkers  []string `json:"flutter_markers,omitempty"`
	DartMarkers     []string `json:"dart_markers,omitempty"`
	Confidence      string   `json:"confidence"`
	FileSize        int64    `json:"file_size"`
	ExecSectionSize uint64   `json:"exec_section_size"`
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

	rep.BuildID = extractBuildID(ef)

	for _, s := range ef.Sections {
		if s.Flags&elf.SHF_EXECINSTR != 0 {
			rep.ExecSectionSize += s.Size
		}
	}

	// Marker/version extraction scans the WHOLE file, not just exec
	// sections -- version banners live in rodata, not code.
	raw := make([]byte, info.Size())
	if _, err := f.ReadAt(raw, 0); err != nil && info.Size() > 0 {
		return nil, fmt.Errorf("fingerprint: read file: %w", err)
	}

	flutterMarkers, dartMarkers := extractEngineMarkers(raw)
	rep.FlutterMarkers = flutterMarkers
	rep.DartMarkers = dartMarkers

	// Iterate ALL markers and take the first semver found. The markers slice
	// is sorted alphabetically (extractEngineMarkers calls sort.Strings), so
	// marker[0] is the alphabetically-first entry, which may not contain a
	// version even if a later marker does (e.g. "Engine revision abc" sorts
	// before "Flutter Engine 3.24.1"). Taking only [0] silently dropped the
	// version in that case.
	rep.FlutterVersion = firstSemverFromMarkers(flutterMarkers)
	rep.DartVersion = firstSemverFromMarkers(dartMarkers)

	hasVersionHint := rep.FlutterVersion != "" || rep.DartVersion != ""
	rep.Confidence = confidenceLevel(rep.BuildID != "", hasVersionHint)

	return rep, nil
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

// extractBuildID hand-parses the ELF note format looking for
// NT_GNU_BUILD_ID (type 3, owner "GNU") inside any section whose name
// contains "note". Mirrors flutterdec's hand-rolled note-section parser
// (Go's debug/elf has no exported build-id helper for arbitrary ELFs).
func extractBuildID(ef *elf.File) string {
	for _, s := range ef.Sections {
		if !strings.Contains(strings.ToLower(s.Name), "note") {
			continue
		}
		data, err := s.Data()
		if err != nil {
			continue
		}
		if id := parseBuildIDNotes(data, ef.ByteOrder); id != "" {
			return id
		}
	}
	return ""
}

// parseBuildIDNotes walks a raw ELF note-section byte stream (repeated
// namesz/descsz/type u32 triples, name padded to 4-byte alignment,
// descriptor padded to 4-byte alignment) looking for name=="GNU" type==3.
// The u32 fields are read using the ELF's native byte order (bo), which is
// ef.ByteOrder from the caller -- not hardcoded little-endian, so big-endian
// ELFs are handled correctly.
func parseBuildIDNotes(data []byte, bo binary.ByteOrder) string {
	off := 0
	for off+12 <= len(data) {
		namesz := bo.Uint32(data[off:])
		descsz := bo.Uint32(data[off+4:])
		ntype := bo.Uint32(data[off+8:])
		off += 12

		nameEnd := off + int(namesz)
		if nameEnd > len(data) {
			return ""
		}
		name := ""
		if namesz > 0 {
			// namesz includes the trailing NUL.
			raw := data[off:nameEnd]
			if i := bytes.IndexByte(raw, 0); i >= 0 {
				name = string(raw[:i])
			} else {
				name = string(raw)
			}
		}
		off = align4(nameEnd)

		descEnd := off + int(descsz)
		if descEnd > len(data) {
			return ""
		}
		desc := data[off:descEnd]
		off = align4(descEnd)

		if name == "GNU" && ntype == 3 { // NT_GNU_BUILD_ID
			return hex.EncodeToString(desc)
		}
	}
	return ""
}

func align4(n int) int {
	return (n + 3) &^ 3
}

// extractEngineMarkers scans raw for printable-ASCII runs (min length 10)
// and buckets any string containing "flutter"/"engine" as a Flutter
// marker, or "dart"/"isolate snapshot"/"vm snapshot" as a Dart marker
// (case-insensitive substring match, matching flutterdec's heuristic --
// this is pure string-scanning, there is no structured snapshot-header
// parser for engine version detection on either side of this port).
func extractEngineMarkers(raw []byte) (flutterMarkers, dartMarkers []string) {
	seenFlutter := make(map[string]bool)
	seenDart := make(map[string]bool)

	for _, s := range asciiStrings(raw, 10) {
		if len(s) > 240 {
			continue
		}
		lower := strings.ToLower(s)
		// Use specific markers instead of bare "engine"/"dart" substrings,
		// which match far too broadly (e.g. any string containing "dart"
		// as a substring of a larger word). Keep the isolate/vm snapshot
		// patterns which are specific enough.
		isFlutter := strings.Contains(lower, "flutter engine")
		isDart := strings.Contains(lower, "dart vm") || strings.Contains(lower, "dart sdk") ||
			strings.Contains(lower, "dart:") || strings.Contains(lower, "isolate snapshot") ||
			strings.Contains(lower, "vm snapshot")
		if isFlutter && !seenFlutter[s] {
			seenFlutter[s] = true
			flutterMarkers = append(flutterMarkers, s)
		}
		if isDart && !seenDart[s] {
			seenDart[s] = true
			dartMarkers = append(dartMarkers, s)
		}
	}
	sort.Strings(flutterMarkers)
	sort.Strings(dartMarkers)
	return flutterMarkers, dartMarkers
}

// asciiStrings extracts printable-ASCII runs of at least minLen bytes.
func asciiStrings(data []byte, minLen int) []string {
	var out []string
	start := -1
	for i := 0; i <= len(data); i++ {
		printable := i < len(data) && data[i] >= 0x20 && data[i] < 0x7f
		if printable {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if i-start >= minLen {
				out = append(out, string(data[start:i]))
			}
			start = -1
		}
	}
	return out
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

// firstSemverFromMarkers returns the first semver token found across all
// markers, or "" if none contains one. Used instead of only checking the
// alphabetically-first marker (markers are sorted, so [0] may lack a version
// while a later marker has one).
func firstSemverFromMarkers(markers []string) string {
	for _, m := range markers {
		if v := extractSemverToken(m); v != "" {
			return v
		}
	}
	return ""
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func confidenceLevel(hasBuildID, hasVersionHint bool) string {
	switch {
	case hasBuildID && hasVersionHint:
		return ConfidenceHigh
	case hasBuildID || hasVersionHint:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}
