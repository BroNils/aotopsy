package analysis

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/snapshot"
)

// FindResult is the output of find-libapp for one APK/zip.
type FindResult struct {
	APK        string          `json:"apk"`
	Found      bool            `json:"found"`
	Reason     string          `json:"reason"`
	Best       *FindCandidate  `json:"best,omitempty"`
	Candidates []FindCandidate `json:"candidates,omitempty"`
}

// FindCandidate is one .so file probed for Dart AOT indicators.
type FindCandidate struct {
	PathInAPK   string `json:"path_in_apk"`
	Hit         string `json:"hit"` // "symbols", "magic", "none"
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	SnapHash    string `json:"snapshot_hash,omitempty"`
	DartVersion string `json:"dart_version,omitempty"`
}

// FindLibappInZip probes a zip/APK for Dart AOT libapp.so files.
func FindLibappInZip(zipPath string) (*FindResult, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	defer func() { _ = zr.Close() }()

	result := &FindResult{APK: zipPath}
	work := &archiveWorkBudget{}

	// Collect all native libraries for architectures the analyser supports.
	var soFiles []*zip.File
	var hasNestedAPK bool
	var soBudget uint64
	nestedCount := 0
	for _, f := range zr.File {
		if isSupportedNativeLibraryPath(f.Name) {
			if len(soFiles) >= maxArchiveCandidates {
				return nil, fmt.Errorf("archive has more than %d supported native-library candidates", maxArchiveCandidates)
			}
			if err := checkedArchiveBudget(&soBudget, f, maxLibappEntryBytes, maxArchiveProbeBytes); err != nil {
				return nil, err
			}
			soFiles = append(soFiles, f)
		}
		if strings.HasSuffix(f.Name, ".apk") {
			hasNestedAPK = true
			nestedCount++
			if nestedCount > maxNestedAPKCandidates {
				return nil, fmt.Errorf("archive has more than %d nested APK candidates", maxNestedAPKCandidates)
			}
		}
	}

	// Probe direct .so files.
	for _, f := range soFiles {
		c, err := probeSOFile(f, f.Name, work)
		if err != nil {
			return nil, fmt.Errorf("probe %q: %w", f.Name, err)
		}
		result.Candidates = append(result.Candidates, *c)
	}

	// If no direct hits and nested APKs exist, probe those.
	if !hasAnyHit(result.Candidates) && hasNestedAPK {
		for _, f := range zr.File {
			if !strings.HasSuffix(f.Name, ".apk") {
				continue
			}
			nested, err := probeNestedAPK(f, work)
			if err != nil {
				return nil, fmt.Errorf("probe nested APK %q: %w", f.Name, err)
			}
			result.Candidates = append(result.Candidates, nested...)
		}
	}

	// Classify.
	classifyFindResult(result)
	return result, nil
}

func probeSOFile(f *zip.File, pathLabel string, work *archiveWorkBudget) (*FindCandidate, error) {
	tmpPath, n, sha, err := extractZipEntryToTemp(f, "probe-*.so", maxLibappEntryBytes, work)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmpPath) }()

	c := &FindCandidate{
		PathInAPK: pathLabel,
		SHA256:    sha,
		Size:      n,
		Hit:       "none",
	}

	// Try ELF + snapshot extract (symbol-based detection).
	ef, err := elfx.Open(tmpPath)
	if err != nil {
		// Not a loadable ELF (any architecture) — check for magic without
		// loading the entire expanded candidate into memory.
		if hasSnapshotMagicInFile(tmpPath) {
			c.Hit = "magic"
		}
		return c, nil
	}
	defer func() { _ = ef.Close() }()

	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}
	info, err := snapshot.Extract(ef, opts)
	if err == nil && info.PrimaryHeader() != nil && info.SnapshotHash() != "" {
		c.Hit = "symbols"
		c.SnapHash = info.SnapshotHash()
		if info.Version != nil {
			c.DartVersion = info.Version.DartVersion
		}
		return c, nil
	}

	// Symbols not found — try magic probe on loadable segments.
	segs := ef.LoadSegments()
	for _, seg := range segs {
		if seg.Filesz == 0 {
			continue
		}
		// Read first 4KB of each segment.
		sz := int(seg.Filesz)
		if sz > 4096 {
			sz = 4096
		}
		buf := make([]byte, sz)
		_, err := ef.ReadAt(buf, int64(seg.Offset))
		if err != nil {
			continue
		}
		if snapshot.ProbeSnapshotMagic(buf) >= 0 {
			c.Hit = "magic"
			return c, nil
		}
	}

	return c, nil
}

func probeNestedAPK(f *zip.File, work *archiveWorkBudget) ([]FindCandidate, error) {
	tmpPath, _, _, err := extractZipEntryToTemp(f, "nested-*.apk", maxNestedAPKBytes, work)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmpPath) }()

	inner, err := zip.OpenReader(tmpPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = inner.Close() }()

	var results []FindCandidate
	var budget uint64
	candidates := 0
	for _, inf := range inner.File {
		if isSupportedNativeLibraryPath(inf.Name) {
			candidates++
			if candidates > maxArchiveCandidates {
				return nil, fmt.Errorf("nested APK %q has more than %d native-library candidates", f.Name, maxArchiveCandidates)
			}
			if err := checkedArchiveBudget(&budget, inf, maxLibappEntryBytes, maxArchiveProbeBytes); err != nil {
				return nil, fmt.Errorf("nested APK %q: %w", f.Name, err)
			}
			label := f.Name + "!" + inf.Name
			c, err := probeSOFile(inf, label, work)
			if err != nil {
				return nil, fmt.Errorf("nested APK %q probe %q: %w", f.Name, inf.Name, err)
			}
			results = append(results, *c)
		}
	}
	return results, nil
}

func hasSnapshotMagicInFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	magic := []byte{0xf5, 0xf5, 0xdc, 0xdc}
	buf := make([]byte, 64*1024+len(magic)-1)
	carry := 0
	for {
		n, err := f.Read(buf[carry:])
		if n > 0 {
			end := carry + n
			if bytes.Contains(buf[:end], magic) {
				return true
			}
			carry = len(magic) - 1
			if end < carry {
				carry = end
			}
			copy(buf[:carry], buf[end-carry:end])
		}
		if err != nil {
			return false
		}
	}
}

func hasAnyHit(candidates []FindCandidate) bool {
	for _, c := range candidates {
		if c.Hit != "none" {
			return true
		}
	}
	return false
}

func classifyFindResult(r *FindResult) {
	// Sort candidates: symbols first, then magic, then none. Stable secondary key on PathInAPK.
	sort.Slice(r.Candidates, func(i, j int) bool {
		pi := hitPriority(r.Candidates[i].Hit)
		pj := hitPriority(r.Candidates[j].Hit)
		if pi != pj {
			return pi < pj
		}
		return r.Candidates[i].PathInAPK < r.Candidates[j].PathInAPK
	})

	for i := range r.Candidates {
		if r.Candidates[i].Hit != "none" {
			r.Found = true
			r.Best = &r.Candidates[i]
			switch r.Candidates[i].Hit {
			case "symbols":
				r.Reason = "MATCHED_SYMBOLS"
			case "magic":
				r.Reason = "MATCHED_MAGIC"
			}
			return
		}
	}

	// No hits.
	r.Found = false
	if len(r.Candidates) == 0 {
		r.Reason = "NO_SUPPORTED_ABI"
	} else {
		r.Reason = "NOT_FLUTTER"
	}
}

func isSupportedNativeLibraryPath(name string) bool {
	if !strings.HasSuffix(name, ".so") {
		return false
	}
	return strings.HasPrefix(name, "lib/arm64-v8a/") || strings.HasPrefix(name, "lib/x86_64/")
}

func IsStandardLibappPath(name string) bool {
	if bang := strings.LastIndex(name, "!"); bang >= 0 {
		name = name[bang+1:]
	}
	return name == "lib/arm64-v8a/libapp.so" || name == "lib/x86_64/libapp.so"
}

func hitPriority(hit string) int {
	switch hit {
	case "symbols":
		return 0
	case "magic":
		return 1
	default:
		return 2
	}
}
