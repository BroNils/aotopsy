package analysis

import (
	"archive/zip"
	"errors"
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
	Hit         string `json:"hit"` // "symbols" or "none"
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
		if errors.Is(err, elfx.ErrMalformed) || errors.Is(err, elfx.ErrChanged) {
			return c, fmt.Errorf("inspect ELF: %w", err)
		}
		// A real supported libapp.so is an ELF64 ET_DYN for a supported machine.
		// Raw magic in a non-ELF/unsupported file is not enough to claim a Dart
		// binary; doing so let four attacker-controlled bytes become Found=true.
		return c, nil
	}
	defer func() { _ = ef.Close() }()
	if abi, ok := nativeLibraryABI(pathLabel); ok {
		if err := validateNativeELFABI(ef, abi); err != nil {
			return c, err
		}
	}

	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}
	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		if errors.Is(err, snapshot.ErrNoSnapshotSymbols) {
			return c, nil
		}
		return c, fmt.Errorf("inspect snapshot: %w", err)
	}
	if err == nil && info.PrimaryHeader() != nil && info.SnapshotHash() != "" {
		c.Hit = "symbols"
		c.SnapHash = info.SnapshotHash()
		if info.Version != nil {
			c.DartVersion = info.Version.DartVersion
		}
		return c, nil
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

func hasAnyHit(candidates []FindCandidate) bool {
	for _, c := range candidates {
		if c.Hit == "symbols" {
			return true
		}
	}
	return false
}

func classifyFindResult(r *FindResult) {
	// Sort verified symbol hits first, then non-matches. Stable secondary key on PathInAPK.
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
	_, ok := nativeLibraryABI(name)
	return ok && strings.HasSuffix(name, ".so")
}

func nativeLibraryABI(name string) (string, bool) {
	if bang := strings.LastIndex(name, "!"); bang >= 0 {
		name = name[bang+1:]
	}
	switch {
	case strings.HasPrefix(name, "lib/arm64-v8a/"):
		return "arm64-v8a", true
	case strings.HasPrefix(name, "lib/x86_64/"):
		return "x86_64", true
	default:
		return "", false
	}
}

func validateNativeELFABI(ef *elfx.File, abi string) error {
	if ef == nil {
		return fmt.Errorf("native ABI %s: missing ELF", abi)
	}
	switch abi {
	case "arm64-v8a":
		if !ef.IsARM64() {
			return fmt.Errorf("native ABI path %s contradicts ELF machine %s", abi, ef.Machine())
		}
	case "x86_64":
		if ef.IsARM64() {
			return fmt.Errorf("native ABI path %s contradicts ELF machine %s", abi, ef.Machine())
		}
	default:
		return fmt.Errorf("unsupported native ABI %q", abi)
	}
	return nil
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
	default:
		return 1
	}
}
