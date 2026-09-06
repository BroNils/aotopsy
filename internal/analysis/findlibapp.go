package analysis

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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

	// Collect all .so paths in lib/arm64-v8a/.
	var soFiles []*zip.File
	var hasNestedAPK bool
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "lib/arm64-v8a/") && strings.HasSuffix(f.Name, ".so") {
			soFiles = append(soFiles, f)
		}
		if strings.HasSuffix(f.Name, ".apk") {
			hasNestedAPK = true
		}
	}

	// Probe direct .so files.
	for _, f := range soFiles {
		c, err := probeSOFile(f, f.Name)
		if err != nil {
			continue
		}
		result.Candidates = append(result.Candidates, *c)
	}

	// If no direct hits and nested APKs exist, probe those.
	if !hasAnyHit(result.Candidates) && hasNestedAPK {
		for _, f := range zr.File {
			if !strings.HasSuffix(f.Name, ".apk") {
				continue
			}
			nested, err := probeNestedAPK(f)
			if err != nil {
				continue
			}
			result.Candidates = append(result.Candidates, nested...)
		}
	}

	// Classify.
	classifyFindResult(result)
	return result, nil
}

func probeSOFile(f *zip.File, pathLabel string) (*FindCandidate, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()

	tmp, err := os.CreateTemp("", "probe-*.so")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	n, err := io.Copy(tmp, rc)
	if err != nil {
		_ = tmp.Close()
		return nil, err
	}
	_ = tmp.Close()

	// Compute SHA256.
	h := sha256.New()
	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		return nil, err
	}
	h.Write(data)
	sha := hex.EncodeToString(h.Sum(nil))

	c := &FindCandidate{
		PathInAPK: pathLabel,
		SHA256:    sha,
		Size:      n,
		Hit:       "none",
	}

	// Try ELF + snapshot extract (symbol-based detection).
	ef, err := elfx.Open(tmp.Name())
	if err != nil {
		// Not a valid ARM64 ELF — check for magic in raw data anyway.
		if off := snapshot.ProbeSnapshotMagic(data); off >= 0 {
			c.Hit = "magic"
		}
		return c, nil
	}
	defer func() { _ = ef.Close() }()

	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}
	info, err := snapshot.Extract(ef, opts)
	if err == nil && info.VmHeader != nil && info.VmHeader.SnapshotHash != "" {
		c.Hit = "symbols"
		c.SnapHash = info.VmHeader.SnapshotHash
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

func probeNestedAPK(f *zip.File) ([]FindCandidate, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}

	tmp, err := os.CreateTemp("", "nested-*.apk")
	if err != nil {
		_ = rc.Close()
		return nil, err
	}
	_, _ = io.Copy(tmp, rc)
	_ = rc.Close()
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmp.Name()) }()

	inner, err := zip.OpenReader(tmp.Name())
	if err != nil {
		return nil, err
	}
	defer func() { _ = inner.Close() }()

	var results []FindCandidate
	for _, inf := range inner.File {
		if strings.HasPrefix(inf.Name, "lib/arm64-v8a/") && strings.HasSuffix(inf.Name, ".so") {
			label := f.Name + "!" + inf.Name
			c, err := probeSOFile(inf, label)
			if err != nil {
				continue
			}
			results = append(results, *c)
		}
	}
	return results, nil
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
		// Check if the issue is split APK or no arm64.
		r.Reason = "NO_ARM64"
	} else {
		r.Reason = "NOT_FLUTTER"
	}
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
