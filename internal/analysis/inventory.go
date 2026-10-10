package analysis

import (
	"archive/zip"
	"errors"
	"fmt"
	"os"
	"strings"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/snapshot"
)

// ErrInventoryNoLibapp distinguishes a valid archive that simply contains no
// supported libapp.so from an archive that could not be inspected safely.
// Batch inventory callers use this to report "no libapp" separately from
// corrupt/oversized/unreadable archive errors.
var ErrInventoryNoLibapp = errors.New("no libapp.so found")

// InventoryRow is one row of the corpus inventory JSONL.
type InventoryRow struct {
	SampleID       string `json:"sample_id"`
	APKPath        string `json:"apk_path"`
	ABI            string `json:"abi"`
	DeclaredLibapp bool   `json:"declared_libapp"`
	SnapshotHash   string `json:"snapshot_hash,omitempty"`
	DartVersion    string `json:"dart_version,omitempty"`
	Features       string `json:"features,omitempty"`
	Error          string `json:"error,omitempty"`
}

// InventoryExtractLibapp finds and extracts libapp.so from a zip.
// Tries arm64-v8a first, then x86_64. Returns (path, abi, error).
func InventoryExtractLibapp(zipPath string) (string, string, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", "", fmt.Errorf("open zip: %w", err)
	}
	defer func() { _ = zr.Close() }()
	work := &archiveWorkBudget{}

	// Direct libapp.so — try both ABIs.
	for _, abi := range []string{"arm64-v8a", "x86_64"} {
		for _, f := range zr.File {
			if f.Name == "lib/"+abi+"/libapp.so" {
				path, err := inventoryExtractFile(f, work)
				return path, abi, err
			}
		}
	}

	// Nested APKs.
	nestedCount := 0
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".apk") {
			continue
		}
		nestedCount++
		if nestedCount > maxNestedAPKCandidates {
			return "", "", fmt.Errorf("more than %d nested APK candidates", maxNestedAPKCandidates)
		}
		tmpPath, _, _, err := extractZipEntryToTemp(f, "apk-*.apk", maxNestedAPKBytes, work)
		if err != nil {
			return "", "", fmt.Errorf("extract nested APK %q: %w", f.Name, err)
		}

		inner, err := zip.OpenReader(tmpPath)
		if err != nil {
			_ = os.Remove(tmpPath)
			return "", "", fmt.Errorf("open nested APK %q: %w", f.Name, err)
		}

		var found, foundABI string
		for _, abi := range []string{"arm64-v8a", "x86_64"} {
			for _, inf := range inner.File {
				if inf.Name == "lib/"+abi+"/libapp.so" {
					found, err = inventoryExtractFile(inf, work)
					if err != nil {
						_ = inner.Close()
						_ = os.Remove(tmpPath)
						return "", "", fmt.Errorf("extract nested %s libapp.so from %q: %w", abi, f.Name, err)
					}
					foundABI = abi
					break
				}
			}
			if found != "" {
				break
			}
		}
		_ = inner.Close()
		_ = os.Remove(tmpPath)

		if found != "" {
			return found, foundABI, err
		}
	}

	return "", "", fmt.Errorf("%w (tried arm64-v8a and x86_64)", ErrInventoryNoLibapp)
}

func inventoryExtractFile(f *zip.File, work *archiveWorkBudget) (string, error) {
	path, _, _, err := extractZipEntryToTemp(f, "libapp-*.so", maxLibappEntryBytes, work)
	return path, err
}

// InventoryScanLibapp opens a libapp.so, verifies that its machine agrees with
// the ABI directory it came from, and extracts snapshot metadata.
func InventoryScanLibapp(path, expectedABI string) (hash, dartVer, features string, err error) {
	ef, err := elfx.Open(path)
	if err != nil {
		return "", "", "", fmt.Errorf("open elf: %w", err)
	}
	defer func() { _ = ef.Close() }()
	if err := validateNativeELFABI(ef, expectedABI); err != nil {
		return "", "", "", err
	}

	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}
	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		return "", "", "", fmt.Errorf("extract: %w", err)
	}

	if h := info.PrimaryHeader(); h != nil {
		hash = h.SnapshotHash
		features = h.Features
	}
	if info.Version != nil {
		dartVer = info.Version.DartVersion
	}
	return hash, dartVer, features, nil
}
