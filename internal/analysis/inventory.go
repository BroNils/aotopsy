package analysis

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"strings"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/snapshot"
)

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

	// Direct libapp.so — try both ABIs.
	for _, abi := range []string{"arm64-v8a", "x86_64"} {
		for _, f := range zr.File {
			if f.Name == "lib/"+abi+"/libapp.so" {
				path, err := inventoryExtractFile(f)
				return path, abi, err
			}
		}
	}

	// Nested APKs.
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".apk") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		tmp, err := os.CreateTemp("", "apk-*.apk")
		if err != nil {
			_ = rc.Close()
			continue
		}
		_, _ = io.Copy(tmp, rc)
		_ = rc.Close()
		_ = tmp.Close()

		inner, err := zip.OpenReader(tmp.Name())
		if err != nil {
			_ = os.Remove(tmp.Name())
			continue
		}

		var found, foundABI string
		for _, abi := range []string{"arm64-v8a", "x86_64"} {
			for _, inf := range inner.File {
				if inf.Name == "lib/"+abi+"/libapp.so" {
					found, err = inventoryExtractFile(inf)
					foundABI = abi
					break
				}
			}
			if found != "" {
				break
			}
		}
		_ = inner.Close()
		_ = os.Remove(tmp.Name())

		if found != "" {
			return found, foundABI, err
		}
	}

	return "", "", fmt.Errorf("no libapp.so found (tried arm64-v8a and x86_64)")
}

func inventoryExtractFile(f *zip.File) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer func() { _ = rc.Close() }()

	tmp, err := os.CreateTemp("", "libapp-*.so")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(tmp, rc); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", err
	}
	_ = tmp.Close()
	return tmp.Name(), nil
}

// InventoryScanLibapp opens a libapp.so and extracts snapshot hash, Dart version, and features.
func InventoryScanLibapp(path string) (hash, dartVer, features string, err error) {
	ef, err := elfx.Open(path)
	if err != nil {
		return "", "", "", fmt.Errorf("open elf: %w", err)
	}
	defer func() { _ = ef.Close() }()

	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}
	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		return "", "", "", fmt.Errorf("extract: %w", err)
	}

	if info.VmHeader != nil {
		hash = info.VmHeader.SnapshotHash
		features = info.VmHeader.Features
	}
	if info.Version != nil {
		dartVer = info.Version.DartVersion
	}
	return hash, dartVer, features, nil
}
