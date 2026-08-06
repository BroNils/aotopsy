package main

import (
	"archive/zip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
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

func cmdInventory(args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ExitOnError)
	dir := fs.String("dir", "samples/flutter", "Directory containing zip files")
	outPath := fs.String("out", "", "Output JSONL file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	entries, err := os.ReadDir(*dir)
	if err != nil {
		return fmt.Errorf("readdir %s: %w", *dir, err)
	}

	var rows []InventoryRow
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".zip") {
			continue
		}
		path := filepath.Join(*dir, e.Name())
		row := InventoryRow{
			SampleID: strings.TrimSuffix(e.Name(), ".zip"),
			APKPath:  path,
			ABI:      "arm64-v8a",
		}

		libapp, err := inventoryExtractLibapp(path)
		if err != nil {
			row.DeclaredLibapp = false
			row.Error = err.Error()
			rows = append(rows, row)
			continue
		}
		row.DeclaredLibapp = true

		hash, dartVer, features, err := inventoryScanLibapp(libapp)
		_ = os.Remove(libapp)
		if err != nil {
			row.Error = err.Error()
			rows = append(rows, row)
			continue
		}

		row.SnapshotHash = hash
		row.DartVersion = dartVer
		row.Features = features
		rows = append(rows, row)
	}

	// Stable sort by sample_id.
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].SampleID < rows[j].SampleID
	})

	var w io.Writer = os.Stdout
	if *outPath != "" {
		if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
			return err
		}
		f, err := os.Create(*outPath)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, row := range rows {
		if err := enc.Encode(row); err != nil {
			return err
		}
	}

	// Summary to stderr.
	var found, notFound, errCount int
	verCount := map[string]int{}
	hashCount := map[string]int{}
	for _, r := range rows {
		if r.Error != "" && !r.DeclaredLibapp {
			notFound++
			continue
		}
		if r.Error != "" {
			errCount++
			continue
		}
		found++
		if r.SnapshotHash != "" {
			hashCount[r.SnapshotHash]++
		}
		ver := r.DartVersion
		if ver == "" {
			ver = "unknown"
		}
		verCount[ver]++
	}

	fmt.Fprintf(os.Stderr, "inventory: %d zips, %d with libapp, %d no libapp, %d errors, %d unique hashes\n",
		len(rows), found, notFound, errCount, len(hashCount))
	type vc struct {
		ver   string
		count int
	}
	var vcs []vc
	for v, c := range verCount {
		vcs = append(vcs, vc{v, c})
	}
	sort.Slice(vcs, func(i, j int) bool { return vcs[i].ver < vcs[j].ver })
	for _, v := range vcs {
		fmt.Fprintf(os.Stderr, "  %-10s %d\n", v.ver, v.count)
	}
	return nil
}

// inventoryExtractLibapp finds and extracts lib/arm64-v8a/libapp.so from a zip.
func inventoryExtractLibapp(zipPath string) (string, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("open zip: %w", err)
	}
	defer func() { _ = zr.Close() }()

	// Direct libapp.so.
	for _, f := range zr.File {
		if f.Name == "lib/arm64-v8a/libapp.so" {
			return inventoryExtractFile(f)
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

		var found string
		for _, inf := range inner.File {
			if inf.Name == "lib/arm64-v8a/libapp.so" {
				found, err = inventoryExtractFile(inf)
				break
			}
		}
		_ = inner.Close()
		_ = os.Remove(tmp.Name())

		if found != "" {
			return found, err
		}
	}

	return "", fmt.Errorf("no lib/arm64-v8a/libapp.so found")
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

func inventoryScanLibapp(path string) (hash, dartVer, features string, err error) {
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
