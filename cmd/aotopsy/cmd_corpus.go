package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cli"
	"aotopsy/internal/output"
)

// cmdParity runs parity checks across sample subdirectories.
func cmdParity(args []string) error {
	fs := flag.NewFlagSet("parity", flag.ContinueOnError)
	samplesDir := fs.String("samples", "", "directory containing sample subdirs (each with libapp.so)")
	outDir := fs.String("out", "", "output directory for parity.csv and summary")

	if err := parseNoPositionals(fs, args); err != nil {
		return err
	}
	if *samplesDir == "" || *outDir == "" {
		return fmt.Errorf("--samples and --out are required")
	}

	return analysis.RunParity(*samplesDir, *outDir)
}

// cmdInventory inventories sample ZIP/APK files and extracts version/snapshot metadata.
func cmdInventory(args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	dir := fs.String("dir", "samples/flutter", "Directory containing zip files")
	outPath := fs.String("out", "", "Output JSONL file (default: stdout)")
	if err := parseNoPositionals(fs, args); err != nil {
		return err
	}

	entries, err := os.ReadDir(*dir)
	if err != nil {
		return fmt.Errorf("readdir %s: %w", *dir, err)
	}

	var rows []analysis.InventoryRow
	for _, e := range entries {
		base, ok := archiveInputBase(e.Name())
		if !ok {
			continue
		}
		path := filepath.Join(*dir, e.Name())
		if *outPath != "" {
			same, err := output.SamePath(*outPath, path)
			if err != nil {
				return fmt.Errorf("compare inventory output/input paths: %w", err)
			}
			if same {
				return fmt.Errorf("inventory output %s aliases input archive %s", *outPath, path)
			}
		}
		row := analysis.InventoryRow{
			SampleID: base,
			APKPath:  path,
		}

		libapp, abi, err := analysis.InventoryExtractLibapp(path)
		if err != nil {
			row.DeclaredLibapp = false
			if !errors.Is(err, analysis.ErrInventoryNoLibapp) {
				row.Error = err.Error()
			}
			rows = append(rows, row)
			continue
		}
		row.DeclaredLibapp = true
		row.ABI = abi

		hash, dartVer, features, err := analysis.InventoryScanLibapp(libapp, abi)
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

	writeRows := func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		for _, row := range rows {
			if err := enc.Encode(row); err != nil {
				return err
			}
		}
		return nil
	}
	if *outPath == "" {
		if err := writeRows(os.Stdout); err != nil {
			return err
		}
	} else if err := output.WriteAtomic(*outPath, 0o644, writeRows); err != nil {
		return fmt.Errorf("write inventory %s: %w", *outPath, err)
	}

	// Summary to stderr.
	var found, notFound, errCount int
	verCount := map[string]int{}
	hashCount := map[string]int{}
	for _, r := range rows {
		if !r.DeclaredLibapp {
			if r.Error == "" {
				notFound++
			} else {
				errCount++
			}
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

	cli.Errf("inventory: %d zips, %d with libapp, %d no libapp, %d errors, %d unique hashes\n",
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
		cli.Errf("  %-10s %d\n", v.ver, v.count)
	}
	if errCount > 0 {
		return fmt.Errorf("inventory completed with %d archive error(s)", errCount)
	}
	return nil
}
