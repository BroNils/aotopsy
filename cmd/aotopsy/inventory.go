package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"aotopsy/internal/analysis"
)

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

	var rows []analysis.InventoryRow
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".zip") {
			continue
		}
		path := filepath.Join(*dir, e.Name())
		row := analysis.InventoryRow{
			SampleID: strings.TrimSuffix(e.Name(), ".zip"),
			APKPath:  path,
		}

		libapp, abi, err := analysis.InventoryExtractLibapp(path)
		if err != nil {
			row.DeclaredLibapp = false
			row.Error = err.Error()
			rows = append(rows, row)
			continue
		}
		row.DeclaredLibapp = true
		row.ABI = abi

		hash, dartVer, features, err := analysis.InventoryScanLibapp(libapp)
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
