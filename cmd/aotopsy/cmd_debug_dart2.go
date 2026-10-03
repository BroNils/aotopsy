package main

import (
	"flag"
	"fmt"
	"sort"
	"strings"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cli"
	"aotopsy/internal/jsonutil"
)

type dart2Bucket struct {
	Hash        string `json:"hash"`
	Count       int    `json:"count"`
	DartVersion string `json:"dart_version"`
	Example     string `json:"example"`
	Features    string `json:"features"`
}

// cmdDart2Buckets implements "aotopsy _debug dart2-buckets": Dart 2.x bucket analysis.
func cmdDart2Buckets(args []string) error {
	fs := flag.NewFlagSet("dart2-buckets", flag.ExitOnError)
	inventoryPath := fs.String("inventory", "", "path to flutter_inventory.jsonl")
	outPath := fs.String("out", "", "output JSONL path")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inventoryPath == "" || *outPath == "" {
		return fmt.Errorf("--inventory and --out are required")
	}

	rows, err := jsonutil.ReadJSONL[analysis.InventoryRow](*inventoryPath, jsonutil.StandardLimits)
	if err != nil {
		return fmt.Errorf("read inventory: %w", err)
	}

	buckets := map[string]*dart2Bucket{}
	for _, row := range rows {
		if strings.TrimSpace(row.SampleID) == "" || strings.TrimSpace(row.APKPath) == "" {
			return fmt.Errorf("inventory record has missing sample_id or apk_path")
		}
		if row.Error != "" || !row.DeclaredLibapp {
			continue
		}
		if strings.TrimSpace(row.ABI) == "" {
			return fmt.Errorf("inventory record for sample %q declares libapp but has no abi", row.SampleID)
		}
		if row.SnapshotHash == "" || row.DartVersion == "" {
			return fmt.Errorf("inventory record for successful sample %q is missing snapshot_hash or dart_version", row.SampleID)
		}
		if row.DartVersion[0] != '2' {
			continue
		}
		b, ok := buckets[row.SnapshotHash]
		if !ok {
			b = &dart2Bucket{
				Hash:        row.SnapshotHash,
				DartVersion: row.DartVersion,
				Example:     row.SampleID,
				Features:    row.Features,
			}
			buckets[row.SnapshotHash] = b
		}
		b.Count++
	}

	sorted := make([]*dart2Bucket, 0, len(buckets))
	for _, b := range buckets {
		sorted = append(sorted, b)
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].DartVersion != sorted[j].DartVersion {
			return sorted[i].DartVersion < sorted[j].DartVersion
		}
		return sorted[i].Hash < sorted[j].Hash
	})

	if _, err := jsonutil.WriteJSONLFile(*outPath, sorted); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	cli.Errf("dart2-buckets: %d hashes, %d total samples\n", len(sorted), func() int {
		n := 0
		for _, b := range sorted {
			n += b.Count
		}
		return n
	}())

	return nil
}
