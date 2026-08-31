package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
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

	data, err := os.ReadFile(*inventoryPath)
	if err != nil {
		return fmt.Errorf("read inventory: %w", err)
	}

	type invRow struct {
		SampleID     string `json:"sample_id"`
		SnapshotHash string `json:"snapshot_hash"`
		DartVersion  string `json:"dart_version"`
		Features     string `json:"features"`
	}

	buckets := map[string]*dart2Bucket{}
	lines := splitLines(data)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var row invRow
		if err := json.Unmarshal(line, &row); err != nil {
			continue
		}
		if row.SnapshotHash == "" || row.DartVersion == "" {
			continue
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

	f, err := os.Create(*outPath)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	defer func() { _ = f.Close() }()

	enc := json.NewEncoder(f)
	for _, b := range sorted {
		if err := enc.Encode(b); err != nil {
			return fmt.Errorf("encode: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "dart2-buckets: %d hashes, %d total samples\n", len(sorted), func() int {
		n := 0
		for _, b := range sorted {
			n += b.Count
		}
		return n
	}())

	return nil
}
