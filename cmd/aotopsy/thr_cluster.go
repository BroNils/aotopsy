package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"aotopsy/internal/thraudit"
)

func cmdTHRCluster(args []string) error {
	fs := flag.NewFlagSet("thr-cluster", flag.ExitOnError)
	inputPath := fs.String("in", "", "input thr_loads.jsonl path")
	outDir := fs.String("out", "", "output directory for bands.json and bands.md")
	maxGap := fs.Int("max-gap", 0x18, "max gap between offsets before splitting bands")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inputPath == "" || *outDir == "" {
		return fmt.Errorf("--in and --out are required")
	}

	// Read audit records.
	f, err := os.Open(*inputPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer func() { _ = f.Close() }()

	records, err := thraudit.ReadAuditRecords(f)
	if err != nil {
		return fmt.Errorf("read records: %w", err)
	}

	// Cluster into bands.
	br := thraudit.ClusterBands(records, *maxGap)

	// Create output directory.
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Write bands.json.
	jsonPath := filepath.Join(*outDir, "bands.json")
	jf, err := os.Create(jsonPath)
	if err != nil {
		return fmt.Errorf("create json: %w", err)
	}
	defer func() { _ = jf.Close() }()
	if err := thraudit.WriteBandsJSON(jf, br); err != nil {
		return fmt.Errorf("write json: %w", err)
	}

	// Write bands.md.
	mdPath := filepath.Join(*outDir, "bands.md")
	mf, err := os.Create(mdPath)
	if err != nil {
		return fmt.Errorf("create md: %w", err)
	}
	defer func() { _ = mf.Close() }()
	thraudit.WriteBandsMD(mf, br)

	fmt.Fprintf(os.Stderr, "%s: %d bands from %d unresolved accesses\n",
		br.Sample, len(br.Bands), br.TotalUnresolved)
	fmt.Fprintf(os.Stderr, "wrote %s\n", jsonPath)
	fmt.Fprintf(os.Stderr, "wrote %s\n", mdPath)

	return nil
}
