package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"aotopsy/internal/disasm"
)

func cmdTHRClassify(args []string) error {
	fs := flag.NewFlagSet("thr-classify", flag.ExitOnError)
	inputPath := fs.String("in", "", "input thr_loads.jsonl path")
	outDir := fs.String("out", "", "output directory")
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

	records, err := disasm.ReadAuditRecords(f)
	if err != nil {
		return fmt.Errorf("read records: %w", err)
	}

	// Cluster into bands.
	bands := disasm.ClusterBands(records, *maxGap)

	// Classify.
	classified := disasm.ClassifyRecords(records, bands)

	// Create output directory.
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Write classified.jsonl.
	classPath := filepath.Join(*outDir, "classified.jsonl")
	cf, err := os.Create(classPath)
	if err != nil {
		return fmt.Errorf("create classified: %w", err)
	}
	defer func() { _ = cf.Close() }()
	enc := json.NewEncoder(cf)
	enc.SetEscapeHTML(false)
	for _, cr := range classified {
		if err := enc.Encode(cr); err != nil {
			return fmt.Errorf("write classified: %w", err)
		}
	}

	// Build and print summary.
	summary := disasm.Summarize(classified)

	fmt.Fprintf(os.Stderr, "%s (Dart %s): %d unresolved\n",
		summary.Sample, summary.DartVersion, summary.Total)

	classes := []disasm.THRClass{
		disasm.ClassRuntimeEntrypoint,
		disasm.ClassObjectStoreCache,
		disasm.ClassIsolateGroupPtr,
		disasm.ClassUnknown,
	}
	for _, cls := range classes {
		count := summary.Counts[cls]
		pct := 0.0
		if summary.Total > 0 {
			pct = float64(count) / float64(summary.Total) * 100
		}
		fmt.Fprintf(os.Stderr, "  %-30s %4d (%5.1f%%)\n", cls, count, pct)
	}

	fmt.Fprintf(os.Stderr, "wrote %s\n", classPath)

	return nil
}
