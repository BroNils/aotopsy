package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aotopsy/internal/decompiler/compare"
	"aotopsy/internal/snapshot"
)

// cmdCompareBlutter compares aotopsy output against blutter output.
// Usage: aotopsy compare-blutter <blutter_dir> <aotopsy_dir>
func cmdCompareBlutter(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: aotopsy compare-blutter <blutter_dir> <aotopsy_dir>")
	}
	blutterDir := args[0]
	aotopsyDir := args[1]

	result, err := compare.CompareBlutter(blutterDir, aotopsyDir)
	if err != nil {
		return fmt.Errorf("compare: %w", err)
	}
	fmt.Print(result.Summary())

	// Write full report as JSON.
	reportPath := filepath.Join(aotopsyDir, "blutter_comparison.json")
	data, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile(reportPath, data, 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	fmt.Printf("\nFull report: %s\n", reportPath)
	return nil
}

// cmdImportDarter imports darter output for older Dart versions.
// Usage: aotopsy import-darter <darter.json> <output.r2>
func cmdImportDarter(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: aotopsy import-darter <darter.json> <output.r2>")
	}
	darterPath := args[0]
	outputPath := args[1]
	data, err := os.ReadFile(darterPath)
	if err != nil {
		return fmt.Errorf("read darter output: %w", err)
	}
	var snap compare.DarterSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("parse darter JSON: %w", err)
	}
	fmt.Printf("Darter snapshot: %s %s, %d functions, %d classes, %d strings\n",
		snap.DartVersion, snap.Arch,
		len(snap.Functions), len(snap.Classes), len(snap.Strings))

	// Coverage notes
	supported := snapshot.SupportedVersions()
	for _, v := range supported {
		if v == snap.DartVersion {
			fmt.Printf("Note: aotopsy analyses Dart %s natively; running it on the\n"+
				"      libapp.so directly recovers more than this import can.\n", v)
			break
		}
	}
	if only := compare.DarterVersionSupport(supported); len(only) > 0 {
		fmt.Printf("Darter-only coverage (%d versions): %s\n",
			len(only), strings.Join(only, ", "))
	}
	r2 := compare.ImportDarter(&snap)
	if err := r2.Write(outputPath); err != nil {
		return fmt.Errorf("write r2 script: %w", err)
	}
	fmt.Printf("R2 script written to %s (%d lines)\n", outputPath, len(r2.Lines))
	return nil
}
