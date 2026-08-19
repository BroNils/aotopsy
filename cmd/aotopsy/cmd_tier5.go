package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aotopsy/internal/decompiler"
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

	result, err := decompiler.CompareBlutter(blutterDir, aotopsyDir)
	if err != nil {
		return fmt.Errorf("compare: %w", err)
	}
	fmt.Print(result.Summary())

	// Write full report as JSON.
	reportPath := filepath.Join(aotopsyDir, "blutter_comparison.json")
	data, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile(reportPath, data, 0644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	fmt.Printf("\nFull report: %s\n", reportPath)
	return nil
}

// cmdBuildFingerprintDict builds a function fingerprint dictionary
// from function_fingerprints.jsonl.
// Usage: aotopsy build-fingerprint-dict <aotopsy_dir> <output.json>
func cmdBuildFingerprintDict(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: aotopsy build-fingerprint-dict <aotopsy_dir> <output.json>")
	}
	aotopsyDir := args[0]
	outputPath := args[1]
	fpPath := filepath.Join(aotopsyDir, "function_fingerprints.jsonl")
	data, err := os.ReadFile(fpPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", fpPath, err)
	}
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("write %s: %w", outputPath, err)
	}
	fmt.Printf("Dictionary written to %s\n", outputPath)
	return nil
}

// cmdApplyFingerprintDict applies a fingerprint dictionary to unnamed functions.
// Usage: aotopsy apply-fingerprint-dict <dictionary.json> <aotopsy_dir>
func cmdApplyFingerprintDict(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: aotopsy apply-fingerprint-dict <dictionary.json> <aotopsy_dir>")
	}
	dictPath := args[0]
	aotopsyDir := args[1]
	data, err := os.ReadFile(dictPath)
	if err != nil {
		return fmt.Errorf("read dictionary: %w", err)
	}
	dict := decompiler.ImportDictionary(string(data))
	fmt.Printf("Dictionary loaded: %d entries (%d named)\n",
		dict.Size(), dict.NamedCount())
	fpPath := filepath.Join(aotopsyDir, "function_fingerprints.jsonl")
	fpData, err := os.ReadFile(fpPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", fpPath, err)
	}
	matched := 0
	total := 0
	for _, line := range splitLines(fpData) {
		var fp struct {
			Hash string `json:"hash"`
			VA   string `json:"va"`
			Name string `json:"name"`
		}
		if json.Unmarshal([]byte(line), &fp) != nil {
			continue
		}
		total++
		if name, _, ok := dict.Lookup(fp.Hash); ok {
			fmt.Printf("  %s: %s -> %s\n", fp.VA, fp.Name, name)
			matched++
		}
	}
	fmt.Printf("\nMatched: %d / %d\n", matched, total)
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
	var snap decompiler.DarterSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("parse darter JSON: %w", err)
	}
	fmt.Printf("Darter snapshot: %s %s, %d functions, %d classes, %d strings\n",
		snap.DartVersion, snap.Arch,
		len(snap.Functions), len(snap.Classes), len(snap.Strings))
	// Importing darter output is a coverage fallback for releases this tool
	// cannot parse itself. When it CAN, say so -- a native run resolves names,
	// types and call edges that a darter dump does not carry.
	supported := snapshot.SupportedVersions()
	for _, v := range supported {
		if v == snap.DartVersion {
			fmt.Printf("Note: aotopsy analyses Dart %s natively; running it on the\n"+
				"      libapp.so directly recovers more than this import can.\n", v)
			break
		}
	}
	if only := decompiler.DarterVersionSupport(supported); len(only) > 0 {
		fmt.Printf("Darter-only coverage (%d versions): %s\n",
			len(only), strings.Join(only, ", "))
	}
	r2 := decompiler.ImportDarter(&snap)
	if err := r2.Write(outputPath); err != nil {
		return fmt.Errorf("write r2 script: %w", err)
	}
	fmt.Printf("R2 script written to %s (%d lines)\n", outputPath, len(r2.Lines))
	return nil
}
