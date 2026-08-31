package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"aotopsy/internal/decompiler/compare"
)

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
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
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
	dict := compare.ImportDictionary(string(data))
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
		if json.Unmarshal(line, &fp) != nil {
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
