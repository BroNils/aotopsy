package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aotopsy/internal/analysis"
	"aotopsy/internal/decompiler/compare"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/output"
)

type fingerprintFileRecord struct {
	Hash  string `json:"hash"`
	VA    string `json:"va"`
	Size  int    `json:"size"`
	Name  string `json:"name"`
	Owner string `json:"owner,omitempty"`
}

// cmdBuildFingerprintDict builds a function fingerprint dictionary
// from function_fingerprints.jsonl.
// Usage: aotopsy build-fingerprint-dict <aotopsy_dir> <dictionary.jsonl>
func cmdBuildFingerprintDict(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: aotopsy build-fingerprint-dict <aotopsy_dir> <dictionary.jsonl>")
	}
	aotopsyDir := args[0]
	outputPath := args[1]
	fpPath := filepath.Join(aotopsyDir, "function_fingerprints.jsonl")
	for _, src := range []string{fpPath, filepath.Join(aotopsyDir, analysis.ProvenanceFileName)} {
		same, err := output.SamePath(outputPath, src)
		if err != nil {
			return fmt.Errorf("compare fingerprint output/input paths: %w", err)
		}
		if same {
			return fmt.Errorf("fingerprint dictionary output %s aliases consumed input %s", outputPath, src)
		}
	}
	records, err := jsonutil.ReadJSONL[fingerprintFileRecord](fpPath, jsonutil.StandardLimits)
	if err != nil {
		return fmt.Errorf("read %s: %w", fpPath, err)
	}
	provenance, ok, err := analysis.ReadProvenance(aotopsyDir)
	if err != nil {
		return fmt.Errorf("read fingerprint provenance: %w", err)
	}
	if !ok || provenance.DartVersion == "" || (provenance.Arch != "arm64" && provenance.Arch != "x64") {
		return fmt.Errorf("build fingerprint dictionary: output lacks exact Dart version/architecture provenance")
	}
	dict, err := compare.NewFunctionDictionary(provenance.DartVersion, provenance.Arch)
	if err != nil {
		return err
	}
	for _, rec := range records {
		if rec.Name == "" || strings.HasPrefix(rec.Name, "sub_") || strings.HasPrefix(rec.Name, "stub_") {
			continue
		}
		dict.Add(compare.FunctionFingerprint{Hash: rec.Hash, Size: rec.Size, FuncName: rec.Name, Owner: rec.Owner})
	}
	encoded, err := dict.Export()
	if err != nil {
		return fmt.Errorf("encode dictionary: %w", err)
	}
	if err := output.WriteFileAtomic(outputPath, []byte(encoded), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outputPath, err)
	}
	fmt.Printf("Dictionary written to %s (%s/%s, %d usable names)\n",
		outputPath, dict.DartVersion(), dict.Arch(), dict.NamedCount())
	return nil
}

// cmdApplyFingerprintDict reruns the full analysis with an exact-version/arch
// dictionary injected before disassembly. Renaming only functions.jsonl after
// the fact is intentionally unsupported: names are duplicated into index,
// call edges, xrefs, signal/evidence and per-function artifact paths.
func cmdApplyFingerprintDict(args []string) error {
	fs := flag.NewFlagSet("apply-fingerprint-dict", flag.ContinueOnError)
	dictPath := fs.String("dict", "", "metadata-bearing fingerprint dictionary")
	outDir := fs.String("out", "", "output directory (default: <lib>.aotopsy)")
	strict := fs.Bool("strict", false, "fail on structural errors")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	quiet := fs.Bool("quiet", false, "suppress verbose output")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *dictPath == "" || fs.NArg() != 1 {
		return fmt.Errorf("usage: aotopsy apply-fingerprint-dict --dict <dictionary.jsonl> [--out <dir>] <libapp.so>")
	}
	libPath := resolvePositionalLib(fs.Arg(0))
	if libPath == "" {
		return fmt.Errorf("file not found: %s", fs.Arg(0))
	}
	if *outDir == "" {
		*outDir = defaultOutDir(libPath)
	}
	containsDict, err := output.ContainsPath(*outDir, *dictPath)
	if err != nil {
		return fmt.Errorf("compare fingerprint dictionary/output paths: %w", err)
	}
	if containsDict {
		return fmt.Errorf("output directory must not contain the fingerprint dictionary input: %s contains %s", *outDir, *dictPath)
	}
	f, err := os.Open(*dictPath)
	if err != nil {
		return fmt.Errorf("read dictionary: %w", err)
	}
	defer func() { _ = f.Close() }()
	dict, err := compare.ImportDictionary(f, int64(jsonutil.StandardLimits.MaxBytes))
	if err != nil {
		return fmt.Errorf("read dictionary: %w", err)
	}
	result, err := analysis.Run(analysis.Opts{
		LibPath:               libPath,
		OutDir:                *outDir,
		Strict:                *strict,
		MaxSteps:              *maxSteps,
		Signal:                true,
		SignalK:               2,
		Meta:                  analysis.MetaIfSupported,
		Quiet:                 *quiet,
		FingerprintDictionary: dict,
	})
	if err != nil {
		return err
	}
	printSummary(result)
	return nil
}
