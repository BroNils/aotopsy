package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"aotopsy/internal/funcdiff"
	"aotopsy/internal/symbolmap"
)

// cmdSymbolMap implements "aotopsy _debug symbolmap": resolves stripped binary direct call targets against unstripped build.
func cmdSymbolMap(args []string) error {
	fs := flag.NewFlagSet("symbolmap", flag.ExitOnError)
	strippedPath := fs.String("stripped", "", "path to the stripped libapp.so")
	unstrippedPath := fs.String("unstripped", "", "path to an unstripped/debug build of the SAME libapp.so")
	outDir := fs.String("out", "", "output directory for symbol_call_sites.tsv + symbol_target_summary.json + symbol_map_report.json (default: stdout summary only)")
	nearestMaxDistance := fs.Uint64("nearest-max-distance", 64, "max byte distance for a nearest-symbol-below match (0 disables nearest matching)")
	includeBranches := fs.Bool("include-branches", false, "also scan unconditional direct branches/jumps, not just calls")
	requireExecMatch := fs.Bool("require-exec-match", false, "abort if exec section bytes differ between the two binaries")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *strippedPath == "" || *unstrippedPath == "" {
		return fmt.Errorf("--stripped and --unstripped are required")
	}

	rep, err := symbolmap.Compare(*strippedPath, *unstrippedPath, symbolmap.Options{
		NearestMaxDistance: *nearestMaxDistance,
		IncludeBranches:    *includeBranches,
		RequireExecMatch:   *requireExecMatch,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "machine=%s exec_layout_match=%v exec_bytes_match=%v unstripped_symbols=%d\n",
		rep.Machine, rep.ExecLayoutMatch, rep.ExecBytesMatch, rep.UnstrippedSymCnt)
	fmt.Fprintf(os.Stderr, "call sites: %d (exact=%d nearest=%d unresolved=%d), unique targets=%d\n",
		len(rep.CallSites), rep.ExactCount, rep.NearestCount, rep.UnresolvedCount, len(rep.Targets))
	for _, n := range rep.Notes {
		fmt.Fprintf(os.Stderr, "note: %s\n", n)
	}

	if *outDir == "" {
		data, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("symbolmap: mkdir %s: %w", *outDir, err)
	}
	if err := symbolmap.WriteCallSitesTSV(filepath.Join(*outDir, "symbol_call_sites.tsv"), rep.CallSites); err != nil {
		return err
	}
	targetsData, _ := json.MarshalIndent(rep.Targets, "", "  ")
	if err := os.WriteFile(filepath.Join(*outDir, "symbol_target_summary.json"), targetsData, 0o644); err != nil {
		return fmt.Errorf("symbolmap: write target summary: %w", err)
	}
	reportData, _ := json.MarshalIndent(rep, "", "  ")
	if err := os.WriteFile(filepath.Join(*outDir, "symbol_map_report.json"), reportData, 0o644); err != nil {
		return fmt.Errorf("symbolmap: write report: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s/{symbol_call_sites.tsv,symbol_target_summary.json,symbol_map_report.json}\n", *outDir)
	return nil
}

// cmdFuncDiff implements "aotopsy _debug funcdiff": diffs the Dart function set between two libapp.so builds.
func cmdFuncDiff(args []string) error {
	fs := flag.NewFlagSet("funcdiff", flag.ExitOnError)
	oldPath := fs.String("old", "", "path to the OLD build's libapp.so")
	newPath := fs.String("new", "", "path to the NEW build's libapp.so")
	topN := fs.Int("top", 200, "max added/removed entries to report each (0 = unlimited)")
	out := fs.String("out", "", "write JSON report to this path (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *oldPath == "" || *newPath == "" {
		return fmt.Errorf("--old and --new are required")
	}

	rep, err := funcdiff.Diff(*oldPath, *newPath, *topN)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "old: %d functions (%s)\nnew: %d functions (%s)\ncommon=%d added=%d removed=%d\n",
		rep.OldCount, rep.OldVersion, rep.NewCount, rep.NewVersion, rep.CommonCount, rep.AddedTotal, rep.RemovedTotal)

	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("funcdiff: marshal: %w", err)
	}
	if *out == "" {
		fmt.Println(string(data))
		return nil
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		return fmt.Errorf("funcdiff: write %s: %w", *out, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
	return nil
}
