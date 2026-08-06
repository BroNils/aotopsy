package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"aotopsy/internal/symbolmap"
)

// cmdSymbolMap implements "aotopsy _debug symbolmap --stripped <path>
// --unstripped <path>": resolves the stripped binary's own direct call
// targets against the unstripped build's real symbols. Ported from
// flutterdec's pipeline/symbol_map.rs, generalized to ARM64+x86_64.
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
