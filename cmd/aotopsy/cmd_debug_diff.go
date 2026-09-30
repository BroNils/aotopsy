package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"aotopsy/internal/cli"
	"aotopsy/internal/funcdiff"
	"aotopsy/internal/symbolmap"
)

// cmdSymbolMap implements "aotopsy _debug symbolmap": resolves stripped binary direct call targets against unstripped build.
func cmdSymbolMap(args []string) error {
	fs := flag.NewFlagSet("symbolmap", flag.ExitOnError)
	strippedPath := fs.String("stripped", "", "path to the stripped libapp.so")
	unstrippedPath := fs.String("unstripped", "", "path to an unstripped/debug build of the SAME libapp.so")
	outDir := fs.String("out", "", "output directory for symbolmap artifacts (default: stdout summary only)")
	nearestMaxDistance := fs.Uint64("nearest-max-distance", 64, "max byte distance for a nearest-symbol-below match (0 disables nearest matching)")
	includeBranches := fs.Bool("include-branches", false, "also scan unconditional direct branches/jumps, not just calls")
	importSymbols := fs.Bool("import-symbols", false, "import the full executable symbol table from the verified unstripped twin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *strippedPath == "" || *unstrippedPath == "" {
		return fmt.Errorf("--stripped and --unstripped are required")
	}

	rep, err := symbolmap.Compare(*strippedPath, *unstrippedPath, symbolmap.Options{
		NearestMaxDistance: *nearestMaxDistance,
		IncludeBranches:    *includeBranches,
		ImportSymbols:      *importSymbols,
	})
	if err != nil {
		return err
	}

	cli.Errf("machine=%s exec_layout_match=%v exec_bytes_match=%v unstripped_symbols=%d\n",
		rep.Machine, rep.ExecLayoutMatch, rep.ExecBytesMatch, rep.UnstrippedSymCnt)
	cli.Errf("call sites: %d (exact=%d nearest=%d unresolved=%d), unique targets=%d\n",
		len(rep.CallSites), rep.ExactCount, rep.NearestCount, rep.UnresolvedCount, len(rep.Targets))
	for _, n := range rep.Notes {
		cli.Errf("note: %s\n", n)
	}

	if *outDir == "" {
		data, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	if err := symbolmap.WriteArtifacts(*outDir, rep); err != nil {
		return err
	}
	cli.Errf("wrote symbolmap artifacts under %s\n", *outDir)
	return nil
}

// cmdFuncDiff implements "aotopsy _debug funcdiff": diffs the Dart function set between two libapp.so builds.
func cmdFuncDiff(args []string) error {
	fs := flag.NewFlagSet("funcdiff", flag.ExitOnError)
	oldPath := fs.String("old", "", "path to the OLD build's libapp.so")
	newPath := fs.String("new", "", "path to the NEW build's libapp.so")
	topN := fs.Int("top", 200, "max added/removed/changed/indeterminate entries to report each (0 = unlimited)")
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

	cli.Errf("old: %d functions (%s, %s)\nnew: %d functions (%s, %s)\ncommon=%d added=%d removed=%d changed=%d indeterminate=%d\n",
		rep.OldCount, rep.OldVersion, rep.OldMachine,
		rep.NewCount, rep.NewVersion, rep.NewMachine,
		rep.CommonCount, rep.AddedTotal, rep.RemovedTotal, rep.ChangedTotal, rep.IndeterminateTotal)
	if !rep.CodeComparable {
		cli.Errf("code comparison disabled: %s\n", rep.IncomparableReason)
	}

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
	cli.Errf("wrote %s\n", *out)
	return nil
}
