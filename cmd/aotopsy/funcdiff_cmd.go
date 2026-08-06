package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"aotopsy/internal/funcdiff"
)

// cmdFuncDiff implements "aotopsy _debug funcdiff --old <path> --new
// <path>": diffs the Dart function set between two libapp.so builds.
// Ported from flutterdec's pipeline/runners_diff.rs, but built on
// aotopsy's real snapshot cluster deserializer instead of a heuristic
// string-extraction model.
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
