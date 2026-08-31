package main

import (
	"flag"
	"fmt"

	"aotopsy/internal/analysis"
)

func cmdGraph(args []string) error {
	fs := flag.NewFlagSet("graph", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	which := fs.String("which", "isolate", "which snapshot: vm, isolate, or both")
	outDir := fs.String("out", "", "output directory for JSONL files")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *libapp == "" {
		return fmt.Errorf("--lib is required")
	}
	if *outDir == "" {
		return fmt.Errorf("--out is required")
	}

	return analysis.RunGraph(*libapp, *outDir, *which, *maxSteps)
}
