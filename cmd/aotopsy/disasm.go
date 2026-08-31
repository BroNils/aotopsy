package main

import (
	"flag"
	"fmt"

	"aotopsy/internal/analysis"
)

func cmdDisasm(args []string) error {
	fs := flag.NewFlagSet("disasm", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so")
	outDir := fs.String("out", "", "output directory")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	limit := fs.Int("limit", 0, "max functions to disassemble (0 = all)")
	graph := fs.Bool("graph", false, "build lattice call graph and CFG (writes DOT files)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *libapp == "" || *outDir == "" {
		return fmt.Errorf("--lib and --out are required")
	}

	_, err := analysis.Run(analysis.Opts{
		LibPath:  *libapp,
		OutDir:   *outDir,
		MaxSteps: *maxSteps,
		Limit:    *limit,
		Graph:    *graph,
		Quiet:    false,
	})
	return err
}
