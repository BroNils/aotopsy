package main

import (
	"flag"
	"fmt"

	"aotopsy/internal/analysis"
)

func cmdParity(args []string) error {
	fs := flag.NewFlagSet("parity", flag.ExitOnError)
	samplesDir := fs.String("samples", "", "directory containing sample subdirs (each with libapp.so)")
	outDir := fs.String("out", "", "output directory for parity.csv and summary")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *samplesDir == "" || *outDir == "" {
		return fmt.Errorf("--samples and --out are required")
	}

	return analysis.RunParity(*samplesDir, *outDir)
}
