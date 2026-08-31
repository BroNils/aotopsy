package main

import (
	"flag"
	"fmt"
	"os"

	"aotopsy/internal/analysis"
)

func cmdSignal(args []string) error {
	fs := flag.NewFlagSet("signal", flag.ExitOnError)
	inDir := fs.String("in", "", "input directory (disasm output)")
	k := fs.Int("k", 2, "context hops from signal functions")
	noAsm := fs.Bool("no-asm", false, "skip loading asm snippets")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inDir == "" {
		return fmt.Errorf("--in is required")
	}

	_, err := analysis.RunSignalStage(*inDir, *k, *noAsm, false, os.Stderr)
	return err
}
