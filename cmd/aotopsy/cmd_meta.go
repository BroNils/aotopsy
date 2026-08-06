package main

import (
	"flag"
	"fmt"
	"os"

	"aotopsy/internal/pipeline"
)

// cmdMeta handles "aotopsy meta <libapp.so>" — full pipeline producing flutter_meta.json.
func cmdMeta(args []string) error {
	args = reorderPositionalArg(args)
	fs := flag.NewFlagSet("meta", flag.ExitOnError)
	outDir := fs.String("out", "", "output directory (default: <basename>.aotopsy/)")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	all := fs.Bool("all", false, "include all functions in focus list")
	var quiet bool
	fs.BoolVar(&quiet, "quiet", false, "suppress verbose output")
	fs.BoolVar(&quiet, "q", false, "suppress verbose output")
	var _verbose bool // accepted for backwards compat, now default
	fs.BoolVar(&_verbose, "verbose", false, "")
	fs.BoolVar(&_verbose, "v", false, "")
	from := fs.String("from", "", "reuse existing disasm output directory")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// If --from is set, skip ELF parse and just regenerate meta.
	if *from != "" {
		if *outDir == "" {
			*outDir = *from
		}
		metaPath, err := pipeline.RunMetaStage(*from, "", *all, quiet, os.Stderr)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", metaPath)
		return nil
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: aotopsy meta <libapp.so> [flags]")
	}

	libPath := fs.Arg(0)
	if resolvePositionalLib(libPath) == "" {
		return fmt.Errorf("file not found: %s", libPath)
	}

	if *outDir == "" {
		*outDir = defaultOutDir(libPath)
	}

	result, err := pipeline.Run(pipeline.Opts{
		LibPath:   libPath,
		OutDir:    *outDir,
		MaxSteps:  *maxSteps,
		Signal:    true,
		Meta:      true,
		DecompAll: *all,
		Quiet:     quiet,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "wrote %s\n", result.MetaPath)
	return nil
}
