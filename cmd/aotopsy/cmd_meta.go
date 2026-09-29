package main

import (
	"flag"
	"fmt"
	"os"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cli"
	"aotopsy/internal/elfx"
)

// cmdMeta handles "aotopsy meta <libapp.so>" — full pipeline producing flutter_meta.json.
func cmdMeta(args []string) error {
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

	if err := parseInterspersed(fs, args); err != nil {
		return err
	}

	// If --from is set, skip ELF parse and just regenerate meta.
	if *from != "" {
		prov, ok, err := analysis.ReadProvenance(*from)
		if err != nil {
			return fmt.Errorf("read --from provenance: %w", err)
		}
		if !ok || prov.Arch != "arm64" {
			return fmt.Errorf("meta --from requires ARM64 analysis provenance")
		}
		if *outDir == "" {
			*outDir = *from
		}
		result, err := analysis.Run(analysis.Opts{
			FromDir:   *from,
			OutDir:    *outDir,
			Meta:      analysis.MetaRequired,
			DecompAll: *all,
			Quiet:     quiet,
			Log:       os.Stderr,
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", cli.SafeLine(result.MetaPath))
		return nil
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: aotopsy meta <libapp.so> [flags]")
	}

	libPath := fs.Arg(0)
	resolvedLib := resolvePositionalLib(libPath)
	if resolvedLib == "" {
		return fmt.Errorf("file not found: %s", libPath)
	}
	ef, err := elfx.Open(resolvedLib)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	isARM64 := ef.IsARM64()
	if err := ef.Close(); err != nil {
		return fmt.Errorf("close input: %w", err)
	}
	if !isARM64 {
		return fmt.Errorf("meta generation is ARM64-only for now; x86_64 Ghidra/IDA metadata is not implemented")
	}

	if *outDir == "" {
		*outDir = defaultOutDir(libPath)
	}

	result, err := analysis.Run(analysis.Opts{
		LibPath:   resolvedLib,
		OutDir:    *outDir,
		MaxSteps:  *maxSteps,
		Signal:    true,
		Meta:      analysis.MetaRequired,
		DecompAll: *all,
		Quiet:     quiet,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "wrote %s\n", cli.SafeLine(result.MetaPath))
	return nil
}
