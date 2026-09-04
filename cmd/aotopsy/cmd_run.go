package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cli"
)

// cmdRun handles "aotopsy <libapp.so>" — full analysis.
func cmdRun(args []string) error {
	// Go's flag package stops at the first non-flag arg.
	// If the first arg is a file path (not a flag), move it to the end
	// so flags like --quiet after it are parsed correctly.
	args = reorderPositionalArg(args)

	fs := flag.NewFlagSet("aotopsy", flag.ExitOnError)
	outDir := fs.String("out", "", "output directory (default: <basename>.aotopsy/)")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	limit := fs.Int("limit", 0, "max functions (0 = all)")
	graph := fs.Bool("graph", false, "build call graph and per-function CFGs")
	strict := fs.Bool("strict", false, "fail on structural errors")
	all := fs.Bool("all", false, "include all functions in focus list")
	var quiet bool
	fs.BoolVar(&quiet, "quiet", false, "suppress verbose output")
	fs.BoolVar(&quiet, "q", false, "suppress verbose output")
	var _verbose bool // accepted for backwards compat, now default
	fs.BoolVar(&_verbose, "verbose", false, "")
	fs.BoolVar(&_verbose, "v", false, "")
	signalK := fs.Int("k", 2, "signal context hops")
	from := fs.String("from", "", "reuse existing disasm output directory")
	decompile := fs.Bool("decompile", false, "write per-function Dart pseudocode to <out>/dart/ (large)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// --from mode: reuse existing output, just rerun signal+meta.
	if *from != "" {
		if *outDir == "" {
			*outDir = *from
		}
		result, err := analysis.Run(analysis.Opts{
			FromDir:   *from,
			OutDir:    *outDir,
			Signal:    true,
			SignalK:   *signalK,
			Meta:      true,
			DecompAll: *all,
			Quiet:     quiet,
		})
		if err != nil {
			return err
		}
		printSummary(result)
		return nil
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: aotopsy <libapp.so> [flags]")
	}

	libPath := fs.Arg(0)
	if resolvePositionalLib(libPath) == "" {
		return fmt.Errorf("file not found: %s", libPath)
	}

	if *outDir == "" {
		*outDir = defaultOutDir(libPath)
	}

	result, err := analysis.Run(analysis.Opts{
		LibPath:   libPath,
		OutDir:    *outDir,
		MaxSteps:  *maxSteps,
		Limit:     *limit,
		Graph:     *graph,
		Strict:    *strict,
		Signal:    true,
		SignalK:   *signalK,
		Meta:      true,
		DecompAll: *all,
		Decompile: *decompile,
		Quiet:     quiet,
	})
	if err != nil {
		return err
	}

	printSummary(result)
	return nil
}

func printSummary(result *analysis.Result) {
	fmt.Fprintf(os.Stderr, "\n%s\n", cli.PinkColor.S("summary"))
	fmt.Fprintf(os.Stderr, "  %s     %s\n", cli.MutedColor.S("output:"), cli.BlueColor.S(result.OutDir))
	if result.DartVersion != "" {
		fmt.Fprintf(os.Stderr, "  %s       %s\n", cli.MutedColor.S("dart:"), cli.GoldColor.S(result.DartVersion))
	}
	fmt.Fprintf(os.Stderr, "  %s   %s\n", cli.MutedColor.S("ptr_size:"), cli.GoldColor.F("%d", result.PointerSize))
	fmt.Fprintf(os.Stderr, "  %s %s\n", cli.MutedColor.S("functions:"), cli.GoldColor.F("%d", result.FuncCount))
	fmt.Fprintf(os.Stderr, "  %s   %s\n", cli.MutedColor.S("classes:"), cli.GoldColor.F("%d", result.ClassCount))
	fmt.Fprintf(os.Stderr, "  %s    %s\n", cli.MutedColor.S("signal:"), cli.GoldColor.F("%d", result.SignalCount))
	if result.MetaPath != "" {
		fmt.Fprintf(os.Stderr, "  %s      %s\n", cli.MutedColor.S("meta:"), cli.BlueColor.S(result.MetaPath))
	}
	if result.DecompiledCount > 0 {
		fmt.Fprintf(os.Stderr, "  %s %s functions\n", cli.MutedColor.S("pseudocode:"), cli.GoldColor.F("%d", result.DecompiledCount))
	}

	// Follow-up commands.
	absOut, _ := filepath.Abs(result.OutDir)
	signalHTML := filepath.Join(absOut, "signal.html")
	fmt.Fprintf(os.Stderr, "\n%s\n", cli.PinkColor.S("next"))
	fmt.Fprintf(os.Stderr, "  %s\n", cli.WhiteColor.S("open "+signalHTML))
	if result.LibPath != "" {
		fmt.Fprintf(os.Stderr, "  %s\n", cli.WhiteColor.S("aotopsy ghidra "+result.LibPath+" --from "+absOut))
		fmt.Fprintf(os.Stderr, "  %s\n", cli.WhiteColor.S("aotopsy ida "+result.LibPath+" --from "+absOut))
	}
}
