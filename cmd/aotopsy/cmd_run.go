package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"aotopsy/internal/cli"
	"aotopsy/internal/pipeline"
)

// cmdRun handles "aotopsy <libapp.so>" — full pipeline.
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

	if err := fs.Parse(args); err != nil {
		return err
	}

	// --from mode: reuse existing output, just rerun signal+meta.
	if *from != "" {
		if *outDir == "" {
			*outDir = *from
		}
		result, err := pipeline.Run(pipeline.Opts{
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

	result, err := pipeline.Run(pipeline.Opts{
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
		Quiet:     quiet,
	})
	if err != nil {
		return err
	}

	printSummary(result)
	return nil
}

func printSummary(result *pipeline.Result) {
	fmt.Fprintf(os.Stderr, "\n%ssummary%s\n", cli.Pink, cli.Reset)
	fmt.Fprintf(os.Stderr, "  %soutput:%s     %s%s%s\n", cli.Muted, cli.Reset, cli.Blue, result.OutDir, cli.Reset)
	if result.DartVersion != "" {
		fmt.Fprintf(os.Stderr, "  %sdart:%s       %s%s%s\n", cli.Muted, cli.Reset, cli.Gold, result.DartVersion, cli.Reset)
	}
	fmt.Fprintf(os.Stderr, "  %sptr_size:%s   %s%d%s\n", cli.Muted, cli.Reset, cli.Gold, result.PointerSize, cli.Reset)
	fmt.Fprintf(os.Stderr, "  %sfunctions:%s %s%d%s\n", cli.Muted, cli.Reset, cli.Gold, result.FuncCount, cli.Reset)
	fmt.Fprintf(os.Stderr, "  %sclasses:%s   %s%d%s\n", cli.Muted, cli.Reset, cli.Gold, result.ClassCount, cli.Reset)
	fmt.Fprintf(os.Stderr, "  %ssignal:%s    %s%d%s\n", cli.Muted, cli.Reset, cli.Gold, result.SignalCount, cli.Reset)
	if result.MetaPath != "" {
		fmt.Fprintf(os.Stderr, "  %smeta:%s      %s%s%s\n", cli.Muted, cli.Reset, cli.Blue, result.MetaPath, cli.Reset)
	}

	// Follow-up commands.
	absOut, _ := filepath.Abs(result.OutDir)
	signalHTML := filepath.Join(absOut, "signal.html")
	fmt.Fprintf(os.Stderr, "\n%snext%s\n", cli.Pink, cli.Reset)
	fmt.Fprintf(os.Stderr, "  %sopen %s%s\n", cli.White, signalHTML, cli.Reset)
	if result.LibPath != "" {
		fmt.Fprintf(os.Stderr, "  %saotopsy ghidra %s --from %s%s\n", cli.White, result.LibPath, absOut, cli.Reset)
		fmt.Fprintf(os.Stderr, "  %saotopsy ida %s --from %s%s\n", cli.White, result.LibPath, absOut, cli.Reset)
	}
}
