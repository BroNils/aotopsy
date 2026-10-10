package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cli"
)

// cmdRun handles "aotopsy <libapp.so>" — full analysis.
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("aotopsy", flag.ContinueOnError)
	outDir := fs.String("out", "", "output directory (default: <basename>.aotopsy/)")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	limit := fs.Int("limit", 0, "max functions (0 = all)")
	graph := fs.Bool("graph", false, "build call graph and per-function CFGs")
	strict := fs.Bool("strict", false, "fail on structural errors")
	all := fs.Bool("all", false, "include all functions in focus list")
	var quiet bool
	fs.BoolVar(&quiet, "quiet", false, "suppress verbose output")
	fs.BoolVar(&quiet, "q", false, "suppress verbose output")
	signalK := fs.Int("k", 2, "signal context hops")
	from := fs.String("from", "", "reuse existing disasm output directory")
	decompile := fs.Bool("decompile", false, "write per-function Dart pseudocode to <out>/dart/ (large)")

	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if err := requireNonNegativeFlag("max-steps", *maxSteps); err != nil {
		return err
	}
	if err := requireNonNegativeFlag("limit", *limit); err != nil {
		return err
	}
	if *signalK <= 0 {
		return fmt.Errorf("--k must be > 0")
	}

	// --from mode: reuse existing output, just rerun signal+meta.
	if *from != "" {
		if fs.NArg() != 0 {
			return fmt.Errorf("--from does not accept a libapp.so positional argument")
		}
		for _, name := range []string{"max-steps", "limit", "graph", "strict", "decompile"} {
			if flagWasSet(fs, name) {
				return fmt.Errorf("--%s cannot be used with --from because fresh snapshot/disassembly stages are skipped", name)
			}
		}
		if *outDir == "" {
			*outDir = *from
		}
		result, err := analysis.Run(analysis.Opts{
			FromDir:   *from,
			OutDir:    *outDir,
			Signal:    true,
			SignalK:   *signalK,
			Meta:      analysis.MetaIfSupported,
			DecompAll: *all,
			Quiet:     quiet,
		})
		if err != nil {
			return err
		}
		printSummary(result)
		return nil
	}

	if fs.NArg() != 1 {
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
		Meta:      analysis.MetaIfSupported,
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
	writeSummary(os.Stderr, result)
}

func writeSummary(w io.Writer, result *analysis.Result) {
	logger := cli.NewLogger(w, false)
	logger.Printf("\n%s%s%s\n", cli.Pink, "summary", cli.Reset)
	logger.Printf("  %soutput:%s     %s%s%s\n", cli.Muted, cli.Reset, cli.Blue, result.OutDir, cli.Reset)
	if result.DartVersion != "" {
		logger.Printf("  %sdart:%s       %s%s%s\n", cli.Muted, cli.Reset, cli.Gold, result.DartVersion, cli.Reset)
	}
	if result.Arch != "" {
		logger.Printf("  %sarch:%s       %s%s%s\n", cli.Muted, cli.Reset, cli.Gold, result.Arch, cli.Reset)
	}
	if result.PointerSize > 0 {
		logger.Printf("  %sptr_size:%s   %s%d%s\n", cli.Muted, cli.Reset, cli.Gold, result.PointerSize, cli.Reset)
	}
	logger.Printf("  %sfunctions:%s %s%d%s\n", cli.Muted, cli.Reset, cli.Gold, result.FuncCount, cli.Reset)
	if result.ClassCount > 0 {
		logger.Printf("  %sclasses:%s   %s%d%s\n", cli.Muted, cli.Reset, cli.Gold, result.ClassCount, cli.Reset)
	}
	logger.Printf("  %ssignal:%s    %s%d%s\n", cli.Muted, cli.Reset, cli.Gold, result.SignalCount, cli.Reset)
	if result.MetaPath != "" {
		logger.Printf("  %smeta:%s      %s%s%s\n", cli.Muted, cli.Reset, cli.Blue, result.MetaPath, cli.Reset)
	}
	if result.DecompiledCount > 0 {
		logger.Printf("  %spseudocode:%s %s%d%s functions\n", cli.Muted, cli.Reset, cli.Gold, result.DecompiledCount, cli.Reset)
	}

	// Follow-up commands.
	absOut := result.OutDir
	if resolved, err := filepath.Abs(result.OutDir); err == nil {
		absOut = resolved
	}
	signalHTML := filepath.Join(absOut, "signal.html")
	logger.Printf("\n%s%s%s\n", cli.Pink, "next", cli.Reset)
	if info, err := os.Stat(signalHTML); err == nil && info.Mode().IsRegular() {
		logger.Printf("  %s%s%s\n", cli.White, "open "+signalHTML, cli.Reset)
	}
	if result.LibPath != "" && result.Arch == "arm64" {
		logger.Printf("  %s%s%s\n", cli.White, "aotopsy ghidra "+result.LibPath+" --from "+absOut, cli.Reset)
		logger.Printf("  %s%s%s\n", cli.White, "aotopsy ida "+result.LibPath+" --from "+absOut, cli.Reset)
	} else if result.LibPath != "" && result.Arch == "x64" {
		logger.Printf("  %s%s%s\n", cli.White, "aotopsy _debug decompile-native --lib "+result.LibPath+" --from-main", cli.Reset)
	}
}
