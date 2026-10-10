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

// cmdSignalPipeline handles either a fresh "aotopsy signal <libapp.so>" run or
// regeneration from an existing analysis directory via --from.
func cmdSignalPipeline(args []string) error {
	fs := flag.NewFlagSet("signal", flag.ContinueOnError)
	outDir := fs.String("out", "", "output directory (default: <basename>.aotopsy/)")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	k := fs.Int("k", 2, "context hops from signal functions")
	noAsm := fs.Bool("no-asm", false, "with --from, skip loading asm snippets")
	var quiet bool
	fs.BoolVar(&quiet, "quiet", false, "suppress verbose output")
	fs.BoolVar(&quiet, "q", false, "suppress verbose output")
	from := fs.String("from", "", "reuse existing disasm output directory")

	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if err := requireNonNegativeFlag("max-steps", *maxSteps); err != nil {
		return err
	}
	if *k <= 0 {
		return fmt.Errorf("--k must be > 0")
	}

	if *from != "" {
		if fs.NArg() != 0 {
			return fmt.Errorf("signal --from does not accept a libapp.so positional argument")
		}
		if flagWasSet(fs, "max-steps") {
			return fmt.Errorf("--max-steps cannot be used with --from because snapshot parsing/disassembly is skipped")
		}
		if *outDir == "" {
			*outDir = *from
		}
		result, err := analysis.Run(analysis.Opts{
			FromDir:     *from,
			OutDir:      *outDir,
			Signal:      true,
			SignalK:     *k,
			SignalNoAsm: *noAsm,
			Quiet:       quiet,
			Log:         os.Stderr,
		})
		if err != nil {
			return err
		}
		printSignalSummary(&analysis.SignalResult{SignalCount: result.SignalCount}, result.OutDir, "", result.Arch)
		return nil
	}
	if *noAsm {
		return fmt.Errorf("--no-asm requires --from")
	}

	if fs.NArg() != 1 {
		return fmt.Errorf("usage: aotopsy signal <libapp.so> [flags] or aotopsy signal --from <dir> [flags]")
	}

	libPath := fs.Arg(0)
	if resolvePositionalLib(libPath) == "" {
		return fmt.Errorf("file not found: %s", libPath)
	}

	if *outDir == "" {
		*outDir = defaultOutDir(libPath)
	}

	result, err := analysis.Run(analysis.Opts{
		LibPath:  libPath,
		OutDir:   *outDir,
		MaxSteps: *maxSteps,
		Signal:   true,
		SignalK:  *k,
		Quiet:    quiet,
	})
	if err != nil {
		return err
	}

	printSignalSummary(&analysis.SignalResult{SignalCount: result.SignalCount}, result.OutDir, libPath, result.Arch)
	return nil
}

func printSignalSummary(sig *analysis.SignalResult, outDir, libPath, arch string) {
	writeSignalSummary(os.Stderr, sig, outDir, libPath, arch)
}

func writeSignalSummary(w io.Writer, sig *analysis.SignalResult, outDir, libPath, arch string) {
	absOut := outDir
	if resolved, err := filepath.Abs(outDir); err == nil {
		absOut = resolved
	}
	signalHTML := filepath.Join(absOut, "signal.html")
	logger := cli.NewLogger(w, false)

	logger.Printf("\n%s%s%s  %s%d%s functions\n",
		cli.Pink, "signal complete", cli.Reset, cli.Gold, sig.SignalCount, cli.Reset)
	for _, artifact := range []struct {
		name string
		desc string
	}{
		{"signal.html", "interactive signal graph"},
		{"signal.svg", "signal graph visualization"},
		{"signal_cfg.dot", "connected CFG"},
	} {
		path := filepath.Join(absOut, artifact.name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			logger.Printf("  %s%s%s  %s\n", cli.Blue, artifact.name, cli.Reset, artifact.desc)
		}
	}

	logger.Printf("\n%s%s%s\n", cli.Pink, "next", cli.Reset)
	if info, err := os.Stat(signalHTML); err == nil && info.Mode().IsRegular() {
		logger.Printf("  %s%s%s\n", cli.White, "open "+signalHTML, cli.Reset)
	}
	if libPath != "" && arch == "arm64" {
		logger.Printf("  %s%s%s\n", cli.White, "aotopsy ghidra "+libPath+" --from "+absOut, cli.Reset)
		logger.Printf("  %s%s%s\n", cli.White, "aotopsy ida "+libPath+" --from "+absOut, cli.Reset)
	} else if libPath != "" && arch == "x64" {
		logger.Printf("  %s%s%s\n", cli.White, "aotopsy _debug decompile-native --lib "+libPath+" --from-main", cli.Reset)
	} else if libPath == "" && arch == "arm64" {
		logger.Printf("  %s%s%s\n", cli.White, "aotopsy ghidra <libapp.so> --from "+absOut, cli.Reset)
		logger.Printf("  %s%s%s\n", cli.White, "aotopsy ida <libapp.so> --from "+absOut, cli.Reset)
	}
}
