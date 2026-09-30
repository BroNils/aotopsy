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

// cmdSignal handles "aotopsy signal" when `--in` is passed (inspecting existing disasm output).
func cmdSignal(args []string) error {
	fs := flag.NewFlagSet("signal", flag.ExitOnError)
	inDir := fs.String("in", "", "input directory (disasm output)")
	k := fs.Int("k", 2, "context hops from signal functions")
	noAsm := fs.Bool("no-asm", false, "skip loading asm snippets")
	var quiet bool
	fs.BoolVar(&quiet, "quiet", false, "suppress verbose output")
	fs.BoolVar(&quiet, "q", false, "suppress verbose output")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inDir == "" {
		return fmt.Errorf("--in is required")
	}

	_, err := analysis.Run(analysis.Opts{
		FromDir:     *inDir,
		OutDir:      *inDir,
		Signal:      true,
		SignalK:     *k,
		SignalNoAsm: *noAsm,
		Quiet:       quiet,
		Log:         os.Stderr,
	})
	return err
}

// cmdSignalPipeline handles "aotopsy signal <libapp.so>" — full pipeline through signal.
func cmdSignalPipeline(args []string) error {
	fs := flag.NewFlagSet("signal", flag.ExitOnError)
	outDir := fs.String("out", "", "output directory (default: <basename>.aotopsy/)")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	k := fs.Int("k", 2, "context hops from signal functions")
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

	// If --from is set, skip ELF parse and just run signal.
	if *from != "" {
		if *outDir == "" {
			*outDir = *from
		}
		result, err := analysis.Run(analysis.Opts{
			FromDir: *from,
			OutDir:  *outDir,
			Signal:  true,
			SignalK: *k,
			Quiet:   quiet,
			Log:     os.Stderr,
		})
		if err != nil {
			return err
		}
		printSignalSummary(&analysis.SignalResult{SignalCount: result.SignalCount}, result.OutDir, "", result.Arch)
		return nil
	}

	if fs.NArg() != 1 {
		return fmt.Errorf("usage: aotopsy signal <libapp.so> [flags]")
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
