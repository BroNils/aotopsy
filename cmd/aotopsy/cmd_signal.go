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
	absOut, _ := filepath.Abs(outDir)
	signalHTML := filepath.Join(absOut, "signal.html")

	fmt.Fprintf(w, "\n%s  %s functions\n",
		cli.PinkColor.S("signal complete"), cli.GoldColor.F("%d", sig.SignalCount))
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
			fmt.Fprintf(w, "  %s  %s\n", cli.BlueColor.S(artifact.name), artifact.desc)
		}
	}

	fmt.Fprintf(w, "\n%s\n", cli.PinkColor.S("next"))
	if info, err := os.Stat(signalHTML); err == nil && info.Mode().IsRegular() {
		fmt.Fprintf(w, "  %s\n", cli.WhiteColor.S("open "+signalHTML))
	}
	if libPath != "" && arch == "arm64" {
		fmt.Fprintf(w, "  %s\n", cli.WhiteColor.S("aotopsy ghidra "+libPath+" --from "+absOut))
		fmt.Fprintf(w, "  %s\n", cli.WhiteColor.S("aotopsy ida "+libPath+" --from "+absOut))
	} else if libPath != "" && arch == "x64" {
		fmt.Fprintf(w, "  %s\n", cli.WhiteColor.S("aotopsy _debug decompile-native --lib "+libPath+" --from-main"))
	} else if libPath == "" && arch == "arm64" {
		fmt.Fprintf(w, "  %s\n", cli.WhiteColor.S("aotopsy ghidra <libapp.so> --from "+absOut))
		fmt.Fprintf(w, "  %s\n", cli.WhiteColor.S("aotopsy ida <libapp.so> --from "+absOut))
	}
}
