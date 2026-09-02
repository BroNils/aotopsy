package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"aotopsy/internal/analysis"
	"aotopsy/internal/elfx"
)

// cmdIDA handles "aotopsy ida <libapp.so>" — full pipeline + IDA decompilation.
func cmdIDA(args []string) error {
	args = reorderPositionalArg(args)
	fs := flag.NewFlagSet("ida", flag.ExitOnError)
	outDir := fs.String("out", "", "output directory (default: <basename>.aotopsy/)")
	all := fs.Bool("all", false, "decompile ALL functions")
	pythonBin := fs.String("python", "", "python3 binary (default: auto-detect)")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
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
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: aotopsy ida <libapp.so> [flags]")
	}

	libPath := fs.Arg(0)
	absLibPath := resolvePositionalLib(libPath)
	if absLibPath == "" {
		return fmt.Errorf("file not found: %s", libPath)
	}
	if ef, err := elfx.Open(absLibPath); err == nil {
		isARM64 := ef.IsARM64()
		_ = ef.Close()
		if !isARM64 {
			return fmt.Errorf("ida decompilation is ARM64-only for now (register retyping scripts aren't ported to x86_64 yet -- see ARCHITECTURE.md); use `aotopsy _debug decompile-native` for x86_64 pseudocode instead")
		}
	}

	if *outDir == "" {
		*outDir = defaultOutDir(libPath)
	}

	// Step 1: Run pipeline (disasm + signal + meta).
	var pipeResult *analysis.Result
	if *from != "" {
		_, err := analysis.RunSignalStage(*from, 2, false, quiet, os.Stderr, true, "")
		if err != nil {
			return fmt.Errorf("signal: %w", err)
		}
		metaPath, err := analysis.RunMetaStage(*from, "", *all, quiet, os.Stderr)
		if err != nil {
			return fmt.Errorf("meta: %w", err)
		}
		pipeResult = &analysis.Result{OutDir: *from, MetaPath: metaPath}
	} else {
		var err error
		pipeResult, err = analysis.Run(analysis.Opts{
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
	}

	metaPath := pipeResult.MetaPath
	if metaPath == "" {
		metaPath = filepath.Join(pipeResult.OutDir, "flutter_meta.json")
	}

	// Step 2: Copy script into artifact directory.
	if copyErr := analysis.CopyIDAArtifacts(pipeResult.OutDir); copyErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not copy IDA script: %v\n", copyErr)
	}

	// Step 3: Find python3 with idapro.
	python, err := analysis.FindPython(*pythonBin)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "python: %s\n", python)

	// Step 4: Find IDA script.
	scriptPath, err := analysis.FindIDAScript()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "script: %s\n", scriptPath)

	// Step 5: Run idalib.
	decompDir := filepath.Join(pipeResult.OutDir, "decompiled")
	absMetaPath, _ := filepath.Abs(metaPath)
	absDecompDir, _ := filepath.Abs(decompDir)

	if *all {
		fmt.Fprintf(os.Stderr, "running IDA idalib analysis (decompiling ALL functions)...\n")
	} else {
		fmt.Fprintf(os.Stderr, "running IDA idalib analysis (signal functions only, use --all for everything)...\n")
	}
	fmt.Fprintf(os.Stderr, "  decompile output: %s\n", absDecompDir)

	cmd := exec.Command(python, scriptPath, absLibPath, absMetaPath, absDecompDir)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ida script failed: %w", err)
	}

	cCount := analysis.CountDecompiledFiles(absDecompDir)
	fmt.Fprintf(os.Stderr, "decompiled %d functions → %s\n", cCount, absDecompDir)

	return nil
}
