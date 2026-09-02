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

// cmdGhidra handles "aotopsy ghidra <libapp.so>" — full pipeline + Ghidra decompilation.
func cmdGhidra(args []string) error {
	args = reorderPositionalArg(args)
	fs := flag.NewFlagSet("ghidra", flag.ExitOnError)
	outDir := fs.String("out", "", "output directory (default: <basename>.aotopsy/)")
	ghidraHome := fs.String("ghidra-home", "", "Ghidra installation directory")
	all := fs.Bool("all", false, "decompile ALL functions")
	gui := fs.Bool("gui", false, "launch Ghidra GUI after generating artifacts")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	var quiet bool
	fs.BoolVar(&quiet, "quiet", false, "suppress verbose output")
	fs.BoolVar(&quiet, "q", false, "suppress verbose output")
	var _verbose bool
	fs.BoolVar(&_verbose, "verbose", false, "")
	fs.BoolVar(&_verbose, "v", false, "")
	projectDir := fs.String("projects", "scratch/ghidra-projects", "Ghidra project directory")
	from := fs.String("from", "", "reuse existing disasm output directory")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: aotopsy ghidra <libapp.so> [flags]")
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
			return fmt.Errorf("ghidra decompilation is ARM64-only for now (register retyping + calling-convention scripts aren't ported to x86_64 yet -- see ARCHITECTURE.md); use `aotopsy _debug decompile-native` for x86_64 pseudocode instead")
		}
	}

	if *outDir == "" {
		*outDir = defaultOutDir(libPath)
	}

	// Step 1: Run pipeline (disasm + signal + meta).
	var pipeResult *analysis.Result
	if *from != "" {
		// Reuse existing output: just regenerate signal + meta.
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

	// Step 2: Copy scripts into artifact directory and use that as scriptPath.
	// This ensures Ghidra always finds both scripts, regardless of install layout.
	absOutDir, _ := filepath.Abs(pipeResult.OutDir)
	scriptPath := filepath.Join(absOutDir, "ghidra")
	if copyErr := analysis.CopyGhidraArtifacts(pipeResult.OutDir); copyErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not copy Ghidra scripts: %v\n", copyErr)
		// Fallback: find scripts in their original location.
		var findErr error
		scriptPath, findErr = analysis.FindScriptPath()
		if findErr != nil {
			return fmt.Errorf("ghidra scripts not found: %v (copy also failed: %v)", findErr, copyErr)
		}
	}

	// Step 3: Find Ghidra.
	ghLauncher, ghHome, err := analysis.FindGhidra(*ghidraHome)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "ghidra: %s\n", ghHome)

	// Step 4: Handle --gui (launch interactive Ghidra).
	if *gui {
		return launchGhidraGUI(ghHome, absLibPath, pipeResult.OutDir)
	}

	// Step 5: Run headless analysis.
	decompDir := filepath.Join(pipeResult.OutDir, "decompiled")
	absMetaPath, _ := filepath.Abs(metaPath)
	absDecompDir, _ := filepath.Abs(decompDir)

	projectName := analysis.SanitizeProjectName(filepath.Base(filepath.Dir(pipeResult.OutDir)))

	absProjDir := analysis.SanitizeGhidraPath(*projectDir)
	if err := os.MkdirAll(absProjDir, 0o755); err != nil {
		return fmt.Errorf("create project dir: %w", err)
	}

	if *all {
		fmt.Fprintf(os.Stderr, "running Ghidra headless analysis (decompiling ALL functions)...\n")
	} else {
		fmt.Fprintf(os.Stderr, "running Ghidra headless analysis (signal functions only, use --all for everything)...\n")
	}
	fmt.Fprintf(os.Stderr, "  project: %s/%s\n", absProjDir, projectName)
	fmt.Fprintf(os.Stderr, "  import: %s\n", absLibPath)
	fmt.Fprintf(os.Stderr, "  decompile output: %s\n", absDecompDir)

	ghidraArgs := []string{
		absProjDir,
		projectName,
		"-import", absLibPath,
		"-overwrite",
		"-processor", "AARCH64:LE:64:v8A",
		"-scriptPath", scriptPath,
		"-preScript", "aotopsy_prescript.py",
		"-postScript", "aotopsy_apply.py", absMetaPath, absDecompDir,
	}

	env := os.Environ()
	if os.Getenv("JAVA_HOME") == "" {
		javaHome := analysis.FindJavaHome(ghHome)
		if javaHome != "" {
			env = append(env, "JAVA_HOME="+javaHome)
		}
	}

	cmd := exec.Command(ghLauncher.Cmd, append(ghLauncher.Prefix, ghidraArgs...)...)
	cmd.Env = env
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("analyzeHeadless failed: %w", err)
	}

	cCount := analysis.CountDecompiledFiles(absDecompDir)
	fmt.Fprintf(os.Stderr, "decompiled %d functions → %s\n", cCount, absDecompDir)

	return nil
}

// launchGhidraGUI starts Ghidra in interactive mode and prints instructions.
func launchGhidraGUI(ghidraHome, libPath, outDir string) error {
	ghidraRun := filepath.Join(ghidraHome, "ghidraRun")
	if _, err := os.Stat(ghidraRun); err != nil {
		return fmt.Errorf("ghidraRun not found at %s", ghidraRun)
	}

	scriptPath, err := analysis.FindScriptPath()
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nLaunching Ghidra GUI...\n")
	fmt.Fprintf(os.Stderr, "  1. Import: %s\n", libPath)
	fmt.Fprintf(os.Stderr, "  2. Open Script Manager (Window → Script Manager)\n")
	fmt.Fprintf(os.Stderr, "  3. Add script directory: %s\n", scriptPath)
	fmt.Fprintf(os.Stderr, "  4. Run aotopsy_prescript.py first, then aotopsy_apply.py\n")
	fmt.Fprintf(os.Stderr, "     (or pass flutter_meta.json path as script argument)\n")
	fmt.Fprintf(os.Stderr, "  Meta: %s/flutter_meta.json\n\n", outDir)

	env := os.Environ()
	if os.Getenv("JAVA_HOME") == "" {
		javaHome := analysis.FindJavaHome(ghidraHome)
		if javaHome != "" {
			env = append(env, "JAVA_HOME="+javaHome)
		}
	}

	cmd := exec.Command(ghidraRun)
	cmd.Env = env
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Start()
}
