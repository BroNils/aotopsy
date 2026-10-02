package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cli"
	"aotopsy/internal/elfx"
)

// cmdGhidra handles "aotopsy ghidra <libapp.so>" — full pipeline + Ghidra decompilation.
func cmdGhidra(args []string) error {
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

	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: aotopsy ghidra <libapp.so> [flags]")
	}

	libPath := fs.Arg(0)
	absLibPath := resolvePositionalLib(libPath)
	if absLibPath == "" {
		return fmt.Errorf("file not found: %s", libPath)
	}
	ef, err := elfx.Open(absLibPath)
	if err != nil {
		return fmt.Errorf("open input ELF: %w", err)
	}
	isARM64 := ef.IsARM64()
	_ = ef.Close()
	if !isARM64 {
		return fmt.Errorf("ghidra decompilation is ARM64-only for now (register retyping + calling-convention scripts aren't ported to x86_64 yet -- see ARCHITECTURE.md); use `aotopsy _debug decompile-native` for x86_64 pseudocode instead")
	}

	if *from != "" && *outDir == "" {
		*outDir = *from
	} else if *outDir == "" {
		*outDir = defaultOutDir(libPath)
	}
	if *from != "" {
		if _, err := analysis.VerifyProvenanceBinary(*from, absLibPath); err != nil {
			return fmt.Errorf("verify Ghidra --from provenance: %w", err)
		}
	}

	// Step 1: Run pipeline (disasm + signal + meta).
	var pipeResult *analysis.Result
	if *from != "" {
		var err error
		pipeResult, err = analysis.Run(analysis.Opts{
			FromDir:   *from,
			OutDir:    *outDir,
			Signal:    true,
			SignalK:   2,
			Meta:      analysis.MetaRequired,
			DecompAll: *all,
			Quiet:     quiet,
			Log:       os.Stderr,
		})
		if err != nil {
			return err
		}
	} else {
		var err error
		pipeResult, err = analysis.Run(analysis.Opts{
			LibPath:   libPath,
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
	}
	prov, err := analysis.VerifyProvenanceBinary(pipeResult.OutDir, absLibPath)
	if err != nil {
		return fmt.Errorf("verify Ghidra binary provenance: %w", err)
	}

	metaPath := pipeResult.MetaPath
	if metaPath == "" {
		metaPath = filepath.Join(pipeResult.OutDir, "flutter_meta.json")
	}

	// Step 2: Copy scripts into the artifact directory and run from there, so
	// the artifact is self-contained. A failure here means the scripts are
	// missing or unreadable, which is fatal — there is no fallback that would
	// keep the artifact portable.
	scriptPath, err := analysis.CopyGhidraArtifacts(pipeResult.OutDir)
	if err != nil {
		return fmt.Errorf("ghidra scripts: %w", err)
	}

	// Step 3: Find Ghidra.
	ghLauncher, ghHome, err := analysis.FindGhidra(*ghidraHome)
	if err != nil {
		return err
	}
	cli.Errf("ghidra: %s\n", ghHome)

	// Step 4: Handle --gui (launch interactive Ghidra).
	if *gui {
		return launchGhidraGUI(ghHome, absLibPath, pipeResult.OutDir, scriptPath)
	}

	// Step 5: Run headless analysis.
	decompDir := filepath.Join(pipeResult.OutDir, "decompiled")
	absMetaPath, _ := filepath.Abs(metaPath)
	absDecompDir, _ := filepath.Abs(decompDir)

	projectName, err := analysis.GhidraProjectName(prov.SourceName, prov.SHA256)
	if err != nil {
		return fmt.Errorf("derive Ghidra project identity: %w", err)
	}

	absProjDir := analysis.SanitizeGhidraPath(*projectDir)
	if err := os.MkdirAll(absProjDir, 0o755); err != nil {
		return fmt.Errorf("create project dir: %w", err)
	}

	if *all {
		cli.Errf("running Ghidra headless analysis (decompiling ALL functions)...\n")
	} else {
		cli.Errf("running Ghidra headless analysis (signal functions only, use --all for everything)...\n")
	}
	cli.Errf("  project: %s/%s\n", absProjDir, projectName)
	cli.Errf("  import: %s\n", absLibPath)
	cli.Errf("  decompile output: %s\n", absDecompDir)

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
	cli.Errf("decompiled %d functions → %s\n", cCount, absDecompDir)

	return nil
}

// launchGhidraGUI starts Ghidra in interactive mode and prints instructions.
// scriptPath is the artifact copy made by the caller, so the directory the
// user is told to add in the Script Manager is the same one headless mode uses.
func launchGhidraGUI(ghidraHome, libPath, outDir, scriptPath string) error {
	ghidraRun, err := analysis.FindGhidraGUI(ghidraHome)
	if err != nil {
		return err
	}

	cli.Errf("\nLaunching Ghidra GUI...\n")
	cli.Errf("  1. Import: %s\n", libPath)
	cli.Errf("  2. Open Script Manager (Window → Script Manager)\n")
	cli.Errf("  3. Add script directory: %s\n", scriptPath)
	cli.Errf("  4. Run aotopsy_prescript.py first, then aotopsy_apply.py\n")
	cli.Errf("     (or pass flutter_meta.json path as script argument)\n")
	cli.Errf("  Meta: %s/flutter_meta.json\n\n", outDir)

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
