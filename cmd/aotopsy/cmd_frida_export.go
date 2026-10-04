package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cli"
	"aotopsy/internal/frida"
	"aotopsy/internal/output"
)

// cmdFridaExport exports analysis metadata and generated hooks for Frida.
func cmdFridaExport(args []string) error {
	fs := flag.NewFlagSet("frida-export", flag.ContinueOnError)
	libPath := fs.String("lib", "", "path to libapp.so")
	fromDir := fs.String("from", "", "reuse existing aotopsy output directory")
	genScript := fs.Bool("gen-script", false, "also generate a ready-to-run Frida JS script")
	maxSteps := fs.Int("max-steps", 0, "global loop cap for a fresh --lib analysis (0 = default)")
	if err := parseNoPositionals(fs, args); err != nil {
		return err
	}
	if err := requireNonNegativeFlag("max-steps", *maxSteps); err != nil {
		return err
	}
	if *fromDir != "" && flagWasSet(fs, "max-steps") {
		return fmt.Errorf("--max-steps cannot be used with --from because snapshot parsing/disassembly is skipped")
	}

	dir := *fromDir
	var provenance analysis.Provenance
	var hasProvenance bool
	if dir == "" {
		if *libPath == "" {
			return fmt.Errorf("--lib or --from is required")
		}
		resolved := resolvePositionalLib(*libPath)
		if resolved == "" {
			return fmt.Errorf("file not found: %s", *libPath)
		}
		*libPath = resolved
		dir = defaultOutDir(*libPath)
		opts := analysis.Opts{
			LibPath:  *libPath,
			OutDir:   dir,
			Quiet:    true,
			Signal:   true,
			SignalK:  2,
			MaxSteps: *maxSteps,
		}
		cli.Errf("Running full analysis...\n")
		_, err := analysis.Run(opts)
		if err != nil {
			return fmt.Errorf("pipeline failed: %w", err)
		}
	} else {
		var err error
		provenance, hasProvenance, err = analysis.ReadProvenance(dir)
		if err != nil {
			return fmt.Errorf("read --from provenance: %w", err)
		}
		if !hasProvenance || provenance.SHA256 == "" || provenance.Arch == "" || provenance.DartVersion == "" {
			return fmt.Errorf("--from directory lacks complete provenance identity")
		}
		if *libPath == "" {
			if provenance.Source == "" || !filepath.IsAbs(provenance.Source) {
				return fmt.Errorf("--lib is required: provenance source path is unavailable or not absolute")
			}
			*libPath = provenance.Source
		}
		resolved := resolvePositionalLib(*libPath)
		if resolved == "" {
			return fmt.Errorf("file not found: %s", *libPath)
		}
		*libPath = resolved
	}

	ctx, err := analysis.LoadContext(*libPath)
	if err != nil {
		return fmt.Errorf("load context: %w", err)
	}
	defer func() { _ = ctx.Close() }()
	if hasProvenance {
		sha, err := ctx.EF.SHA256()
		if err != nil {
			return fmt.Errorf("hash --lib for provenance check: %w", err)
		}
		arch := "x64"
		if ctx.IsARM64 {
			arch = "arm64"
		}
		if !strings.EqualFold(sha, provenance.SHA256) || provenance.Arch != arch ||
			provenance.DartVersion != ctx.DartVersion ||
			(provenance.Size > 0 && provenance.Size != ctx.EF.FileSize()) {
			return fmt.Errorf("--lib does not match --from provenance (sha256/arch/version/size mismatch)")
		}
	}

	meta, err := analysis.BuildFridaMetadata(ctx, dir)
	if err != nil {
		return err
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Frida metadata: %w", err)
	}
	metaBytes = append(metaBytes, '\n')
	binding := frida.BindingFromMetadata(meta)
	bindingBytes, err := json.MarshalIndent(binding, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Frida generation binding: %w", err)
	}
	bindingBytes = append(bindingBytes, '\n')
	outPath := filepath.Join(dir, "frida_metadata.json")
	bindingPath := filepath.Join(dir, frida.BindingFileName)
	scriptPath := filepath.Join(dir, "frida_hooks.js")
	var script string
	if *genScript {
		script, err = frida.GenerateFridaScript(meta)
		if err != nil {
			return err
		}
	}

	// Export updates an existing static analysis generation. Clone it into a
	// directory transaction and publish metadata, binding, and optional script
	// together; custom cross-directory destinations are intentionally no longer
	// supported because they cannot share one atomic generation boundary.
	tx, err := output.BeginDirTransaction(dir)
	if err != nil {
		return fmt.Errorf("begin Frida export transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Abort()
		}
	}()
	stage := tx.StageDir()
	if err := output.CloneTree(dir, stage); err != nil {
		return fmt.Errorf("clone static generation for Frida export: %w", err)
	}
	if err := output.WriteArtifactFile(stage, "frida_metadata.json", metaBytes, 0o644); err != nil {
		return fmt.Errorf("stage Frida metadata: %w", err)
	}
	if err := output.WriteArtifactFile(stage, frida.BindingFileName, bindingBytes, 0o644); err != nil {
		return fmt.Errorf("stage Frida generation binding: %w", err)
	}
	if *genScript {
		if err := output.WriteArtifactFile(stage, "frida_hooks.js", []byte(script), 0o644); err != nil {
			return fmt.Errorf("stage Frida script: %w", err)
		}
	} else if err := tx.RemoveStageFile("frida_hooks.js"); err != nil {
		return fmt.Errorf("remove stale Frida script: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("publish Frida export generation: %w", err)
	}
	committed = true

	cli.Errf("Frida metadata exported: %s\n", outPath)
	cli.Errf("  Functions: %d\n", len(meta.Functions))
	cli.Errf("  Call probes: %d\n", len(meta.CallProbes))
	cli.Errf("  Dispatch entries: %d\n", len(meta.DispatchTable))
	cli.Errf("  String refs: %d\n", len(meta.StringRefs))
	cli.Errf("  Generation binding: %s\n", bindingPath)

	if *genScript {
		cli.Errf("  Frida script: %s\n", scriptPath)
		cli.Errf("  Run: frida -H 127.0.0.1:8888 -f com.example.app -l %s\n", scriptPath)
	}

	return nil
}
