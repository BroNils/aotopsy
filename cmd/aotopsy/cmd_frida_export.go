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
	fs := flag.NewFlagSet("frida-export", flag.ExitOnError)
	libPath := fs.String("lib", "", "path to libapp.so")
	fromDir := fs.String("from", "", "reuse existing aotopsy output directory")
	outPath := fs.String("out", "", "output JSON path (default: <from>/frida_metadata.json)")
	genScript := fs.Bool("gen-script", false, "also generate a ready-to-run Frida JS script")
	scriptPath := fs.String("script-out", "", "output path for Frida script (default: <from>/frida_hooks.js)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: aotopsy frida-export (--lib <libapp.so> | --from <aotopsy_dir>) [--out <metadata.json>] [--gen-script] [--script-out <hooks.js>]")
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
			MaxSteps: 100000,
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

	if *outPath == "" {
		*outPath = filepath.Join(dir, "frida_metadata.json")
	}
	if *genScript && *scriptPath == "" {
		*scriptPath = filepath.Join(dir, "frida_hooks.js")
	}

	// Export consumes these files from dir. A custom destination may live
	// anywhere else, but must never overwrite an input artifact or the analysed
	// binary while export is still using that generation.
	if err := validateFridaExportDestinations(*libPath, dir, *outPath, *scriptPath, *genScript); err != nil {
		return err
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
	bindingPath := filepath.Join(dir, frida.BindingFileName)
	artifacts := []output.FileArtifact{
		{Path: *outPath, Data: metaBytes, Perm: 0o644},
		{Path: bindingPath, Data: bindingBytes, Perm: 0o644},
	}
	var script string
	if *genScript {
		script, err = frida.GenerateFridaScript(meta)
		if err != nil {
			return err
		}
		artifacts = append(artifacts, output.FileArtifact{Path: *scriptPath, Data: []byte(script), Perm: 0o644})
	}
	if err := output.PublishFileSet(artifacts); err != nil {
		return fmt.Errorf("publish Frida export generation: %w", err)
	}

	cli.Errf("Frida metadata exported: %s\n", *outPath)
	cli.Errf("  Functions: %d\n", len(meta.Functions))
	cli.Errf("  Unresolved BLRs: %d\n", len(meta.UnresolvedBLRs))
	cli.Errf("  Dispatch entries: %d\n", len(meta.DispatchTable))
	cli.Errf("  String refs: %d\n", len(meta.StringRefs))
	cli.Errf("  Generation binding: %s\n", bindingPath)

	if *genScript {
		cli.Errf("  Frida script: %s\n", *scriptPath)
		cli.Errf("  Run: frida -H 127.0.0.1:8888 -f com.example.app -l %s\n", *scriptPath)
	}

	return nil
}

func validateFridaExportDestinations(libPath, dir, metadataPath, scriptPath string, genScript bool) error {
	bindingPath := filepath.Join(dir, frida.BindingFileName)
	protected := []string{
		libPath,
		bindingPath,
		filepath.Join(dir, analysis.ProvenanceFileName),
		filepath.Join(dir, "functions.jsonl"),
		filepath.Join(dir, "call_edges.jsonl"),
		filepath.Join(dir, "dispatch_table.jsonl"),
		filepath.Join(dir, "string_refs.jsonl"),
		filepath.Join(dir, "evidence.jsonl"),
	}
	allowedInStatic := map[string]string{
		metadataPath: filepath.Join(dir, "frida_metadata.json"),
	}
	if genScript {
		allowedInStatic[scriptPath] = filepath.Join(dir, "frida_hooks.js")
	}
	for _, dst := range []string{metadataPath, scriptPath} {
		if dst == "" {
			continue
		}
		for _, src := range protected {
			same, err := output.SamePath(dst, src)
			if err != nil {
				return fmt.Errorf("compare Frida output/input paths: %w", err)
			}
			if same {
				return fmt.Errorf("frida output %s aliases consumed input %s", dst, src)
			}
		}
		inside, err := output.ContainsPath(dir, dst)
		if err != nil {
			return fmt.Errorf("compare Frida output/static generation paths: %w", err)
		}
		if inside {
			allowed := allowedInStatic[dst]
			same, err := output.SamePath(dst, allowed)
			if err != nil {
				return fmt.Errorf("compare Frida output/default paths: %w", err)
			}
			if !same {
				return fmt.Errorf("custom Frida output %s must not overwrite files inside static generation %s", dst, dir)
			}
		}
	}
	if genScript {
		same, err := output.SamePath(metadataPath, scriptPath)
		if err != nil {
			return fmt.Errorf("compare Frida metadata/script paths: %w", err)
		}
		if same {
			return fmt.Errorf("frida metadata and script outputs must be different files")
		}
	}
	return nil
}
