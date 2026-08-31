package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aotopsy/internal/analysis"
	"aotopsy/internal/frida"
)

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

	dir := *fromDir
	if dir == "" {
		if *libPath == "" {
			return fmt.Errorf("--lib or --from is required")
		}
		base := strings.TrimSuffix(filepath.Base(*libPath), ".so")
		dir = base + ".aotopsy"
		opts := analysis.Opts{
			LibPath:  *libPath,
			OutDir:   dir,
			Quiet:    true,
			Signal:   true,
			SignalK:  2,
			MaxSteps: 100000,
		}
		fmt.Fprintf(os.Stderr, "Running full analysis...\n")
		result, err := analysis.Run(opts)
		if err != nil {
			return fmt.Errorf("pipeline failed: %v", err)
		}
		_ = result
	} else {
		if *libPath == "" {
			*libPath = filepath.Join(dir, "..", "libapp.so")
			if _, err := os.Stat(*libPath); err != nil {
				return fmt.Errorf("--lib is required when using --from (could not auto-detect)")
			}
		}
	}

	ctx, err := analysis.LoadContext(*libPath)
	if err != nil {
		return fmt.Errorf("load context: %v", err)
	}
	defer func() { _ = ctx.Close() }()

	if *outPath == "" {
		*outPath = filepath.Join(dir, "frida_metadata.json")
	}

	meta := analysis.BuildFridaMetadata(ctx, dir)

	f, err := os.Create(*outPath)
	if err != nil {
		return fmt.Errorf("create output: %v", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(meta); err != nil {
		return fmt.Errorf("encode: %v", err)
	}

	fmt.Fprintf(os.Stderr, "Frida metadata exported: %s\n", *outPath)
	fmt.Fprintf(os.Stderr, "  Functions: %d\n", len(meta.Functions))
	fmt.Fprintf(os.Stderr, "  Unresolved BLRs: %d\n", len(meta.UnresolvedBLRs))
	fmt.Fprintf(os.Stderr, "  Dispatch entries: %d\n", len(meta.DispatchTable))
	fmt.Fprintf(os.Stderr, "  String refs: %d\n", len(meta.StringRefs))
	fmt.Fprintf(os.Stderr, "  FFI call sites: %d\n", len(meta.FFICallSites))

	if *genScript {
		if *scriptPath == "" {
			*scriptPath = filepath.Join(dir, "frida_hooks.js")
		}
		script := frida.GenerateFridaScriptFromMeta(*outPath)
		if err := os.WriteFile(*scriptPath, []byte(script), 0644); err != nil {
			return fmt.Errorf("write frida script: %v", err)
		}
		fmt.Fprintf(os.Stderr, "  Frida script: %s\n", *scriptPath)
		fmt.Fprintf(os.Stderr, "  Run: frida -H 127.0.0.1:8888 -f com.example.app -l %s\n", *scriptPath)
	}

	return nil
}
