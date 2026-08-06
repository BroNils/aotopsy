package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"aotopsy/internal/ffitrace"
	"aotopsy/internal/pipeline"
)

// cmdFFITrace implements "aotopsy _debug ffi-trace --lib <path>":
// static detection of dart:ffi DynamicLibrary.open/lookup call sites
// (resolving the target native library + symbol name when passed as
// literals) plus every function whose pseudocode already shows the
// vm_tag native/FFI-leaf-call marker ("nativeCall(...)"). Pure static
// analysis, no CPU emulation, no live device -- see docs/plan-phase1-
// dart-aot-emulation-harness.md's Komponen H.
func cmdFFITrace(args []string) error {
	fs := flag.NewFlagSet("ffi-trace", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so (ARM64 or x86_64)")
	out := fs.String("out", "", "write findings as JSONL to this path (default: stdout)")
	filter := fs.String("filter", "", "restrict to functions whose resolved name contains this substring -- prefer this over --allow-unbounded when a specific neighborhood is already known")
	maxScan := fs.Int("max-scan", 0, "cap how many functions ffi-trace processes (0 = package default of 500). See ffitrace.Options's doc comment: a real Flutter app's libapp.so bundles the whole framework, and this project's own README/WORKFLOW.md document a confirmed whole-host crash history from unbounded full-binary sweeps of this same underlying operation -- also independently reproduced during this feature's own development (5.4GB RSS + 1.7GB swap on an 8149-function SAMPLE app, on a 5.8GB-RAM machine)")
	allowUnbounded := fs.Bool("allow-unbounded", false, "scan EVERY function, no cap -- DANGEROUS on a resource-constrained host, see --max-scan's doc; prefer --filter to narrow scope instead")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *libapp == "" {
		return fmt.Errorf("--lib is required")
	}

	ctx, err := pipeline.LoadContext(*libapp)
	if err != nil {
		return err
	}
	defer func() { _ = ctx.Close() }()
	fmt.Fprintf(os.Stderr, "Dart SDK version: %s, arch64: %v\n", ctx.DartVersion, ctx.IsARM64)

	findings, scanned := ffitrace.Trace(ctx, ffitrace.Options{
		MaxScan:        *maxScan,
		AllowUnbounded: *allowUnbounded,
		Filter:         *filter,
	})

	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return fmt.Errorf("create %s: %w", *out, err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	enc := json.NewEncoder(w)
	dynCalls, nativeCalls, resolved := 0, 0, 0
	for _, f := range findings {
		if err := enc.Encode(f); err != nil {
			return err
		}
		switch f.Kind {
		case "dynamic_library_call":
			dynCalls++
			if f.Resolved {
				resolved++
			}
		case "native_call_site":
			nativeCalls++
		}
	}
	fmt.Fprintf(os.Stderr, "ffi-trace: scanned %d function(s), %d dynamic_library_call finding(s) (%d with a resolved literal arg), %d native_call_site finding(s), %d total\n",
		scanned, dynCalls, resolved, nativeCalls, len(findings))
	return nil
}
