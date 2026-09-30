package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cli"
	"aotopsy/internal/ffitrace"
)

// cmdFFITrace implements "aotopsy _debug ffi-trace --lib <path>":
// static detection of dart:ffi DynamicLibrary.open/lookup call sites and
// compiler-generated Dart-to-native FFI wrappers.
func cmdFFITrace(args []string) error {
	fs := flag.NewFlagSet("ffi-trace", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so (ARM64 or x86_64)")
	out := fs.String("out", "", "write findings as JSONL to this path (default: stdout)")
	filter := fs.String("filter", "", "restrict to functions whose resolved name contains this substring")
	maxScan := fs.Int("max-scan", 0, "cap how many functions ffi-trace processes (0 = package default of 500)")
	allowUnbounded := fs.Bool("allow-unbounded", false, "scan EVERY function, no cap")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *libapp == "" {
		return fmt.Errorf("--lib is required")
	}

	ctx, err := analysis.LoadContext(*libapp)
	if err != nil {
		return err
	}
	defer func() { _ = ctx.Close() }()
	cli.Errf("Dart SDK version: %s, arch64: %v\n", ctx.DartVersion, ctx.IsARM64)

	// Trace intentionally derives literal arguments from each outgoing call
	// site's own stack/register setup. Do not run BuildArgRegMasks here: that
	// whole-binary pass describes callees' incoming Dart calling conventions,
	// costs far more than a bounded ffi-trace, and is not evidence for the
	// arguments of the call site currently being inspected.
	findings, scanned, err := ffitrace.Trace(ctx, ffitrace.Options{
		MaxScan:        *maxScan,
		AllowUnbounded: *allowUnbounded,
		Filter:         *filter,
	})
	if err != nil {
		return err
	}

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
	cli.Errf("ffi-trace: scanned %d function(s), %d dynamic_library_call finding(s) (%d with a resolved literal arg), %d native_call_site finding(s), %d total\n",
		scanned, dynCalls, resolved, nativeCalls, len(findings))
	return nil
}
