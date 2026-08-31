package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"aotopsy/internal/fingerprint"
)

// cmdFingerprint implements "aotopsy _debug fingerprint --lib <path>":
// build-id + Flutter/Dart engine version detection, ported from
// flutterdec's engine_fingerprint.rs but arch-agnostic (ARM64 and x86_64).
func cmdFingerprint(args []string) error {
	fs := flag.NewFlagSet("fingerprint", flag.ExitOnError)
	libPath := fs.String("lib", "", "path to libapp.so (or any ELF) to fingerprint")
	out := fs.String("out", "", "write JSON report to this path (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *libPath == "" {
		return fmt.Errorf("--lib is required")
	}

	rep, err := fingerprint.Run(*libPath)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("fingerprint: marshal: %w", err)
	}

	if *out == "" {
		fmt.Println(string(data))
		return nil
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		return fmt.Errorf("fingerprint: write %s: %w", *out, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
	return nil
}
