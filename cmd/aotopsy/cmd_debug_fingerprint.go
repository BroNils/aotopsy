package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"aotopsy/internal/cli"
	"aotopsy/internal/fingerprint"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/output"
)

// cmdFingerprint implements "aotopsy _debug fingerprint --lib <path>":
// bounded ELF/snapshot identity facts plus explicitly heuristic Dart
// Version::String evidence. The JSON keeps those evidence classes separate.
func cmdFingerprint(args []string) error {
	fs := flag.NewFlagSet("fingerprint", flag.ContinueOnError)
	libPath := fs.String("lib", "", "path to supported ELF64 little-endian ET_DYN libapp.so to fingerprint")
	out := fs.String("out", "", "write JSON report to this path (default: stdout)")
	if err := parseNoPositionals(fs, args); err != nil {
		return err
	}
	if *libPath == "" {
		return fmt.Errorf("--lib is required")
	}
	if *out != "" {
		same, err := output.SamePath(*libPath, *out)
		if err != nil {
			return fmt.Errorf("fingerprint: compare input/output paths: %w", err)
		}
		if same {
			return fmt.Errorf("fingerprint output must not replace the input binary")
		}
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
	if err := jsonutil.WriteJSONFile(*out, rep); err != nil {
		return fmt.Errorf("fingerprint: write %s: %w", *out, err)
	}
	cli.Errf("wrote %s\n", *out)
	return nil
}
