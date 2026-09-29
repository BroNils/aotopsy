package main

import (
	"flag"
	"fmt"
	"os"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/snapshot"
)

// cmdDoctor handles "aotopsy doctor <libapp.so>" — diagnostic scan.
func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	maxSteps := fs.Int("max-steps", 0, "global loop cap")

	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: aotopsy doctor <libapp.so>")
	}

	libPath := fs.Arg(0)
	if resolvePositionalLib(libPath) == "" {
		return fmt.Errorf("file not found: %s", libPath)
	}

	opts := dartfmt.Options{
		Mode:     dartfmt.ModeBestEffort,
		MaxSteps: *maxSteps,
	}

	ef, err := elfx.Open(libPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stdout, "ELF:        FAIL (%v)\n", err)
		return fmt.Errorf("elf: %w", err)
	}
	defer func() { _ = ef.Close() }()
	_, _ = fmt.Fprintf(os.Stdout, "ELF:        OK (%d bytes)\n", ef.FileSize())

	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stdout, "Snapshot:    FAIL (%v)\n", err)
		return fmt.Errorf("snapshot: %w", err)
	}
	profile, err := doctorVersionProfile(info)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stdout, "Snapshot:    FAIL (%v)\n", err)
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "Snapshot:    OK\n")

	if profile != nil {
		_, _ = fmt.Fprintf(os.Stdout, "Dart:        %s\n", profile.DartVersion)
		if profile.CompressedPointers {
			_, _ = fmt.Fprintf(os.Stdout, "Pointers:    compressed (4 bytes)\n")
		} else {
			_, _ = fmt.Fprintf(os.Stdout, "Pointers:    uncompressed (8 bytes)\n")
		}
		if !profile.Supported {
			_, _ = fmt.Fprintf(os.Stdout, "Support:     UNSUPPORTED\n")
			return fmt.Errorf("unsupported dart version: %s", profile.DartVersion)
		}
		_, _ = fmt.Fprintf(os.Stdout, "Support:     OK\n")
	}

	if info.VmHeader != nil {
		_, _ = fmt.Fprintf(os.Stdout, "Hash:        %s\n", info.VmHeader.SnapshotHash)
	}
	if info.IsolateHeader != nil && info.IsolateHeader.Features != "" {
		// Reveals build-time flags relevant to RE (e.g.
		// no-dwarf_stack_traces_mode -- confirmed to directly gate
		// whether Function Code objects get discarded from the
		// snapshot, see ARCHITECTURE.md's "Discarded-Code function
		// naming" section) without needing the separate `inventory`
		// command's JSONL output.
		_, _ = fmt.Fprintf(os.Stdout, "Features:    %s\n", info.IsolateHeader.Features)
	}

	if len(info.Diags) > 0 {
		_, _ = fmt.Fprintf(os.Stdout, "Diagnostics: %d\n", len(info.Diags))
		for _, d := range info.Diags {
			_, _ = fmt.Fprintf(os.Stdout, "  %s\n", d)
		}
	}

	return nil
}

func doctorVersionProfile(info *snapshot.Info) (*snapshot.VersionProfile, error) {
	if info == nil || info.Version == nil || info.Version.DartVersion == "" {
		return nil, fmt.Errorf("snapshot version/profile could not be resolved")
	}
	return info.Version, nil
}
