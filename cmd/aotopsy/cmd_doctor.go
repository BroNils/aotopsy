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
	args = reorderPositionalArg(args)
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	maxSteps := fs.Int("max-steps", 0, "global loop cap")

	if err := fs.Parse(args); err != nil {
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
	_, _ = fmt.Fprintf(os.Stdout, "Snapshot:    OK\n")

	if info.Version != nil {
		_, _ = fmt.Fprintf(os.Stdout, "Dart:        %s\n", info.Version.DartVersion)
		if info.Version.CompressedPointers {
			_, _ = fmt.Fprintf(os.Stdout, "Pointers:    compressed (4 bytes)\n")
		} else {
			_, _ = fmt.Fprintf(os.Stdout, "Pointers:    uncompressed (8 bytes)\n")
		}
		if !info.Version.Supported {
			_, _ = fmt.Fprintf(os.Stdout, "Support:     UNSUPPORTED\n")
			return fmt.Errorf("unsupported dart version: %s", info.Version.DartVersion)
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
