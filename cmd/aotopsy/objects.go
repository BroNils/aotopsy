package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/analysis"
)

type poolRecord struct {
	Index   int    `json:"index"`
	Offset  string `json:"offset"`
	Kind    string `json:"kind"`
	Display string `json:"display"`
	RefID   int    `json:"ref,omitempty"`
	Imm     int64  `json:"imm,omitempty"`
}

func cmdObjects(args []string) error {
	fs := flag.NewFlagSet("objects", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so")
	jsonOut := fs.Bool("json", false, "output JSONL instead of text")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *libapp == "" {
		return fmt.Errorf("--lib is required")
	}

	opts := dartfmt.Options{
		Mode:     dartfmt.ModeBestEffort,
		MaxSteps: *maxSteps,
	}

	sc, err := analysis.LoadSnapshot(*libapp, opts)
	if err != nil {
		return err
	}
	defer func() { _ = sc.Close() }()

	info := sc.Info
	result := sc.Result
	poolDisplay := sc.PoolDisplay

	if info.Version != nil && info.Version.DartVersion != "" {
		fmt.Fprintf(os.Stderr, "Dart SDK version: %s\n", info.Version.DartVersion)
	}
	if sc.VMResult != nil {
		fmt.Fprintf(os.Stderr, "vm snapshot: %d clusters, %d strings, %d named\n",
			len(sc.VMResult.Clusters), len(sc.VMResult.Strings), len(sc.VMResult.Named))
	}
	fmt.Fprintf(os.Stderr, "pool: %d entries (%d resolved)\n", len(result.Pool), len(poolDisplay))

	// Output.
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		for _, pe := range result.Pool {
			rec := poolRecord{
				Index:  pe.Index,
				Offset: fmt.Sprintf("0x%x", (pe.Index+2)*8),
				Kind:   poolKindString(pe.Kind),
			}
			if d, ok := poolDisplay[pe.Index]; ok {
				rec.Display = d
			}
			if pe.Kind == cluster.PoolTagged {
				rec.RefID = pe.RefID
			}
			if pe.Kind == cluster.PoolImmediate {
				rec.Imm = pe.Imm
			}
			if err := enc.Encode(rec); err != nil {
				return fmt.Errorf("write json: %w", err)
			}
		}
	} else {
		for _, pe := range result.Pool {
			offset := (pe.Index + 2) * 8
			display := poolDisplay[pe.Index]
			switch pe.Kind {
			case cluster.PoolTagged:
				if display != "" {
					fmt.Printf("[pp+0x%x] %s\n", offset, display)
				} else {
					fmt.Printf("[pp+0x%x] <ref:%d>\n", offset, pe.RefID)
				}
			case cluster.PoolImmediate:
				fmt.Printf("[pp+0x%x] IMM: 0x%x\n", offset, pe.Imm)
			case cluster.PoolNative:
				fmt.Printf("[pp+0x%x] Native\n", offset)
			case cluster.PoolEmpty:
				fmt.Printf("[pp+0x%x] Empty\n", offset)
			}
		}
	}

	return nil
}

func poolKindString(k cluster.PoolEntryKind) string {
	switch k {
	case cluster.PoolTagged:
		return "tagged"
	case cluster.PoolImmediate:
		return "immediate"
	case cluster.PoolNative:
		return "native"
	case cluster.PoolEmpty:
		return "empty"
	default:
		return fmt.Sprintf("unknown_%d", k)
	}
}
