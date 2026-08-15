package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/pipeline"
	"aotopsy/internal/snapshot"
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

	ef, err := elfx.Open(*libapp)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = ef.Close() }()

	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}

	if info.Version != nil && info.Version.DartVersion != "" {
		fmt.Fprintf(os.Stderr, "Dart SDK version: %s\n", info.Version.DartVersion)
	}
	if info.Version != nil && !info.Version.Supported {
		return fmt.Errorf("HALT_UNSUPPORTED_VERSION: Dart %s (hash %s)", info.Version.DartVersion, info.VmHeader.SnapshotHash)
	}

	// Parse isolate snapshot.
	data := info.IsolateData.Data
	if len(data) < 64 {
		return fmt.Errorf("isolate data too short (%d bytes)", len(data))
	}

	clusterStart, err := cluster.FindClusterDataStart(data)
	if err != nil {
		return fmt.Errorf("cluster start: %w", err)
	}

	result, err := cluster.ScanClusters(data, clusterStart, info.Version, false, opts)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	if os.Getenv("DEFLUTTER_DEBUG_FILL") != "" {
		if err := cluster.DebugFillPositions(data, result, info.Version, false, os.Stderr); err != nil {
			return fmt.Errorf("fill debug: %w", err)
		}
	}
	if err := cluster.ReadFill(data, result, info.Version, false, info.IsolateHeader.TotalSize); err != nil {
		return fmt.Errorf("fill: %w", err)
	}

	// Parse VM snapshot for base object resolution (strings, names, CIDs).
	var vmResult *cluster.Result
	vmData := info.VmData.Data
	if len(vmData) >= 64 && info.VmHeader != nil {
		vmStart, err := cluster.FindClusterDataStart(vmData)
		if err == nil {
			vmRes, err := cluster.ScanClusters(vmData, vmStart, info.Version, true, opts)
			if err == nil {
				// ReadFill handles strings (FillString/FillROData) and named objects.
				_ = cluster.ReadFill(vmData, vmRes, info.Version, true, info.VmHeader.TotalSize)
				vmResult = vmRes
				fmt.Fprintf(os.Stderr, "vm snapshot: %d clusters, %d strings, %d named\n",
					len(vmRes.Clusters), len(vmRes.Strings), len(vmRes.Named))
			}
		}
	}

	// Resolve pool entries.
	pl := pipeline.BuildPoolLookups(result, info.Version.CIDs, vmResult, info.Version.CodeIndexOneBased, info.Version.DartVersion, info.Version.TypeClassIdIsRef)
	poolDisplay := pipeline.ResolvePoolDisplay(result.Pool, pl)

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
