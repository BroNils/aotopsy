package main

import (
	"flag"
	"fmt"
	"os"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/snapshot"
)

func cmdClusters(args []string) error {
	fs := flag.NewFlagSet("clusters", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	which := fs.String("which", "both", "which snapshot: vm, isolate, or both")
	debugFill := fs.Bool("debug-fill", false, "print fill position per cluster")

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
		fmt.Printf("Dart SDK version: %s (header fields: %d, tag style: %d)\n",
			info.Version.DartVersion, info.Version.HeaderFields, info.Version.Tags)
	}
	if info.Version != nil && !info.Version.Supported {
		return fmt.Errorf("HALT_UNSUPPORTED_VERSION: Dart %s (hash %s)", info.Version.DartVersion, info.VmHeader.SnapshotHash)
	}

	type target struct {
		name string
		data []byte
	}
	var targets []target
	switch *which {
	case "vm":
		targets = []target{{"VM", info.VmData.Data}}
	case "isolate":
		targets = []target{{"Isolate", info.IsolateData.Data}}
	default:
		targets = []target{
			{"VM", info.VmData.Data},
			{"Isolate", info.IsolateData.Data},
		}
	}

	for _, t := range targets {
		if len(t.data) < 64 {
			fmt.Fprintf(os.Stderr, "%s: data too short (%d bytes)\n", t.name, len(t.data))
			continue
		}

		clusterStart, err := cluster.FindClusterDataStart(t.data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", t.name, err)
			continue
		}

		isVM := t.name == "VM"
		result, err := cluster.ScanClusters(t.data, clusterStart, info.Version, isVM, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: scan error: %v\n", t.name, err)
			continue
		}

		fmt.Printf("\n%s Snapshot Clusters:\n", t.name)
		fmt.Printf("  ClusterDataStart=0x%x\n", clusterStart)
		fmt.Printf("  NumBaseObjects=%d  NumObjects=%d  NumClusters=%d\n",
			result.Header.NumBaseObjects, result.Header.NumObjects, result.Header.NumClusters)
		fmt.Printf("  InstructionsTableLen=%d  InstructionTableDataOffset=%d\n",
			result.Header.InstructionsTableLen, result.Header.InstructionTableDataOffset)

		fmt.Printf("  Clusters (%d decoded):\n", len(result.Clusters))
		var ct *snapshot.CIDTable
		if info.Version != nil {
			ct = info.Version.CIDs
		}
		for _, c := range result.Clusters {
			var name string
			if ct != nil {
				name = cluster.CidNameV(c.CID, ct)
			} else {
				// L-4 fix: use CidNameV with a fallback table instead of
				// the hardcoded CidName (which was only correct for v3.9.2).
				// When version is unknown, use the v3.9.2 CID table as fallback
				// (same as DetectVersion's default for unknown hashes).
				name = cluster.CidNameV(c.CID, snapshot.DetectVersion("").CIDs)
			}
			if name == "" {
				name = fmt.Sprintf("CID_%d", c.CID)
			}
			flags := ""
			if c.IsCanonical {
				flags += " canonical"
			}
			if c.IsImmutable {
				flags += " immutable"
			}
			fmt.Printf("    [%d] CID=%-3d %-24s count=%-5d  off=0x%x..0x%x%s\n",
				c.Index, c.CID, name, c.Count, c.StartOffset, c.EndOffset, flags)
		}

		if len(result.Diags) > 0 {
			fmt.Printf("  Diagnostics (%d):\n", len(result.Diags))
			for _, d := range result.Diags {
				fmt.Printf("    %s\n", d)
			}
		}

		if *debugFill {
			fmt.Printf("\n  Fill Positions (%s, fill_start=0x%x):\n", t.name, result.FillStart)
			err := cluster.DebugFillPositions(t.data, result, info.Version, isVM, os.Stdout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  fill debug error: %v\n", err)
			}
		}
	}

	return nil
}
