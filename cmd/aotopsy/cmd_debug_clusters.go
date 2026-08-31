package main

import (
	"flag"
	"fmt"
	"os"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

// cmdClusters implements "aotopsy _debug clusters" for decoding snapshot clusters.
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

	ef, info, err := analysis.LoadSnapshotRaw(*libapp, opts)
	if err != nil {
		return err
	}
	defer func() { _ = ef.Close() }()

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

// cmdRefInfo implements "aotopsy _debug refinfo" for inspecting raw ref IDs / owner chains.
func cmdRefInfo(args []string) error {
	fs := flag.NewFlagSet("refinfo", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so")
	refsFlag := fs.String("refs", "", "comma-separated ref IDs to inspect")
	codeRefFlag := fs.Int("find-owner-of-code-ref", -1, "given a Code cluster's own ref ID, find its owning Function via code_index cross-reference")
	siblingsOfFlag := fs.Int("siblings-of-owner", -1, "list all Function/Field NamedObjects whose OwnerRefID equals this ref")
	listToplevel := fs.Bool("list-toplevel", false, "list every Function whose effective owner is a \"::\" class")
	fieldsOfCID := fs.Int("fields-of-instance-cid", -1, "find Class with this CID, list its Field records")
	walk := fs.Bool("walk", true, "follow OwnerRefID chain until it terminates")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *libapp == "" || (*refsFlag == "" && *codeRefFlag < 0 && *siblingsOfFlag < 0 && !*listToplevel && *fieldsOfCID < 0) {
		return fmt.Errorf("--lib and one of --refs/--find-owner-of-code-ref/--siblings-of-owner/--list-toplevel/--fields-of-instance-cid are required")
	}

	var refs []int
	if *refsFlag != "" {
		var err error
		refs, err = analysis.ParseRefIDs(*refsFlag)
		if err != nil {
			return err
		}
	}

	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}
	sc, err := analysis.LoadSnapshot(*libapp, opts)
	if err != nil {
		return err
	}
	defer func() { _ = sc.Close() }()

	info := sc.Info
	result := sc.Result
	pl := sc.Pool
	ct := info.Version.CIDs

	fmt.Fprintf(os.Stderr, "Dart SDK version: %s\n", info.Version.DartVersion)

	for _, r := range refs {
		analysis.PrintRefChain(r, pl, ct, *walk, make(map[int]bool))
	}

	if *codeRefFlag >= 0 {
		if err := analysis.FindOwnerViaCodeIndex(*codeRefFlag, result, pl, ct, *walk, info.Version.CodeIndexOneBased); err != nil {
			return err
		}
	}

	if *siblingsOfFlag >= 0 {
		analysis.FindSiblingsByOwner(*siblingsOfFlag, result, pl, ct)
	}

	if *listToplevel {
		analysis.ListToplevelFunctions(result, pl, ct)
	}

	if *fieldsOfCID >= 0 {
		analysis.FindFieldsOfInstanceCID(*fieldsOfCID, result, pl, ct)
	}
	return nil
}
