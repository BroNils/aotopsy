package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/analysis"
	"aotopsy/internal/strxref"
)

func cmdStrings(args []string) error {
	fs := flag.NewFlagSet("strings", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	which := fs.String("which", "both", "which snapshot: vm, isolate, or both. Was \"isolate\" by default -- confirmed a real, previously-unnoticed gap: VM-isolate strings (shared base objects across every app on this Dart SDK build, e.g. Dart's own internal runtime messages) were silently excluded from any search that didn't explicitly pass --which vm/both, even though they can contain real, searchable content. Defaulting to \"both\" now for exhaustive-by-default search; pass --which isolate explicitly to restore the old narrower behavior.")
	maxLen := fs.Int("max-len", 200, "max display length per string (0 = unlimited)")
	names := fs.Bool("names", false, "extract and display named objects (Function, Class, Library, Script)")
	find := fs.String("find", "", "only show strings containing this substring (case-insensitive) -- makes a large dump actually usable")
	xref := fs.Bool("xref", false, "for each string matched by --find, also show which function(s) actually load it from the object pool (internal/strxref, full-scan by default -- see --xref-max-scan). Requires --find.")
	xrefMaxScan := fs.Int("xref-max-scan", 0, "cap how many functions --xref scans (0 = scan every function; measured safe even on a real 129k-function production app, see internal/strxref's doc comment -- set this only to narrow a run deliberately)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *libapp == "" {
		return fmt.Errorf("--lib is required")
	}
	if *xref && *find == "" {
		return fmt.Errorf("--xref requires --find (cross-referencing every string in a real app would be enormous output, not narrower work -- see internal/strxref, which itself scans efficiently, but the OUTPUT needs a target)")
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
		fmt.Fprintf(os.Stderr, "Dart SDK version: %s\n", info.Version.DartVersion)
	}
	if info.Version != nil && !info.Version.Supported {
		return fmt.Errorf("HALT_UNSUPPORTED_VERSION: Dart %s (hash %s)", info.Version.DartVersion, info.VmHeader.SnapshotHash)
	}

	type target struct {
		name         string
		data         []byte
		snapshotSize int64
	}
	var targets []target
	switch {
	case *names:
		// Always parse both to build complete ref→string map.
		targets = []target{
			{"VM", info.VmData.Data, info.VmHeader.TotalSize},
			{"Isolate", info.IsolateData.Data, info.IsolateHeader.TotalSize},
		}
	case *which == "vm":
		targets = []target{{"VM", info.VmData.Data, info.VmHeader.TotalSize}}
	case *which == "isolate":
		targets = []target{{"Isolate", info.IsolateData.Data, info.IsolateHeader.TotalSize}}
	default:
		targets = []target{
			{"VM", info.VmData.Data, info.VmHeader.TotalSize},
			{"Isolate", info.IsolateData.Data, info.IsolateHeader.TotalSize},
		}
	}

	// When --names is set, build a combined ref→string map from all snapshots
	// so cross-snapshot refs (e.g., isolate name pointing to VM string) resolve.
	type parsedTarget struct {
		name   string
		result *cluster.Result
	}
	var parsed []parsedTarget

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

		// C-3 fix: Always use ReadFill (not the deprecated ReadFillStrings)
		// to properly handle all cluster types including ROData strings for
		// Dart 2.12 (StringRODataPerSubclass) and non-compressed-pointers.
		if err := cluster.ReadFill(t.data, result, info.Version, isVM, t.snapshotSize); err != nil {
			fmt.Fprintf(os.Stderr, "%s: fill error: %v\n", t.name, err)
			continue
		}

		parsed = append(parsed, parsedTarget{name: t.name, result: result})
	}

	// Build combined ref→string map across all snapshots.
	refToStr := make(map[int]string)
	if *names {
		for _, pt := range parsed {
			for _, ps := range pt.result.Strings {
				refToStr[ps.RefID] = ps.Value
			}
		}
		// Also build ref→named lookup for owner resolution.
		refToNamed := make(map[int]*cluster.NamedObject)
		for _, pt := range parsed {
			for i := range pt.result.Named {
				no := &pt.result.Named[i]
				refToNamed[no.RefID] = no
			}
		}
		// Resolve owner names through the named object chain.
		for _, pt := range parsed {
			for i := range pt.result.Named {
				no := &pt.result.Named[i]
				if no.OwnerRefID >= 0 {
					if owner, ok := refToNamed[no.OwnerRefID]; ok && owner.NameRefID >= 0 {
						if _, ok := refToStr[no.OwnerRefID]; !ok {
							// Store the owner's name string at the owner's ref ID.
							if ownerName, ok := refToStr[owner.NameRefID]; ok {
								refToStr[no.OwnerRefID] = ownerName
							}
						}
					}
				}
			}
		}
	}

	// matchedRefIDs collects every string ref that passed --find, across
	// both VM and Isolate tables, for the --xref pass below.
	var matchedRefIDs []int
	findLower := strings.ToLower(*find)

	ct := info.Version.CIDs
	for _, pt := range parsed {
		shown := 0
		for _, ps := range pt.result.Strings {
			if *find != "" && !strings.Contains(strings.ToLower(ps.Value), findLower) {
				continue
			}
			shown++
		}
		if *find != "" {
			fmt.Printf("%s Strings (%d matching %q of %d total):\n", pt.name, shown, *find, len(pt.result.Strings))
		} else {
			fmt.Printf("%s Strings (%d):\n", pt.name, len(pt.result.Strings))
		}
		for _, ps := range pt.result.Strings {
			if *find != "" && !strings.Contains(strings.ToLower(ps.Value), findLower) {
				continue
			}
			matchedRefIDs = append(matchedRefIDs, ps.RefID)
			display := ps.Value
			display = strings.ReplaceAll(display, "\n", "\\n")
			display = strings.ReplaceAll(display, "\r", "\\r")
			display = strings.ReplaceAll(display, "\t", "\\t")

			truncated := false
			if *maxLen > 0 && len(display) > *maxLen {
				display = display[:*maxLen]
				truncated = true
			}

			enc := "1b"
			if !ps.IsOneByte {
				enc = "2b"
			}

			suffix := ""
			if truncated {
				suffix = "..."
			}
			fmt.Printf("  [ref=%d] (%s) %q%s\n", ps.RefID, enc, display, suffix)
		}

		if *names && len(pt.result.Named) > 0 {
			fmt.Printf("\n%s Named Objects (%d):\n", pt.name, len(pt.result.Named))
			for _, no := range pt.result.Named {
				name := refToStr[no.NameRefID]
				if name == "" {
					name = fmt.Sprintf("<ref:%d>", no.NameRefID)
				}
				cidName := cluster.CidNameV(no.CID, ct)
				if cidName == "" {
					cidName = fmt.Sprintf("CID_%d", no.CID)
				}

				owner := ""
				if no.OwnerRefID >= 0 {
					if ownerName, ok := refToStr[no.OwnerRefID]; ok {
						owner = fmt.Sprintf(" owner=%q", ownerName)
					} else {
						owner = fmt.Sprintf(" owner=<ref:%d>", no.OwnerRefID)
					}
				}

				display := name
				if *maxLen > 0 && len(display) > *maxLen {
					display = display[:*maxLen] + "..."
				}
				fmt.Printf("  [ref=%d] %-20s %q%s\n", no.RefID, cidName, display, owner)
			}
		}
	}

	if *xref {
		if len(matchedRefIDs) == 0 {
			fmt.Fprintf(os.Stderr, "\n--xref: no strings matched %q, nothing to cross-reference\n", *find)
			return nil
		}
		fmt.Fprintf(os.Stderr, "\n--xref: cross-referencing %d matched string ref(s) against every function's object-pool loads...\n", len(matchedRefIDs))

		// Separate parse pass via analysis.LoadContext -- this command
		// builds its own VM+Isolate string tables above (needed for the
		// "which snapshot" dump format), not the Ranges/FuncIR machinery
		// --xref needs, so this reuses Komponen A's shared context loader
		// instead of duplicating decompile_native_cmd.go's setup a third
		// time in this file.
		ctx, err := analysis.LoadContext(*libapp)
		if err != nil {
			return fmt.Errorf("--xref: load context: %w", err)
		}
		defer func() { _ = ctx.Close() }()

		refSet := make(map[int]bool, len(matchedRefIDs))
		for _, r := range matchedRefIDs {
			refSet[r] = true
		}
		poolIndices := ctx.PoolIndicesForRefIDs(refSet)
		if len(poolIndices) == 0 {
			fmt.Fprintf(os.Stderr, "--xref: matched string(s) aren't referenced by any object-pool slot in the app isolate (may only appear in the VM-isolate table, which functions can't directly index into the same way)\n")
			return nil
		}

		refs, scanned := strxref.FindPoolReferences(ctx, poolIndices, strxref.Options{MaxScan: *xrefMaxScan})
		fmt.Fprintf(os.Stderr, "--xref: scanned %d function(s), found %d reference(s)\n\n", scanned, len(refs))
		for _, r := range refs {
			fmt.Printf("  used in: %s @ 0x%x (pool load @ 0x%x, pool[%d])\n", r.FuncName, r.FuncVA, r.InstrAddr, r.PoolIndex)
		}
	}

	return nil
}
