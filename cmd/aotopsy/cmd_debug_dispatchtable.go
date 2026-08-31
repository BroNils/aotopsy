package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cluster"
)

// cmdDispatchTable implements "aotopsy _debug dispatch-table --lib <path>":
// statically recovers real function/stub names for the AOT snapshot's DispatchTable.
func cmdDispatchTable(args []string) error {
	fs := flag.NewFlagSet("dispatch-table", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so (ARM64 or x86_64)")
	filter := fs.String("filter", "", "only print entries whose resolved name contains this substring")
	showAll := fs.Bool("all", false, "print every entry, including null/unresolved (default: only entries with a resolved name)")
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
	fmt.Fprintf(os.Stderr, "Dart SDK version: %s, arch64: %v\n", ctx.DartVersion, ctx.IsARM64)

	entries, err := analysis.ResolveDispatchTable(ctx)
	if err != nil {
		return err
	}
	if entries == nil {
		fmt.Fprintf(os.Stderr, "dispatch-table: no dispatch table in this snapshot (length 0)\n")
		return nil
	}

	nullCount, codeCount, stubCount, unnamedCount, printed := 0, 0, 0, 0, 0
	for _, e := range entries {
		switch e.Kind {
		case cluster.DispatchNull:
			nullCount++
		case cluster.DispatchCode:
			codeCount++
		case cluster.DispatchStub:
			stubCount++
		}
		if e.Kind != cluster.DispatchNull && e.Name == "" {
			unnamedCount++
		}

		if e.Kind == cluster.DispatchNull && !*showAll {
			continue
		}
		if e.Name == "" && !*showAll {
			continue
		}
		if *filter != "" && !strings.Contains(e.Name, *filter) {
			continue
		}
		kind := "code"
		if e.Kind == cluster.DispatchStub {
			kind = "stub"
		} else if e.Kind == cluster.DispatchNull {
			kind = "null"
		}
		fmt.Printf("dispatch[%d] kind=%s name=%q\n", e.Index, kind, e.Name)
		printed++
	}

	fmt.Fprintf(os.Stderr, "dispatch-table: %d entries total (null=%d code=%d stub=%d unnamed=%d), printed %d\n",
		len(entries), nullCount, codeCount, stubCount, unnamedCount, printed)
	return nil
}
