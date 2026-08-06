package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	cmd := os.Args[1]

	switch cmd {
	// --- Primary commands (new CLI) ---
	case "meta":
		err = cmdMeta(os.Args[2:])
	case "ghidra":
		err = cmdGhidra(os.Args[2:])
	case "ida":
		err = cmdIDA(os.Args[2:])
	case "doctor":
		err = cmdDoctor(os.Args[2:])
	case "find-libapp":
		err = cmdFindLibapp(os.Args[2:])
	case "frida-export":
		err = cmdFridaExport(os.Args[2:])
	case "frida-import":
		err = cmdFridaImport(os.Args[2:])
	case "reflutter-import":
		err = cmdReflutterImport(os.Args[2:])
	case "parity":
		err = cmdParity(os.Args[2:])
	case "inventory":
		err = cmdInventory(os.Args[2:])
	case "_debug":
		err = cmdDebug(os.Args[2:])

	// --- Deprecated commands (shims with warnings) ---
	case "disasm":
		deprecationWarning("disasm", "aotopsy <libapp.so>")
		err = cmdDisasm(os.Args[2:])
	case "signal":
		// "signal" with --in is the old form; without flags it's the new positional form.
		if hasFlag(os.Args[2:], "-in", "--in") {
			deprecationWarning("signal --in", "aotopsy signal <libapp.so>")
			err = cmdSignal(os.Args[2:])
		} else {
			err = cmdSignalPipeline(os.Args[2:])
		}
	case "dump":
		deprecationWarning("dump", "aotopsy _debug dump")
		err = cmdDump(os.Args[2:])
	case "strings":
		deprecationWarning("strings", "aotopsy _debug strings")
		err = cmdStrings(os.Args[2:])
	case "graph":
		deprecationWarning("graph", "aotopsy _debug graph")
		err = cmdGraph(os.Args[2:])
	case "clusters":
		deprecationWarning("clusters", "aotopsy _debug clusters")
		err = cmdClusters(os.Args[2:])
	case "render":
		deprecationWarning("render", "aotopsy _debug render")
		err = cmdRender(os.Args[2:])
	case "thr-audit":
		deprecationWarning("thr-audit", "aotopsy _debug thr-audit")
		err = cmdTHRAudit(os.Args[2:])
	case "thr-cluster":
		deprecationWarning("thr-cluster", "aotopsy _debug thr-cluster")
		err = cmdTHRCluster(os.Args[2:])
	case "thr-classify":
		deprecationWarning("thr-classify", "aotopsy _debug thr-classify")
		err = cmdTHRClassify(os.Args[2:])
	case "find-libapp-batch":
		deprecationWarning("find-libapp-batch", "aotopsy _debug find-libapp-batch")
		err = cmdFindLibappBatch(os.Args[2:])
	case "dart2-buckets":
		deprecationWarning("dart2-buckets", "aotopsy _debug dart2-buckets")
		err = cmdDart2Buckets(os.Args[2:])

	case "help", "-h", "--help":
		usage()
		os.Exit(0)

	default:
		// If the first arg is a file on disk, treat as "aotopsy <libapp.so>".
		if resolvePositionalLib(cmd) != "" {
			err = cmdRun(os.Args[1:])
		} else if strings.HasPrefix(cmd, "-") {
			// Flags before file path: pass all args to cmdRun which will reorder.
			err = cmdRun(os.Args[1:])
		} else {
			fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
			usage()
			os.Exit(1)
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func deprecationWarning(old, new string) {
	fmt.Fprintf(os.Stderr, "warning: '%s' is deprecated, use '%s' instead\n\n", old, new)
}

// hasFlag checks if any arg matches one of the given flag names.
func hasFlag(args []string, names ...string) bool {
	for _, a := range args {
		for _, n := range names {
			if a == n {
				return true
			}
		}
	}
	return false
}

func usage() {
	fmt.Fprintf(os.Stderr, `aotopsy — Dart AOT snapshot analyzer

Usage:
  aotopsy <libapp.so>                         Full analysis pipeline
  aotopsy meta <libapp.so>                    Generate flutter_meta.json
  aotopsy ghidra <libapp.so>                   Ghidra headless decompilation
  aotopsy ida <libapp.so>                     IDA headless decompilation
  aotopsy signal <libapp.so>                  Signal analysis
  aotopsy doctor <libapp.so>                  Diagnostic scan
  aotopsy find-libapp <apk>                   Find Dart library in APK
  aotopsy frida-export <libapp.so>            Export metadata for Frida scripts
  aotopsy frida-import <results.json>         Import Frida runtime results
  aotopsy reflutter-import <dump.dart>        Import reFlutter dump
  aotopsy parity <dir>                        Corpus parity report
  aotopsy inventory <dir>                     Sample inventory
  aotopsy _debug <cmd>                        Internal commands

Flags:
  --out <dir>         Output directory (default: <basename>.aotopsy/)
  --quiet, -q         Suppress verbose output (verbose is default)
  --strict            Fail on structural errors
  --all               Include all functions (not just signal)
  --from <dir>        Reuse existing disasm output
  --k <n>             Signal context hops (default: 2)
  --graph             Build call graph and per-function CFGs
  --max-steps <n>     Global loop cap
`)
}
