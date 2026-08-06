package main

import (
	"fmt"
	"os"
)

// cmdDebug handles "aotopsy _debug <cmd>" — internal/debug commands.
func cmdDebug(args []string) error {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, `aotopsy _debug — internal commands

Usage:
  aotopsy _debug <command> [args]

Commands:
  dump            Disassemble and dump symbols
  objects         Dump object pool
  strings         Extract strings from snapshot
  graph           Extract named object graph
  clusters        Parse clusters
  render          Render callgraph and HTML from JSONL
  thr-audit       Audit THR-relative memory accesses
  thr-cluster     Cluster unresolved THR offsets
  thr-classify    Classify unresolved THR offsets
  dart2-buckets   Dart 2.x bucket analysis
  find-libapp-batch   Batch find-libapp + report
  refinfo         Inspect raw ref IDs / owner chains
  x64refs         x86_64 disasm/callers-of/hash-scan
  fingerprint     Build-id + Flutter/Dart engine version detection
  symbolmap       Diff a stripped vs unstripped libapp.so's symbols
  funcdiff        Diff functions between two libapp.so builds
  decompile-native  Dart-AOT-aware pseudocode (no Ghidra dependency)
  ffi-trace       Static dart:ffi DynamicLibrary.open/lookup call-site tracing
  dispatch-table  Recover real names for megamorphic/polymorphic dispatch targets
`)
		return nil
	}

	cmd := args[0]
	subArgs := args[1:]

	switch cmd {
	case "dump":
		return cmdDump(subArgs)
	case "objects":
		return cmdObjects(subArgs)
	case "strings":
		return cmdStrings(subArgs)
	case "graph":
		return cmdGraph(subArgs)
	case "clusters":
		return cmdClusters(subArgs)
	case "render":
		return cmdRender(subArgs)
	case "thr-audit":
		return cmdTHRAudit(subArgs)
	case "thr-cluster":
		return cmdTHRCluster(subArgs)
	case "thr-classify":
		return cmdTHRClassify(subArgs)
	case "dart2-buckets":
		return cmdDart2Buckets(subArgs)
	case "find-libapp-batch":
		return cmdFindLibappBatch(subArgs)
	case "refinfo":
		return cmdRefInfo(subArgs)
	case "x64refs":
		return cmdX64Refs(subArgs)
	case "fingerprint":
		return cmdFingerprint(subArgs)
	case "symbolmap":
		return cmdSymbolMap(subArgs)
	case "funcdiff":
		return cmdFuncDiff(subArgs)
	case "decompile-native":
		return cmdDecompileNative(subArgs)
	case "ffi-trace":
		return cmdFFITrace(subArgs)
	case "dispatch-table":
		return cmdDispatchTable(subArgs)
	default:
		return fmt.Errorf("unknown debug command: %s", cmd)
	}
}
