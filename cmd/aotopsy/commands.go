package main

import (
	"fmt"
	"os"
)

// Command describes one CLI subcommand. The registry replaces the
// switch statements that used to live in main.go (20+ cases) and
// cmd_debug.go (18+ cases): adding a command is now one entry here,
// not three edits across two files plus a help string.
type Command struct {
	Name  string // command name as typed by the user
	Short string // one-line description for help output
	Run   func(args []string) error

	// Debug marks _debug subcommands. When true, the command is listed
	// under "aotopsy _debug" help, not top-level help.
	Debug bool

	// Deprecated marks commands that still work but print a warning.
	// DeprecatedRepl is the replacement shown in the warning.
	Deprecated     bool
	DeprecatedRepl string

	// Special handles non-standard dispatch logic that cannot be expressed
	// as a simple Run(args) call (e.g. "signal" with --in flag, or the
	// positional "aotopsy <libapp.so>" fallback). When Special is non-nil,
	// it takes over the entire dispatch for this command name and Run is
	// ignored.
	Special func(cmd string, allArgs []string) (handled bool, err error)
}

// primaryCommands is the registry of top-level (non-_debug) commands.
var primaryCommands = []Command{
	{Name: "meta", Short: "Generate flutter_meta.json", Run: cmdMeta},
	{Name: "ghidra", Short: "Ghidra headless decompilation", Run: cmdGhidra},
	{Name: "ida", Short: "IDA headless decompilation", Run: cmdIDA},
	{Name: "doctor", Short: "Diagnostic scan", Run: cmdDoctor},
	{Name: "find-libapp", Short: "Find Dart library in APK", Run: cmdFindLibapp},
	{Name: "frida-export", Short: "Export metadata for Frida scripts", Run: cmdFridaExport},
	{Name: "frida-import", Short: "Import Frida runtime results", Run: cmdFridaImport},
	{Name: "reflutter-import", Short: "Import reFlutter dump", Run: cmdReflutterImport},
	{Name: "parity", Short: "Corpus parity report", Run: cmdParity},
	{Name: "inventory", Short: "Sample inventory", Run: cmdInventory},
	{Name: "compare-blutter", Short: "Compare output with blutter", Run: cmdCompareBlutter},
	{Name: "build-fingerprint-dict", Short: "Build function fingerprint dictionary", Run: cmdBuildFingerprintDict},
	{Name: "apply-fingerprint-dict", Short: "Apply fingerprint dictionary to unnamed functions", Run: cmdApplyFingerprintDict},
	{Name: "import-darter", Short: "Import darter output for older Dart versions", Run: cmdImportDarter},
	{Name: "export-dart", Short: "Export decompiled Dart project structure to .dart files", Run: cmdExportDart},
	{Name: "_debug", Short: "Internal commands", Run: cmdDebug},

	// Deprecated commands — still work, print a warning.
	{Name: "disasm", Short: "Disassemble and dump symbols", Run: cmdDisasm, Deprecated: true, DeprecatedRepl: "aotopsy <libapp.so>"},
	{Name: "dump", Short: "Disassemble and dump symbols", Run: cmdDump, Deprecated: true, DeprecatedRepl: "aotopsy _debug dump"},
	{Name: "strings", Short: "Extract strings from snapshot", Run: cmdStrings, Deprecated: true, DeprecatedRepl: "aotopsy _debug strings"},
	{Name: "graph", Short: "Extract named object graph", Run: cmdGraph, Deprecated: true, DeprecatedRepl: "aotopsy _debug graph"},
	{Name: "clusters", Short: "Parse clusters", Run: cmdClusters, Deprecated: true, DeprecatedRepl: "aotopsy _debug clusters"},
	{Name: "render", Short: "Render callgraph and HTML from JSONL", Run: cmdRender, Deprecated: true, DeprecatedRepl: "aotopsy _debug render"},
	{Name: "thr-audit", Short: "Audit THR-relative memory accesses", Run: cmdTHRAudit, Deprecated: true, DeprecatedRepl: "aotopsy _debug thr-audit"},
	{Name: "thr-cluster", Short: "Cluster unresolved THR offsets", Run: cmdTHRCluster, Deprecated: true, DeprecatedRepl: "aotopsy _debug thr-cluster"},
	{Name: "thr-classify", Short: "Classify unresolved THR offsets", Run: cmdTHRClassify, Deprecated: true, DeprecatedRepl: "aotopsy _debug thr-classify"},
	{Name: "find-libapp-batch", Short: "Batch find-libapp + report", Run: cmdFindLibappBatch, Deprecated: true, DeprecatedRepl: "aotopsy _debug find-libapp-batch"},
	{Name: "dart2-buckets", Short: "Dart 2.x bucket analysis", Run: cmdDart2Buckets, Deprecated: true, DeprecatedRepl: "aotopsy _debug dart2-buckets"},

	// "signal" has special dispatch: --in flag means old form, otherwise new.
	{Name: "signal", Short: "Signal analysis", Special: func(cmd string, allArgs []string) (bool, error) {
		if hasFlag(allArgs[1:], "-in", "--in") {
			deprecationWarning("signal --in", "aotopsy signal <libapp.so>")
			return true, cmdSignal(allArgs[1:])
		}
		return true, cmdSignalPipeline(allArgs[1:])
	}},
}

// debugCommands is the registry of _debug subcommands.
var debugCommands = []Command{
	{Name: "dump", Short: "Disassemble and dump symbols", Run: cmdDump, Debug: true},
	{Name: "objects", Short: "Dump object pool", Run: cmdObjects, Debug: true},
	{Name: "strings", Short: "Extract strings from snapshot", Run: cmdStrings, Debug: true},
	{Name: "graph", Short: "Extract named object graph", Run: cmdGraph, Debug: true},
	{Name: "clusters", Short: "Parse clusters", Run: cmdClusters, Debug: true},
	{Name: "render", Short: "Render callgraph and HTML from JSONL", Run: cmdRender, Debug: true},
	{Name: "thr-audit", Short: "Audit THR-relative memory accesses", Run: cmdTHRAudit, Debug: true},
	{Name: "thr-cluster", Short: "Cluster unresolved THR offsets", Run: cmdTHRCluster, Debug: true},
	{Name: "thr-classify", Short: "Classify unresolved THR offsets", Run: cmdTHRClassify, Debug: true},
	{Name: "dart2-buckets", Short: "Dart 2.x bucket analysis", Run: cmdDart2Buckets, Debug: true},
	{Name: "find-libapp-batch", Short: "Batch find-libapp + report", Run: cmdFindLibappBatch, Debug: true},
	{Name: "refinfo", Short: "Inspect raw ref IDs / owner chains", Run: cmdRefInfo, Debug: true},
	{Name: "x64refs", Short: "x86_64 disasm/callers-of/hash-scan", Run: cmdX64Refs, Debug: true},
	{Name: "fingerprint", Short: "Build-id + Flutter/Dart engine version detection", Run: cmdFingerprint, Debug: true},
	{Name: "symbolmap", Short: "Diff a stripped vs unstripped libapp.so's symbols", Run: cmdSymbolMap, Debug: true},
	{Name: "funcdiff", Short: "Diff functions between two libapp.so builds", Run: cmdFuncDiff, Debug: true},
	{Name: "decompile-native", Short: "Dart-AOT-aware pseudocode (no Ghidra dependency)", Run: cmdDecompileNative, Debug: true},
	{Name: "ffi-trace", Short: "Static dart:ffi DynamicLibrary.open/lookup call-site tracing", Run: cmdFFITrace, Debug: true},
	{Name: "dispatch-table", Short: "Recover real names for megamorphic/polymorphic dispatch targets", Run: cmdDispatchTable, Debug: true},
}

// findCommand looks up a command by name in a registry.
func findCommand(registry []Command, name string) *Command {
	for i := range registry {
		if registry[i].Name == name {
			return &registry[i]
		}
	}
	return nil
}

// printPrimaryUsage prints the top-level help text, generated from the
// command registry.
func printPrimaryUsage() {
	fmt.Fprintf(os.Stderr, `aotopsy — Dart AOT snapshot analyzer

Usage:
  aotopsy <libapp.so>                         Full analysis pipeline
`)
	for _, c := range primaryCommands {
		if c.Deprecated || c.Debug || c.Name == "_debug" || c.Special != nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "  aotopsy %-36s %s\n", c.Name+" <args>", c.Short)
	}
	// signal has Special dispatch, so it's not in the loop above.
	if sc := findCommand(primaryCommands, "signal"); sc != nil {
		fmt.Fprintf(os.Stderr, "  aotopsy %-36s %s\n", "signal <libapp.so>", sc.Short)
	}
	fmt.Fprintf(os.Stderr, "  aotopsy _debug <cmd>                        Internal commands\n")
	fmt.Fprintf(os.Stderr, `
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

// printDebugUsage prints the _debug help text, generated from the
// debug command registry.
func printDebugUsage() {
	fmt.Fprintf(os.Stderr, `aotopsy _debug — internal commands

Usage:
  aotopsy _debug <command> [args]

Commands:
`)
	for _, c := range debugCommands {
		fmt.Fprintf(os.Stderr, "  %-20s %s\n", c.Name, c.Short)
	}
}
