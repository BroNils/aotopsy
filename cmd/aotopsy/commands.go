package main

import (
	"aotopsy/internal/cli"
)

// Command describes one CLI subcommand. The registry replaces the
// switch statements that used to live in main.go (20+ cases) and
// cmd_debug.go (18+ cases): adding a command is now one entry here,
// not three edits across two files plus a help string.
type Command struct {
	Name  string // command name as typed by the user
	Usage string // syntax after "aotopsy "; empty falls back to "<name> [args]"
	Short string // one-line description for help output
	Run   func(args []string) error

	// Debug marks _debug subcommands. When true, the command is listed
	// under "aotopsy _debug" help, not top-level help.
	Debug bool
}

// primaryCommands is the registry of top-level (non-_debug) commands.
var primaryCommands = []Command{
	{Name: "meta", Usage: "meta <libapp.so> [flags] | meta --from <dir> [flags]", Short: "Generate flutter_meta.json", Run: cmdMeta},
	{Name: "ghidra", Usage: "ghidra <libapp.so> [flags]", Short: "Ghidra headless decompilation", Run: cmdGhidra},
	{Name: "ida", Usage: "ida <libapp.so> [flags]", Short: "IDA headless decompilation", Run: cmdIDA},
	{Name: "doctor", Usage: "doctor <libapp.so> [flags]", Short: "Diagnostic scan", Run: cmdDoctor},
	{Name: "find-libapp", Usage: "find-libapp --apk <apk-or-zip> [--out <dir>]", Short: "Find Dart library in APK", Run: cmdFindLibapp},
	{Name: "frida-export", Usage: "frida-export [flags]", Short: "Export metadata for Frida scripts", Run: cmdFridaExport},
	{Name: "frida-import", Usage: "frida-import --in <log> --static <dir> [--out <dir>]", Short: "Import Frida runtime results", Run: cmdFridaImport},
	{Name: "reflutter-import", Usage: "reflutter-import --dump <dump.dart> --static <dir> --lib <libapp.so> [flags]", Short: "Import reFlutter dump", Run: cmdReflutterImport},
	{Name: "parity", Usage: "parity [flags]", Short: "Corpus parity report", Run: cmdParity},
	{Name: "inventory", Usage: "inventory [flags]", Short: "Sample inventory", Run: cmdInventory},
	{Name: "compare-blutter", Usage: "compare-blutter <blutter-dir> <aotopsy-dir>", Short: "Compare output with blutter", Run: cmdCompareBlutter},
	{Name: "import-darter", Usage: "import-darter <darter.json> <out.r2>", Short: "Import darter output for older Dart versions", Run: cmdImportDarter},
	{Name: "export-dart", Usage: "export-dart [<libapp.so> [out-dir]] [flags]", Short: "Export decompiled Dart project structure to .dart files", Run: cmdExportDart},
	{Name: "sdk-check", Usage: "sdk-check [flags]", Short: "Verify SDK tables (THR, ObjectStore, stubs, roots) against dart-lang/sdk", Run: cmdSDKCheck},
	{Name: "signal", Usage: "signal <libapp.so> [flags] | signal --from <dir> [flags]", Short: "Signal analysis", Run: cmdSignalPipeline},
	{Name: "_debug", Usage: "_debug <command> [args]", Short: "Internal commands", Run: cmdDebug},
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
	{Name: "fingerprint", Short: "ELF/snapshot identity + Dart version evidence", Run: cmdFingerprint, Debug: true},
	{Name: "symbolmap", Short: "Diff a stripped vs unstripped libapp.so's symbols", Run: cmdSymbolMap, Debug: true},
	{Name: "funcdiff", Short: "Diff function identity + instruction bytes between builds", Run: cmdFuncDiff, Debug: true},
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
	cli.Errf(`aotopsy — Dart AOT snapshot analyzer

Usage:
  aotopsy <libapp.so>                         Full analysis pipeline
  aotopsy --from <analysis-dir> [flags]       Re-run signal/meta from existing output
	`)
	for _, c := range primaryCommands {
		if c.Debug {
			continue
		}
		usage := c.Usage
		if usage == "" {
			usage = c.Name + " [args]"
		}
		cli.Errf("  aotopsy %-52s %s\n", usage, c.Short)
	}
	cli.Errf(`
Full-analysis flags:
  --out <dir>         Output directory (default: <basename>.aotopsy/). It is
                      replaced as a whole, so an existing one must be empty or
                      a previous aotopsy output (it carries .aotopsy-generation)
  --quiet, -q         Suppress verbose output (verbose is default)
  --all               Include all functions in the focus list
  --k <n>             Signal context hops (default: 2; must be > 0)
  --from <dir>        Reuse existing disasm output; supports --out/--quiet/--all/--k

Fresh-binary-only flags:
  --strict            Fail on structural errors
  --limit <n>         Max functions for per-function stages (0 = all)
  --graph             Build call graph and per-function CFGs
  --decompile         Write per-function Dart pseudocode to <out>/dart/
  --max-steps <n>     Global loop cap (0 = default)
`)
}

// printDebugUsage prints the _debug help text, generated from the
// debug command registry.
func printDebugUsage() {
	cli.Errf(`aotopsy _debug — internal commands

Usage:
  aotopsy _debug <command> [args]

Commands:
`)
	for _, c := range debugCommands {
		cli.Errf("  %-20s %s\n", c.Name, c.Short)
	}
}
