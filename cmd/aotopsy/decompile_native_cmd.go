package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/frida"
	"aotopsy/internal/naming"
	"aotopsy/internal/pipeline"
)

// cmdDecompileNative implements "aotopsy _debug decompile-native --lib
// <path> --func <hex VA>": Dart-AOT-aware pseudocode generation, ported
// from flutterdec's flutterdec-decompiler crate, with NO dependency on
// Ghidra (unlike aotopsy's existing top-level "decompile" command,
// which is purely a Ghidra-headless orchestration wrapper). Works for
// both ARM64 and x86_64 builds -- flutterdec itself is ARM64-only.
func cmdDecompileNative(args []string) error {
	fs := flag.NewFlagSet("decompile-native", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so (ARM64 or x86_64)")
	funcVAStr := fs.String("func", "", "hex VA of any address inside the target function")
	all := fs.Bool("all", false, "decompile every function, writing one combined.dart file under --out -- EXPENSIVE (a real Flutter app's libapp.so bundles the whole framework, easily thousands of functions), prefer --find first and consider --filter. A full-binary sweep against a real ~130k-function app has been observed needing roughly 64GB of RAM to complete without crashing the whole host -- confirmed the hard way: two separate whole-VM crashes/reboots on a 5.8GB-RAM machine from --all runs during this project's development (once with --max unbounded, once with --max set to the FULL matched-function count, which is exactly as expensive as --max 0). If you don't have that much RAM, use --find + --func on specific addresses, or --all with a SMALL bounded --max (a few dozen, not thousands) -- never rely on --all's own budget/heartbeat/GC hardening alone to keep memory in check on a constrained host.")
	fromMain := fs.Bool("from-main", false, "decompile the app's own code reachable from its main() entry point, transitively following direct call sites (plus a class-touch expansion for canonicalized const instances seen via the object pool), writing one combined.dart file under --out -- unlike --all+--filter, this needs NO class/package name known in advance: reachability is determined by walking the call graph from main(), and any function whose owning Dart library resolves to dart:* or package:flutter* is skipped (not decompiled, not descended into) rather than matched by name. CONFIRMED LIMITATION: virtual/polymorphic dispatch (Widget.build(), State.initState(), UI callbacks) is invisible to a direct-call-graph walk, same as any other static call-graph tool -- class-touch expansion recovers some of these cases but is a documented over-approximation, not a proof of reachability. See ARCHITECTURE.md for the full analysis, including cases where an entry function's own argument is supplied by the Dart VM's isolate-startup machinery rather than any disassemblable instruction -- use --gen-frida to confirm reachability/argument values dynamically when static analysis alone hits this wall. Use --filter for a name-based sweep when you already know a class name.")
	genFrida := fs.Bool("gen-frida", false, "also emit a ready-to-run Frida script (see https://frida.re/docs/javascript-api/) hooking every function this invocation decompiles, dumping argument registers (only the REAL declared arity when confidently resolved, see the arity-inference note in ARCHITECTURE.md -- falls back to the full raw register set otherwise) + return value at runtime, PLUS a second set of probes at every still-unresolved indirect-call site (dynamicCall(indirectTarget_xN, ...) in the pseudocode) that reads the actual runtime call target and logs its module-relative offset -- the natural next step when static analysis alone can't resolve something (virtual dispatch, VM-supplied arguments, etc.). Probes are capped (maxFridaProbes in frida_gen.go) and skip memory-operand dispatch-table call shapes (not a single register to read) -- narrow with --filter/--func if you hit the cap.")
	genFridaOut := fs.String("gen-frida-out", "", "output path for the generated Frida script (default: <out>/hooks.js in --all/--from-main mode, or stdout after the pseudocode in --func mode)")
	genFridaStalker := fs.Bool("gen-frida-stalker", false, "add Stalker call tracing to the --gen-frida script: follows every non-VM-internal thread and prints a periodic per-target call summary (module+offset), which catches calls that no hook covers -- virtual dispatch, VM-initiated entry points, work done on threads you did not know existed. Stalker rewrites and re-executes every basic block of every followed thread, so expect a large slowdown and use --gen-frida-stalker-min to cut the noise. Off by default.")
	genFridaStalkerMin := fs.Int("gen-frida-stalker-min", 10, "with --gen-frida-stalker, suppress call targets seen fewer than this many times within one summary window (0 = report every target)")
	findSubstr := fs.String("find", "", "list VA + resolved name for every function whose name contains this substring, WITHOUT decompiling any of them -- cheap, safe way to locate a target address before using --func")
	outDir := fs.String("out", "", "output directory for --all mode -- writes ONE combined.dart file inside it (not one file per function; avoids thousands of small file-create syscalls, which correlated with real host crashes during this tool's own testing)")
	maxFuncs := fs.Int("max", 500, "max functions to emit in --all mode (0 = unlimited -- can be very slow/memory-heavy on a real app with tens of thousands of functions; prefer a bounded value)")
	skipFuncs := fs.Int("skip", 0, "skip this many matching functions before starting to emit -- combine with --max to process the whole binary in separate SHARDS (separate process invocations), each covering one slice, then concatenate the resulting combined.dart files. This is the recommended way to decompile a full real-world app: it bounds each individual run's resource/time footprint and lets one bad shard be re-run alone instead of restarting the whole batch")
	maxStepsFlag := fs.Int("max-steps", 0, "override the per-function emitter step budget (default 20000, 0 = use default). Increase for very complex functions that get truncated; decrease for faster processing.")
	filterSubstr := fs.String("filter", "", "modifier for --all ONLY (not its own mode, and not accepted with --from-main): restricts --all to functions whose name contains this substring (e.g. your own app's class name) -- a real Flutter build's libapp.so bundles the ENTIRE framework (widgets/rendering/Material/dart:core/etc), so an unfiltered --all against even a tiny app can mean thousands of framework functions that were never the actual target. Requires knowing a name substring in advance -- if you don't (a real RE scenario against an unfamiliar binary), use --from-main instead, which classifies by owning-library URL (dart:*/package:flutter*) instead of by name.")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Set configurable emitter step budget.
	decompiler.SetMaxStepsPerEmitter(*maxStepsFlag)
	if *libapp == "" {
		return fmt.Errorf("--lib is required")
	}
	if *funcVAStr == "" && !*all && !*fromMain && *findSubstr == "" {
		return fmt.Errorf("--func <hex VA>, --find <substring>, --all, or --from-main is required")
	}
	if *all && *fromMain {
		return fmt.Errorf("--all and --from-main are mutually exclusive -- pick one traversal mode")
	}
	if *filterSubstr != "" && !*all {
		return fmt.Errorf("--filter only applies to --all (it is a name-based restriction on --all's full-binary sweep, not a standalone mode); did you mean --all --filter %q, or --from-main for a name-free reachability walk?", *filterSubstr)
	}

	ctx, err := pipeline.LoadContext(*libapp)
	if err != nil {
		return err
	}
	defer func() { _ = ctx.Close() }()
	// Confident real arity needs the whole-binary call-site arg-mask pass (opt-in).
	ctx.BuildArgRegMasks()

	info := ctx.Info
	result := ctx.Result
	ranges := ctx.Ranges
	codeOff := ctx.CodeOff
	codeVA := ctx.CodeVA
	isARM64 := ctx.IsARM64
	pl := ctx.Pool
	symbolNames := ctx.SymbolNames
	symbolSizes := ctx.SymbolSizes

	symbolLookup := func(va uint64) (string, bool) {
		if n, ok := symbolNames[va]; ok && n != "" {
			return n, true
		}
		return "", false
	}
	poolLookup := func(off int) (string, bool) {
		if ctx.PoolDisplay != nil {
			if s, ok := ctx.PoolDisplay[off]; ok {
				return s, true
			}
		}
		return "", false
	}
	// One fully-enriched FuncIR builder, shared with every consumer.
	buildFuncIR := ctx.FuncIRFor

	// Reachability/pool helpers used by --from-main (not the builder).
	ctEarly := info.Version.CIDs
	classByRef := make(map[int]cluster.ClassInfo, len(result.Classes))
	for _, ci := range result.Classes {
		classByRef[ci.RefID] = ci
	}
	effectiveOwnerClassRef := func(funcObj *cluster.NamedObject) int {
		effectiveClass := funcObj.OwnerRefID
		if owner, ok := pl.RefToNamed[effectiveClass]; ok && owner.CID == ctEarly.PatchClass {
			effectiveClass = owner.OwnerRefID
		}
		return effectiveClass
	}
	poolByIndex := make(map[int]cluster.PoolEntry, len(result.Pool))
	for _, pe := range result.Pool {
		poolByIndex[pe.Index] = pe
	}


	// decompileRangeWithIR returns both the pseudocode Artifact and the
	// intermediate FuncIR -- --gen-frida needs the FuncIR to build
	// real-arity-aware hooks and indirect-call-site probes (see
	// frida_gen.go) without disassembling the same range twice.
	decompileRangeWithIR := func(r cluster.CodeRange) (*decompiler.FuncIR, decompiler.Artifact, error) {
		fir, err := buildFuncIR(r)
		if err != nil {
			return nil, decompiler.Artifact{}, err
		}
		artifact := decompiler.EmitPseudocode(fir, symbolLookup, poolLookup)
		// Item 12: CFG structural verification — compare pseudocode
		// control flow against binary CFG and log mismatches.
		verification := decompiler.VerifyCFG(fir, artifact)
		if verification.MismatchedBranches > 0 || verification.MismatchedReturns > 0 {
			artifact.Source += fmt.Sprintf("\n// CFG verification: %s\n", verification.Summary())
		}
		return fir, artifact, nil
	}

	// --- --from-main support: classify each function's owning library as
	// framework/SDK (dart:*, package:flutter*) vs. application code, so a
	// reachability walk from main() can decompile only the app's own code
	// without needing to know any class/package name in advance (unlike
	// --filter, which needs a name substring known up front). Resolution
	// chain: CodeRange.RefID (Code ref) -> Code.owner (Function ref) ->
	// Function.OwnerRefID (Class or PatchClass ref; PatchClass hops one
	// more level to wrapped_class, mirroring internal/funcdiff's owner
	// resolution) -> ClassInfo.LibraryRefID -> Library.url string.
	ct := info.Version.CIDs
	// Resolved via pipeline.ResolveCodeOwner rather than trusting
	// ce.OwnerRef directly -- Code.OwnerRef is confirmed unreliable on
	// some real snapshots (Dart 3.7.0 x86_64: ~5.4% of functions get a
	// bogus shared owner resolving to CID 61/Mint), which would
	// misclassify those functions' library (framework vs. app) here.
	byCodeIndex := naming.CodeIndexToFunc(result, ct, info.Version.CodeIndexOneBased)
	codeOwnerFunc := make(map[int]int, len(result.Codes))
	for _, ce := range result.Codes {
		if owner, ok := naming.ResolveCodeOwner(ce, pl.RefToNamed, byCodeIndex); ok {
			codeOwnerFunc[ce.RefID] = owner.RefID
		}
	}
	libraryURLForClassRef := func(classRef int) string {
		classInfo, ok := classByRef[classRef]
		if !ok || classInfo.LibraryRefID < 0 {
			return ""
		}
		libObj, ok := pl.RefToNamed[classInfo.LibraryRefID]
		if !ok {
			return ""
		}
		if url := pl.ResolveName(libObj); url != "" {
			return url
		}
		return pl.ResolveVMName(libObj)
	}
	libraryURLForCodeRef := func(codeRef int) string {
		funcRef, ok := codeOwnerFunc[codeRef]
		if !ok {
			return ""
		}
		funcObj, ok := pl.RefToNamed[funcRef]
		if !ok {
			return ""
		}
		return libraryURLForClassRef(effectiveOwnerClassRef(funcObj))
	}
	isFrameworkLibraryURL := func(url string) bool {
		return strings.HasPrefix(url, "dart:") || strings.HasPrefix(url, "package:flutter")
	}

	// --- Class-touch expansion support: a virtual/polymorphic call (e.g.
	// Flutter's Element/State dispatch calling Widget.build()/State.
	// initState()) is invisible to callTargetsOf's direct-call scan --
	// confirmed empirically this session testing --from-main against a
	// real compiled app, where main()'s reachable set from a plain
	// `runApp(const MyApp())` was just 2 functions, never reaching
	// MyApp's own build()/State methods at all. Verified against
	// dart-lang/sdk source (runtime/vm/app_snapshot.cc's
	// InstanceSerializationCluster, constructed per concrete `cid`, and
	// runtime/vm/class_table.h's ClassTable::At(cid)) that every Instance
	// object's cluster CID *is* its concrete class's ClassInfo.ClassID --
	// so when a reachable function's object pool holds a canonicalized
	// instance of an app-code class (e.g. the const MyApp() the
	// trampoline passes to runApp), that class's ClassID is directly
	// recoverable from the pool ref's cluster CID, with no dispatch
	// needed. Once a class is "touched" this way, ALL of its own methods
	// (build/initState/etc., whatever we can't reach by direct call) are
	// added to the BFS queue too -- a deliberate, documented
	// over-approximation (like class-hierarchy-analysis in other static
	// call-graph tools), not a precise proof of runtime reachability.
	classIDToClassRef := make(map[int32]int, len(result.Classes))
	for _, ci := range result.Classes {
		classIDToClassRef[ci.ClassID] = ci.RefID
	}
	functionsByOwnerClassRef := make(map[int][]uint64, len(result.Classes))
	for _, r := range ranges {
		if r.Size == 0 || r.RefID < 0 {
			continue
		}
		funcRef, ok := codeOwnerFunc[r.RefID]
		if !ok {
			continue
		}
		funcObj, ok := pl.RefToNamed[funcRef]
		if !ok {
			continue
		}
		classRef := effectiveOwnerClassRef(funcObj)
		funcStart := uint64(r.PCOffset) - codeOff
		funcVA := codeVA + funcStart
		functionsByOwnerClassRef[classRef] = append(functionsByOwnerClassRef[classRef], funcVA)
	}
	// classRefTouchedByPoolLoad resolves an OpLoadPool instruction's pool
	// index to the concrete class ref of whatever object it loads (if the
	// pool entry is a tagged ref to an Instance/canonicalized const), or
	// -1 if it doesn't resolve to a known app-code class.
	classRefTouchedByPoolLoad := func(poolIndex int) int {
		if poolIndex < 0 {
			return -1
		}
		pe, ok := poolByIndex[poolIndex]
		if !ok || pe.Kind != cluster.PoolTagged {
			return -1
		}
		cid, ok := pl.RefCID[pe.RefID]
		if !ok {
			return -1
		}
		classRef, ok := classIDToClassRef[int32(cid)] //nolint:gosec // cid is a Dart class ID, always well within int32 range
		if !ok {
			return -1
		}
		return classRef
	}

	if *findSubstr != "" {
		// Pure name lookup -- no disassembly, no CFG walk, no emitter.
		// Safe to run against a full real-world app (tens of thousands
		// of functions) without the cost/risk of --all's actual
		// decompilation of every one of them.
		hits := 0
		for va, name := range symbolNames {
			if strings.Contains(name, *findSubstr) {
				fmt.Printf("0x%x  size=%d  %s\n", va, symbolSizes[va], name)
				hits++
			}
		}
		fmt.Fprintf(os.Stderr, "%d match(es) for %q among %d functions\n", hits, *findSubstr, len(symbolNames))
		return nil
	}

	if !*all && !*fromMain {
		if *funcVAStr == "" {
			return fmt.Errorf("--func is required (hex VA of an address inside the target function)")
		}
		var targetVA uint64
		_, scanErr := fmt.Sscanf(*funcVAStr, "0x%x", &targetVA)
		if scanErr != nil || targetVA == 0 {
			if _, err := fmt.Sscanf(*funcVAStr, "%x", &targetVA); err != nil || targetVA == 0 {
				return fmt.Errorf("--func %q: not a valid hex address", *funcVAStr)
			}
		}
		// Prefer the TIGHTEST containing range, and among equally-tight
		// candidates prefer a real Code entry (RefID >= 0) over a bare
		// stub -- CodeRange sets from ResolveCodeRanges/ResolveStubRanges
		// can overlap (e.g. a stub range spanning several real Code
		// ranges), and picking merely the FIRST containing range (this
		// command's original behavior) sometimes resolved to the wrong,
		// much larger enclosing range instead of the actual function
		// starting exactly at --func's address -- found by testing this
		// exact command against real libapp.so files with known-good
		// function addresses.
		found := findRangeContainingVA(ranges, codeVA, codeOff, targetVA)
		if found == nil {
			return fmt.Errorf("no CodeRange contains VA 0x%x", targetVA)
		}
		fir, art, err := decompileRangeWithIR(*found)
		if err != nil {
			return err
		}
		fmt.Println(art.Source)
		statsData, _ := json.MarshalIndent(art.Stats, "", "  ")
		fmt.Fprintf(os.Stderr, "stats: %s\n", statsData)
		if *genFrida {
			if err := emitSingleFuncFrida(*libapp, isARM64, fir, art, targetVA, *genFridaOut,
			frida.FridaOptions{Stalker: *genFridaStalker, StalkerMinCalls: *genFridaStalkerMin}); err != nil {
				return err
			}
		}
		return nil
	}

	if *outDir == "" {
		return fmt.Errorf("--out is required with --all/--from-main")
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", *outDir, err)
	}

	// Hardening for --all against a real, repeated incident this session:
	// running --all --max N (even a few thousand) against a full real
	// Flutter app build crashed the WHOLE HOST (not a Go panic, not an
	// OOM this process's own heap stats ever showed -- MemStats stayed
	// at a flat few MiB every single time it crashed) more than once,
	// always after a few thousand functions and only a few seconds of
	// wall-clock time. Since heap never grew, this pointed away from a
	// memory bug in this process and toward a much simpler suspect: this
	// loop used to call os.WriteFile once per function, i.e. thousands
	// of small separate file-create syscalls onto a WSL2-mounted
	// filesystem in a short burst -- a known stressor for WSL2/Windows
	// Defender real-time-scanning interaction. Fixed by writing every
	// function's pseudocode into ONE buffered, append-only combined
	// file instead (bufio.Writer, explicit periodic Flush -- NOT one
	// os.Create per function). This removes the suspected root cause
	// entirely, independent of whether the exact mechanism was ever
	// fully confirmed. The other hardening below is kept as defense in
	// depth regardless:
	//   1. GOMAXPROCS capped -- this command is single-threaded logic;
	//      capping avoids the Go GC's default NumCPU-scaled worker pool
	//      contending for memory/scheduler time on a resource-constrained
	//      VM (WSL2 here, but this is a real risk on any small host).
	//   2. Explicit periodic GC + debug.FreeOSMemory() -- actively
	//      returns freed heap pages to the OS at regular intervals.
	//   3. A per-function recover() -- if decompiling one function
	//      panics for any reason (a bug we haven't found yet), that
	//      function is skipped and counted, not fatal to the batch.
	//   4. Progress heartbeat, flushed to disk periodically -- so a long
	//      run is visibly alive AND partial progress survives even if
	//      the process is later killed for an unrelated reason.
	runtime.GOMAXPROCS(2)
	debug.SetMemoryLimit(1536 << 20)

	combinedPath := filepath.Join(*outDir, "combined.dart")
	outFile, err := os.Create(combinedPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", combinedPath, err)
	}
	defer func() { _ = outFile.Close() }()
	w := bufio.NewWriterSize(outFile, 256*1024)

	const gcEveryN = 250
	startTime := time.Now()
	// Temporary diagnostic: print+flush every attempted function's VA
	// immediately BEFORE decompiling it, so if the process is killed
	// externally (not a Go panic, not a memory blowup -- both already
	// ruled out this session), the very last flushed line names the
	// exact function that was in progress at the moment of death.
	debugTrace := os.Getenv("AOTOPSY_DEBUG_TRACE") != ""

	if *fromMain {
		return runFromMain(fromMainDeps{
			ranges:                    ranges,
			codeOff:                   codeOff,
			codeVA:                    codeVA,
			symbolNames:               symbolNames,
			buildFuncIR:               buildFuncIR,
			callTargetsOf:             callTargetsOf,
			libraryURLForCodeRef:      libraryURLForCodeRef,
			libraryURLForClassRef:     libraryURLForClassRef,
			isFrameworkLibraryURL:     isFrameworkLibraryURL,
			functionsByOwnerClassRef:  functionsByOwnerClassRef,
			classRefTouchedByPoolLoad: classRefTouchedByPoolLoad,
			symbolLookup:              symbolLookup,
			poolLookup:                poolLookup,
			maxFuncs:                  *maxFuncs,
			w:                         w,
			combinedPath:              combinedPath,
			debugTrace:                debugTrace,
			gcEveryN:                  gcEveryN,
			startTime:                 startTime,
			isARM64:                   isARM64,
			genFrida:                  *genFrida,
			genFridaOut:               *genFridaOut,
			fridaOpts:                 frida.FridaOptions{Stalker: *genFridaStalker, StalkerMinCalls: *genFridaStalkerMin},
			libPath:                   *libapp,
			outDir:                    *outDir,
		})
	}

	return runDecompileLoop(decompLoopDeps{
		ranges:               ranges,
		codeOff:              codeOff,
		codeVA:               codeVA,
		symbolNames:          symbolNames,
		filterSubstr:         *filterSubstr,
		skipFuncs:            *skipFuncs,
		maxFuncs:             *maxFuncs,
		debugTrace:           debugTrace,
		decompileRangeWithIR: decompileRangeWithIR,
		w:                    w,
		combinedPath:         combinedPath,
		gcEveryN:             gcEveryN,
		startTime:            startTime,
		pl:                   pl,
		genFrida:             *genFrida,
		genFridaOut:          *genFridaOut,
		outDir:               *outDir,
		libapp:               *libapp,
		isARM64:              isARM64,
		genFridaStalker:      *genFridaStalker,
		genFridaStalkerMin:   *genFridaStalkerMin,
	})
}
