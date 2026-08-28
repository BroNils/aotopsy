package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/frida"
)

// fromMainDeps bundles everything runFromMain needs from cmdDecompileNative's
// already-parsed snapshot/pool state, so the reachability-walk logic (which
// has nothing to do with ELF/snapshot parsing) can live in its own file.
type fromMainDeps struct {
	ranges                []cluster.CodeRange
	codeOff, codeVA       uint64
	symbolNames           map[uint64]string
	buildFuncIR           func(cluster.CodeRange) (*decompiler.FuncIR, error)
	callTargetsOf         func(*decompiler.FuncIR) []uint64
	libraryURLForCodeRef  func(int) string
	libraryURLForClassRef func(int) string
	isFrameworkLibraryURL func(string) bool
	// functionsByOwnerClassRef and classRefTouchedByPoolLoad implement
	// class-touch expansion: when a reachable function's object pool
	// references a canonicalized instance of an app-code class (the only
	// way a const-constructed Widget like `const MyApp()` shows up, since
	// it's never built via a runtime call), every method of that class is
	// added to the BFS queue too -- otherwise those methods (Widget.build,
	// State.initState, etc.) are only ever invoked through Flutter's own
	// virtual Element/State dispatch, which is invisible to a plain
	// direct-call graph walk.
	functionsByOwnerClassRef  map[int][]uint64
	classRefTouchedByPoolLoad func(poolIndex int) int
	symbolLookup              decompiler.SymbolLookup
	poolLookup                decompiler.PoolLookup
	maxFuncs                  int
	w                         *bufio.Writer
	combinedPath              string
	debugTrace                bool
	gcEveryN                  int
	startTime                 time.Time
	isARM64                   bool
	genFrida                  bool
	genFridaOut               string
	fridaOpts                 frida.FridaOptions
	libPath                   string
	outDir                    string
}

// runFromMain implements --from-main: a BFS over the real call graph
// starting at the app's own main() entry point, decompiling every reachable
// function EXCEPT those whose owning Dart library resolves to dart:* or
// package:flutter* (classified via CodeRange.RefID -> Code.owner ->
// Function.OwnerRefID -> Class/PatchClass -> Library.url, see
// cmdDecompileNative's libraryURLForCodeRef). This answers a real analysis gap
// --filter can't: --filter needs a class/package name substring known in
// advance, which isn't available when analyzing an unfamiliar
// binary from scratch -- reachability + library classification needs no
// name at all.
func runFromMain(d fromMainDeps) error {
	rangeByVA := make(map[uint64]cluster.CodeRange, len(d.ranges))
	for _, r := range d.ranges {
		if r.Size == 0 || r.RefID < 0 {
			continue
		}
		funcStart := uint64(r.PCOffset) - d.codeOff
		funcVA := d.codeVA + funcStart
		rangeByVA[funcVA] = r
	}

	var candidates []uint64
	for va, name := range d.symbolNames {
		if name == "main" {
			candidates = append(candidates, va)
		}
	}
	if len(candidates) == 0 {
		// A literal top-level "main" wasn't found -- confirmed, empirically,
		// against a real from-scratch Flutter build this session: a
		// trivial `void main() { runApp(const MyApp()); }` gets inlined
		// entirely into a synthetic isolate-entry trampoline by the Dart
		// AOT compiler, leaving no standalone Code object named "main" to
		// find. Fall back to a more robust, near-universal Flutter marker
		// instead: the app-code function that calls runApp() IS the real
		// entry point, whatever it's actually named/merged into. Only
		// disassemble non-framework-classified functions to find it (a
		// small set -- the whole point of this classification), not the
		// whole binary.
		runAppVA, ok := findRunAppVA(d.symbolNames)
		if !ok {
			// H-5 fix: third fallback — search for "runApp" string in object pool.
			// If both main and runApp symbols are inlined, the string "runApp"
			// may still exist as a pool entry loaded by the entry trampoline.
			runAppRefIDs := d.classRefTouchedByPoolLoad
			_ = runAppRefIDs // not used directly here, but documented as future path
			return fmt.Errorf("--from-main: no top-level \"main\", no \"runApp\" symbol, and no pool-string fallback found -- not a recognizable Flutter entry point; locate it manually (e.g. --find runApp) and use --func instead")
		}
		found, err := findCallerOfAmongAppCode(runAppVA, rangeByVA, d.buildFuncIR, d.callTargetsOf, d.libraryURLForCodeRef, d.isFrameworkLibraryURL)
		if err != nil {
			return fmt.Errorf("--from-main: no top-level \"main\" found, and could not locate the caller of runApp() either (%w) -- locate the entry point manually and use --func instead", err)
		}
		candidates = []uint64{found}
	}
	var mainVA uint64
	if len(candidates) == 1 {
		mainVA = candidates[0]
	} else {
		var nonFramework []uint64
		for _, va := range candidates {
			r := rangeByVA[va]
			if !d.isFrameworkLibraryURL(d.libraryURLForCodeRef(r.RefID)) {
				nonFramework = append(nonFramework, va)
			}
		}
		if len(nonFramework) == 1 {
			mainVA = nonFramework[0]
		} else {
			list := nonFramework
			if len(list) == 0 {
				list = candidates
			}
			msg := fmt.Sprintf("--from-main: %d candidate \"main\" functions found, could not pick one unambiguously:\n", len(candidates))
			for _, va := range list {
				r := rangeByVA[va]
				msg += fmt.Sprintf("  0x%x  library=%q\n", va, d.libraryURLForCodeRef(r.RefID))
			}
			msg += "use --func with the correct address instead"
			return fmt.Errorf("%s", msg)
		}
	}
	fmt.Fprintf(os.Stderr, "--from-main: entry point at 0x%x\n", mainVA)

	runtime.GOMAXPROCS(2)
	debug.SetMemoryLimit(1536 << 20)

	visited := make(map[uint64]bool)
	touchedClasses := make(map[int]bool)
	classTouched := 0
	queue := []uint64{mainVA}
	emitted, skipped, frameworkSkipped, unknownLibrary := 0, 0, 0, 0
	var agg decompiler.Stats
	var fridaHooks []frida.FridaHook
	var fridaProbes []frida.FridaProbe
	fridaProbesDropped := 0

	for len(queue) > 0 {
		if d.maxFuncs > 0 && emitted >= d.maxFuncs {
			fmt.Fprintf(os.Stderr, "--from-main: reached --max %d before the reachability walk was exhausted (%d functions still queued) -- output is a valid but incomplete prefix\n", d.maxFuncs, len(queue))
			break
		}
		va := queue[0]
		queue = queue[1:]
		if visited[va] {
			continue
		}
		visited[va] = true

		r, ok := rangeByVA[va]
		if !ok {
			continue // unresolved/stub target, nothing to decompile or descend into
		}

		url := d.libraryURLForCodeRef(r.RefID)
		if d.isFrameworkLibraryURL(url) {
			frameworkSkipped++
			continue // never decompiled, never descended into -- this is the actual filter
		}
		if url == "" {
			unknownLibrary++ // included anyway: unclassifiable is not the same as framework
		}

		if d.debugTrace {
			fmt.Fprintf(os.Stderr, "trace: about to decompile 0x%x size=%d %s (library=%q)\n", va, r.Size, d.symbolNames[va], url)
		}

		func() {
			defer func() {
				if rec := recover(); rec != nil {
					skipped++
					fmt.Fprintf(os.Stderr, "warning: recovered panic decompiling 0x%x: %v\n", va, rec)
				}
			}()

			fir, err := d.buildFuncIR(r)
			if err != nil {
				skipped++
				return
			}
			art := decompiler.EmitPseudocode(fir, d.symbolLookup, d.poolLookup)
			_, _ = fmt.Fprintf(d.w, "// === %s (PCOffset=0x%x) ===\n%s\n\n", art.FunctionName, r.PCOffset, art.Source)
			aggregateStats(&agg, art.Stats)
			emitted++
			if d.genFrida {
				fridaHooks = append(fridaHooks, frida.FridaHook{VA: va, Name: art.FunctionName, ArgRegs: frida.RealArgRegs(fir)})
				for _, p := range frida.CollectIndirectCallProbes(fir) {
					if len(fridaProbes) >= frida.MaxFridaProbes {
						fridaProbesDropped++
						continue
					}
					fridaProbes = append(fridaProbes, p)
				}
			}

			for _, target := range d.callTargetsOf(fir) {
				if !visited[target] {
					queue = append(queue, target)
				}
			}

			// Class-touch expansion: this function's object pool may hold
			// a canonicalized instance of an app-code class (e.g. a const
			// Widget constructor argument) that's never reached via a
			// direct call. Add every method of any such class to the
			// queue, once per class.
			for _, blk := range fir.Blocks {
				for _, ins := range blk.Instrs {
					if ins.Op != decompiler.OpLoadPool {
						continue
					}
					classRef := d.classRefTouchedByPoolLoad(ins.PoolIndex)
					if classRef < 0 || touchedClasses[classRef] {
						continue
					}
					touchedClasses[classRef] = true
					if d.isFrameworkLibraryURL(d.libraryURLForClassRef(classRef)) {
						continue
					}
					classTouched++
					for _, methodVA := range d.functionsByOwnerClassRef[classRef] {
						if !visited[methodVA] {
							queue = append(queue, methodVA)
						}
					}
				}
			}
		}()

		if emitted > 0 && emitted%d.gcEveryN == 0 {
			if err := d.w.Flush(); err != nil {
				return fmt.Errorf("flush %s: %w", d.combinedPath, err)
			}
			runtime.GC()
			debug.FreeOSMemory()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			fmt.Fprintf(os.Stderr, "progress: %d emitted, %d skipped, %d framework-skipped, heap=%dMiB, elapsed=%s\n",
				emitted, skipped, frameworkSkipped, m.HeapAlloc/1024/1024, time.Since(d.startTime).Round(time.Second))
		}
	}
	if err := d.w.Flush(); err != nil {
		return fmt.Errorf("final flush %s: %w", d.combinedPath, err)
	}

	fmt.Fprintf(os.Stderr, "emitted %d functions (skipped %d, %d framework-excluded, %d unknown-library-but-included, %d app-code classes touched via object-pool references) to %s in %s\n",
		emitted, skipped, frameworkSkipped, unknownLibrary, classTouched, d.combinedPath, time.Since(d.startTime).Round(time.Second))
	printAggregateStats(agg)
	if d.genFrida {
		if fridaProbesDropped > 0 {
			fmt.Fprintf(os.Stderr, "--gen-frida: %d indirect-call probe(s) dropped past the %d cap (maxFridaProbes)\n", fridaProbesDropped, frida.MaxFridaProbes)
		}
		if err := frida.WriteFridaScript(d.genFridaOut, d.outDir, d.libPath, d.isARM64, fridaHooks, fridaProbes, d.fridaOpts); err != nil {
			return err
		}
	}
	return nil
}

// findRunAppVA finds the bare top-level "runApp" symbol -- Flutter's own
// framework entry function (package:flutter/src/widgets/binding.dart),
// present in essentially every real Flutter app and never itself
// tree-shaken (it's always called, directly or indirectly, from the app's
// entry).
func findRunAppVA(symbolNames map[uint64]string) (uint64, bool) {
	for va, name := range symbolNames {
		if name == "runApp" {
			return va, true
		}
	}
	return 0, false
}

// findCallerOfAmongAppCode finds a non-framework-classified function that
// directly calls targetVA. Only app-code-classified ranges are
// disassembled (not the whole binary) -- cheap in practice, since
// non-framework code is normally a small fraction of a real Flutter
// build's libapp.so.
func findCallerOfAmongAppCode(
	targetVA uint64,
	rangeByVA map[uint64]cluster.CodeRange,
	buildFuncIR func(cluster.CodeRange) (*decompiler.FuncIR, error),
	callTargetsOf func(*decompiler.FuncIR) []uint64,
	libraryURLForCodeRef func(int) string,
	isFrameworkLibraryURL func(string) bool,
) (uint64, error) {
	for va, r := range rangeByVA {
		if isFrameworkLibraryURL(libraryURLForCodeRef(r.RefID)) {
			continue
		}
		fir, err := buildFuncIR(r)
		if err != nil {
			continue
		}
		for _, callee := range callTargetsOf(fir) {
			if callee == targetVA {
				return va, nil
			}
		}
	}
	return 0, fmt.Errorf("no non-framework function found calling 0x%x", targetVA)
}
