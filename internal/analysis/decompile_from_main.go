package analysis

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

// FromMainDeps bundles everything RunFromMain needs from the
// already-parsed snapshot/pool state.
type FromMainDeps struct {
	Ranges                    []cluster.CodeRange
	CodeOff, CodeVA           uint64
	SymbolNames               map[uint64]string
	BuildFuncIR               func(cluster.CodeRange) (*decompiler.FuncIR, error)
	CallTargetsOf             func(*decompiler.FuncIR) []uint64
	LibraryURLForCodeRef      func(int) string
	LibraryURLForClassRef     func(int) string
	IsFrameworkLibraryURL     func(string) bool
	FunctionsByOwnerClassRef  map[int][]uint64
	ClassRefTouchedByPoolLoad func(poolIndex int) int
	SymbolLookup              decompiler.SymbolLookup
	PoolLookup                decompiler.PoolLookup
	MaxFuncs                  int
	W                         *bufio.Writer
	CombinedPath              string
	DebugTrace                bool
	GcEveryN                  int
	StartTime                 time.Time
	IsARM64                   bool
	GenFrida                  bool
	GenFridaOut               string
	FridaOpts                 frida.FridaOptions
	LibPath                   string
	OutDir                    string
}

// RunFromMain implements --from-main: a BFS over the real call graph
// starting at the app's own main() entry point, decompiling every reachable
// function EXCEPT those whose owning Dart library resolves to dart:* or
// package:flutter*.
func RunFromMain(d FromMainDeps) error {
	if d.GcEveryN <= 0 {
		d.GcEveryN = 100
	}
	rangeByVA := make(map[uint64]cluster.CodeRange, len(d.Ranges))
	for _, r := range d.Ranges {
		if r.Size == 0 || r.RefID < 0 {
			continue
		}
		funcStart := uint64(r.PCOffset) - d.CodeOff
		funcVA := d.CodeVA + funcStart
		rangeByVA[funcVA] = r
	}

	var candidates []uint64
	for va, name := range d.SymbolNames {
		if name == "main" {
			candidates = append(candidates, va)
		}
	}
	if len(candidates) == 0 {
		runAppVA, ok := FindRunAppVA(d.SymbolNames)
		if !ok {
			return fmt.Errorf("--from-main: no top-level \"main\", no \"runApp\" symbol, and no pool-string fallback found -- not a recognizable Flutter entry point; locate it manually (e.g. --find runApp) and use --func instead")
		}
		found, err := FindCallerOfAmongAppCode(runAppVA, rangeByVA, d.BuildFuncIR, d.CallTargetsOf, d.LibraryURLForCodeRef, d.IsFrameworkLibraryURL)
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
			if !d.IsFrameworkLibraryURL(d.LibraryURLForCodeRef(r.RefID)) {
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
				msg += fmt.Sprintf("  0x%x  library=%q\n", va, d.LibraryURLForCodeRef(r.RefID))
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
		if d.MaxFuncs > 0 && emitted >= d.MaxFuncs {
			fmt.Fprintf(os.Stderr, "--from-main: reached --max %d before the reachability walk was exhausted (%d functions still queued) -- output is a valid but incomplete prefix\n", d.MaxFuncs, len(queue))
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
			continue
		}

		url := d.LibraryURLForCodeRef(r.RefID)
		if d.IsFrameworkLibraryURL(url) {
			frameworkSkipped++
			continue
		}
		if url == "" {
			unknownLibrary++
		}

		if d.DebugTrace {
			fmt.Fprintf(os.Stderr, "trace: about to decompile 0x%x size=%d %s (library=%q)\n", va, r.Size, d.SymbolNames[va], url)
		}

		func() {
			defer func() {
				if rec := recover(); rec != nil {
					skipped++
					fmt.Fprintf(os.Stderr, "warning: recovered panic decompiling 0x%x: %v\n", va, rec)
				}
			}()

			fir, err := d.BuildFuncIR(r)
			if err != nil {
				skipped++
				return
			}
			art := decompiler.EmitPseudocode(fir, d.SymbolLookup, d.PoolLookup)
			_, _ = fmt.Fprintf(d.W, "// === %s (PCOffset=0x%x) ===\n%s\n\n", art.FunctionName, r.PCOffset, art.Source)
			AggregateStats(&agg, art.Stats)
			emitted++
			if d.GenFrida {
				fridaHooks = append(fridaHooks, frida.FridaHook{VA: va, Name: art.FunctionName, ArgRegs: frida.RealArgRegs(fir)})
				for _, p := range frida.CollectIndirectCallProbes(fir) {
					if len(fridaProbes) >= frida.MaxFridaProbes {
						fridaProbesDropped++
						continue
					}
					fridaProbes = append(fridaProbes, p)
				}
			}

			for _, target := range d.CallTargetsOf(fir) {
				if !visited[target] {
					queue = append(queue, target)
				}
			}

			for _, blk := range fir.Blocks {
				for _, ins := range blk.Instrs {
					if ins.Op != decompiler.OpLoadPool {
						continue
					}
					classRef := d.ClassRefTouchedByPoolLoad(ins.PoolIndex)
					if classRef < 0 || touchedClasses[classRef] {
						continue
					}
					touchedClasses[classRef] = true
					if d.IsFrameworkLibraryURL(d.LibraryURLForClassRef(classRef)) {
						continue
					}
					classTouched++
					for _, methodVA := range d.FunctionsByOwnerClassRef[classRef] {
						if !visited[methodVA] {
							queue = append(queue, methodVA)
						}
					}
				}
			}
		}()

		if emitted > 0 && d.GcEveryN > 0 && emitted%d.GcEveryN == 0 {
			if err := d.W.Flush(); err != nil {
				return fmt.Errorf("flush %s: %w", d.CombinedPath, err)
			}
			runtime.GC()
			debug.FreeOSMemory()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			fmt.Fprintf(os.Stderr, "progress: %d emitted, %d skipped, %d framework-skipped, heap=%dMiB, elapsed=%s\n",
				emitted, skipped, frameworkSkipped, m.HeapAlloc/1024/1024, time.Since(d.StartTime).Round(time.Second))
		}
	}
	if err := d.W.Flush(); err != nil {
		return fmt.Errorf("final flush %s: %w", d.CombinedPath, err)
	}

	fmt.Fprintf(os.Stderr, "emitted %d functions (skipped %d, %d framework-excluded, %d unknown-library-but-included, %d app-code classes touched via object-pool references) to %s in %s\n",
		emitted, skipped, frameworkSkipped, unknownLibrary, classTouched, d.CombinedPath, time.Since(d.StartTime).Round(time.Second))
	PrintAggregateStats(agg)
	if d.GenFrida {
		if fridaProbesDropped > 0 {
			fmt.Fprintf(os.Stderr, "--gen-frida: %d indirect-call probe(s) dropped past the %d cap (maxFridaProbes)\n", fridaProbesDropped, frida.MaxFridaProbes)
		}
		if err := frida.WriteFridaScript(d.GenFridaOut, d.OutDir, d.LibPath, d.IsARM64, fridaHooks, fridaProbes, d.FridaOpts); err != nil {
			return err
		}
	}
	return nil
}

// FindRunAppVA finds the bare top-level "runApp" symbol.
func FindRunAppVA(symbolNames map[uint64]string) (uint64, bool) {
	for va, name := range symbolNames {
		if name == "runApp" {
			return va, true
		}
	}
	return 0, false
}

// FindCallerOfAmongAppCode finds a non-framework-classified function that
// directly calls targetVA.
func FindCallerOfAmongAppCode(
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
