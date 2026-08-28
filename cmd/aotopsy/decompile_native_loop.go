package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/frida"
	"aotopsy/internal/naming"
)

// callTargetsOf extracts every resolved direct-call target VA from a
// FuncIR's blocks -- used by --from-main's reachability walk to
// discover callees without re-running EmitPseudocode's full
// text-emission pipeline just to find call sites.
func callTargetsOf(fir *decompiler.FuncIR) []uint64 {
	var out []uint64
	for _, blk := range fir.Blocks {
		for _, ins := range blk.Instrs {
			if ins.Op != decompiler.OpCall || ins.Target == "" {
				continue
			}
			if va, err := strconv.ParseUint(strings.TrimPrefix(ins.Target, "0x"), 16, 64); err == nil {
				out = append(out, va)
			}
		}
	}
	return out
}

// ownerRange pairs a CodeRange with its resolved owner class name,
// for sorting matched ranges by owner so methods of the same class
// are contiguous in the output (P3: class method reconstruction).
type ownerRange struct {
	r     cluster.CodeRange
	owner string
}

// classBuffer accumulates artifacts for one class so they can be
// emitted as a real `class Owner { ... }` block instead of invalid
// Dart (multiple class declarations for the same class).
type classBuffer struct {
	owner     string
	artifacts []decompiler.Artifact
}

// decompLoopDeps bundles everything runDecompileLoop needs from
// cmdDecompileNative's already-parsed snapshot/pool state, so the
// per-function decompilation loop (which has nothing to do with
// flag parsing or context loading) can live in its own file --
// mirroring fromMainDeps for --from-main.
type decompLoopDeps struct {
	ranges               []cluster.CodeRange
	codeOff, codeVA      uint64
	symbolNames          map[uint64]string
	filterSubstr         string
	skipFuncs            int
	maxFuncs             int
	debugTrace           bool
	decompileRangeWithIR func(cluster.CodeRange) (*decompiler.FuncIR, decompiler.Artifact, error)
	w                    *bufio.Writer
	combinedPath         string
	gcEveryN             int
	startTime            time.Time
	pl                   *naming.PoolLookups
	genFrida             bool
	genFridaOut          string
	outDir               string
	libapp               string
	isARM64              bool
	genFridaStalker      bool
	genFridaStalkerMin   int
}

// runDecompileLoop implements --all: iterate every matching
// CodeRange (optionally filtered by --filter), decompile each one,
// buffer per-class methods into `class Owner { ... }` blocks, emit
// standalone functions directly, and periodically GC + report
// progress. Writes one combined.dart file.
func runDecompileLoop(d decompLoopDeps) error {
	// rangeMatchesFilter applies --filter (if set) on top of the base
	// Size!=0/RefID>=0 eligibility check, so a filtered run's
	// --skip/--max counts and "N total matching functions" figure are
	// ALL computed against the SAME (filtered) set -- default (no
	// --filter) still covers the full framework, unchanged; --filter
	// is purely additive.
	rangeMatchesFilter := func(r cluster.CodeRange) bool {
		if r.Size == 0 || r.RefID < 0 {
			return false
		}
		if d.filterSubstr == "" {
			return true
		}
		funcStart := uint64(r.PCOffset) - d.codeOff
		funcVA := d.codeVA + funcStart
		return strings.Contains(d.symbolNames[funcVA], d.filterSubstr)
	}

	totalMatching := 0
	for _, r := range d.ranges {
		if rangeMatchesFilter(r) {
			totalMatching++
		}
	}
	if d.skipFuncs >= totalMatching {
		fmt.Fprintf(os.Stderr, "--skip %d >= %d total matching functions -- nothing to do, this shard is past the end\n", d.skipFuncs, totalMatching)
		return nil
	}

	matched := 0
	// P3: Class method reconstruction — sort matched ranges by owner name
	// so methods of the same class are contiguous, then emit real
	// `class Owner { ... }` syntax. This avoids invalid Dart (multiple
	// class declarations for the same class).
	var matchedRanges []ownerRange
	for _, r := range d.ranges {
		if !rangeMatchesFilter(r) {
			continue
		}
		owner := ""
		if r.RefID >= 0 {
			if ci, ok := d.pl.CodeNames[r.RefID]; ok && ci.OwnerName != "" {
				owner = ci.OwnerName
			}
		}
		matchedRanges = append(matchedRanges, ownerRange{r: r, owner: owner})
	}
	sort.SliceStable(matchedRanges, func(i, j int) bool {
		return matchedRanges[i].owner < matchedRanges[j].owner
	})

	var curClass *classBuffer
	flushClass := func() {
		if curClass == nil || len(curClass.artifacts) == 0 {
			curClass = nil
			return
		}
		_, _ = fmt.Fprintf(d.w, "class %s {\n", curClass.owner)
		for _, art := range curClass.artifacts {
			body := strings.ReplaceAll(art.Source, "\n", "\n  ")
			_, _ = fmt.Fprintf(d.w, "  // === %s ===\n  %s\n\n", art.FunctionName, body)
		}
		_, _ = fmt.Fprintf(d.w, "}\n\n")
		curClass = nil
	}

	emitted := 0
	skipped := 0
	var agg decompiler.Stats
	var fridaHooks []frida.FridaHook
	var fridaProbes []frida.FridaProbe
	fridaProbesDropped := 0

	for _, mr := range matchedRanges {
		r := mr.r
		matched++
		if matched <= d.skipFuncs {
			continue // this shard's --skip window hasn't started yet
		}
		if d.maxFuncs > 0 && emitted >= d.maxFuncs {
			break
		}

		if d.debugTrace {
			funcStart := uint64(r.PCOffset) - d.codeOff
			funcVA := d.codeVA + funcStart
			fmt.Fprintf(os.Stderr, "trace: about to decompile 0x%x size=%d %s\n", funcVA, r.Size, d.symbolNames[funcVA])
		}

		func() {
			defer func() {
				if rec := recover(); rec != nil {
					skipped++
					fmt.Fprintf(os.Stderr, "warning: recovered panic decompiling range (PCOffset=0x%x): %v\n", r.PCOffset, rec)
				}
			}()

			fir, art, err := d.decompileRangeWithIR(r)
			if err != nil {
				skipped++
				return
			}
			// P3: Class method reconstruction — buffer per class, emit
			// real `class Owner { ... }` when owner changes.
			ownerName := mr.owner
			if ownerName != "" {
				// Function belongs to a class — buffer it.
				if curClass == nil || curClass.owner != ownerName {
					flushClass()
					curClass = &classBuffer{owner: ownerName}
				}
				curClass.artifacts = append(curClass.artifacts, art)
			} else {
				// Standalone function (stub, top-level) — flush any open
				// class, then emit directly.
				flushClass()
				_, _ = fmt.Fprintf(d.w, "// === %s (PCOffset=0x%x) ===\n%s\n\n", art.FunctionName, r.PCOffset, art.Source)
			}
			aggregateStats(&agg, art.Stats)
			emitted++
			if d.genFrida {
				funcStart := uint64(r.PCOffset) - d.codeOff
				fridaHooks = append(fridaHooks, frida.FridaHook{VA: d.codeVA + funcStart, Name: art.FunctionName, ArgRegs: frida.RealArgRegs(fir)})
				for _, p := range frida.CollectIndirectCallProbes(fir) {
					if len(fridaProbes) >= frida.MaxFridaProbes {
						fridaProbesDropped++
						continue
					}
					fridaProbes = append(fridaProbes, p)
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
			fmt.Fprintf(os.Stderr, "progress: %d emitted, %d skipped, heap=%dMiB, elapsed=%s\n",
				emitted, skipped, m.HeapAlloc/1024/1024, time.Since(d.startTime).Round(time.Second))
		}
	}
	// P3: flush last class buffer.
	flushClass()
	if err := d.w.Flush(); err != nil {
		return fmt.Errorf("final flush %s: %w", d.combinedPath, err)
	}
	fmt.Fprintf(os.Stderr, "emitted %d functions (skipped %d) to %s in %s -- shard covered matched-index [%d, %d) of %d total matching functions in this binary\n",
		emitted, skipped, d.combinedPath, time.Since(d.startTime).Round(time.Second), d.skipFuncs, d.skipFuncs+emitted+skipped, totalMatching)
	printAggregateStats(agg)
	if d.genFrida {
		if err := finalizeFridaOutput(d.genFridaOut, d.outDir, d.libapp, d.isARM64, fridaHooks, fridaProbes, fridaProbesDropped,
			frida.FridaOptions{Stalker: d.genFridaStalker, StalkerMinCalls: d.genFridaStalkerMin}); err != nil {
			return err
		}
	}
	return nil
}
