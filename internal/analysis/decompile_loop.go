package analysis

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/frida"
	"aotopsy/internal/naming"
)

// OwnerRange pairs a CodeRange with its resolved owner class name,
// for sorting matched ranges by owner so methods of the same class
// are contiguous in the output.
type OwnerRange struct {
	R     cluster.CodeRange
	Owner string
}

// ClassBuffer accumulates artifacts for one class so they can be
// emitted as a real `class Owner { ... }` block.
type ClassBuffer struct {
	Owner     string
	Artifacts []decompiler.Artifact
}

// DecompLoopDeps bundles everything RunDecompileLoop needs from
// the already-parsed snapshot/pool state.
type DecompLoopDeps struct {
	Ranges               []cluster.CodeRange
	CodeOff, CodeVA      uint64
	SymbolNames          map[uint64]string
	FilterSubstr         string
	SkipFuncs            int
	MaxFuncs             int
	DebugTrace           bool
	DecompileRangeWithIR func(cluster.CodeRange) (*decompiler.FuncIR, decompiler.Artifact, error)
	W                    *bufio.Writer
	CombinedPath         string
	GcEveryN             int
	StartTime            time.Time
	Pl                   *naming.PoolLookups
	GenFrida             bool
	GenFridaOut          string
	OutDir               string
	Libapp               string
	IsARM64              bool
	GenFridaStalker      bool
	GenFridaStalkerMin   int
}

// RunDecompileLoop implements --all: iterate every matching
// CodeRange (optionally filtered by --filter), decompile each one,
// buffer per-class methods into `class Owner { ... }` blocks, emit
// standalone functions directly, and periodically GC + report
// progress. Writes one combined.dart file.
func RunDecompileLoop(d DecompLoopDeps) error {
	if d.GcEveryN <= 0 {
		d.GcEveryN = 100
	}
	im := cluster.CodeImage{CodeVA: d.CodeVA, CodeOff: d.CodeOff}
	rangeMatchesFilter := func(r cluster.CodeRange) bool {
		if r.RefID < 0 {
			return false
		}
		funcVA, ok := im.FuncVA(r)
		if !ok {
			return false
		}
		if d.FilterSubstr == "" {
			return true
		}
		return strings.Contains(d.SymbolNames[funcVA], d.FilterSubstr)
	}

	totalMatching := 0
	for _, r := range d.Ranges {
		if rangeMatchesFilter(r) {
			totalMatching++
		}
	}
	if d.SkipFuncs >= totalMatching {
		fmt.Fprintf(os.Stderr, "--skip %d >= %d total matching functions -- nothing to do, this shard is past the end\n", d.SkipFuncs, totalMatching)
		return nil
	}

	matched := 0
	var matchedRanges []OwnerRange
	for _, r := range d.Ranges {
		if !rangeMatchesFilter(r) {
			continue
		}
		owner := ""
		if r.RefID >= 0 {
			if ci, ok := d.Pl.CodeNames[r.RefID]; ok && ci.OwnerName != "" {
				owner = ci.OwnerName
			}
		}
		matchedRanges = append(matchedRanges, OwnerRange{R: r, Owner: owner})
	}
	sort.SliceStable(matchedRanges, func(i, j int) bool {
		return matchedRanges[i].Owner < matchedRanges[j].Owner
	})

	var curClass *ClassBuffer
	flushClass := func() {
		if curClass == nil || len(curClass.Artifacts) == 0 {
			curClass = nil
			return
		}
		_, _ = fmt.Fprintf(d.W, "class %s {\n", curClass.Owner)
		for _, art := range curClass.Artifacts {
			body := strings.ReplaceAll(art.Source, "\n", "\n  ")
			_, _ = fmt.Fprintf(d.W, "  // === %s ===\n  %s\n\n", art.FunctionName, body)
		}
		_, _ = fmt.Fprintf(d.W, "}\n\n")
		curClass = nil
	}

	emitted := 0
	skipped := 0
	var agg decompiler.Stats
	var fridaHooks []frida.FridaHook
	var fridaProbes []frida.FridaProbe
	fridaProbesDropped := 0

	for _, mr := range matchedRanges {
		r := mr.R
		matched++
		if matched <= d.SkipFuncs {
			continue
		}
		if d.MaxFuncs > 0 && emitted >= d.MaxFuncs {
			break
		}

		if d.DebugTrace {
			if funcVA, ok := im.FuncVA(r); ok {
				fmt.Fprintf(os.Stderr, "trace: about to decompile 0x%x size=%d %s\n", funcVA, r.Size, d.SymbolNames[funcVA])
			}
		}

		func() {
			defer func() {
				if rec := recover(); rec != nil {
					skipped++
					fmt.Fprintf(os.Stderr, "warning: recovered panic decompiling range (PCOffset=0x%x): %v\n", r.PCOffset, rec)
				}
			}()

			fir, art, err := d.DecompileRangeWithIR(r)
			if err != nil {
				skipped++
				return
			}
			ownerName := mr.Owner
			if ownerName != "" {
				if curClass == nil || curClass.Owner != ownerName {
					flushClass()
					curClass = &ClassBuffer{Owner: ownerName}
				}
				curClass.Artifacts = append(curClass.Artifacts, art)
			} else {
				flushClass()
				_, _ = fmt.Fprintf(d.W, "// === %s (PCOffset=0x%x) ===\n%s\n\n", art.FunctionName, r.PCOffset, art.Source)
			}
			AggregateStats(&agg, art.Stats)
			emitted++
			if d.GenFrida {
				// Probe collection stays outside the address check: a hook
				// needs a VA, an indirect-call probe does not, and gating
				// both on the address would drop probes for a function
				// whose range merely failed to place.
				if funcVA, ok := im.FuncVA(r); ok {
					fridaHooks = append(fridaHooks, frida.FridaHook{VA: funcVA, Name: art.FunctionName, ArgRegs: frida.RealArgRegs(fir)})
				}
				for _, p := range frida.CollectIndirectCallProbes(fir) {
					if len(fridaProbes) >= frida.MaxFridaProbes {
						fridaProbesDropped++
						continue
					}
					fridaProbes = append(fridaProbes, p)
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
			fmt.Fprintf(os.Stderr, "progress: %d emitted, %d skipped, heap=%dMiB, elapsed=%s\n",
				emitted, skipped, m.HeapAlloc/1024/1024, time.Since(d.StartTime).Round(time.Second))
		}
	}
	flushClass()
	if err := d.W.Flush(); err != nil {
		return fmt.Errorf("final flush %s: %w", d.CombinedPath, err)
	}
	fmt.Fprintf(os.Stderr, "emitted %d functions (skipped %d) to %s in %s -- shard covered matched-index [%d, %d) of %d total matching functions in this binary\n",
		emitted, skipped, d.CombinedPath, time.Since(d.StartTime).Round(time.Second), d.SkipFuncs, d.SkipFuncs+emitted+skipped, totalMatching)
	PrintAggregateStats(agg)
	if d.GenFrida {
		if err := FinalizeFridaOutput(d.GenFridaOut, d.OutDir, d.Libapp, d.IsARM64, fridaHooks, fridaProbes, fridaProbesDropped,
			frida.FridaOptions{Stalker: d.GenFridaStalker, StalkerMinCalls: d.GenFridaStalkerMin}); err != nil {
			return err
		}
	}
	return nil
}
