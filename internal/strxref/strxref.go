// Package strxref finds which Dart functions load a given object-pool
// slot -- i.e., cross-references a string (or any pool-resolvable
// value) back to every function that actually references it, closing
// the gap that a plain string dump can't answer: "this string exists
// somewhere in the snapshot, but WHERE is it actually used?"
package strxref

import (
	"runtime"
	"runtime/debug"
	"strings"

	"aotopsy/internal/analysis"
	"aotopsy/internal/decompiler"
)

// Reference is one function that loads one of the target pool indices.
type Reference struct {
	FuncName  string // resolved function name
	FuncVA    uint64 // function's start VA
	InstrAddr uint64 // exact address of the pool-load instruction
	PoolIndex int    // which pool slot it loaded
}

// Options bounds FindPoolReferences' cost.
//
// Defaults to a FULL, unbounded scan -- deliberately different from
// internal/ffitrace's safety-first default. Measured directly (not
// assumed) against a production Dart sample libapp.so (129,000
// functions, the largest real sample available): a full FuncIR-only
// scan (this package never calls EmitPseudocode, the expensive
// operation that actually caused internal/ffitrace's 5.4GB-RSS
// incident) completed in 9.3 seconds with memory completely flat
// throughout. FuncIR construction alone -- disassembly + IR lifting,
// no pseudocode text emission/naming/compaction -- is a fundamentally
// cheaper operation, confirmed empirically at real scale, not just by
// removing the expensive detector and hoping. Set MaxScan if you want
// to narrow a run anyway (e.g. a quick partial check, or a future app
// dramatically larger than anything tested here).
type Options struct {
	// MaxScan caps how many functions are scanned. 0 (the default)
	// means scan every function -- see the type doc comment for the
	// empirical justification.
	MaxScan int
	// Filter restricts scanning to functions whose resolved name
	// contains this substring.
	Filter string
}

// FindPoolReferences scans functions for OpLoadPool instructions whose
// PoolIndex is in poolIndices, bounded per Options (unbounded by
// default -- see Options' doc comment). Returns the matches and how
// many functions were actually scanned.
func FindPoolReferences(ctx *analysis.AnalysisContext, poolIndices []int, opts Options) ([]Reference, int) {
	target := make(map[int]bool, len(poolIndices))
	for _, idx := range poolIndices {
		target[idx] = true
	}

	// L-8 fix: save and restore process-wide settings instead of
	// permanently overriding them. These are global state that affects
	// all goroutines, so callers shouldn't be surprised by side effects.
	oldProcs := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(oldProcs)
	oldLimit := debug.SetMemoryLimit(1536 << 20)
	defer debug.SetMemoryLimit(oldLimit)

	var refs []Reference
	scanned := 0
	for _, r := range ctx.Ranges {
		if opts.MaxScan > 0 && scanned >= opts.MaxScan {
			break
		}
		if r.Size == 0 || r.RefID < 0 {
			continue
		}
		fir, err := ctx.FuncIRFor(r)
		if err != nil {
			continue
		}
		if opts.Filter != "" && !strings.Contains(fir.Name, opts.Filter) {
			continue
		}
		funcStart := uint64(r.PCOffset) - ctx.CodeOff
		funcVA := ctx.CodeVA + funcStart
		scanned++

		for _, blk := range fir.Blocks {
			for _, ins := range blk.Instrs {
				if ins.Op == decompiler.OpLoadPool && target[ins.PoolIndex] {
					refs = append(refs, Reference{
						FuncName:  fir.Name,
						FuncVA:    funcVA,
						InstrAddr: ins.Addr,
						PoolIndex: ins.PoolIndex,
					})
				}
			}
		}
		if scanned%500 == 0 {
			runtime.GC()
			debug.FreeOSMemory()
		}
	}
	return refs, scanned
}
