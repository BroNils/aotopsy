// Package strxref finds which Dart functions load a given object-pool
// slot -- i.e., cross-references a string (or any pool-resolvable
// value) back to every function that actually references it, closing
// the gap that a plain string dump can't answer: "this string exists
// somewhere in the snapshot, but WHERE is it actually used?"
package strxref

import (
	"aotopsy/internal/analysis"
	"aotopsy/internal/decompiler"
)

// Reference is one function that loads one of the target pool indices.
type Reference struct {
	FuncName  string `json:"func_name"`
	FuncVA    uint64 `json:"func_va"`
	InstrAddr uint64 `json:"instr_addr"`
	PoolIndex int    `json:"pool_index"`
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

	var refs []Reference
	scanOpts := analysis.ScanOptions{
		MaxScan:        opts.MaxScan,
		AllowUnbounded: opts.MaxScan == 0, // strxref is unbounded by default when MaxScan == 0
		Filter:         opts.Filter,
		GcEveryN:       500,
	}

	scanned := ctx.ScanFuncs(scanOpts, func(fir *decompiler.FuncIR, funcVA uint64) {
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
	})

	return refs, scanned
}
