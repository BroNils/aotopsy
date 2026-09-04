package analysis

import (
	"runtime"
	"runtime/debug"
	"strings"

	"aotopsy/internal/decompiler"
)

// ScanOptions configures bounded function scanning across an AnalysisContext.
type ScanOptions struct {
	// MaxScan caps the number of functions to process.
	MaxScan int

	// AllowUnbounded permits scanning all functions when MaxScan is 0.
	AllowUnbounded bool

	// Filter matches substring in function names.
	Filter string

	// GcEveryN triggers garbage collection and FreeOSMemory every N scanned functions (default 500).
	GcEveryN int
}

// ScanFuncs runs a bounded, memory-hardened scan over functions in the AnalysisContext.
// It manages GOMAXPROCS and memory limits safely, performs range filtering,
// and invokes fn for each function's FuncIR and virtual address.
func (c *AnalysisContext) ScanFuncs(opts ScanOptions, fn func(fir *decompiler.FuncIR, funcVA uint64)) int {
	maxScan := opts.MaxScan
	if maxScan == 0 && !opts.AllowUnbounded {
		maxScan = 500
	}
	gcInterval := opts.GcEveryN
	if gcInterval <= 0 {
		gcInterval = 500
	}

	oldProcs := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(oldProcs)
	oldLimit := debug.SetMemoryLimit(1536 << 20)
	defer debug.SetMemoryLimit(oldLimit)

	scanned := 0
	for _, r := range c.Ranges {
		if !opts.AllowUnbounded && maxScan > 0 && scanned >= maxScan {
			break
		}
		if r.Size == 0 || r.RefID < 0 {
			continue
		}
		fir, err := c.FuncIRFor(r)
		if err != nil || fir == nil {
			continue
		}
		if opts.Filter != "" && !strings.Contains(fir.Name, opts.Filter) {
			continue
		}
		funcStart := uint64(r.PCOffset) - c.CodeOff
		funcVA := c.CodeVA + funcStart
		scanned++

		fn(fir, funcVA)

		if scanned%gcInterval == 0 {
			runtime.GC()
			debug.FreeOSMemory()
		}
	}
	return scanned
}
