package analysis

import (
	"runtime"
	"runtime/debug"
	"strings"

	"aotopsy/internal/decompiler"
)

// DefaultMaxScan bounds ScanFuncs when the caller sets neither MaxScan nor
// AllowUnbounded.
//
// It is exported because it is the real default: it used to be duplicated
// as an unexported const in ffitrace, which after the scan loop moved here
// survived only in ffitrace's own test. A test asserting against a copy of
// a number that no longer drives anything passes whatever the code does.
const DefaultMaxScan = 500

// DefaultScanGcEveryN is how often ScanFuncs forces a GC when the caller
// does not choose an interval.
const DefaultScanGcEveryN = 500

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
		maxScan = DefaultMaxScan
	}
	gcInterval := opts.GcEveryN
	if gcInterval <= 0 {
		gcInterval = DefaultScanGcEveryN
	}

	oldProcs := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(oldProcs)
	oldLimit := debug.SetMemoryLimit(1536 << 20)
	defer debug.SetMemoryLimit(oldLimit)

	im := c.Image()
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
		funcVA, ok := im.FuncVA(r)
		if !ok {
			continue
		}
		scanned++

		fn(fir, funcVA)

		if scanned%gcInterval == 0 {
			runtime.GC()
			debug.FreeOSMemory()
		}
	}
	return scanned
}
