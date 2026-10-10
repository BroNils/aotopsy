package analysis

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"aotopsy/internal/cluster"
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

// ScanResult reports both completed work and whether a function-count cap made
// the result incomplete. Attempted is incremented before FuncIR construction so
// a malformed/undecodable function cannot bypass the resource cap.
type ScanResult struct {
	Attempted        int
	Scanned          int
	ScanLimitReached bool
}

// ScanFuncs runs a bounded, memory-hardened scan over functions in the AnalysisContext.
// It manages GOMAXPROCS and memory limits safely, performs range filtering,
// and invokes fn for each function's FuncIR and virtual address.
func (c *AnalysisContext) ScanFuncs(opts ScanOptions, fn func(r cluster.CodeRange, fir *decompiler.FuncIR, funcVA uint64)) (ScanResult, error) {
	var result ScanResult
	if c == nil {
		return result, fmt.Errorf("scan functions: nil analysis context")
	}
	if fn == nil {
		return result, fmt.Errorf("scan functions: nil callback")
	}
	maxScan := opts.MaxScan
	if maxScan <= 0 && !opts.AllowUnbounded {
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

	for _, r := range c.Ranges {
		if r.Size == 0 || r.RefID < 0 {
			continue
		}
		// Resolve the exact same name FuncIRFor will use, but before paying for
		// disassembly and IR construction. Filter is a cost bound as well as an
		// output predicate; applying it after FuncIRFor defeats its purpose.
		fs, ok := c.Slice(r)
		if !ok {
			continue
		}
		name := c.SymbolNames[fs.VA]
		if name == "" {
			name = fs.Name
		}
		if opts.Filter != "" && !strings.Contains(name, opts.Filter) {
			continue
		}
		if !opts.AllowUnbounded && maxScan > 0 && result.Attempted >= maxScan {
			result.ScanLimitReached = true
			break
		}
		result.Attempted++
		fir, err := c.FuncIRFor(r)
		if err != nil {
			return result, fmt.Errorf("build IR for %s: %w", name, err)
		}
		if fir == nil {
			continue
		}
		funcVA := fs.VA
		result.Scanned++

		fn(r, fir, funcVA)

		if result.Scanned%gcInterval == 0 {
			runtime.GC()
			debug.FreeOSMemory()
		}
	}
	return result, nil
}
