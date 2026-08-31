// Package ffitrace statically traces Dart AOT code for dart:ffi usage:
// which functions call out to a native library, and (where the
// arguments are literal strings, not computed at runtime) which
// library path and symbol name a DynamicLibrary.open/lookup call
// resolves to. Pure static analysis -- no CPU emulation, no live
// device, no Unicorn/cgo dependency. See docs/plan-phase1-dart-aot-
// emulation-harness.md's Komponen H.
package ffitrace

import (
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

	"aotopsy/internal/analysis"
	"aotopsy/internal/decompiler"
)

// Finding is one FFI-relevant observation: either a resolved (or
// attempted) DynamicLibrary.open/lookup call site, or a function whose
// pseudocode contains the vm_tag native/FFI-leaf-call bookkeeping
// marker (internal/decompiler's "nativeCall(...)").
type Finding struct {
	CallerFunc string // resolved name of the function containing the call site
	CallerVA   uint64 // start VA of the caller function
	CallSitePC uint64 // address of the call instruction itself (0 for native_call_site findings, which are function-level, not instruction-level)
	Kind       string // "dynamic_library_call" | "native_call_site"
	CalleeName string // resolved callee name for dynamic_library_call findings, e.g. "DynamicLibrary.lookup"
	LiteralArg string // resolved string literal argument (library path or symbol name), if one was recoverable
	Resolved   bool   // true only if LiteralArg was actually recovered from a literal pool string
}

// Options bounds Trace's cost. A real Flutter app's libapp.so bundles
// the entire framework -- thousands to tens of thousands of functions,
// per this project's own README -- and running EITHER detector over
// ALL of them unbounded is architecturally the same operation
// `decompile-native --all` without --max already does, which this
// project's own README/WORKFLOW.md/ARCHITECTURE.md document as needing
// ~64GB of RAM and having crashed the whole host (not just the
// process) TWICE on a 5.8GB-RAM machine.
//
// CONFIRMED DIRECTLY during this package's own development (not just
// inherited caution): running Trace with AllowUnbounded against a
// SMALL sample app (3MB libapp.so, 8149 functions -- far smaller than
// a real production app) drove resident set size to 5.4GB on a
// 5.8GB-RAM machine, pushed 1.7GB into swap, evicted nearly all page
// cache, and still hadn't finished after 90 seconds. An earlier
// assumption that FuncIR construction alone (without EmitPseudocode)
// was "cheap enough to run unbounded" was WRONG and is not repeated
// here -- BOTH detectors are gated by the same scan bound below.
type Options struct {
	// MaxScan caps how many functions Trace processes with EITHER
	// detector. 0 means use the package default (500, matching
	// decompile-native --all's own default --max). Ignored if
	// AllowUnbounded is true.
	MaxScan int
	// AllowUnbounded opts into scanning every function, same as
	// decompile-native --all with --max 0 -- the caller is asserting
	// they understand the RAM/host-crash risk documented above
	// (measured directly at 5.4GB RSS + 1.7GB swap on an 8149-function
	// SAMPLE app) and have sized the host accordingly. Do not set this
	// against a real production app's libapp.so on a memory-
	// constrained host.
	AllowUnbounded bool
	// Filter restricts scanning to functions whose resolved name
	// contains this substring, mirroring decompile-native --all
	// --filter. Empty means no restriction. Prefer this over
	// AllowUnbounded when a specific neighborhood is already known.
	Filter string
}

const defaultMaxScan = 500

// Trace runs two detectors per function, both gated by the same scan
// bound (see Options):
//
//  1. findDynamicLibraryCalls: resolved direct calls whose callee name
//     references dart:ffi's DynamicLibrary (open/lookup/lookupFunction),
//     paired with the nearest preceding object-pool string literal in
//     the same basic block (the library path or symbol name, when
//     passed as a literal rather than read from a cached field -- see
//     the plan's Komponen H "Trap" note on shared-bindings-object
//     indirection, which this simple per-block scan does NOT follow;
//     that's a known, documented limitation, not a bug).
//  2. the decompiled pseudocode's own decompiler.FFICallMarker
//     ("ffi_call(") -- internal/decompiler's vm_tag-based FFI-leaf-call
//     detection -- via EmitPseudocode.
//
// Applies the same hardening decompile-native --all uses for the same
// underlying cost profile: GOMAXPROCS cap, a hard memory-limit
// backstop, and periodic GC.
//
// Returns the findings plus how many functions were actually
// processed -- callers (and this package's own regression tests) can
// use the scanned count to verify bounding actually took effect,
// rather than only inferring it indirectly from findings.
func Trace(ctx *analysis.AnalysisContext, opts Options) ([]Finding, int) {
	maxScan := opts.MaxScan
	if maxScan == 0 && !opts.AllowUnbounded {
		maxScan = defaultMaxScan
	}

	// M-11 fix: save/restore GOMAXPROCS and memory limit (same as strxref L-8 fix)
	oldProcs := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(oldProcs)
	oldLimit := debug.SetMemoryLimit(1536 << 20)
	defer debug.SetMemoryLimit(oldLimit)

	var findings []Finding
	scanned := 0
	for _, r := range ctx.Ranges {
		if !opts.AllowUnbounded && scanned >= maxScan {
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

		findings = append(findings, findDynamicLibraryCalls(ctx, fir, funcVA)...)

		// The marker is `ffi_call(`, which is what emitIndirectCall
		// actually writes when a register carries the vm_tag sentinel.
		// This read `nativeCall(` -- a string the decompiler has never
		// emitted -- so signal 2 could not fire at all, on any sample or
		// architecture, and the only findings came from signal 1.
		art := decompiler.EmitPseudocode(fir, ctx.SymbolLookup, ctx.PoolLookup)
		if strings.Contains(art.Source, decompiler.FFICallMarker) {
			findings = append(findings, Finding{
				CallerFunc: fir.Name,
				CallerVA:   funcVA,
				Kind:       "native_call_site",
			})
		}
		if scanned%100 == 0 {
			runtime.GC()
			debug.FreeOSMemory()
		}
	}
	return findings, scanned
}

// findDynamicLibraryCalls scans one function's blocks for direct calls
// resolving to a dart:ffi DynamicLibrary open/lookup method, tracking
// the most recent object-pool load within the SAME basic block as a
// candidate literal argument (a simple, deliberately local heuristic --
// it does not follow control flow across blocks or through a cached
// field read; see the Finding.Resolved field, which is false whenever
// no such literal was found in scope).
func findDynamicLibraryCalls(ctx *analysis.AnalysisContext, fir *decompiler.FuncIR, funcVA uint64) []Finding {
	var out []Finding
	for _, blk := range fir.Blocks {
		var lastPoolLiteral string
		var haveLiteral bool
		for _, ins := range blk.Instrs {
			if ins.Op == decompiler.OpLoadPool {
				if s, ok := ctx.PoolDisplay[ins.PoolIndex]; ok && strings.HasPrefix(s, `"`) {
					lastPoolLiteral = strings.Trim(s, `"`)
					haveLiteral = true
				} else {
					haveLiteral = false
				}
				continue
			}
			if ins.Op != decompiler.OpCall || ins.Target == "" {
				continue
			}
			if !strings.HasPrefix(ins.Target, "0x") {
				// Pre-resolved callee name (not a hex VA). If it already
				// looks like an ffi DynamicLibrary.open / lookupFunction
				// call site, record it directly without needing a symbol
				// lookup -- the decompiler resolved the target name already.
				if looksLikeFfiOpenOrLookup(ins.Target) {
					f := Finding{
						CallerFunc: fir.Name,
						CallerVA:   funcVA,
						CallSitePC: ins.Addr,
						Kind:       "dynamic_library_call",
						CalleeName: ins.Target,
					}
					if haveLiteral {
						f.LiteralArg = lastPoolLiteral
						f.Resolved = true
					}
					out = append(out, f)
				}
				continue // indirect call (register target) -- not a directly-resolved callee name
			}
			va, err := strconv.ParseUint(strings.TrimPrefix(ins.Target, "0x"), 16, 64)
			if err != nil {
				continue
			}
			name, ok := ctx.SymbolNames[va]
			if !ok || !looksLikeFfiOpenOrLookup(name) {
				continue
			}
			f := Finding{
				CallerFunc: fir.Name,
				CallerVA:   funcVA,
				CallSitePC: ins.Addr,
				Kind:       "dynamic_library_call",
				CalleeName: name,
			}
			if haveLiteral {
				f.LiteralArg = lastPoolLiteral
				f.Resolved = true
			}
			out = append(out, f)
		}
	}
	return out
}

func looksLikeFfiOpenOrLookup(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "dynamiclibrary") || strings.Contains(lower, "lookupfunction")
}
