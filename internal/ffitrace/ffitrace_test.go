package ffitrace

import (
	"testing"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
)

// arm64Ret is the 4-byte little-endian encoding of ARM64 "ret" (0xD65F03C0)
// -- used to build minimal, valid, non-crashing synthetic "functions" for
// analysis.AnalysisContext.FuncIRFor without needing a real ELF/snapshot.
var arm64Ret = []byte{0xC0, 0x03, 0x5F, 0xD6}

// TestFindDynamicLibraryCalls_ResolvesLiteralArg verifies the happy path:
// a pool-load of a string literal immediately followed (same block) by a
// resolved direct call to a symbol named like a dart:ffi DynamicLibrary
// method produces a Finding with Resolved=true and the literal captured.
func TestFindDynamicLibraryCalls_ResolvesLiteralArg(t *testing.T) {
	ctx := &analysis.AnalysisContext{
		SymbolNames: map[uint64]string{0x2000: "DynamicLibrary.open"},
		PoolDisplay: map[int]string{7: `"libbatteryOpt.so"`},
	}
	fir := &decompiler.FuncIR{
		Name: "caller_fn",
		Blocks: []decompiler.Block{
			{Instrs: []decompiler.Instr{
				{Addr: 0x1000, Op: decompiler.OpLoadPool, PoolIndex: 7},
				{Addr: 0x1004, Op: decompiler.OpCall, Target: "0x2000"},
			}},
		},
	}

	findings := findDynamicLibraryCalls(ctx, fir, 0x1000)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if !f.Resolved {
		t.Errorf("expected Resolved=true")
	}
	if f.LiteralArg != "libbatteryOpt.so" {
		t.Errorf("expected LiteralArg=%q, got %q", "libbatteryOpt.so", f.LiteralArg)
	}
	if f.Kind != "dynamic_library_call" {
		t.Errorf("expected Kind=dynamic_library_call, got %q", f.Kind)
	}
}

// TestFindDynamicLibraryCalls_UnresolvedWithoutLiteral verifies the
// honest-negative path: a resolved DynamicLibrary.* call with NO
// preceding pool-load literal in scope must report Resolved=false, not
// guess or fabricate a value -- per Komponen H's "don't guess" rule.
func TestFindDynamicLibraryCalls_UnresolvedWithoutLiteral(t *testing.T) {
	ctx := &analysis.AnalysisContext{
		SymbolNames: map[uint64]string{0x2000: "DynamicLibrary.lookup"},
		PoolDisplay: map[int]string{},
	}
	fir := &decompiler.FuncIR{
		Name: "caller_fn",
		Blocks: []decompiler.Block{
			{Instrs: []decompiler.Instr{
				{Addr: 0x1004, Op: decompiler.OpCall, Target: "0x2000"},
			}},
		},
	}

	findings := findDynamicLibraryCalls(ctx, fir, 0x1000)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resolved {
		t.Errorf("expected Resolved=false when no literal is in scope, got LiteralArg=%q", findings[0].LiteralArg)
	}
}

// TestFindDynamicLibraryCalls_IgnoresIndirectAndUnrelatedCalls verifies
// false positives are avoided: indirect (register-target) calls and
// direct calls to unrelated symbols must not produce findings.
func TestFindDynamicLibraryCalls_IgnoresIndirectAndUnrelatedCalls(t *testing.T) {
	ctx := &analysis.AnalysisContext{
		SymbolNames: map[uint64]string{0x2000: "SomeUnrelatedFunction"},
		PoolDisplay: map[int]string{7: `"not_a_library_call"`},
	}
	fir := &decompiler.FuncIR{
		Name: "caller_fn",
		Blocks: []decompiler.Block{
			{Instrs: []decompiler.Instr{
				{Addr: 0x1000, Op: decompiler.OpLoadPool, PoolIndex: 7},
				{Addr: 0x1004, Op: decompiler.OpCall, Target: "x9"},     // indirect
				{Addr: 0x1008, Op: decompiler.OpCall, Target: "0x2000"}, // unrelated direct call
			}},
		},
	}

	findings := findDynamicLibraryCalls(ctx, fir, 0x1000)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

// TestTrace_DefaultBoundLimitsScan is a regression test for the exact
// incident this package's own development hit: an earlier version of
// Trace ran the expensive EmitPseudocode detector (and, it turned out,
// the FuncIR-construction pass too) over EVERY function unconditionally.
// Verified directly against a real 8149-function sample app that this
// drove RSS to 5.4GB + 1.7GB swap on a 5.8GB-RAM host. This test proves
// Trace's default bound actually caps the number of functions processed,
// using synthetic ranges (no real ELF needed) so it runs anywhere
// without depending on an external sample file.
func TestTrace_DefaultBoundLimitsScan(t *testing.T) {
	// Bound against analysis.DefaultMaxScan, the constant ScanFuncs
	// actually reads. ffitrace kept its own copy of 500 after the scan
	// loop moved to analysis, so this test pinned a number that no longer
	// had any effect on what Trace did.
	const numFuncs = analysis.DefaultMaxScan + 50 // deliberately more than the default cap
	ctx := syntheticContext(numFuncs)

	_, scanned := Trace(ctx, Options{}) // no MaxScan, no AllowUnbounded -- must use the default cap
	if scanned == 0 || scanned > analysis.DefaultMaxScan {
		t.Fatalf("expected Trace to process at most %d functions by default, processed %d", analysis.DefaultMaxScan, scanned)
	}
}

// TestTrace_AllowUnboundedProcessesEverything verifies the opt-in escape
// hatch actually removes the cap (using a small synthetic function
// count, NOT a real binary -- this test must never exercise the real
// unbounded-cost path against real data).
func TestTrace_AllowUnboundedProcessesEverything(t *testing.T) {
	const numFuncs = 20
	ctx := syntheticContext(numFuncs)

	_, scanned := Trace(ctx, Options{AllowUnbounded: true})
	if scanned != numFuncs {
		t.Fatalf("expected AllowUnbounded to process all %d functions, processed %d", numFuncs, scanned)
	}
}

// TestTrace_MaxScanOverridesDefault verifies an explicit MaxScan is
// honored instead of the package default.
func TestTrace_MaxScanOverridesDefault(t *testing.T) {
	const numFuncs = 30
	const explicitMax = 5
	ctx := syntheticContext(numFuncs)

	_, scanned := Trace(ctx, Options{MaxScan: explicitMax})
	if scanned != explicitMax {
		t.Fatalf("expected explicit MaxScan=%d to be honored, processed %d", explicitMax, scanned)
	}
}

// syntheticContext builds a minimal, valid analysis.AnalysisContext with n
// bare-"ret" synthetic functions, laid out contiguously starting at VA
// 0x1000, 4 bytes apart -- enough for FuncIRFor to disassemble without
// a real ELF/snapshot. Only the fields FuncIRFor/Trace actually read
// (Code, CodeVA, CodeOff, Ranges, SymbolNames, IsARM64, DartVersion,
// PoolDisplay) are populated; EF/Info/Result/Pool/SymbolSizes are left
// zero-valued since nothing under test touches them.
func syntheticContext(n int) *analysis.AnalysisContext {
	code := make([]byte, 0, n*len(arm64Ret))
	ranges := make([]cluster.CodeRange, 0, n)
	symbolNames := make(map[uint64]string, n)
	for i := 0; i < n; i++ {
		off := uint32(i * len(arm64Ret)) //nolint:gosec // test-only, n is small
		code = append(code, arm64Ret...)
		ranges = append(ranges, cluster.CodeRange{RefID: i, PCOffset: off, Size: uint32(len(arm64Ret))})
		symbolNames[0x1000+uint64(off)] = "synthetic_fn"
	}
	return &analysis.AnalysisContext{
		Code:        code,
		CodeVA:      0x1000,
		CodeOff:     0,
		Ranges:      ranges,
		SymbolNames: symbolNames,
		PoolDisplay: map[int]string{},
		IsARM64:     true,
		DartVersion: "3.7.0",
	}
}
