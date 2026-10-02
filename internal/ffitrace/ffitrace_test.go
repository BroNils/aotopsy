package ffitrace

import (
	"strings"
	"testing"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/naming"
	"aotopsy/internal/snapshot"
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
		SymbolNames: map[uint64]string{0x2000: "DynamicLibrary.lookup_abc123"},
		PoolDisplay: map[int]string{7: `"libbatteryOpt.so"`},
		DartVersion: "3.13.0",
	}
	fir := &decompiler.FuncIR{
		Name:     "caller_fn",
		StackReg: "rsp",
		Blocks: []decompiler.Block{
			{Instrs: []decompiler.Instr{
				{Addr: 0x1000, Op: decompiler.OpLoadPool, PoolIndex: 7, Target: "r11", DefRegs: []string{"r11"}},
				{Addr: 0x1004, Op: decompiler.OpOther, Src: "mov [rsp+reg(0)], r11"},
				{Addr: 0x1008, Op: decompiler.OpCall, Target: "0x2000"},
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

func TestFindDynamicLibraryCalls_TracksLiteralIntoArgumentRegister(t *testing.T) {
	ctx := &analysis.AnalysisContext{
		SymbolNames: map[uint64]string{0x2000: "dart:ffi::DynamicLibrary.open"},
		PoolDisplay: map[int]string{
			7: `"libreal.so"`,
			8: `"decoy-nearest.so"`,
		},
		DartVersion: "3.13.0",
	}
	fir := &decompiler.FuncIR{
		Name: "caller_fn",
		Blocks: []decompiler.Block{{Instrs: []decompiler.Instr{
			{Addr: 0x1000, Op: decompiler.OpLoadPool, PoolIndex: 7, Target: "rdi", DefRegs: []string{"rdi"}},
			// This is physically nearer to the call but r11 is not a Dart
			// argument register, so it must not replace the actual path arg.
			{Addr: 0x1004, Op: decompiler.OpLoadPool, PoolIndex: 8, Target: "r11", DefRegs: []string{"r11"}},
			{Addr: 0x1008, Op: decompiler.OpCall, Target: "0x2000"},
		}}},
	}

	findings := findDynamicLibraryCalls(ctx, fir, 0x1000)
	if len(findings) != 1 || !findings[0].Resolved || findings[0].LiteralArg != "libreal.so" {
		t.Fatalf("argument dataflow = %+v, want resolved libreal.so", findings)
	}
}

func TestFindDynamicLibraryCalls_InvalidatesOverwrittenArgument(t *testing.T) {
	ctx := &analysis.AnalysisContext{
		SymbolNames: map[uint64]string{0x2000: "DynamicLibrary.lookup"},
		PoolDisplay: map[int]string{7: `"native_symbol"`},
		DartVersion: "3.13.0",
	}
	fir := &decompiler.FuncIR{
		Name: "caller_fn",
		Blocks: []decompiler.Block{{Instrs: []decompiler.Instr{
			{Addr: 0x1000, Op: decompiler.OpLoadPool, PoolIndex: 7, Target: "rdi", DefRegs: []string{"rdi"}},
			{Addr: 0x1004, Op: decompiler.OpOther, Src: "mov rdi, rax", DefRegs: []string{"rdi"}},
			{Addr: 0x1008, Op: decompiler.OpCall, Target: "0x2000"},
		}}},
	}

	findings := findDynamicLibraryCalls(ctx, fir, 0x1000)
	if len(findings) != 1 || findings[0].Resolved {
		t.Fatalf("overwritten argument = %+v, want one unresolved finding", findings)
	}
}

func TestFindDynamicLibraryCalls_UnquotesPoolDisplay(t *testing.T) {
	ctx := &analysis.AnalysisContext{
		SymbolNames: map[uint64]string{0x2000: "DynamicLibrary.open"},
		PoolDisplay: map[int]string{7: `"C:\\native\\lib\tname.so"`},
		DartVersion: "3.13.0",
	}
	fir := &decompiler.FuncIR{
		Name:     "caller_fn",
		StackReg: "rsp",
		Blocks: []decompiler.Block{{Instrs: []decompiler.Instr{
			{Addr: 0x1000, Op: decompiler.OpLoadPool, PoolIndex: 7, Target: "r11", DefRegs: []string{"r11"}},
			{Addr: 0x1004, Op: decompiler.OpOther, Src: "mov [rsp], r11"},
			{Addr: 0x1008, Op: decompiler.OpCall, Target: "0x2000"},
		}}},
	}

	findings := findDynamicLibraryCalls(ctx, fir, 0x1000)
	if len(findings) != 1 || findings[0].LiteralArg != "C:\\native\\lib\tname.so" {
		t.Fatalf("unquoted literal = %q, want Go-unquoted path", findings[0].LiteralArg)
	}
}

func TestFindDynamicLibraryCalls_TracksARM64StackArgument(t *testing.T) {
	ctx := &analysis.AnalysisContext{
		SymbolNames: map[uint64]string{0x2000: "DynamicLibrary.lookup_20abc"},
		PoolDisplay: map[int]string{7: `"native_symbol"`},
		DartVersion: "3.2.5", // stack-only Dart calling convention
		IsARM64:     true,
	}
	fir := &decompiler.FuncIR{
		Name:     "caller_fn",
		StackReg: "x15",
		Blocks: []decompiler.Block{{Instrs: []decompiler.Instr{
			{Addr: 0x1000, Op: decompiler.OpLoadPool, PoolIndex: 7, Target: "x9", DefRegs: []string{"x9"}},
			{Addr: 0x1004, Op: decompiler.OpOther, Src: "str x9, [x15, #0x8]"},
			{Addr: 0x1008, Op: decompiler.OpCall, Target: "0x2000"},
		}}},
	}

	findings := findDynamicLibraryCalls(ctx, fir, 0x1000)
	if len(findings) != 1 || !findings[0].Resolved || findings[0].LiteralArg != "native_symbol" {
		t.Fatalf("ARM64 stack argument = %+v, want resolved native_symbol", findings)
	}
}

func TestFindDynamicLibraryCalls_TracksDart2PushArgument(t *testing.T) {
	ctx := &analysis.AnalysisContext{
		SymbolNames: map[uint64]string{0x2000: "DynamicLibrary.lookup_3af14"},
		PoolDisplay: map[int]string{7: `"legacy_symbol"`},
		DartVersion: "2.10.0",
	}
	fir := &decompiler.FuncIR{
		Name:     "caller_fn",
		StackReg: "rsp",
		Blocks: []decompiler.Block{{Instrs: []decompiler.Instr{
			{Addr: 0x1000, Op: decompiler.OpLoadPool, PoolIndex: 7, Target: "r11", DefRegs: []string{"r11"}},
			{Addr: 0x1004, Op: decompiler.OpOther, Src: "push r11"},
			{Addr: 0x1005, Op: decompiler.OpCall, Target: "0x2000"},
		}}},
	}

	findings := findDynamicLibraryCalls(ctx, fir, 0x1000)
	if len(findings) != 1 || !findings[0].Resolved || findings[0].LiteralArg != "legacy_symbol" {
		t.Fatalf("Dart 2 PUSH argument = %+v, want resolved legacy_symbol", findings)
	}
}

func TestFindDynamicLibraryCalls_StackOverwriteInvalidatesLiteral(t *testing.T) {
	ctx := &analysis.AnalysisContext{
		SymbolNames: map[uint64]string{0x2000: "DynamicLibrary.lookup"},
		PoolDisplay: map[int]string{7: `"stale_symbol"`},
		DartVersion: "3.13.0",
	}
	fir := &decompiler.FuncIR{
		Name:     "caller_fn",
		StackReg: "rsp",
		Blocks: []decompiler.Block{{Instrs: []decompiler.Instr{
			{Addr: 0x1000, Op: decompiler.OpLoadPool, PoolIndex: 7, Target: "r11", DefRegs: []string{"r11"}},
			{Addr: 0x1004, Op: decompiler.OpOther, Src: "mov [rsp], r11"},
			{Addr: 0x1008, Op: decompiler.OpOther, Src: "mov [rsp], -0xe"},
			{Addr: 0x100c, Op: decompiler.OpCall, Target: "0x2000"},
		}}},
	}

	findings := findDynamicLibraryCalls(ctx, fir, 0x1000)
	if len(findings) != 1 || findings[0].Resolved {
		t.Fatalf("overwritten stack argument = %+v, want unresolved", findings)
	}
}

func TestLiteralPassedToOpenHelperIgnoresUnrelatedStringCall(t *testing.T) {
	ctx := &analysis.AnalysisContext{
		PoolDisplay: map[int]string{
			7: `"not-the-library.so"`,
			8: `"libreal.so"`,
		},
		DartVersion: "3.2.5",
	}

	// First prove an unrelated string-bearing call is not enough to fabricate
	// a DynamicLibrary.open path when _open itself receives a computed value.
	unresolved := &decompiler.FuncIR{
		StackReg: "rsp",
		Blocks: []decompiler.Block{{Instrs: []decompiler.Instr{
			{Addr: 0x1000, Op: decompiler.OpLoadPool, PoolIndex: 7, Target: "r11", DefRegs: []string{"r11"}},
			{Addr: 0x1004, Op: decompiler.OpOther, Src: "mov [rsp], r11"},
			{Addr: 0x1008, Op: decompiler.OpCall, Target: "logMessage"},
			{Addr: 0x100c, Op: decompiler.OpCall, Target: "dart:ffi::_open"},
		}}},
	}
	if got, ok := literalPassedToOpenHelper(ctx, unresolved); ok {
		t.Fatalf("unrelated call fabricated DynamicLibrary.open literal %q", got)
	}

	resolved := &decompiler.FuncIR{
		StackReg: "rsp",
		Blocks: []decompiler.Block{{Instrs: []decompiler.Instr{
			{Addr: 0x2000, Op: decompiler.OpLoadPool, PoolIndex: 8, Target: "r11", DefRegs: []string{"r11"}},
			{Addr: 0x2004, Op: decompiler.OpOther, Src: "mov [rsp], r11"},
			{Addr: 0x2008, Op: decompiler.OpCall, Target: "dart:ffi::_open"},
		}}},
	}
	if got, ok := literalPassedToOpenHelper(ctx, resolved); !ok || got != "libreal.so" {
		t.Fatalf("_open literal = %q, %v; want libreal.so, true", got, ok)
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

	res, err := Trace(ctx, Options{}) // no MaxScan, no AllowUnbounded -- must use the default cap
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanned == 0 || res.Scanned > analysis.DefaultMaxScan {
		t.Fatalf("expected Trace to process at most %d functions by default, processed %d", analysis.DefaultMaxScan, res.Scanned)
	}
	if !res.ScanLimitReached {
		t.Fatal("default capped trace was presented as complete")
	}
}

// TestTrace_AllowUnboundedProcessesEverything verifies the opt-in escape
// hatch actually removes the cap (using a small synthetic function
// count, NOT a real binary -- this test must never exercise the real
// unbounded-cost path against real data).
func TestTrace_AllowUnboundedProcessesEverything(t *testing.T) {
	const numFuncs = 20
	ctx := syntheticContext(numFuncs)

	res, err := Trace(ctx, Options{AllowUnbounded: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanned != numFuncs || res.ScanLimitReached {
		t.Fatalf("expected AllowUnbounded to process all %d functions completely, scanned=%d limited=%v", numFuncs, res.Scanned, res.ScanLimitReached)
	}
}

// TestTrace_MaxScanOverridesDefault verifies an explicit MaxScan is
// honored instead of the package default.
func TestTrace_MaxScanOverridesDefault(t *testing.T) {
	const numFuncs = 30
	const explicitMax = 5
	ctx := syntheticContext(numFuncs)

	res, err := Trace(ctx, Options{MaxScan: explicitMax})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanned != explicitMax || !res.ScanLimitReached {
		t.Fatalf("expected explicit MaxScan=%d with truncation, scanned=%d limited=%v", explicitMax, res.Scanned, res.ScanLimitReached)
	}
}

func TestTrace_NegativeMaxScanUsesSafetyDefault(t *testing.T) {
	ctx := syntheticContext(analysis.DefaultMaxScan + 25)

	res, err := Trace(ctx, Options{MaxScan: -1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanned != analysis.DefaultMaxScan || !res.ScanLimitReached {
		t.Fatalf("negative MaxScan scanned=%d limited=%v, want safety default %d with truncation", res.Scanned, res.ScanLimitReached, analysis.DefaultMaxScan)
	}
}

func TestLooksLikeFfiOpenOrLookupRejectsOtherDynamicLibraryMembers(t *testing.T) {
	accepted := []string{
		"DynamicLibrary.open",
		"new DynamicLibrary.open_3dec8",
		"dart:ffi::DynamicLibrary.lookup",
		"DynamicLibrary.lookup_3dd24",
		"DynamicLibraryExtension.lookupFunction<int, int>",
	}
	for _, name := range accepted {
		if !looksLikeFfiOpenOrLookup(name) {
			t.Errorf("expected %q to be recognized", name)
		}
	}

	rejected := []string{
		"DynamicLibrary.close",
		"DynamicLibrary.process",
		"DynamicLibrary.executable",
		"DynamicLibrary.providesSymbol",
		"DynamicLibrary.hashCode",
		"NotDynamicLibrary.open",
		"Other.lookupFunction",
	}
	for _, name := range rejected {
		if looksLikeFfiOpenOrLookup(name) {
			t.Errorf("false positive for %q", name)
		}
	}
}

func TestLooksLikePrivateFfiOpenNameRequiresExactHelper(t *testing.T) {
	for _, name := range []string{"_open", "_open@8050071_46f50", "dart:ffi::_open"} {
		if !looksLikePrivateFfiOpenName(name) {
			t.Errorf("expected private dart:ffi open spelling %q to be recognized", name)
		}
	}
	for _, name := range []string{"_openLibrary@8050071_46f50", "reopen@8050071_46f50", "_open@notdigits_46f50"} {
		if looksLikePrivateFfiOpenName(name) {
			t.Errorf("private open name false positive for %q", name)
		}
	}
}

func TestClassifyFfiRangeDistinguishesCallbacksAndModernClosures(t *testing.T) {
	ffiOwner := &cluster.NamedObject{CID: 99, RefID: 41, DataRefID: 90, FuncKind: cluster.FunctionKindFfiTrampoline}
	ctx := &analysis.AnalysisContext{
		DartVersion: "3.2.5",
		Pool: &naming.PoolLookups{
			CT:         &snapshot.CIDTable{Function: 99},
			RefToNamed: map[int]*cluster.NamedObject{41: ffiOwner},
		},
	}
	r := cluster.CodeRange{RefID: 100, OwnerRef: 41, Index: 7}
	data := map[int]cluster.FfiTrampolineInfo{
		90: {RefID: 90, CallbackTargetRef: cluster.RefNull},
	}
	class := classifyFfiRange(ctx, r, "FfiTrampoline_main_47970", nil, data)
	if class != cluster.FfiDirectionOutbound {
		t.Fatalf("old outbound FFI trampoline classification = %q", class)
	}

	data[90] = cluster.FfiTrampolineInfo{RefID: 90, CallbackTargetRef: 77}
	class = classifyFfiRange(ctx, r, "_FfiCallbackcallback_123", nil, data)
	if class != cluster.FfiDirectionCallback {
		t.Fatalf("native-to-Dart callback classification = %q", class)
	}
	delete(data, 90)
	class = classifyFfiRange(ctx, r, "FfiTrampoline_main_47970", nil, data)
	if class != cluster.FfiDirectionUnknown {
		t.Fatalf("FFI trampoline with missing direction metadata = %q; must stay unresolved", class)
	}

	// Dart 3.3+ kFfiTrampoline is callback-only. Even malformed modern metadata
	// with a null callback_target must not revive the old outbound rule.
	ctx.DartVersion = "3.13.0"
	data[90] = cluster.FfiTrampolineInfo{RefID: 90, CallbackTargetRef: cluster.RefNull}
	class = classifyFfiRange(ctx, r, "_FfiCallbackcallback_123", nil, data)
	if class != cluster.FfiDirectionCallback {
		t.Fatalf("modern callback trampoline classification = %q; malformed null target must not revive outbound", class)
	}

	closureOwner := &cluster.NamedObject{CID: 99, RefID: 42, FuncKind: cluster.FunctionKindClosure}
	ctx.Pool.RefToNamed[42] = closureOwner
	r.OwnerRef = 42
	class = classifyFfiRange(ctx, r, "main.#ffiClosure0_3e2f0", nil, data)
	if class != cluster.FfiDirectionOutbound {
		t.Fatalf("modern compiler-generated #ffiClosure classification = %q", class)
	}
	class = classifyFfiRange(ctx, r, "main.<anonymous closure>_3e2f0", nil, data)
	if class != cluster.FfiDirectionUnknown {
		t.Fatalf("ordinary closure classification = %q", class)
	}

	// @Native functions are ordinary Functions whose kind_tag carries the
	// exact predicate used by Function::is_ffi_native() from Dart 3.3 onward.
	nativeOwner := &cluster.NamedObject{
		CID: 99, RefID: 43, FuncKind: cluster.FunctionKindRegular,
		HasKindTag: true, IsNative: true, IsExternal: true,
	}
	ctx.Pool.RefToNamed[43] = nativeOwner
	r.OwnerRef = 43
	class = classifyFfiRange(ctx, r, "nativeAssetEntry_123", nil, data)
	if class != cluster.FfiDirectionOutbound {
		t.Fatalf("3.13 @Native/is_ffi_native classification = %q", class)
	}

	nativeOwner.IsExternal = false
	class = classifyFfiRange(ctx, r, "oldNativeEntry_123", nil, data)
	if class != cluster.FfiDirectionUnknown {
		t.Fatalf("native but non-external function classification = %q", class)
	}
	nativeOwner.IsExternal = true
	nativeOwner.HasKindTag = false
	class = classifyFfiRange(ctx, r, "missingKindTag_123", nil, data)
	if class != cluster.FfiDirectionUnknown {
		t.Fatalf("uncaptured kind_tag flags classification = %q", class)
	}
	nativeOwner.HasKindTag = true
	ctx.DartVersion = "3.2.5"
	class = classifyFfiRange(ctx, r, "preNativeLowering_123", nil, data)
	if class != cluster.FfiDirectionUnknown {
		t.Fatalf("pre-3.3 native/external classification = %q", class)
	}
}

func TestUsesModernFfiLoweringVersionBoundary(t *testing.T) {
	for _, version := range []string{"3.3.0", "3.13.0"} {
		if !usesModernFfiLowering(version) {
			t.Errorf("usesModernFfiLowering(%q) = false, want true", version)
		}
	}
	for _, version := range []string{"", "3", "3.2.5", "2.19.0", "3.99.0", "4.0.0", "not-a-version"} {
		if usesModernFfiLowering(version) {
			t.Errorf("usesModernFfiLowering(%q) = true, want false", version)
		}
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

func TestTrace_FilterOnlyProcessesMatchingNames(t *testing.T) {
	ctx := syntheticContext(4)
	for va := range ctx.SymbolNames {
		ctx.SymbolNames[va] = "skip_me"
	}
	ctx.SymbolNames[0x1008] = "target_match"

	res, err := Trace(ctx, Options{Filter: "target_"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanned != 1 || res.ScanLimitReached {
		t.Fatalf("filtered scan scanned=%d limited=%v, want one complete match", res.Scanned, res.ScanLimitReached)
	}
	for _, f := range res.Findings {
		if !strings.Contains(f.CallerFunc, "target_") {
			t.Fatalf("filtered scan leaked finding from %q", f.CallerFunc)
		}
	}
}
