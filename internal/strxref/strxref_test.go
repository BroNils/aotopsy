package strxref

import (
	"encoding/binary"
	"testing"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cluster"
)

// arm64Ret is the 4-byte little-endian encoding of ARM64 "ret".
var arm64Ret = []byte{0xC0, 0x03, 0x5F, 0xD6}

// TestFindPoolReferences_FindsMatchingLoad verifies the core mechanics:
// a synthetic function with a real OpLoadPool instruction (an actual
// ARM64 "ldr x0, [x27, #24]" -- pool index 1 under the SDK layout
// (elements start at +16, 8 bytes each; see disasm.ARM64PoolIndex) is
// found when its pool index is targeted.
func TestFindPoolReferences_FindsMatchingLoad(t *testing.T) {
	code := []byte{
		0x60, 0x0F, 0x40, 0xF9, // ldr x0, [x27, #24] (pool index 1)
		0xC0, 0x03, 0x5F, 0xD6, // ret
	}
	ctx := &analysis.AnalysisContext{
		Code:        code,
		CodeVA:      0x1000,
		IsARM64:     true,
		DartVersion: "3.7.0",
		Ranges: []cluster.CodeRange{
			{RefID: 1, PCOffset: 0, Size: uint32(len(code))},
		},
		SymbolNames: map[uint64]string{0x1000: "test_fn"},
	}

	res, err := FindPoolReferences(ctx, []int{1}, Options{})
	if err != nil {
		t.Fatalf("FindPoolReferences: %v", err)
	}
	if res.Scanned != 1 || res.Attempted != 1 {
		t.Fatalf("expected 1 function attempted/scanned, got attempted=%d scanned=%d", res.Attempted, res.Scanned)
	}
	if len(res.References) != 1 {
		t.Fatalf("expected 1 reference, got %d: %+v", len(res.References), res.References)
	}
	if res.References[0].FuncName != "test_fn" || res.References[0].PoolIndex != 1 {
		t.Errorf("unexpected reference: %+v", res.References[0])
	}
}

// TestFindPoolReferences_NoMatchForUnrelatedIndex verifies a pool load
// of an UNTARGETED index produces no false positive.
func TestFindPoolReferences_NoMatchForUnrelatedIndex(t *testing.T) {
	code := []byte{
		0x60, 0x0F, 0x40, 0xF9, // ldr x0, [x27, #24] (pool index 1)
		0xC0, 0x03, 0x5F, 0xD6, // ret
	}
	ctx := &analysis.AnalysisContext{
		Code:        code,
		CodeVA:      0x1000,
		IsARM64:     true,
		DartVersion: "3.7.0",
		Ranges: []cluster.CodeRange{
			{RefID: 1, PCOffset: 0, Size: uint32(len(code))},
		},
		SymbolNames: map[uint64]string{0x1000: "test_fn"},
	}

	res, err := FindPoolReferences(ctx, []int{999}, Options{})
	if err != nil {
		t.Fatalf("FindPoolReferences: %v", err)
	}
	if len(res.References) != 0 {
		t.Errorf("expected 0 references for an untargeted pool index, got %d: %+v", len(res.References), res.References)
	}
}

func TestFindPoolReferences_UnboundedOptInScansEverything(t *testing.T) {
	const numFuncs = 600
	code := make([]byte, 0, numFuncs*len(arm64Ret))
	ranges := make([]cluster.CodeRange, 0, numFuncs)
	symbolNames := make(map[uint64]string, numFuncs)
	for i := 0; i < numFuncs; i++ {
		off := uint32(i * len(arm64Ret)) //nolint:gosec // test-only, n is small
		code = append(code, arm64Ret...)
		ranges = append(ranges, cluster.CodeRange{RefID: i, PCOffset: off, Size: uint32(len(arm64Ret))})
		symbolNames[0x1000+uint64(off)] = "synthetic_fn"
	}
	ctx := &analysis.AnalysisContext{
		Code:        code,
		CodeVA:      0x1000,
		IsARM64:     true,
		DartVersion: "3.7.0",
		Ranges:      ranges,
		SymbolNames: symbolNames,
	}

	res, err := FindPoolReferences(ctx, []int{0}, Options{AllowUnbounded: true})
	if err != nil {
		t.Fatalf("FindPoolReferences: %v", err)
	}
	if res.Scanned != numFuncs || res.ScanLimitReached {
		t.Fatalf("expected explicit unbounded scan of %d functions, got scanned=%d limited=%v", numFuncs, res.Scanned, res.ScanLimitReached)
	}
}

// TestFindPoolReferences_MaxScanNarrowsWhenSet verifies the opt-in
// narrowing still works for callers who want it.
func TestFindPoolReferences_MaxScanNarrowsWhenSet(t *testing.T) {
	const numFuncs = 30
	const explicitMax = 5
	code := make([]byte, 0, numFuncs*len(arm64Ret))
	ranges := make([]cluster.CodeRange, 0, numFuncs)
	for i := 0; i < numFuncs; i++ {
		off := uint32(i * len(arm64Ret)) //nolint:gosec // test-only, n is small
		code = append(code, arm64Ret...)
		ranges = append(ranges, cluster.CodeRange{RefID: i, PCOffset: off, Size: uint32(len(arm64Ret))})
	}
	ctx := &analysis.AnalysisContext{
		Code:        code,
		CodeVA:      0x1000,
		IsARM64:     true,
		DartVersion: "3.7.0",
		Ranges:      ranges,
	}

	res, err := FindPoolReferences(ctx, []int{0}, Options{MaxScan: explicitMax})
	if err != nil {
		t.Fatalf("FindPoolReferences: %v", err)
	}
	if res.Scanned != explicitMax || !res.ScanLimitReached {
		t.Fatalf("expected MaxScan=%d with explicit truncation, scanned=%d limited=%v", explicitMax, res.Scanned, res.ScanLimitReached)
	}
}

func TestFindPoolReferencesEmptyTargetsDoesNoWork(t *testing.T) {
	ctx := &analysis.AnalysisContext{Ranges: []cluster.CodeRange{{RefID: 1, PCOffset: 0, Size: 4}}}
	res, err := FindPoolReferences(ctx, nil, Options{})
	if err != nil {
		t.Fatalf("FindPoolReferences: %v", err)
	}
	if res.Attempted != 0 || res.Scanned != 0 || len(res.References) != 0 {
		t.Fatalf("empty targets did work: %+v", res)
	}
}

func TestFindPoolReferencesX64DirectCompareOperand(t *testing.T) {
	// 41 3b 47 3f = CMP EAX, [R15+0x3f]. x64 PP is tagged, so 0x3f
	// maps to pool index (0x3f-(0x10-1))/8 = 6. This is the exact operand
	// shape Dart's Assembler::CompareObject can emit without a MOV load.
	code := []byte{0x41, 0x3b, 0x47, 0x3f, 0xc3} // ... ; RET
	ctx := &analysis.AnalysisContext{
		Code: code, CodeVA: 0x4000, IsARM64: false,
		Ranges:      []cluster.CodeRange{{RefID: 1, PCOffset: 0, Size: uint32(len(code))}},
		SymbolNames: map[uint64]string{0x4000: "cmp_pool"},
	}
	res, err := FindPoolReferences(ctx, []int{6}, Options{})
	if err != nil {
		t.Fatalf("FindPoolReferences: %v", err)
	}
	if len(res.References) != 1 || res.References[0].PoolIndex != 6 || res.References[0].InstrAddr != 0x4000 {
		t.Fatalf("direct x64 PP compare = %+v, want one pool[6] ref", res.References)
	}
}

func TestFindPoolReferencesARM64PairLoadReportsBothSlots(t *testing.T) {
	// LDP X0, X1, [X27,#24]. Object-pool elements start at +16, so the
	// pair references pool[1] and pool[2].
	raw := uint32(0xA9400000 | (3 << 15) | (1 << 10) | (27 << 5))
	code := make([]byte, 8)
	binary.LittleEndian.PutUint32(code[:4], raw)
	binary.LittleEndian.PutUint32(code[4:], 0xD65F03C0) // RET
	ctx := &analysis.AnalysisContext{
		Code: code, CodeVA: 0x5000, IsARM64: true,
		Ranges:      []cluster.CodeRange{{RefID: 1, PCOffset: 0, Size: uint32(len(code))}},
		SymbolNames: map[uint64]string{0x5000: "pair_pool"},
	}
	res, err := FindPoolReferences(ctx, []int{1, 2}, Options{})
	if err != nil {
		t.Fatalf("FindPoolReferences: %v", err)
	}
	if len(res.References) != 2 || res.References[0].PoolIndex != 1 || res.References[1].PoolIndex != 2 {
		t.Fatalf("pair refs = %+v, want pool[1], pool[2]", res.References)
	}
}

func TestFindPoolReferencesReferenceCapIsExplicit(t *testing.T) {
	code := []byte{
		0x60, 0x0F, 0x40, 0xF9, // pool[1]
		0x61, 0x0F, 0x40, 0xF9, // pool[1]
		0xC0, 0x03, 0x5F, 0xD6,
	}
	ctx := &analysis.AnalysisContext{
		Code: code, CodeVA: 0x6000, IsARM64: true,
		Ranges: []cluster.CodeRange{{RefID: 1, PCOffset: 0, Size: uint32(len(code))}},
	}
	res, err := FindPoolReferences(ctx, []int{1}, Options{MaxRefs: 1})
	if err != nil {
		t.Fatalf("FindPoolReferences: %v", err)
	}
	if len(res.References) != 1 || !res.ReferenceLimitReached {
		t.Fatalf("reference cap not explicit: %+v", res)
	}
}

func TestFindPoolReferencesRejectsMalformedX64(t *testing.T) {
	ctx := &analysis.AnalysisContext{
		Code: []byte{0xc4}, CodeVA: 0x7000, IsARM64: false, // truncated VEX prefix
		Ranges: []cluster.CodeRange{{RefID: 1, PCOffset: 0, Size: 1}},
	}
	if _, err := FindPoolReferences(ctx, []int{1}, Options{}); err == nil {
		t.Fatal("malformed x64 function accepted")
	}
}
