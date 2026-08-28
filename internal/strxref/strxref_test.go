package strxref

import (
	"testing"

	"aotopsy/internal/cluster"
	"aotopsy/internal/analysis"
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

	refs, scanned := FindPoolReferences(ctx, []int{1}, Options{})
	if scanned != 1 {
		t.Fatalf("expected 1 function scanned, got %d", scanned)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 reference, got %d: %+v", len(refs), refs)
	}
	if refs[0].FuncName != "test_fn" || refs[0].PoolIndex != 1 {
		t.Errorf("unexpected reference: %+v", refs[0])
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

	refs, _ := FindPoolReferences(ctx, []int{999}, Options{})
	if len(refs) != 0 {
		t.Errorf("expected 0 references for an untargeted pool index, got %d: %+v", len(refs), refs)
	}
}

// TestFindPoolReferences_DefaultIsUnbounded is a regression test for
// the deliberate design choice documented in Options: unlike internal/
// ffitrace, this package defaults to a FULL scan (MaxScan=0 means "no
// cap"), justified by measuring FuncIR-only construction as cheap even
// at real production scale (129k functions, 9.3s, flat memory). This
// test proves the zero-value Options actually scans every eligible
// function, using a function count well above ffitrace's own default
// bound (500), so a regression back to a hidden cap would be caught.
func TestFindPoolReferences_DefaultIsUnbounded(t *testing.T) {
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

	_, scanned := FindPoolReferences(ctx, []int{0}, Options{})
	if scanned != numFuncs {
		t.Fatalf("expected default (MaxScan=0) to scan all %d functions, scanned %d", numFuncs, scanned)
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

	_, scanned := FindPoolReferences(ctx, []int{0}, Options{MaxScan: explicitMax})
	if scanned != explicitMax {
		t.Fatalf("expected explicit MaxScan=%d to be honored, scanned %d", explicitMax, scanned)
	}
}
