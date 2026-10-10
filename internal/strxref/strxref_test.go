package strxref

import (
	"encoding/binary"
	"testing"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cluster"
)

// arm64Ret is the 4-byte little-endian encoding of ARM64 "ret".
var arm64Ret = []byte{0xC0, 0x03, 0x5F, 0xD6}

func arm64Code(words ...uint32) []byte {
	code := make([]byte, len(words)*4)
	for i, word := range words {
		binary.LittleEndian.PutUint32(code[i*4:], word)
	}
	return code
}

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
	if res.Scanned != numFuncs || res.ScanLimitReached || !res.Complete() {
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
	if res.Scanned != explicitMax || !res.ScanLimitReached || res.Complete() {
		t.Fatalf("expected MaxScan=%d with explicit truncation, scanned=%d limited=%v", explicitMax, res.Scanned, res.ScanLimitReached)
	}
}

func TestFindPoolReferencesScanCapStopsBeforeNextMalformedRange(t *testing.T) {
	ctx := &analysis.AnalysisContext{
		Code:    arm64Ret,
		CodeVA:  0x1100,
		IsARM64: true,
		Ranges: []cluster.CodeRange{
			{RefID: 1, PCOffset: 0, Size: uint32(len(arm64Ret))},
			{RefID: 2, PCOffset: uint32(len(arm64Ret)), Size: 0x1000},
		},
	}
	res, err := FindPoolReferences(ctx, []int{0}, Options{MaxScan: 1})
	if err != nil {
		t.Fatalf("range after scan cap was inspected: %v", err)
	}
	if res.Attempted != 1 || res.Scanned != 1 || !res.ScanLimitReached || res.Complete() {
		t.Fatalf("scan-cap accounting = %+v", res)
	}
}

func TestFindPoolReferencesDeduplicatesPhysicalInstruction(t *testing.T) {
	code := []byte{
		0x60, 0x0F, 0x40, 0xF9, // ldr x0, [x27, #24] -> pool[1]
		0xC0, 0x03, 0x5F, 0xD6,
	}
	r := cluster.CodeRange{RefID: 1, PCOffset: 0, Size: uint32(len(code))}
	ctx := &analysis.AnalysisContext{
		Code:        code,
		CodeVA:      0xd000,
		IsARM64:     true,
		Ranges:      []cluster.CodeRange{r, r},
		SymbolNames: map[uint64]string{0xd000: "duplicate_range"},
	}
	// Duplicate targets and duplicate ranges exercise both sources of duplicate
	// discovery. The API returns physical instruction-slot xrefs, not one row per
	// input record.
	res, err := FindPoolReferences(ctx, []int{1, 1}, Options{})
	if err != nil {
		t.Fatalf("FindPoolReferences: %v", err)
	}
	if len(res.References) != 1 || res.References[0].InstrAddr != 0xd000 || res.References[0].PoolIndex != 1 {
		t.Fatalf("dedup result = %+v, want one physical pool[1] reference", res.References)
	}
	if res.Attempted != 2 || res.Scanned != 2 || !res.Complete() {
		t.Fatalf("duplicate range scan accounting = %+v", res)
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

func TestFindPoolReferencesX64AllStaticPPOperandsAndRejectsIndexed(t *testing.T) {
	// Assembled with GNU as from exact [r15+0x3f] forms. The first five
	// instructions are MOV/CMP/TEST/CALL/JMP with a directly-addressable PP
	// operand, followed by the exact MOV-store shape used by
	// StoreWordToPoolIndex. The indexed MOV must NOT be treated as a
	// constant pool slot because the runtime index is unknown.
	code := []byte{
		0x49, 0x8b, 0x47, 0x3f, // mov  0x3f(%r15), %rax
		0x49, 0x3b, 0x47, 0x3f, // cmp  0x3f(%r15), %rax
		0x49, 0x85, 0x47, 0x3f, // test %rax, 0x3f(%r15)
		0x41, 0xff, 0x57, 0x3f, // call *0x3f(%r15)
		0x41, 0xff, 0x67, 0x3f, // jmp  *0x3f(%r15)
		0x49, 0x89, 0x47, 0x3f, // mov  %rax, 0x3f(%r15) -- pool store
		0x49, 0x8b, 0x4c, 0xc7, 0x3f, // mov 0x3f(%r15,%rax,8), %rcx -- indexed
		0xc3,
	}
	ctx := &analysis.AnalysisContext{
		Code: code, CodeVA: 0x8000, IsARM64: false,
		Ranges:      []cluster.CodeRange{{RefID: 1, PCOffset: 0, Size: uint32(len(code))}},
		SymbolNames: map[uint64]string{0x8000: "all_pp_forms"},
	}
	res, err := FindPoolReferences(ctx, []int{6}, Options{})
	if err != nil {
		t.Fatalf("FindPoolReferences: %v", err)
	}
	wantPCs := []uint64{0x8000, 0x8004, 0x8008, 0x800c, 0x8010, 0x8014}
	if len(res.References) != len(wantPCs) {
		t.Fatalf("direct x64 PP refs = %+v, want %d refs", res.References, len(wantPCs))
	}
	for i, wantPC := range wantPCs {
		if got := res.References[i]; got.InstrAddr != wantPC || got.PoolIndex != 6 {
			t.Fatalf("ref[%d] = %+v, want PC=%#x pool[6]", i, got, wantPC)
		}
	}
	if !res.Complete() || res.Attempted != 1 || res.Scanned != 1 {
		t.Fatalf("complete x64 scan stats = %+v", res)
	}
}

func TestFindPoolReferencesX64WidePoolOperandReportsBothSlots(t *testing.T) {
	// Exact LoadQImmediate x64 shape: movups 0x3f(%r15),%xmm0. Immediate128
	// occupies two consecutive 8-byte pool entries on 64-bit Dart, so the one
	// 16-byte memory operand references pool[6] and pool[7].
	code := []byte{0x41, 0x0f, 0x10, 0x47, 0x3f, 0xc3}
	ctx := &analysis.AnalysisContext{
		Code: code, CodeVA: 0x8800, IsARM64: false,
		Ranges: []cluster.CodeRange{{RefID: 1, PCOffset: 0, Size: uint32(len(code))}},
	}
	res, err := FindPoolReferences(ctx, []int{6, 7}, Options{})
	if err != nil {
		t.Fatalf("FindPoolReferences: %v", err)
	}
	if len(res.References) != 2 || res.References[0].InstrAddr != 0x8800 || res.References[1].InstrAddr != 0x8800 ||
		res.References[0].PoolIndex != 6 || res.References[1].PoolIndex != 7 {
		t.Fatalf("wide x64 pool refs = %+v, want pool[6], pool[7] at one MOVUPS", res.References)
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

func TestFindPoolReferencesARM64LargeWordFallback(t *testing.T) {
	// Exact LoadWordFromPoolIndex fallback for byte offset 0x01000010:
	//   movz x16,#0x10
	//   movk x16,#0x100,lsl#16
	//   ldr  x16,[x27,x16]
	// SDK assembler_arm64.cc uses this when the offset fits neither direct LDR
	// nor ADD-immediate+LDR. Pool index = (0x01000010 - 16) / 8 = 0x200000.
	movz := uint32(0xD2800000 | (0x10 << 5) | 16)
	movk := uint32(0xF2800000 | (1 << 21) | (0x100 << 5) | 16)
	ldr := uint32(0xF8606800 | (16 << 16) | (27 << 5) | 16)
	code := arm64Code(movz, movk, ldr, 0xD65F03C0)
	ctx := &analysis.AnalysisContext{
		Code: code, CodeVA: 0x9000, IsARM64: true,
		Ranges:      []cluster.CodeRange{{RefID: 1, PCOffset: 0, Size: uint32(len(code))}},
		SymbolNames: map[uint64]string{0x9000: "large_word"},
	}
	res, err := FindPoolReferences(ctx, []int{0x200000}, Options{})
	if err != nil {
		t.Fatalf("FindPoolReferences: %v", err)
	}
	if len(res.References) != 1 || res.References[0].InstrAddr != 0x9008 || res.References[0].PoolIndex != 0x200000 {
		t.Fatalf("large-word refs = %+v, want one pool[0x200000] LDR", res.References)
	}
}

func TestFindPoolReferencesARM64LargePairFallback(t *testing.T) {
	// Exact >=3.10 large LoadDoubleWordFromPoolIndex shape for a 32-bit byte
	// offset: materialize the displacement, add untagged PP, then LDP.
	movz := uint32(0xD2800000 | (0x10 << 5) | 16)
	movk := uint32(0xF2800000 | (1 << 21) | (0x100 << 5) | 16)
	add := uint32(0x8B000000 | (27 << 16) | (16 << 5) | 16) // add x16,x16,x27
	ldp := uint32(0xA9400000 | (24 << 10) | (16 << 5) | 5)  // ldp x5,x24,[x16]
	code := arm64Code(movz, movk, add, ldp, 0xD65F03C0)
	ctx := &analysis.AnalysisContext{
		Code: code, CodeVA: 0xa000, IsARM64: true,
		Ranges:      []cluster.CodeRange{{RefID: 1, PCOffset: 0, Size: uint32(len(code))}},
		SymbolNames: map[uint64]string{0xa000: "large_pair"},
	}
	res, err := FindPoolReferences(ctx, []int{0x200000, 0x200001}, Options{})
	if err != nil {
		t.Fatalf("FindPoolReferences: %v", err)
	}
	if len(res.References) != 2 || res.References[0].InstrAddr != 0xa00c || res.References[1].InstrAddr != 0xa00c ||
		res.References[0].PoolIndex != 0x200000 || res.References[1].PoolIndex != 0x200001 {
		t.Fatalf("large-pair refs = %+v, want adjacent pool slots from one LDP", res.References)
	}
}

func TestFindPoolReferencesARM64WideQPoolLoadReportsBothSlots(t *testing.T) {
	// ldr q2,[x27,#16] is the direct LoadQImmediate pool access for index 0.
	// The 16-byte load covers Immediate128's two adjacent pool entries.
	code := arm64Code(0x3DC00762, 0xD65F03C0)
	ctx := &analysis.AnalysisContext{
		Code: code, CodeVA: 0xa080, IsARM64: true,
		Ranges: []cluster.CodeRange{{RefID: 1, PCOffset: 0, Size: uint32(len(code))}},
	}
	res, err := FindPoolReferences(ctx, []int{0, 1}, Options{})
	if err != nil {
		t.Fatalf("FindPoolReferences: %v", err)
	}
	if len(res.References) != 2 || res.References[0].InstrAddr != 0xa080 || res.References[1].InstrAddr != 0xa080 ||
		res.References[0].PoolIndex != 0 || res.References[1].PoolIndex != 1 {
		t.Fatalf("wide ARM64 Q refs = %+v, want pool[0], pool[1] at one LDR Q", res.References)
	}
}

func TestFindPoolReferencesARM64StoreWordShapes(t *testing.T) {
	// Exact StoreWordToPoolIndex lowerings from assembler_arm64.cc >=3.3:
	//   str x3,[PP,#24]                     -> pool[1]
	//   add x16,PP,#0x4000; str x3,[x16,#16] -> pool[2048]
	//   movz/movk x16,#0x01000010; str x3,[PP,x16] -> pool[0x200000]
	// The raw words were replay-assembled with aarch64-linux-gnu-as.
	code := arm64Code(
		0xF9000F63,
		0x91401370,
		0xF9000A03,
		0xD2800210,
		0xF2A02010,
		0xF8306B63,
		0xD65F03C0,
	)
	ctx := &analysis.AnalysisContext{
		Code: code, CodeVA: 0xa100, IsARM64: true,
		Ranges:      []cluster.CodeRange{{RefID: 1, PCOffset: 0, Size: uint32(len(code))}},
		SymbolNames: map[uint64]string{0xa100: "pool_stores"},
	}
	res, err := FindPoolReferences(ctx, []int{1, 2048, 0x200000}, Options{})
	if err != nil {
		t.Fatalf("FindPoolReferences: %v", err)
	}
	want := []Reference{
		{InstrAddr: 0xa100, PoolIndex: 1},
		{InstrAddr: 0xa108, PoolIndex: 2048},
		{InstrAddr: 0xa114, PoolIndex: 0x200000},
	}
	if len(res.References) != len(want) {
		t.Fatalf("ARM64 store refs = %+v, want %d refs", res.References, len(want))
	}
	for i := range want {
		if res.References[i].InstrAddr != want[i].InstrAddr || res.References[i].PoolIndex != want[i].PoolIndex {
			t.Fatalf("store ref[%d] = %+v, want PC=%#x pool[%d]", i, res.References[i], want[i].InstrAddr, want[i].PoolIndex)
		}
	}
}

func TestFindPoolReferencesARM64DoesNotCarryPoolBaseAcrossJoin(t *testing.T) {
	// One predecessor reaches the LDR without executing the ADD. A linear
	// provenance scanner therefore fabricates pool[2046]; block-local SDK-shape
	// extraction must reject it.
	bEqToLdr := uint32(0x54000000 | (2 << 5))
	addX0PP := uint32(0x91000000 | (1 << 22) | (4 << 10) | (27 << 5))
	ldrX16X0 := uint32(0xF9400010)
	code := arm64Code(bEqToLdr, addX0PP, ldrX16X0, 0xD65F03C0)
	ctx := &analysis.AnalysisContext{
		Code: code, CodeVA: 0xb000, IsARM64: true,
		Ranges:      []cluster.CodeRange{{RefID: 1, PCOffset: 0, Size: uint32(len(code))}},
		SymbolNames: map[uint64]string{0xb000: "join"},
	}
	res, err := FindPoolReferences(ctx, []int{2046}, Options{})
	if err != nil {
		t.Fatalf("FindPoolReferences: %v", err)
	}
	if len(res.References) != 0 {
		t.Fatalf("join-bypassed ADD fabricated PP reference: %+v", res.References)
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
	if len(res.References) != 1 || !res.ReferenceLimitReached || res.Complete() {
		t.Fatalf("reference cap not explicit: %+v", res)
	}
	if res.Attempted != 1 || res.Scanned != 0 {
		t.Fatalf("partially scanned capped function counted as complete: attempted=%d scanned=%d", res.Attempted, res.Scanned)
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

func TestFindPoolReferencesRejectsTruncatedDeclaredRange(t *testing.T) {
	ctx := &analysis.AnalysisContext{
		Code: arm64Ret, CodeVA: 0xc000, IsARM64: true,
		Ranges: []cluster.CodeRange{{RefID: 1, PCOffset: 0, Size: 8}},
	}
	if _, err := FindPoolReferences(ctx, []int{1}, Options{}); err == nil {
		t.Fatal("declared function range extending beyond code image was clamped instead of rejected")
	}
}
