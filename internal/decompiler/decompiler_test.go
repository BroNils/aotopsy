package decompiler

import (
	"strings"
	"testing"

	"aotopsy/internal/decompiler/compare"
	"aotopsy/internal/sdk"
)

// TestEmitSimpleBranch builds a tiny synthetic FuncIR by hand (bypassing
// the ARM64/x86 lifters, which are exercised separately) to check the
// core emit+compact+naming pipeline produces sane, non-crashing,
// non-empty pseudocode for a simple two-way branch.
func TestEmitSimpleBranch(t *testing.T) {
	fir := newFuncIR("test_fn", 0x1000)
	fir.ArgRegs = arm64ArgRegs
	fir.FrameReg = sdk.ARM64FrameRegStr
	fir.ReturnReg = sdk.ARM64ReturnRegStr
	fir.LinkReg = sdk.ARM64LinkRegStr
	fir.PoolReg = sdk.ARM64PoolRegStr
	fir.ThreadReg = sdk.ARM64ThreadRegStr

	// block 0: cmp x0, x1; b.eq -> block 1 (taken) else block 2 (fallthrough)
	fir.addBlock(Block{
		ID:      0,
		StartVA: 0x1000,
		Instrs: []Instr{
			{Addr: 0x1000, Op: OpOther, Src: "cmp x0, x1"},
			{Addr: 0x1004, Op: OpBranch, Src: "b.eq 0x1010", Target: "0x1010", CondKind: "cmp", CondOp: "=="},
		},
		Succs: []Succ{{BlockID: 1, Cond: "T"}, {BlockID: 2, Cond: "F"}},
	})
	// block 1 (taken): mov x0, #1; ret
	fir.addBlock(Block{
		ID:      1,
		StartVA: 0x1010,
		Instrs: []Instr{
			{Addr: 0x1010, Op: OpOther, Src: "mov x0, #1"},
			{Addr: 0x1014, Op: OpReturn, Src: "ret"},
		},
	})
	// block 2 (fallthrough): mov x0, #0; ret
	fir.addBlock(Block{
		ID:      2,
		StartVA: 0x1008,
		Instrs: []Instr{
			{Addr: 0x1008, Op: OpOther, Src: "mov x0, #0"},
			{Addr: 0x100c, Op: OpReturn, Src: "ret"},
		},
	})

	art := EmitPseudocode(fir, nil, nil)
	if art.Source == "" {
		t.Fatal("expected non-empty pseudocode")
	}
	if !strings.Contains(art.Source, "if (") {
		t.Errorf("expected an if-condition in output, got:\n%s", art.Source)
	}
	if !strings.Contains(art.Source, "return 1;") || !strings.Contains(art.Source, "return 0;") {
		t.Errorf("expected both branch outcomes to appear, got:\n%s", art.Source)
	}
	t.Logf("emitted pseudocode:\n%s", art.Source)
}

// TestEmitCallWithSymbol exercises direct-call symbol resolution and
// call-intent decoding end-to-end.
func TestEmitCallWithSymbol(t *testing.T) {
	fir := newFuncIR("caller_fn", 0x2000)
	fir.ArgRegs = arm64ArgRegs
	fir.FrameReg = sdk.ARM64FrameRegStr
	fir.ReturnReg = sdk.ARM64ReturnRegStr
	fir.LinkReg = sdk.ARM64LinkRegStr
	fir.PoolReg = sdk.ARM64PoolRegStr
	fir.ThreadReg = sdk.ARM64ThreadRegStr

	fir.addBlock(Block{
		ID:      0,
		StartVA: 0x2000,
		Instrs: []Instr{
			{Addr: 0x2000, Op: OpCall, Src: "bl 0x3000", Target: "0x3000"},
			{Addr: 0x2004, Op: OpReturn, Src: "ret"},
		},
	})

	symbols := func(va uint64) (string, bool) {
		if va == 0x3000 {
			return "dart_core_String_substring", true
		}
		return "", false
	}

	art := EmitPseudocode(fir, symbols, nil)
	if !strings.Contains(art.Source, "dart_core_String_substring") {
		t.Errorf("expected symbol name in output, got:\n%s", art.Source)
	}
	if !strings.Contains(art.Source, "stdlib:dart.core") {
		t.Errorf("expected resolved call intent comment, got:\n%s", art.Source)
	}
	if art.Stats.TotalCalls != 1 || art.Stats.SemanticDirectCalls != 1 {
		t.Errorf("unexpected call stats: %+v", art.Stats)
	}
}

// TestDecodeX86RangeMultipleReturns is a regression test for a real bug
// found comparing this decompiler's output against a from-scratch Flutter
// app's known Dart source: DecodeX86Range used to stop at the FIRST RET
// instruction, silently dropping any code after an early-return guard
// clause (e.g. MathTools.factorial's `if (n <= 1) return 1;` followed by
// the real recursive-multiply case) -- the recursive call's target VA
// then fell outside the decoded instruction set entirely, rendering as
// an "unresolved branch target" instead of the real call.
func TestDecodeX86RangeMultipleReturns(t *testing.T) {
	// push rbp; mov rbp,rsp; ret; nop; ret  -- a function shape with two
	// RET instructions, the second one representing code that must still
	// be decoded (a real function would have real logic here, but the
	// point is purely: does decoding continue past the first RET?).
	code := []byte{
		0x55,             // push rbp
		0x48, 0x89, 0xe5, // mov rbp, rsp
		0xc3, // ret
		0x90, // nop
		0xc3, // ret
	}
	insts := DecodeX86Range(code, 0x1000)
	if len(insts) != 5 {
		t.Fatalf("DecodeX86Range: got %d instructions, want 5 (decoding must not stop at the first RET); insts=%+v", len(insts), insts)
	}
	if insts[len(insts)-1].VA != 0x1006 {
		t.Errorf("last decoded instruction at 0x%x, want 0x1006 (the second ret)", insts[len(insts)-1].VA)
	}
}

func TestSelectorCandidates(t *testing.T) {
	got := classifyStandardSelector("_nativeSetInt64")
	if got == "" {
		t.Fatal("expected a selector-table match for _nativeSetInt64")
	}
	if !strings.Contains(got, "setInt64") {
		t.Errorf("expected setInt64 in resolved path, got %q", got)
	}
}

// TestParseOperandNegativeDisplacement is a regression test for a real
// bug found testing this decompiler against an actual libapp.so: x86's
// bare-minus "[RBP-0x8]" memory syntax (no leading '+') was mis-parsed,
// producing a garbage huge local-slot key instead of -8.
func TestParseOperandNegativeDisplacement(t *testing.T) {
	op := parseOperand("[rbp-0x8]")
	if !op.isMem || op.memBase != "rbp" || !op.hasDisp || op.memDisp != -8 {
		t.Fatalf("parseOperand([rbp-0x8]) = %+v, want base=rbp disp=-8", op)
	}

	op2 := parseOperand("[x1, #0x10]")
	if !op2.isMem || op2.memBase != "x1" || op2.memDisp != 0x10 {
		t.Fatalf("parseOperand([x1, #0x10]) = %+v, want base=x1 disp=16", op2)
	}

	op3 := parseOperand("[rax+rcx*4+0x8]")
	if !op3.isMem || op3.memBase != "rax" || op3.memDisp != 8 {
		t.Fatalf("parseOperand([rax+rcx*4+0x8]) = %+v, want base=rax disp=8 (scaled index ignored)", op3)
	}
}

func TestReplaceIdentToken(t *testing.T) {
	in := "x29.f0 + x2 - x29foo"
	out := compare.ReplaceIdentToken(in, "x29", "framePointer")
	want := "framePointer.f0 + x2 - x29foo"
	if out != want {
		t.Errorf("ReplaceIdentToken: got %q want %q", out, want)
	}
}

// simpleRetFir builds a minimal one-block FuncIR that just returns,
// enough to exercise EmitPseudocode's signature-line construction
// without needing a real branch/CFG.
func simpleRetFir(argRegIndices []int, paramTypeNames []string) *FuncIR {
	fir := newFuncIR("test_fn", 0x1000)
	fir.ArgRegs = arm64ArgRegs
	fir.FrameReg = sdk.ARM64FrameRegStr
	fir.ReturnReg = sdk.ARM64ReturnRegStr
	fir.LinkReg = sdk.ARM64LinkRegStr
	fir.PoolReg = sdk.ARM64PoolRegStr
	fir.ThreadReg = sdk.ARM64ThreadRegStr
	fir.ArgRegIndices = argRegIndices
	fir.ParamTypeNames = paramTypeNames
	fir.addBlock(Block{
		ID:      0,
		StartVA: 0x1000,
		Instrs:  []Instr{{Addr: 0x1000, Op: OpReturn, Src: "ret"}},
	})
	return fir
}

// TestEmitPseudocode_ParamTypeNames_CountMatchShowsRealTypes verifies
// the positive path: when ParamTypeNames' length exactly matches the
// confidently-resolved arity (ArgRegIndices), real type names appear in
// the signature instead of "dynamic".
func TestEmitPseudocode_ParamTypeNames_CountMatchShowsRealTypes(t *testing.T) {
	fir := simpleRetFir([]int{0, 1}, []string{"int", "String"})
	art := EmitPseudocode(fir, nil, nil)
	// Trusted types also drive arg renaming, so the parameters are shown as
	// "<semantic-name><index>" -- the index keeps the mapping back to argN
	// unambiguous and prevents two same-typed params sharing a name.
	if !strings.Contains(art.Source, "int n0") || !strings.Contains(art.Source, "String str1") {
		t.Errorf("expected real param types in signature, got:\n%s", art.Source)
	}
	// The signature and the body must agree on the parameter name.
	if strings.Contains(art.Source, "arg0") {
		t.Errorf("renamed parameter must not still appear as arg0, got:\n%s", art.Source)
	}
}

// TestEmitPseudocode_ParamTypeNames_CountMismatchFallsBackToDynamic is
// the safety-gate regression test: this exact class of data
// (FunctionType/signature_) was already tried once for arity display
// and reverted after being found unreliable (wrong at least once for a
// real function) -- see ARCHITECTURE.md and FuncIR.ParamTypeNames' doc
// comment. A count mismatch between ParamTypeNames and the
// independently-verified ArgRegIndices must silently fall back to
// "dynamic", never show a possibly-misaligned type as if trustworthy.
func TestEmitPseudocode_ParamTypeNames_CountMismatchFallsBackToDynamic(t *testing.T) {
	fir := simpleRetFir([]int{0, 1}, []string{"int"}) // 1 name, 2 args
	art := EmitPseudocode(fir, nil, nil)
	if !strings.Contains(art.Source, "dynamic arg0") || !strings.Contains(art.Source, "dynamic arg1") {
		t.Errorf("expected fallback to dynamic on count mismatch, got:\n%s", art.Source)
	}
	if strings.Contains(art.Source, "int arg0") {
		t.Errorf("must not show a type when counts disagree, got:\n%s", art.Source)
	}
}

// TestEmitPseudocode_ParamTypeNames_UnresolvedArityFallsBackToDynamic
// verifies the OTHER half of the gate: even if ParamTypeNames happens
// to have the same length as the raw ArgRegs fallback set, it must not
// be trusted unless ArgRegIndices was ITSELF confidently resolved (the
// independent cross-check this gate relies on doesn't exist otherwise).
func TestEmitPseudocode_ParamTypeNames_UnresolvedArityFallsBackToDynamic(t *testing.T) {
	fir := simpleRetFir(nil, make([]string, len(arm64ArgRegs))) // arity unresolved
	for i := range fir.ParamTypeNames {
		fir.ParamTypeNames[i] = "int"
	}
	art := EmitPseudocode(fir, nil, nil)
	if strings.Contains(art.Source, "int arg") {
		t.Errorf("must not trust ParamTypeNames when ArgRegIndices is unresolved, got:\n%s", art.Source)
	}
}

// TestEmitPseudocode_ParamTypeNames_QuestionMarkFallsBackPerArgument
// verifies "?" (an individually-unresolved element within an otherwise
// count-matching, trusted list) falls back to "dynamic" for just that
// one argument, not the whole signature.
func TestEmitPseudocode_ParamTypeNames_QuestionMarkFallsBackPerArgument(t *testing.T) {
	fir := simpleRetFir([]int{0, 1}, []string{"String", "?"})
	art := EmitPseudocode(fir, nil, nil)
	if !strings.Contains(art.Source, "String str0") {
		t.Errorf("expected real type for arg0, got:\n%s", art.Source)
	}
	if !strings.Contains(art.Source, "dynamic arg1") {
		t.Errorf("expected dynamic fallback for the \"?\" arg1, got:\n%s", art.Source)
	}
}

// TestLiftStateClone_LocalsShared (P4-6 / E-004/E-005) verifies that
// Clone shares the Locals map by reference — this is intentional.
// emitBranch relies on cross-branch local-name visibility: a local
// defined in branch A must be visible in branch B. Deep-copying Locals
// would break this contract.
func TestLiftStateClone_LocalsShared(t *testing.T) {
	s := newLiftState("")
	s.Locals[0x10] = "var_a"
	s.Regs["x0"] = "expr_x0"

	c := s.Clone()

	// Locals must be shared by reference: writing via clone should be
	// visible in the original. This is the intentional behavior that
	// emitBranch relies on for cross-branch local-name visibility.
	c.Locals[0x20] = "var_b"
	if s.Locals[0x20] != "var_b" {
		t.Error("Locals should be shared by reference — write via clone must be visible in original")
	}

	// Regs must be deep-copied (independent maps).
	c.Regs["x1"] = "expr_x1"
	if s.Regs["x1"] != "" {
		t.Error("Regs should be deep-copied (independent maps)")
	}

	// Original Regs should still be intact.
	if s.Regs["x0"] != "expr_x0" {
		t.Error("Original Regs should be unchanged after clone modification")
	}
}

// TestApplyOther_NewMnemonics (P3-feasible-1) verifies that the newly
// added mnemonic handlers produce correct symbolic state instead of
// silently dropping to /* unknown */.
func TestApplyOther_NewMnemonics(t *testing.T) {
	fir := newFuncIR("test_fn", 0x1000)
	fir.ArgRegs = arm64ArgRegs
	fir.FrameReg = sdk.ARM64FrameRegStr
	fir.ReturnReg = sdk.ARM64ReturnRegStr
	fir.LinkReg = sdk.ARM64LinkRegStr
	fir.PoolReg = sdk.ARM64PoolRegStr
	fir.ThreadReg = sdk.ARM64ThreadRegStr

	tests := []struct {
		name string
		src  string
		reg  string
		want string
	}{
		{"mvn", "mvn x0, x1", "x0", "(~x1)"},
		{"neg", "neg x0, x1", "x0", "(-x1)"},
		{"not", "not x0, x1", "x0", "(~x1)"},
		{"adr", "adr x0, #0x100", "x0", "256"},
		{"adrp", "adrp x0, #0x100000", "x0", "1048576"},
		{"movzx", "movzx x0, x1", "x0", "x1"},
		{"movsxd", "movsxd x0, x1", "x0", "(int64)(x1)"},
		{"movsx", "movsx x0, x1", "x0", "(int)(x1)"},
		{"cmove", "cmove rax, rbx", "rax", "(/* e */ ? rbx : rax)"},
		{"sete", "sete al", "al", "(/* e */ ? 1 : 0)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newLiftState("")
			ins := Instr{Addr: 0x1000, Op: OpOther, Src: tt.src}
			ApplyOther(fir, s, ins)
			got := s.lookupReg(tt.reg)
			if got != tt.want {
				t.Errorf("ApplyOther(%q): Regs[%s] = %q, want %q", tt.src, tt.reg, got, tt.want)
			}
		})
	}
}

// TestVoidCallDetection (P3-feasible-3) verifies that known void calls
// are emitted without a temp variable assignment.
func TestVoidCallDetection(t *testing.T) {
	if !isVoidCall("print", "") {
		t.Error("print should be detected as void")
	}
	if !isVoidCall("", "setState") {
		t.Error("setState selector hint should be detected as void")
	}
	if isVoidCall("someFunction", "") {
		t.Error("someFunction should not be detected as void")
	}
	if isVoidCall("", "unknownMethod") {
		t.Error("unknownMethod should not be detected as void")
	}
}
