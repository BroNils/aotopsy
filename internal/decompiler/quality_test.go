package decompiler

import (
	"strings"
	"testing"

	"aotopsy/internal/sdk"
)

// TestCFGVerificationCoverageCorrectness tests that VerifyCFG accurately
// reports >0% coverage on cleanly structured pseudocode (reversing the inverted D12 metric bug).
func TestCFGVerificationCoverageCorrectness(t *testing.T) {
	fir := newFuncIR("test_structured_fn", 0x1000)
	fir.ArgRegs = arm64ArgRegs
	fir.FrameReg = sdk.ARM64FrameRegStr
	fir.ReturnReg = sdk.ARM64ReturnRegStr
	fir.LinkReg = sdk.ARM64LinkRegStr
	fir.PoolReg = sdk.ARM64PoolRegStr
	fir.ThreadReg = sdk.ARM64ThreadRegStr

	// 3-block simple if/else function
	fir.addBlock(Block{
		ID:      0,
		StartVA: 0x1000,
		Instrs: []Instr{
			{Addr: 0x1000, Op: OpOther, Src: "cmp x0, #0"},
			{Addr: 0x1004, Op: OpBranch, Src: "b.eq 0x1010", Target: "0x1010", CondKind: "cmp", CondOp: "=="},
		},
		Succs: []Succ{{BlockID: 1, Cond: "T"}, {BlockID: 2, Cond: "F"}},
	})
	fir.addBlock(Block{
		ID:      1,
		StartVA: 0x1010,
		Instrs: []Instr{
			{Addr: 0x1010, Op: OpOther, Src: "mov x0, #42"},
			{Addr: 0x1014, Op: OpReturn, Src: "ret"},
		},
	})
	fir.addBlock(Block{
		ID:      2,
		StartVA: 0x1008,
		Instrs: []Instr{
			{Addr: 0x1008, Op: OpOther, Src: "mov x0, #0"},
			{Addr: 0x100c, Op: OpReturn, Src: "ret"},
		},
	})

	art := EmitPseudocode(fir, nil, nil)
	ver := VerifyCFG(fir, art)

	if ver.CoveragePct < 50.0 {
		t.Errorf("expected CoveragePct >= 50%%, got %.2f%% (D12 inverted metric bug)", ver.CoveragePct)
	}
	if len(art.VisitedBlocks) != 3 {
		t.Errorf("expected 3 visited blocks in artifact, got %d: %v", len(art.VisitedBlocks), art.VisitedBlocks)
	}
	if ver.MatchedBranches != 1 {
		t.Errorf("expected 1 matched branch, got %d", ver.MatchedBranches)
	}
	if ver.MatchedReturns < 1 {
		t.Errorf("expected at least 1 matched return, got %d", ver.MatchedReturns)
	}
}

// TestQualityGateArm64AndX64Synthetic ensures both ARM64 and x86_64
// FuncIR can be decompiled, validated via ValidatePseudocode, and pass CFG verification.
func TestQualityGateArm64AndX64Synthetic(t *testing.T) {
	// 1. ARM64 test
	armFir := newFuncIR("arm64_sample", 0x4000)
	armFir.ArgRegs = arm64ArgRegs
	armFir.FrameReg = sdk.ARM64FrameRegStr
	armFir.ReturnReg = sdk.ARM64ReturnRegStr
	armFir.LinkReg = sdk.ARM64LinkRegStr
	armFir.PoolReg = sdk.ARM64PoolRegStr
	armFir.ThreadReg = sdk.ARM64ThreadRegStr

	armFir.addBlock(Block{
		ID:      0,
		StartVA: 0x4000,
		Instrs: []Instr{
			{Addr: 0x4000, Op: OpOther, Src: "add x0, x0, #1"},
			{Addr: 0x4004, Op: OpReturn, Src: "ret"},
		},
	})
	armArt := EmitPseudocode(armFir, nil, nil)
	if probs := ValidateSource(armArt.Source); len(probs) > 0 {
		t.Errorf("ARM64 pseudocode validation failed: %v\nSource:\n%s", probs, armArt.Source)
	}

	// 2. x86_64 test
	x64Fir := newFuncIR("x64_sample", 0x5000)
	x64Fir.ArgRegs = x86ArgRegs
	x64Fir.FrameReg = sdk.X86FrameRegStr
	x64Fir.ReturnReg = sdk.X86ReturnRegStr
	x64Fir.PoolReg = sdk.X86PoolRegStr
	x64Fir.ThreadReg = sdk.X86ThreadRegStr

	x64Fir.addBlock(Block{
		ID:      0,
		StartVA: 0x5000,
		Instrs: []Instr{
			{Addr: 0x5000, Op: OpOther, Src: "inc rax"},
			{Addr: 0x5004, Op: OpReturn, Src: "ret"},
		},
	})
	x64Art := EmitPseudocode(x64Fir, nil, nil)
	if probs := ValidateSource(x64Art.Source); len(probs) > 0 {
		t.Errorf("x86_64 pseudocode validation failed: %v\nSource:\n%s", probs, x64Art.Source)
	}

	// Check ident stats
	idStats := collectIdentStats(armArt.Source)
	if len(idStats) == 0 {
		t.Errorf("expected ident stats on ARM64, got 0")
	}
}

// TestLoopStructuringQuality tests that backward jumps form structured while loops
// and do not leak broken gotos.
func TestLoopStructuringQuality(t *testing.T) {
	fir := newFuncIR("loop_sample", 0x6000)
	fir.ArgRegs = arm64ArgRegs
	fir.FrameReg = sdk.ARM64FrameRegStr
	fir.ReturnReg = sdk.ARM64ReturnRegStr

	// Block 0: Header, cmp x0, #10; b.ge -> Block 2 (exit), else Block 1 (body)
	fir.addBlock(Block{
		ID:      0,
		StartVA: 0x6000,
		Instrs: []Instr{
			{Addr: 0x6000, Op: OpOther, Src: "cmp x0, #10"},
			{Addr: 0x6004, Op: OpBranch, Src: "b.ge 0x6020", Target: "0x6020", CondKind: "cmp", CondOp: ">="},
		},
		Succs: []Succ{{BlockID: 2, Cond: "T"}, {BlockID: 1, Cond: "F"}},
	})
	// Block 1: Body, add x0, x0, #1; b -> Block 0 (back-edge)
	fir.addBlock(Block{
		ID:      1,
		StartVA: 0x6008,
		Instrs: []Instr{
			{Addr: 0x6008, Op: OpOther, Src: "add x0, x0, #1"},
			{Addr: 0x600c, Op: OpJump, Src: "b 0x6000", Target: "0x6000"},
		},
		Succs: []Succ{{BlockID: 0}},
	})
	// Block 2: Exit, ret
	fir.addBlock(Block{
		ID:      2,
		StartVA: 0x6020,
		Instrs: []Instr{
			{Addr: 0x6020, Op: OpReturn, Src: "ret"},
		},
	})

	art := EmitPseudocode(fir, nil, nil)
	if !strings.Contains(art.Source, "while (") && !strings.Contains(art.Source, "while(") {
		t.Logf("emitted loop code:\n%s", art.Source)
	}
	if probs := ValidateSource(art.Source); len(probs) > 0 {
		t.Errorf("Loop pseudocode validation failed: %v\nSource:\n%s", probs, art.Source)
	}
}

// TestStackOverflowElision verifies D1: prologue and loop stack-overflow checks
// are elided so function bodies are not duplicated into fake if/else branches.
func TestStackOverflowElision(t *testing.T) {
	fir := newFuncIR("check_stack_fn", 0x7000)
	fir.ArgRegs = arm64ArgRegs
	fir.FrameReg = sdk.ARM64FrameRegStr
	fir.ReturnReg = sdk.ARM64ReturnRegStr
	fir.LinkReg = sdk.ARM64LinkRegStr
	fir.PoolReg = sdk.ARM64PoolRegStr
	fir.ThreadReg = sdk.ARM64ThreadRegStr
	fir.StackReg = sdk.ARM64StackRegStr

	// Block 0: Prologue stack overflow check
	// ldr ip0, [x26, #0x58] (THR.stack_limit)
	// cmp x15, ip0
	// b.ls -> Block 2 (slow path), else Block 1 (main body)
	fir.addBlock(Block{
		ID:      0,
		StartVA: 0x7000,
		Instrs: []Instr{
			{Addr: 0x7000, Op: OpOther, Src: "ldr ip0, [x26, #0x58]"},
			{Addr: 0x7004, Op: OpOther, Src: "cmp x15, THR.stack_limit"},
			{Addr: 0x7008, Op: OpBranch, Src: "b.ls 0x7030", Target: "0x7030", CondKind: "cmp", CondOp: "<="},
		},
		Succs: []Succ{{BlockID: 2, Cond: "T"}, {BlockID: 1, Cond: "F"}},
	})
	// Block 1 (Main body): mov x0, #100; ret
	fir.addBlock(Block{
		ID:      1,
		StartVA: 0x7010,
		Instrs: []Instr{
			{Addr: 0x7010, Op: OpOther, Src: "mov x0, #100"},
			{Addr: 0x7014, Op: OpReturn, Src: "ret"},
		},
	})
	// Block 2 (Slow path): bl CallToRuntime; ret
	fir.addBlock(Block{
		ID:      2,
		StartVA: 0x7030,
		Instrs: []Instr{
			{Addr: 0x7030, Op: OpCall, Src: "bl 0x8000", Target: "0x8000"},
			{Addr: 0x7034, Op: OpReturn, Src: "ret"},
		},
	})

	art := EmitPseudocode(fir, nil, nil)
	if strings.Contains(art.Source, "if (x15 <= THR.stack_limit)") || strings.Contains(art.Source, "if (SP <= THR.stack_limit)") {
		t.Errorf("D1 violation: stack overflow check was emitted as if/else:\n%s", art.Source)
	}
	if strings.Contains(art.Source, "else {") {
		t.Errorf("D1 violation: function body was split into else block:\n%s", art.Source)
	}
	if !strings.Contains(art.Source, "return 100;") {
		t.Errorf("expected return 100 from main body, got:\n%s", art.Source)
	}
}

// TestCallArityTrimming verifies D2: call sites don't emit unassigned 8-argument register dumps.
func TestCallArityTrimming(t *testing.T) {
	fir := newFuncIR("test_call_arity", 0x8000)
	fir.ArgRegs = arm64ArgRegs
	fir.ReturnReg = sdk.ARM64ReturnRegStr

	// Block 0: Call a function with only x0 assigned
	fir.addBlock(Block{
		ID:      0,
		StartVA: 0x8000,
		Instrs: []Instr{
			{Addr: 0x8000, Op: OpOther, Src: "mov x1, #42"},
			{Addr: 0x8004, Op: OpCall, Src: "bl 0x9000", Target: "0x9000"},
			{Addr: 0x8008, Op: OpReturn, Src: "ret"},
		},
	})

	symbols := func(va uint64) (string, bool) {
		if va == 0x9000 {
			return "printInt", true
		}
		return "", false
	}

	art := EmitPseudocode(fir, symbols, nil)
	if strings.Contains(art.Source, "x1, x2, x3, x4, x5, x6, x7") {
		t.Errorf("D2 violation: call emitted trailing unassigned registers:\n%s", art.Source)
	}
	if !strings.Contains(art.Source, "printInt(42)") && !strings.Contains(art.Source, "printInt(x1)") {
		t.Errorf("expected call with trimmed arguments, got:\n%s", art.Source)
	}
}

// TestNullRegIdentityMath verifies the SAFE numeric identity foldings (x+0, x-0,
// x*1). It also verifies that NULL_REG arithmetic is NOT folded (audit A2):
// NULL_REG (x22) holds a pointer to the null object, not the integer 0, so
// `null + 10` must be preserved, not fabricated into `10`.
func TestNullRegIdentityMath(t *testing.T) {
	input := []string{
		"x0 = null + 10;",
		"x1 = x + 0;",
		"x2 = y - 0;",
		"x3 = 10 * 1;",
	}
	tree := parseStmts(input)
	cleanExprs(tree)
	out := printStmts(tree)
	joined := strings.Join(out, "\n")

	if !strings.Contains(joined, "null + 10") {
		t.Errorf("expected 'null + 10' to be PRESERVED (x22 is a pointer, not 0), got:\n%s", joined)
	}
	if strings.Contains(joined, "x + 0") {
		t.Errorf("expected 'x + 0' to fold to x, got:\n%s", joined)
	}
	if strings.Contains(joined, "y - 0") {
		t.Errorf("expected 'y - 0' to fold to y, got:\n%s", joined)
	}
	if strings.Contains(joined, "10 * 1") {
		t.Errorf("expected '10 * 1' to fold to 10, got:\n%s", joined)
	}
}

// TestIntraproceduralArityInference verifies D2: function signature declarations
// accurately reflect live-in registers (0-arg, 1-arg getter, 2-arg setter) instead of 8 fake args.
func TestIntraproceduralArityInference(t *testing.T) {
	// Case 1: 0-arg function (static constant return)
	fir0 := newFuncIR("getConstant", 0x1000)
	fir0.ArgRegs = arm64ArgRegs
	fir0.ReturnReg = sdk.ARM64ReturnRegStr
	fir0.addBlock(Block{
		ID:      0,
		StartVA: 0x1000,
		Instrs: []Instr{
			{Addr: 0x1000, Op: OpOther, Src: "mov x0, #42"},
			{Addr: 0x1004, Op: OpReturn, Src: "ret"},
		},
	})
	art0 := EmitPseudocode(fir0, nil, nil)
	if !strings.Contains(art0.Source, "dynamic getConstant() {") {
		t.Errorf("expected 0-arg signature 'dynamic getConstant() {', got:\n%s", art0.Source)
	}

	// Case 2: 1-arg getter (reads receiver x0)
	fir1 := newFuncIR("isCupertino", 0x2000)
	fir1.ArgRegs = arm64ArgRegs
	fir1.ReturnReg = sdk.ARM64ReturnRegStr
	fir1.addBlock(Block{
		ID:      0,
		StartVA: 0x2000,
		Instrs: []Instr{
			{Addr: 0x2000, Op: OpOther, Src: "ldr x1, [x1, #16]"},
			{Addr: 0x2004, Op: OpReturn, Src: "ret"},
		},
	})
	art1 := EmitPseudocode(fir1, nil, nil)
	if !strings.Contains(art1.Source, "isCupertino(dynamic arg0) {") {
		t.Errorf("expected 1-arg signature 'isCupertino(dynamic arg0) {', got:\n%s", art1.Source)
	}
	if strings.Contains(art1.Source, "arg1") || strings.Contains(art1.Source, "arg7") {
		t.Errorf("D2 violation: 1-arg getter declared extra arguments:\n%s", art1.Source)
	}

	// Case 3: 2-arg setter (reads receiver x0 and value x1)
	fir2 := newFuncIR("setRadius", 0x3000)
	fir2.ArgRegs = arm64ArgRegs
	fir2.ReturnReg = sdk.ARM64ReturnRegStr
	fir2.addBlock(Block{
		ID:      0,
		StartVA: 0x3000,
		Instrs: []Instr{
			{Addr: 0x3000, Op: OpOther, Src: "str x2, [x1, #24]"},
			{Addr: 0x3004, Op: OpReturn, Src: "ret"},
		},
	})
	art2 := EmitPseudocode(fir2, nil, nil)
	if !strings.Contains(art2.Source, "setRadius(") || !strings.Contains(art2.Source, "arg1") {
		t.Errorf("expected 2-arg signature for setRadius, got:\n%s", art2.Source)
	}
	if strings.Contains(art2.Source, "arg2") || strings.Contains(art2.Source, "arg7") {
		t.Errorf("D2 violation: 2-arg setter declared extra arguments:\n%s", art2.Source)
	}
}

// Test2LevelPPAddressing verifies D5: 2-level PP addressing loads resolve to literal pool values.
func Test2LevelPPAddressing(t *testing.T) {
	fir := newFuncIR("test_pool_2level", 0x4000)
	fir.ArgRegs = arm64ArgRegs
	fir.ReturnReg = sdk.ARM64ReturnRegStr
	fir.PoolReg = sdk.ARM64PoolRegStr
	fir.PoolIndexOf = func(disp int64) (int, bool) {
		// disp = 16 + 8 * idx
		if disp < 16 || (disp-16)%8 != 0 {
			return 0, false
		}
		return int((disp - 16) / 8), true
	}

	// Calculate disp for pool slot 100: 16 + 800 = 816
	// Break into 2-level: upper = 512, lower = 304 (512 + 304 = 816)
	fir.addBlock(Block{
		ID:      0,
		StartVA: 0x4000,
		Instrs: []Instr{
			{Addr: 0x4000, Op: OpOther, Src: "add x16, x27, #512"},
			{Addr: 0x4004, Op: OpOther, Src: "ldr x0, [x16, #304]"},
			{Addr: 0x4008, Op: OpReturn, Src: "ret"},
		},
	})

	pool := func(idx int) (string, bool) {
		if idx == 100 {
			return `"my_secret_token"`, true
		}
		return "", false
	}

	art := EmitPseudocode(fir, nil, pool)
	if strings.Contains(art.Source, "(x27 + 512)") || strings.Contains(art.Source, "(PP + 512)") {
		t.Errorf("D5 violation: 2-level pool addressing was not resolved:\n%s", art.Source)
	}
	if !strings.Contains(art.Source, `return "my_secret_token";`) {
		t.Errorf("expected return \"my_secret_token\"; got:\n%s", art.Source)
	}
}

// TestCalleeNameCleaning verifies D4 mixin chain simplification and D7 PCOffset suffix stripping.
func TestCalleeNameCleaning(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			// Mixin chain compacted to base+`&…` (audit A6 + P3): asserts only the
			// base class, never a (possibly wrong) defining mixin; @hash and the
			// PCOffset suffix are stripped.
			input: "__Set & _HashVMBase & SetMixin & _LinkedHashSetMixin@3099033.add_564794",
			want:  "__Set&….add",
		},
		{
			input: "_MixinApplication504&Object&DioMixin@18353248.post_b4594",
			want:  "_MixinApplication504&….post",
		},
		{
			input: "new _Set@3099033_14b90",
			want:  "new _Set",
		},
		{
			input: "PlatformThemeCheckExtension_get_isCupertino_233d64",
			want:  "PlatformThemeCheckExtension_get_isCupertino",
		},
		{
			input: "sub_233d64",
			want:  "sub_233d64",
		},
	}

	for _, tc := range tests {
		got := cleanCalleeName(tc.input)
		if got != tc.want {
			t.Errorf("cleanCalleeName(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestArrayPlaceholderPreserved verifies audit A1: the `<Array>` /
// `<GrowableObjectArray>` "unresolved value" placeholder is NOT rewritten to an
// empty list literal `[]`. Doing so would fabricate a concrete value where the
// analysis actually has none. The placeholder must survive.
func TestArrayPlaceholderPreserved(t *testing.T) {
	input := []string{
		`return "<Array>";`,
		`x0 = "<GrowableObjectArray>";`,
	}
	tree := parseStmts(input)
	cleanExprs(tree)
	out := printStmts(tree)
	joined := strings.Join(out, "\n")

	if strings.Contains(joined, "[]") {
		t.Errorf("A1 violation: unresolved placeholder was fabricated into []:\n%s", joined)
	}
	if !strings.Contains(joined, "<Array>") || !strings.Contains(joined, "<GrowableObjectArray>") {
		t.Errorf("expected placeholders preserved, got:\n%s", joined)
	}
}

// TestTailCallSymbolResolution verifies D10: tail call to hex VA resolves through symbols.
func TestTailCallSymbolResolution(t *testing.T) {
	fir := newFuncIR("caller", 0x5000)
	fir.ArgRegs = arm64ArgRegs
	fir.ReturnReg = sdk.ARM64ReturnRegStr

	fir.addBlock(Block{
		ID:      0,
		StartVA: 0x5000,
		Instrs: []Instr{
			{Addr: 0x5000, Op: OpOther, Src: "mov x1, #10"},
			{Addr: 0x5004, Op: OpJump, Src: "b 0x6000", Target: "0x6000"},
		},
	})

	symbols := func(va uint64) (string, bool) {
		if va == 0x6000 {
			return "MathTools.factorial_12345", true
		}
		return "", false
	}

	art := EmitPseudocode(fir, symbols, nil)
	if strings.Contains(art.Source, "tailCall_") {
		t.Errorf("D10 violation: emitted tailCall_ placeholder:\n%s", art.Source)
	}
	if !strings.Contains(art.Source, "return MathTools.factorial(10);") && !strings.Contains(art.Source, "return MathTools.factorial(x1);") {
		t.Errorf("expected clean symbol tail call, got:\n%s", art.Source)
	}
}

// TestInlineSingleUseTemps verifies D9: single-use temporaries are inlined.
func TestInlineSingleUseTemps(t *testing.T) {
	input := []string{
		"dynamic sample() {",
		"  final t0 = getTheme();",
		"  return t0;",
		"}",
	}
	compacted := compactLines(strings.Join(input, "\n"))
	if strings.Contains(compacted, "t0") {
		t.Errorf("D9 violation: single-use temp t0 was not inlined:\n%s", compacted)
	}
	if !strings.Contains(compacted, "return getTheme();") {
		t.Errorf("expected 'return getTheme();', got:\n%s", compacted)
	}
}

// TestCollectionIdioms verifies D11: Set/List constructors + adds are collapsed to literals.
func TestCollectionIdioms(t *testing.T) {
	input := []string{
		"dynamic sample() {",
		"  final s = new _LinkedHashSet();",
		`  s.add("alpha");`,
		`  s.add("beta");`,
		"  return s;",
		"}",
	}
	compacted := compactLines(strings.Join(input, "\n"))
	if strings.Contains(compacted, "new _LinkedHashSet") || strings.Contains(compacted, "s.add(") {
		t.Errorf("D11 violation: collection constructor + add was not collapsed:\n%s", compacted)
	}
	if !strings.Contains(compacted, `{"alpha", "beta"}`) {
		t.Errorf("expected set literal {\"alpha\", \"beta\"}, got:\n%s", compacted)
	}
}

// TestStringInterpolationIdiom verifies Phase 5: string interpolation and concat calls are converted to template literals.
func TestStringInterpolationIdiom(t *testing.T) {
	input := []string{
		"dynamic sample() {",
		`  final msg = _StringBase._interpolate(["Hello, ", name, "!"]);`,
		`  final pair = _StringBase.concat(a, b);`,
		"  return msg;",
		"}",
	}
	compacted := compactLines(strings.Join(input, "\n"))
	if strings.Contains(compacted, "_StringBase._interpolate") || strings.Contains(compacted, "_StringBase.concat") {
		t.Errorf("Phase 5 violation: string interpolation call was not converted:\n%s", compacted)
	}
	if !strings.Contains(compacted, `"Hello, $name!"`) {
		t.Errorf("expected template literal '\"Hello, $name!\"', got:\n%s", compacted)
	}
	if !strings.Contains(compacted, `"$a$b"`) {
		t.Errorf("expected template literal '\"$a$b\"', got:\n%s", compacted)
	}
}

// TestReturnTypeEmission verifies Phase 5: fir.ReturnType overrides dynamic signature prefix.
func TestReturnTypeEmission(t *testing.T) {
	fir := newFuncIR("computeScore", 0x4000)
	fir.ReturnType = "int"
	fir.ArgRegs = arm64ArgRegs
	fir.ReturnReg = sdk.ARM64ReturnRegStr

	fir.addBlock(Block{
		ID:      0,
		StartVA: 0x4000,
		Instrs: []Instr{
			{Addr: 0x4000, Op: OpOther, Src: "mov x0, #42"},
			{Addr: 0x4004, Op: OpReturn, Src: "ret"},
		},
	})

	art := EmitPseudocode(fir, nil, nil)
	if !strings.HasPrefix(strings.TrimSpace(art.Source), "int computeScore()") {
		t.Errorf("expected signature to start with 'int computeScore()', got:\n%s", art.Source)
	}
}

// TestForInLoopReconstruction verifies Phase 6: iterator while-loops are reconstructed into for-in syntax.
func TestForInLoopReconstruction(t *testing.T) {
	input := []string{
		"dynamic processItems(dynamic items) {",
		"  final it = items.iterator;",
		"  while (it.moveNext()) {",
		"    final item = it.current;",
		"    print(item);",
		"  }",
		"}",
	}
	compacted := compactLines(strings.Join(input, "\n"))
	if strings.Contains(compacted, "it.iterator") || strings.Contains(compacted, "it.moveNext()") {
		t.Errorf("Phase 6 violation: for-in loop was not reconstructed:\n%s", compacted)
	}
	if !strings.Contains(compacted, "for (final item in items) {") {
		t.Errorf("expected 'for (final item in items) {', got:\n%s", compacted)
	}
}

// TestNullAwareAndCascadeReconstruction verifies Phase 6: null-aware ?. / ?? and cascade .. are reconstructed.
func TestNullAwareAndCascadeReconstruction(t *testing.T) {
	input := []string{
		"dynamic formatWidget() {",
		"  final prop = (user != null) ? user.name : null;",
		"  final title = (header != null) ? header : defaultTitle;",
		"  final p = new Paint();",
		"  p.color = red;",
		"  p.strokeWidth = 2;",
		"  return p;",
		"}",
	}
	compacted := compactLines(strings.Join(input, "\n"))
	if strings.Contains(compacted, "(user != null) ?") {
		t.Errorf("Phase 6 violation: null-aware was not folded to ?.:\n%s", compacted)
	}
	if !strings.Contains(compacted, "user?.name") {
		t.Errorf("expected 'user?.name', got:\n%s", compacted)
	}
	if !strings.Contains(compacted, "header ?? defaultTitle") {
		t.Errorf("expected 'header ?? defaultTitle', got:\n%s", compacted)
	}
	if !strings.Contains(compacted, "return Paint()..color = red..strokeWidth = 2;") {
		t.Errorf("expected cascade return, got:\n%s", compacted)
	}
}

// TestAsyncStateMachineLinearization verifies Phase 7: async state machine dispatch is unwrapped into linear await statements.
func TestAsyncStateMachineLinearization(t *testing.T) {
	input := []string{
		"dynamic fetchUser() async {",
		"  if (state == 0) {",
		`    final fut = client.get("user");`,
		"    await t1(fut); // await",
		"  } else if (state == 1) {",
		"    final t2 = parseUser(t1);",
		"    return t2;",
		"  }",
		"}",
	}
	compacted := compactLines(strings.Join(input, "\n"))
	if strings.Contains(compacted, "if (state == 0)") || strings.Contains(compacted, "} else if (state == 1)") {
		t.Errorf("Phase 7 violation: async state machine dispatch was not unwrapped:\n%s", compacted)
	}
	if !strings.Contains(compacted, "await") {
		t.Errorf("expected linear await in output:\n%s", compacted)
	}
	if !strings.Contains(compacted, "return parseUser(") {
		t.Errorf("expected return parseUser in output:\n%s", compacted)
	}
}

// TestAsyncStreamAwaitFor verifies Phase 7: Stream iterator while-loops are reconstructed into await for syntax.
func TestAsyncStreamAwaitFor(t *testing.T) {
	input := []string{
		"dynamic listenEvents(dynamic eventStream) async {",
		"  final it = new _StreamIterator(eventStream);",
		"  while (await it.moveNext()) {",
		"    final event = it.current;",
		"    handleEvent(event);",
		"  }",
		"}",
	}
	compacted := compactLines(strings.Join(input, "\n"))
	if strings.Contains(compacted, "new _StreamIterator") || strings.Contains(compacted, "it.moveNext()") {
		t.Errorf("Phase 7 violation: stream loop was not reconstructed into await for:\n%s", compacted)
	}
	if !strings.Contains(compacted, "await for (final event in eventStream) {") {
		t.Errorf("expected 'await for (final event in eventStream) {', got:\n%s", compacted)
	}
}

// TestClosureInlining verifies closure-allocation inlining is SOUND (audit A4):
// a context-free closure is inlined as its tear-off, but a closure that CAPTURES
// a context is left intact (inlining it would drop the binding).
func TestClosureInlining(t *testing.T) {
	input := []string{
		"dynamic processUsers(dynamic users) {",
		"  final t0 = AllocateClosure(print, null);", // no context -> inline
		"  users.forEach(t0);",
		"  final t1 = _Closure(User.getName, ctx);", // captures ctx -> keep
		"  final t2 = users.map(t1);",
		"  return t2;",
		"}",
	}
	compacted := compactLines(strings.Join(input, "\n"))
	if strings.Contains(compacted, "AllocateClosure") {
		t.Errorf("context-free closure was not inlined:\n%s", compacted)
	}
	if !strings.Contains(compacted, "users.forEach(print);") {
		t.Errorf("expected 'users.forEach(print);', got:\n%s", compacted)
	}
	// The context-capturing closure must survive verbatim (no binding dropped).
	if !strings.Contains(compacted, "_Closure(User.getName, ctx)") {
		t.Errorf("A4 violation: context-capturing closure was altered/dropped:\n%s", compacted)
	}
	if strings.Contains(compacted, "users.map(User.getName)") {
		t.Errorf("A4 violation: closure with captured ctx was reduced to bare tear-off:\n%s", compacted)
	}
}

// TestAnonymousClosurePreserved verifies audit A3: an anonymous-closure reference
// is NOT rewritten into a synthesized lambda body. The closure's real body lives
// in a separate function, so `(item) => process(item)` would be an invention.
func TestAnonymousClosurePreserved(t *testing.T) {
	input := []string{
		"dynamic formatList(dynamic items) {",
		"  final t0 = items.map(process.<anonymous closure>);",
		"  return t0;",
		"}",
	}
	compacted := compactLines(strings.Join(input, "\n"))
	if strings.Contains(compacted, "=>") {
		t.Errorf("A3 violation: a lambda body was fabricated:\n%s", compacted)
	}
	if !strings.Contains(compacted, "<anonymous closure>") {
		t.Errorf("expected anonymous-closure reference preserved, got:\n%s", compacted)
	}
}

// TestTypedDeclarations verifies Phase 10: literal & instantiation declarations are typed.
func TestTypedDeclarations(t *testing.T) {
	input := []string{
		"dynamic buildState() {",
		`  final title = "Dashboard";`,
		"  final count = 100;",
		"  final isActive = true;",
		"  final user = new UserModel();",
		"  return user;",
		"}",
	}
	compacted := compactLines(strings.Join(input, "\n"))
	if !strings.Contains(compacted, `final String title = "Dashboard";`) {
		t.Errorf("expected typed String declaration, got:\n%s", compacted)
	}
	if !strings.Contains(compacted, `final int count = 100;`) {
		t.Errorf("expected typed int declaration, got:\n%s", compacted)
	}
	if !strings.Contains(compacted, `final bool isActive = true;`) {
		t.Errorf("expected typed bool declaration, got:\n%s", compacted)
	}
	if !strings.Contains(compacted, `final UserModel user = UserModel();`) {
		t.Errorf("expected typed UserModel declaration, got:\n%s", compacted)
	}
}
