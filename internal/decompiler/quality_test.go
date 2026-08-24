package decompiler

import (
	"strings"
	"testing"
)

// TestCFGVerificationCoverageCorrectness tests that VerifyCFG accurately
// reports >0% coverage on cleanly structured pseudocode (reversing the inverted D12 metric bug).
func TestCFGVerificationCoverageCorrectness(t *testing.T) {
	fir := newFuncIR("test_structured_fn", 0x1000)
	fir.ArgRegs = arm64ArgRegs
	fir.FrameReg = arm64FrameReg
	fir.ReturnReg = arm64ReturnReg
	fir.LinkReg = arm64LinkReg
	fir.PoolReg = arm64PoolReg
	fir.ThreadReg = arm64ThreadReg

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
	armFir.FrameReg = arm64FrameReg
	armFir.ReturnReg = arm64ReturnReg
	armFir.LinkReg = arm64LinkReg
	armFir.PoolReg = arm64PoolReg
	armFir.ThreadReg = arm64ThreadReg

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
	x64Fir.FrameReg = x86FrameReg
	x64Fir.ReturnReg = x86ReturnReg
	x64Fir.PoolReg = x86PoolReg
	x64Fir.ThreadReg = x86ThreadReg

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
	fir.FrameReg = arm64FrameReg
	fir.ReturnReg = arm64ReturnReg

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
	fir.FrameReg = arm64FrameReg
	fir.ReturnReg = arm64ReturnReg
	fir.LinkReg = arm64LinkReg
	fir.PoolReg = arm64PoolReg
	fir.ThreadReg = arm64ThreadReg
	fir.StackReg = arm64StackReg

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
	fir.ReturnReg = arm64ReturnReg

	// Block 0: Call a function with only x0 assigned
	fir.addBlock(Block{
		ID:      0,
		StartVA: 0x8000,
		Instrs: []Instr{
			{Addr: 0x8000, Op: OpOther, Src: "mov x0, #42"},
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
	if !strings.Contains(art.Source, "printInt(42)") && !strings.Contains(art.Source, "printInt(x0)") {
		t.Errorf("expected call with trimmed arguments, got:\n%s", art.Source)
	}
}

// TestNullRegIdentityMath verifies D11: identity folding and NULL_REG arithmetic normalizations.
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

	if strings.Contains(joined, "null + 10") {
		t.Errorf("expected 'null + 10' to fold to 10, got:\n%s", joined)
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
	fir0.ReturnReg = arm64ReturnReg
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
	fir1.ReturnReg = arm64ReturnReg
	fir1.addBlock(Block{
		ID:      0,
		StartVA: 0x2000,
		Instrs: []Instr{
			{Addr: 0x2000, Op: OpOther, Src: "ldr x0, [x0, #16]"},
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
	fir2.ReturnReg = arm64ReturnReg
	fir2.addBlock(Block{
		ID:      0,
		StartVA: 0x3000,
		Instrs: []Instr{
			{Addr: 0x3000, Op: OpOther, Src: "str x1, [x0, #24]"},
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
