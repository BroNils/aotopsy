package decompiler

import (
	"aotopsy/internal/arch/x86"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/arch/x86/x86asm"

	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
)

// x86_64 Dart AOT reserved-register roles are now defined in internal/sdk,
// verified against runtime/vm/constants_x64.h @3.12.2.

// x86ArgRegs is the SDK-verified Dart calling-convention argument register
// set (constants_x64.h DartCallingConvention::kCpuRegistersForArgs =
// {RDI, RSI, RDX, RBX, R8, R9}), NOT the C ABI {RDI, RSI, RDX, RCX, R8, R9}.
// The previous list had RCX instead of RBX — RCX is kClassIdReg, not an
// argument register.
var x86ArgRegs = sdk.DartArgRegNames(sdk.ArchX86)

// DecodeX86Range decodes every instruction in the ENTIRE given byte range
// starting at baseVA, stopping only at a decode error or end of data --
// matching internal/disasm.Disassemble's ARM64 convention exactly.
//
// This function used to stop at the first RET, on the mistaken
// assumption that RET always means "end of function." That is wrong for
// any function with more than one return statement (e.g. an early-return
// guard clause followed by more logic, like MathTools.factorial's `if (n
// <= 1) return 1;` early exit followed by the real recursive-multiply
// case) -- confirmed as a real bug by testing this decompiler against a
// from-scratch-compiled sample app and comparing the pseudocode against
// the known Dart source: the early-RET-stop caused everything after the
// first return to be silently missing, making the recursive call/branch
// resolve as "unresolved branch target" even though the bytes were right
// there in the CodeRange the caller already sized correctly.
func DecodeX86Range(data []byte, baseVA uint64) []x86.Decoded {
	return x86.DecodeUntilBad(data, baseVA)
}

// BuildX86IR lifts a decoded x86_64 instruction range into FuncIR, using
// the same leader/partition/successor algorithm as
// internal/disasm.BuildCFG (kept as a local, simpler implementation since
// x86 instructions are variable-length and carry structured Args, unlike
// ARM64's fixed 4-byte raw-encoding approach).
func BuildX86IR(name string, insts []x86.Decoded) *FuncIR {
	if len(insts) == 0 {
		return newFuncIR(name, 0)
	}
	fir := newFuncIR(name, insts[0].VA)
	fir.ArgRegs = x86ArgRegs
	fir.FrameReg = sdk.X86FrameRegStr
	fir.ReturnReg = sdk.X86ReturnRegStr
	fir.PoolReg = sdk.X86PoolRegStr
	// PP is tagged on x86_64, so FieldAddress has already subtracted the
	// heap-object tag and the displacement is 16+8*index-1.
	fir.PoolIndexOf = disasm.X64PoolIndex
	fir.ThreadReg = sdk.X86ThreadRegStr
	fir.StackReg = sdk.X86StackRegStr
	fir.CodeReg = sdk.X86CodeRegStr
	fir.ArgsDescReg = sdk.X86ArgsDescStr
	fir.FpuArgRegs = sdk.X86FpuArgRegNames()
	fir.FpuReturnReg = sdk.X86FpuReturnRegName

	funcStart := insts[0].VA
	funcEnd := insts[len(insts)-1].VA + uint64(insts[len(insts)-1].Len) //nolint:gosec // instruction length is always non-negative

	addrToIdx := make(map[uint64]int, len(insts))
	for i, in := range insts {
		addrToIdx[in.VA] = i
	}

	leaders := map[int]bool{0: true}
	kind := make([]branchKind, len(insts)) // classification per instruction
	target := make([]uint64, len(insts))
	hasTarget := make([]bool, len(insts))

	for i, in := range insts {
		k, tgt, ok := classifyX86Branch(in)
		kind[i] = k
		if ok {
			target[i] = tgt
			hasTarget[i] = true
		}
		if k == branchNone {
			continue
		}
		if i+1 < len(insts) {
			leaders[i+1] = true
		}
		if ok && tgt >= funcStart && tgt < funcEnd {
			if idx, exists := addrToIdx[tgt]; exists {
				leaders[idx] = true
			}
		}
	}

	sorted := make([]int, 0, len(leaders))
	for idx := range leaders {
		sorted = append(sorted, idx)
	}
	sort.Ints(sorted)

	leaderToBlock := make(map[int]int, len(sorted))
	blocks := make([]Block, len(sorted))
	for i, start := range sorted {
		end := len(insts)
		if i+1 < len(sorted) {
			end = sorted[i+1]
		}
		blocks[i] = Block{ID: i, StartVA: insts[start].VA}
		for j := start; j < end; j++ {
			var prev *x86.Decoded
			if j > start {
				prev = &insts[j-1]
			}
			blocks[i].Instrs = append(blocks[i].Instrs, liftX86Instr(insts[j], kind[j], target[j], hasTarget[j], prev))
		}
		leaderToBlock[start] = i
	}

	for i, start := range sorted {
		end := len(insts)
		if i+1 < len(sorted) {
			end = sorted[i+1]
		}
		if end <= start {
			continue
		}
		lastIdx := end - 1
		k := kind[lastIdx]
		switch k {
		case branchNone:
			if nb, ok := leaderToBlock[end]; ok {
				blocks[i].Succs = append(blocks[i].Succs, Succ{BlockID: nb})
			}
		case branchRet:
			blocks[i].IsTerm = true
		case branchJmpDirect:
			if hasTarget[lastIdx] {
				if idx, ok := addrToIdx[target[lastIdx]]; ok {
					if bid, ok := leaderToBlock[idx]; ok {
						blocks[i].Succs = append(blocks[i].Succs, Succ{BlockID: bid})
						break
					}
				}
			}
			blocks[i].IsTerm = true
		case branchJmpIndirect:
			blocks[i].IsTerm = true
		case branchCond:
			if hasTarget[lastIdx] {
				if idx, ok := addrToIdx[target[lastIdx]]; ok {
					if bid, ok := leaderToBlock[idx]; ok {
						blocks[i].Succs = append(blocks[i].Succs, Succ{BlockID: bid, Cond: "T"})
					}
				}
			}
			if nb, ok := leaderToBlock[end]; ok {
				blocks[i].Succs = append(blocks[i].Succs, Succ{BlockID: nb, Cond: "F"})
			}
		}
	}

	for _, b := range blocks {
		fir.addBlock(b)
	}
	return fir
}

type branchKind int

const (
	branchNone branchKind = iota
	branchRet
	branchJmpDirect
	branchJmpIndirect
	branchCond
)

func classifyX86Branch(in x86.Decoded) (branchKind, uint64, bool) {
	op := in.Inst.Op
	if op == x86asm.RET {
		return branchRet, 0, false
	}
	if x86.IsCondJump(op) {
		if tgt, ok := x86.RelTarget(in.Inst, in.VA, in.Len); ok {
			return branchCond, tgt, true
		}
		return branchCond, 0, false
	}
	if op == x86asm.JMP {
		if tgt, ok := x86.RelTarget(in.Inst, in.VA, in.Len); ok {
			return branchJmpDirect, tgt, true
		}
		return branchJmpIndirect, 0, false
	}
	return branchNone, 0, false
}

// x86CondOp maps a Jcc opcode to a Dart comparison operator, applied
// against the block's last CMP/TEST operands (same lastCmp mechanism as
// ARM64's B.cc). Unsigned variants (A/AE/B/BE) map to the same operators
// as their signed counterparts (G/GE/L/LE), the same known simplification
// flutterdec's own cond_from_cmp makes.
func x86CondOp(op x86asm.Op) string {
	switch op {
	case x86asm.JE:
		return "=="
	case x86asm.JNE:
		return "!="
	case x86asm.JL, x86asm.JB:
		return "<"
	case x86asm.JLE, x86asm.JBE:
		return "<="
	case x86asm.JG, x86asm.JA:
		return ">"
	case x86asm.JGE, x86asm.JAE:
		return ">="
	}
	return "?"
}

func liftX86Instr(in x86.Decoded, k branchKind, tgt uint64, hasTgt bool, prev *x86.Decoded) Instr {
	src := strings.ToLower(in.Inst.String())
	ir := Instr{Addr: in.VA, Src: src, PoolIndex: -1}

	switch {
	case k == branchRet:
		ir.Op = OpReturn
	case in.Inst.Op == x86asm.CALL:
		ir.Op = OpCall
		if r, ok := x86.RelTarget(in.Inst, in.VA, in.Len); ok {
			ir.Target = fmt.Sprintf("0x%x", r)
		} else {
			ir.Target = x86IndirectTargetText(in)
		}
	case k == branchJmpDirect:
		ir.Op = OpJump
		ir.Target = fmt.Sprintf("0x%x", tgt)
	case k == branchJmpIndirect:
		ir.Op = OpJump
		ir.Target = x86IndirectTargetText(in)
	case k == branchCond:
		ir.Op = OpBranch
		ir.CondOp = x86CondOp(in.Inst.Op)
		if hasTgt {
			ir.Target = fmt.Sprintf("0x%x", tgt)
		}
		// Classify the condition based on what instruction set the
		// flags. x86 doesn't have separate branch instructions for
		// eqz/nez/bittest — it uses Jcc after CMP, TEST, or BT. The
		// condition kind depends on the flag-setting instruction,
		// not just the Jcc opcode.
		//
		// SDK reference (assembler_x64.h @3.9.2):
		//   btl/btq: BT instruction, sets CF to the tested bit.
		//   testq reg, 1<<N: TEST with power-of-two immediate, sets
		//     ZF to NOT(bit).
		//   testq reg, reg: self-test, sets ZF to (reg == 0).
		//
		// After BT:  JC = bit is 1 (bittest1), JNC = bit is 0 (bittest0)
		// After TEST reg, 1<<N:  JE = bit is 0 (bittest0), JNE = bit is 1 (bittest1)
		// After TEST reg, reg:  JE = reg == 0 (eqz), JNE = reg != 0 (nez)
		// After CMP:  JE/JNE/JL/etc = comparison (cmp)
		ir.CondKind = classifyX86Condition(in.Inst, prev)
		if ir.CondKind == "eqz" || ir.CondKind == "nez" {
			ir.CondReg = x86CondRegFromTest(prev)
		} else if ir.CondKind == "bittest0" || ir.CondKind == "bittest1" {
			ir.CondReg, ir.CondBit = x86CondRegBitFromTest(prev, in.Inst.Op)
		}
	case in.Inst.Op == x86asm.MOV && isX86PoolLoad(in):
		ir.Op = OpLoadPool
		ir.PoolIndex = x86PoolIndex(in)
		if len(in.Inst.Args) > 0 {
			if reg, ok := in.Inst.Args[0].(x86asm.Reg); ok {
				ir.Target = strings.ToLower(reg.String())
			}
		}
	}
	return ir
}

// x86IndirectTargetText renders an indirect call/jump target operand as
// readable text (register name, or a "[base+disp]" memory description)
// for the emitter's call-intent resolution to inspect.
func x86IndirectTargetText(in x86.Decoded) string {
	for _, arg := range in.Inst.Args {
		if arg == nil {
			continue
		}
		if reg, ok := arg.(x86asm.Reg); ok {
			return strings.ToLower(reg.String())
		}
		if mem, ok := arg.(x86asm.Mem); ok {
			return strings.ToLower(mem.String())
		}
	}
	return ""
}

// isX86PoolLoad recognizes "mov reg, [r15+disp]" -- a load from the
// object pool register.
func isX86PoolLoad(in x86.Decoded) bool {
	for _, arg := range in.Inst.Args {
		mem, ok := arg.(x86asm.Mem)
		if !ok {
			continue
		}
		if strings.ToLower(mem.Base.String()) == sdk.X86PoolRegStr {
			return true
		}
	}
	return false
}

// x86PoolIndex converts a "[r15+disp]" displacement to a pool slot index
// using this project's own already-established x86_64 convention
// (disp/8 - 2, confirmed identical in cmd/aotopsy/x64refs.go and
// gdtcall.go's poolIdx computation -- x86_64's PP register points 2
// slots further into the pool array than ARM64's does, unlike ARM64
// where idx is a plain byteOff/8 with no adjustment, per
// internal/disasm/annotate.go's PPAnnotator).
func x86PoolIndex(in x86.Decoded) int {
	for _, arg := range in.Inst.Args {
		mem, ok := arg.(x86asm.Mem)
		if !ok || strings.ToLower(mem.Base.String()) != sdk.X86PoolRegStr {
			continue
		}
		idx, idxOK := disasm.X64PoolIndex(mem.Disp)
		if !idxOK {
			return -1
		}
		return idx
	}
	return -1
}

// classifyX86Condition determines the CondKind for a Jcc instruction
// based on what instruction set the flags. x86 doesn't have separate
// branch instructions for eqz/nez/bittest — it uses Jcc after CMP,
// TEST, or BT. The condition kind depends on the flag-setting
// instruction, not just the Jcc opcode.
//
// SDK reference (assembler_x64.h @3.9.2):
//
//	btl/btq: BT instruction, sets CF to the tested bit value.
//	testq reg, 1<<N: TEST with power-of-two immediate, sets ZF to
//	  NOT(bit).
//	testq reg, reg: self-test, sets ZF to (reg == 0).
//
// After BT:        JC = bit is 1 (bittest1), JNC = bit is 0 (bittest0)
// After TEST 1<<N: JE = bit is 0 (bittest0), JNE = bit is 1 (bittest1)
// After TEST reg:  JE = reg == 0 (eqz), JNE = reg != 0 (nez)
// After CMP:       JE/JNE/JL/etc = comparison (cmp)
//
// If we can't identify the flag-setting instruction (prev is nil or
// not CMP/TEST/BT), fall back to "cmp" — the emitter will use
// LastCmp if available, or print a placeholder if not.
func classifyX86Condition(jcc x86asm.Inst, prev *x86.Decoded) string {
	if prev == nil {
		return "cmp"
	}
	prevOp := prev.Inst.Op

	// BT instruction: sets CF to the tested bit.
	// JC (carry set) → bit is 1; JNC (carry clear) → bit is 0.
	if prevOp == x86asm.BT {
		switch jcc.Op {
		case x86asm.JB: // JC
			return "bittest1"
		case x86asm.JAE: // JNC
			return "bittest0"
		}
		return "cmp" // BT with other Jcc — unusual, fall back
	}

	// TEST instruction: sets ZF and SF based on AND result.
	if prevOp == x86asm.TEST && len(prev.Inst.Args) >= 2 {
		// TEST reg, reg (self-test): ZF = (reg == 0).
		// JE → eqz, JNE → nez.
		if isX86SelfTest(prev.Inst) {
			switch jcc.Op {
			case x86asm.JE:
				return "eqz"
			case x86asm.JNE:
				return "nez"
			}
		}

		// TEST reg, 1<<N (power-of-two immediate): ZF = NOT(bit N).
		// JE → bit is 0 (bittest0), JNE → bit is 1 (bittest1).
		if bit := x86TestPowerOfTwoBit(prev.Inst); bit >= 0 {
			switch jcc.Op {
			case x86asm.JE:
				return "bittest0"
			case x86asm.JNE:
				return "bittest1"
			}
		}
	}

	// Default: CMP or unrecognized flag-setter → use "cmp" kind.
	// The emitter will use LastCmp if available, or print a
	// placeholder "/* cond */" if not.
	return "cmp"
}

// isX86SelfTest reports whether inst is `TEST reg, reg` (same
// register in both operands), which tests whether reg == 0.
func isX86SelfTest(inst x86asm.Inst) bool {
	if inst.Op != x86asm.TEST || len(inst.Args) < 2 {
		return false
	}
	r1, ok1 := inst.Args[0].(x86asm.Reg)
	r2, ok2 := inst.Args[1].(x86asm.Reg)
	return ok1 && ok2 && r1 == r2
}

// x86TestPowerOfTwoBit returns the bit number N if inst is
// `TEST reg, (1 << N)`, or -1 if not.
func x86TestPowerOfTwoBit(inst x86asm.Inst) int {
	if inst.Op != x86asm.TEST || len(inst.Args) < 2 {
		return -1
	}
	imm, ok := inst.Args[1].(x86asm.Imm)
	if !ok {
		return -1
	}
	v := uint64(imm)
	if v == 0 || v&(v-1) != 0 {
		return -1 // not a power of two
	}
	// Find the bit position.
	for bit := range 64 {
		if v&(1<<uint(bit)) != 0 {
			return bit
		}
	}
	return -1
}

// x86CondRegFromTest extracts the register name from a `TEST reg, reg`
// instruction (the register being tested for zero/nonzero).
func x86CondRegFromTest(prev *x86.Decoded) string {
	if prev == nil || prev.Inst.Op != x86asm.TEST || len(prev.Inst.Args) < 1 {
		return ""
	}
	if reg, ok := prev.Inst.Args[0].(x86asm.Reg); ok {
		return strings.ToLower(reg.String())
	}
	return ""
}

// x86CondRegBitFromTest extracts the register name and bit number from
// a `TEST reg, (1 << N)` or `BT reg, N` instruction.
// For TEST: JE means bit is 0, JNE means bit is 1.
// For BT:   JB (JC) means bit is 1, JAE (JNC) means bit is 0.
func x86CondRegBitFromTest(prev *x86.Decoded, jccOp x86asm.Op) (string, int) {
	if prev == nil {
		return "", 0
	}

	if prev.Inst.Op == x86asm.TEST && len(prev.Inst.Args) >= 2 {
		reg, ok := prev.Inst.Args[0].(x86asm.Reg)
		if !ok {
			return "", 0
		}
		bit := x86TestPowerOfTwoBit(prev.Inst)
		if bit < 0 {
			return "", 0
		}
		return strings.ToLower(reg.String()), bit
	}

	if prev.Inst.Op == x86asm.BT && len(prev.Inst.Args) >= 2 {
		reg, ok := prev.Inst.Args[0].(x86asm.Reg)
		if !ok {
			return "", 0
		}
		// BT's second operand can be a register or an immediate.
		if imm, ok := prev.Inst.Args[1].(x86asm.Imm); ok {
			return strings.ToLower(reg.String()), int(imm)
		}
	}

	return "", 0
}

// applyOtherX86 handles x86_64-only mnemonics in ApplyOther's switch.
// Returns (line, hasLine, handled=true) if the mnemonic was consumed,
// (handled=false) if it should fall through to the shared/ARM64 cases.
func applyOtherX86(fir *FuncIR, s *LiftState, mnemonic string, ops []string) (line string, hasLine, handled bool) {
	switch mnemonic {
	case "movzx":
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.setReg(dst, operandExpr(fir, s, ops[1]))
		}
		return "", false, true
	case "movsxd":
		// movsxd sign-extends a 32-bit value to 64-bit — needs a cast
		// to preserve sign-extension semantics in the pseudocode.
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.setReg(dst, fmt.Sprintf("(int64)(%s)", operandExpr(fir, s, ops[1])))
		}
		return "", false, true
	case "movsx":
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.setReg(dst, fmt.Sprintf("(int)(%s)", operandExpr(fir, s, ops[1])))
		}
		return "", false, true
	case "push":
		if len(ops) >= 1 {
			return fmt.Sprintf("push(%s);", operandExpr(fir, s, ops[0])), true, true
		}
		return "", false, true
	case "pop":
		if len(ops) >= 1 {
			dst := strings.ToLower(ops[0])
			s.setReg(dst, "/* pop */")
		}
		return "", false, true
	case "addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd":
		// x86_64 scalar double arithmetic (SSE2).
		// addsd xmm, xmm/mem → xmm = xmm + src
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			src := operandExpr(fir, s, ops[1])
			var op string
			switch mnemonic {
			case "addsd":
				op = "+"
			case "subsd":
				op = "-"
			case "mulsd":
				op = "*"
			case "divsd":
				op = "/"
			case "minsd":
				s.setReg(dst, fmt.Sprintf("min(%s, %s)", s.lookupReg(dst), src))
				return "", false, true
			case "maxsd":
				s.setReg(dst, fmt.Sprintf("max(%s, %s)", s.lookupReg(dst), src))
				return "", false, true
			}
			old := s.lookupReg(dst)
			if old == "" {
				old = "0.0"
			}
			s.setReg(dst, fmt.Sprintf("(%s %s %s)", old, op, src))
		}
		return "", false, true
	case "addss", "subss", "mulss", "divss":
		// x86_64 scalar single (float32) arithmetic.
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			src := operandExpr(fir, s, ops[1])
			var op string
			switch mnemonic {
			case "addss":
				op = "+"
			case "subss":
				op = "-"
			case "mulss":
				op = "*"
			case "divss":
				op = "/"
			}
			old := s.lookupReg(dst)
			if old == "" {
				old = "0.0"
			}
			s.setReg(dst, fmt.Sprintf("(%s %s %s)", old, op, src))
		}
		return "", false, true
	case "sqrtsd":
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.setReg(dst, fmt.Sprintf("sqrt(%s)", operandExpr(fir, s, ops[1])))
		}
		return "", false, true
	case "ucomisd", "comisd":
		// Double compare — sets flags like cmp.
		if len(ops) >= 2 {
			s.LastCmp = [2]string{operandExpr(fir, s, ops[0]), operandExpr(fir, s, ops[1])}
			s.HasCmp = true
		}
		return "", false, true
	case "cvtsi2sd", "cvtsi2ss":
		// Integer to double/float conversion.
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.setReg(dst, fmt.Sprintf("(%s).toDouble()", operandExpr(fir, s, ops[1])))
		}
		return "", false, true
	case "cvttsd2si", "cvttss2si":
		// Double/float to integer (truncate toward zero).
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.setReg(dst, fmt.Sprintf("(%s).toInt()", operandExpr(fir, s, ops[1])))
		}
		return "", false, true
	case "cvtsd2ss":
		// Double to float (precision narrowing).
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.setReg(dst, operandExpr(fir, s, ops[1]))
		}
		return "", false, true
	case "cvtss2sd":
		// Float to double (precision widening).
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.setReg(dst, operandExpr(fir, s, ops[1]))
		}
		return "", false, true
	case "movsd", "movss":
		// SSE move: movsd xmm, xmm/mem — register-to-register copy.
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.setReg(dst, operandExpr(fir, s, ops[1]))
		}
		return "", false, true
	}

	if strings.HasPrefix(mnemonic, "cmov") {
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			src := operandExpr(fir, s, ops[1])
			suf := strings.TrimPrefix(mnemonic, "cmov")
			condOp := x86CondOpFromSuffix(suf)
			condStr := fmt.Sprintf("/* %s */", suf)
			if s.HasCmp && condOp != "?" {
				condStr = fmt.Sprintf("%s %s %s", s.LastCmp[0], condOp, s.LastCmp[1])
			}
			old := s.lookupReg(dst)
			if old == "" {
				old = dst
			}
			s.setReg(dst, fmt.Sprintf("(%s ? %s : %s)", condStr, src, old))
		}
		return "", false, true
	}

	if strings.HasPrefix(mnemonic, "set") && len(mnemonic) > 3 {
		if len(ops) >= 1 {
			dst := strings.ToLower(ops[0])
			suf := strings.TrimPrefix(mnemonic, "set")
			condOp := x86CondOpFromSuffix(suf)
			condStr := fmt.Sprintf("/* %s */", suf)
			if s.HasCmp && condOp != "?" {
				condStr = fmt.Sprintf("%s %s %s", s.LastCmp[0], condOp, s.LastCmp[1])
			}
			s.setReg(dst, fmt.Sprintf("(%s ? 1 : 0)", condStr))
		}
		return "", false, true
	}

	return "", false, false
}

func x86CondOpFromSuffix(suf string) string {
	switch suf {
	case "e", "z":
		return "=="
	case "ne", "nz":
		return "!="
	case "l", "b", "c", "nae", "nge":
		return "<"
	case "le", "be", "na", "ng":
		return "<="
	case "g", "a", "nbe", "nle":
		return ">"
	case "ge", "ae", "nb", "nc", "nl":
		return ">="
	}
	return "?"
}
