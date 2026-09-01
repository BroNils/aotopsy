package decompiler

import (
	"fmt"
	"strconv"
	"strings"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
)

// ARM64 Dart AOT reserved-register roles are now defined in internal/sdk,
// verified against runtime/vm/constants_arm64.h @3.12.2. This file wires
// them into the FuncIR; the constants themselves are shared with disasm,
// typetrack, and signal.

// arm64ArgRegs is the SDK-verified Dart calling-convention argument
// register set (constants_arm64.h DartCallingConvention::kCpuRegistersForArgs
// = {R1, R2, R3, R5, R6, R7}), NOT the C ABI x0–x7. The previous x0–x7 list
// included R0 (kClassIdReg) and R4 (ARGS_DESC_REG), which are NOT argument
// registers — declaring them as args leaked confident-wrong parameter names.
var arm64ArgRegs = sdk.DartArgRegNames(sdk.ArchARM64)

// BuildARM64IR lifts a disassembled ARM64 function (as produced by
// aotopsy's existing internal/disasm.Disassemble+BuildCFG) into the
// arch-neutral FuncIR the pseudocode emitter consumes.
func BuildARM64IR(name string, insts []disasm.Inst) *FuncIR {
	if len(insts) == 0 {
		return newFuncIR(name, 0)
	}
	cfg := disasm.BuildCFG(name, insts)
	fir := newFuncIR(name, insts[0].Addr)
	fir.ArgRegs = arm64ArgRegs
	fir.FrameReg = sdk.ARM64FrameRegStr
	fir.ReturnReg = sdk.ARM64ReturnRegStr
	fir.LinkReg = sdk.ARM64LinkRegStr
	fir.PoolReg = sdk.ARM64PoolRegStr
	// PP is untagged on ARM64, so the displacement is a plain 16+8*index.
	fir.PoolIndexOf = func(disp int64) (int, bool) { return disasm.ARM64PoolIndex(int(disp)) }
	fir.ThreadReg = sdk.ARM64ThreadRegStr
	fir.NullReg = sdk.ARM64NullRegStr
	fir.HeapBitsReg = sdk.ARM64HeapBitsStr
	fir.StackReg = sdk.ARM64StackRegStr
	fir.CodeReg = sdk.ARM64CodeRegStr
	fir.ArgsDescReg = sdk.ARM64ArgsDescStr
	fir.FpuArgRegs = sdk.ARM64FpuArgRegNames()
	fir.FpuReturnReg = sdk.ARM64FpuReturnRegName

	for _, bb := range cfg.Blocks {
		blk := Block{ID: bb.ID, IsTerm: bb.IsTerm}
		if bb.Start < len(insts) {
			blk.StartVA = insts[bb.Start].Addr
		}
		// Pool bases established by `add xT, PP, #hi` earlier in this
		// block, keyed by destination register. Block-local on purpose:
		// carrying them across a control-flow join would pair an ADD on
		// one path with an LDR on another.
		poolBase := map[int]int64{}
		for i := bb.Start; i < bb.End && i < len(insts); i++ {
			blk.Instrs = append(blk.Instrs, liftARM64Instr(insts[i], poolBase))
		}
		for _, s := range bb.Succs {
			blk.Succs = append(blk.Succs, Succ{BlockID: s.BlockID, Cond: s.Cond})
		}
		fir.addBlock(blk)
	}
	return fir
}

// liftARM64Instr lifts one instruction. poolBase carries the two-instruction
// object-pool form across the block (see trackARM64PoolBase); it is mutated
// as instructions define and redefine registers.
func liftARM64Instr(inst disasm.Inst, poolBase map[int]int64) Instr {
	mnemonic := strings.ToLower(inst.Mnemonic)
	src := strings.ToLower(inst.Text)
	ir := Instr{Addr: inst.Addr, Src: src, PoolIndex: -1}

	// Resolve against the base BEFORE this instruction updates the map:
	// `add x2, x27, #0x4000; ldr x2, [x2, #8]` reuses the same register,
	// and the load reads the base the add produced.
	baseIdx := arm64PoolIndexViaBase(inst, poolBase)
	defer trackARM64PoolBase(inst, poolBase)

	if baseIdx >= 0 && (mnemonic == "ldr" || mnemonic == "ldur") {
		ir.Op = OpLoadPool
		ir.PoolIndex = baseIdx
		ir.Target = firstOperandReg(inst.Operands)
		return ir
	}

	switch {
	case mnemonic == "ret":
		ir.Op = OpReturn
	case mnemonic == "bl":
		ir.Op = OpCall
		if target, ok := arm64.BL(inst.Raw, inst.Addr); ok {
			ir.Target = fmt.Sprintf("0x%x", target)
		}
	case mnemonic == "blr":
		ir.Op = OpCall
		ir.Target = firstOperandReg(inst.Operands)
	case mnemonic == "b":
		// This project's ARM64 disassembler (internal/disasm, backed by
		// golang.org/x/arch/arm64/arm64asm) renders a conditional branch
		// as Mnemonic="b" with the condition code as the FIRST token of
		// Operands (e.g. "LS, .+0x3c"), NOT as a dotted mnemonic suffix
		// like "b.ls" -- confirmed by dumping real decoded instructions
		// from a from-scratch-compiled sample app while debugging why
		// every conditional branch in a real function (MathTools.
		// factorial) was silently falling through as OpOther, truncating
		// the whole function's pseudocode after its first instruction.
		// bi.Cond (from raw-encoding-level DecodeBranch, the same
		// decoder BuildCFG itself trusts) is the authoritative signal
		// for conditional-vs-unconditional, not any text-based mnemonic
		// shape.
		bi := disasm.DecodeBranch(inst.Raw, inst.Addr)
		if bi == nil {
			break
		}
		if !bi.Cond {
			ir.Op = OpJump
			ir.Target = fmt.Sprintf("0x%x", bi.Target)
			break
		}
		ir.Op = OpBranch
		ir.Target = fmt.Sprintf("0x%x", bi.Target)
		ir.CondKind = "cmp"
		ir.CondOp = arm64CondOp(strings.ToLower(firstOperandToken(inst.Operands)))
	case mnemonic == "br":
		// P6: br xN — indirect branch (jump table, tail call, or computed goto).
		// Mark as OpJump with the register as target so the emitter can
		// render it as a tail call or switch dispatch.
		ir.Op = OpJump
		ir.Target = firstOperandReg(inst.Operands)
	case mnemonic == "cbz" || mnemonic == "cbnz":
		if bi := disasm.DecodeBranch(inst.Raw, inst.Addr); bi != nil {
			ir.Op = OpBranch
			ir.Target = fmt.Sprintf("0x%x", bi.Target)
			if mnemonic == "cbz" {
				ir.CondKind = "eqz"
			} else {
				ir.CondKind = "nez"
			}
			ir.CondReg = firstOperandReg(inst.Operands)
		}
	case mnemonic == "tbz" || mnemonic == "tbnz":
		if bi := disasm.DecodeBranch(inst.Raw, inst.Addr); bi != nil {
			ir.Op = OpBranch
			ir.Target = fmt.Sprintf("0x%x", bi.Target)
			if mnemonic == "tbz" {
				ir.CondKind = "bittest0"
			} else {
				ir.CondKind = "bittest1"
			}
			parts := splitARM64Operands(inst.Operands)
			if len(parts) >= 1 {
				ir.CondReg = strings.ToLower(parts[0])
			}
			if len(parts) >= 2 {
				if v, ok := parseImm(parts[1]); ok {
					ir.CondBit = int(v)
				}
			}
		}
	case (mnemonic == "ldr" || mnemonic == "ldur") && isARM64PoolLoad(inst.Operands):
		ir.Op = OpLoadPool
		ir.PoolIndex = arm64PoolIndex(inst.Operands)
		ir.Target = firstOperandReg(inst.Operands)
	}
	return ir
}

// firstOperandReg extracts the first register token from an ARM64
// operand string like "x2" or "x2, #0x8".
func firstOperandReg(operands string) string {
	parts := splitARM64Operands(operands)
	if len(parts) == 0 {
		return ""
	}
	return strings.ToLower(parts[0])
}

// splitARM64Operands splits a top-level comma list.
func splitARM64Operands(operands string) []string {
	return splitTopLevelCommas(strings.TrimSpace(operands))
}

// arm64CondOp maps a B.cc condition-code suffix to a Dart comparison
// operator. Unsigned variants (hi/ls/lo/hs) map to the same operators as
// their signed counterparts -- a known, documented simplification also
// present in flutterdec's own cond_from_cmp (it loses the signed/unsigned
// distinction identically).
func arm64CondOp(cc string) string {
	switch cc {
	case "eq":
		return "=="
	case "ne":
		return "!="
	case "lt", "lo", "cc":
		return "<"
	case "le", "ls":
		return "<="
	case "gt", "hi":
		return ">"
	case "ge", "hs", "cs":
		return ">="
	}
	// AL/NV are handled before this point: DecodeBranch reports them as
	// unconditional, so they never become an OpBranch. They used to map to
	// the string "true", which buildCondition then spliced into its
	// "%s %s %s" comparison template, emitting `lhs true rhs`. Falling
	// through to "?" here means that shape is not reachable even if a caller
	// classifies one as conditional by mistake.
	// mi/pl/vs/vc (sign/overflow-flag-only conditions) have no direct
	// Dart comparison-operator equivalent without knowing the specific
	// arithmetic op that set the flags -- left unresolved on purpose
	// (renders as a placeholder "/* cond */" via the emitter's existing
	// "no CondOp match" fallback) rather than emitting a wrong operator.
	return "?"
}

// firstOperandToken extracts the first comma-separated token from an
// operand string, e.g. "LS, .+0x3c" -> "LS" (the condition-code token
// this disassembler's "b" mnemonic rendering puts first).
func firstOperandToken(operands string) string {
	parts := splitARM64Operands(operands)
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

// trackARM64PoolBase maintains the register -> pool-base map for the
// two-instruction object-pool form.
//
// Dart's LoadWordFromPoolIndex emits a single `ldr xD, [PP, #imm]` only
// while the displacement fits the 12-bit unsigned-offset field. Past that
// it emits `add xT, PP, #hi` then `ldr xD, [xT, #lo]`, and the lifter
// recognised only the first form -- so on a real production binary 38716
// of 64601 pool loads (60%) produced no OpLoadPool at all, and every
// string, class and stub reference behind them was invisible to the
// pseudocode, to strxref, and to anything else reading PoolIndex.
func trackARM64PoolBase(inst disasm.Inst, poolBase map[int]int64) {
	if rd, rn, imm, ok := arm64.ADD64Immediate(inst.Raw); ok && rn == sdk.ARM64PP && rd < 31 {
		poolBase[rd] = int64(imm)
		return
	}
	// Anything else that writes a tracked register invalidates it. A base
	// that survived its register being overwritten would resolve a later
	// load against an address that no longer exists.
	for _, rd := range arm64.DstRegsOfInst(inst.Raw) {
		delete(poolBase, rd)
	}
}

// arm64PoolIndexViaBase resolves `ldr xD, [xT, #lo]` where xT was set by
// an earlier `add xT, PP, #hi`, returning the pool slot index or -1.
func arm64PoolIndexViaBase(inst disasm.Inst, poolBase map[int]int64) int {
	if len(poolBase) == 0 {
		return -1
	}
	base, off, ok := arm64.LDR64UnsignedOffset(inst.Raw)
	if !ok {
		b, _, o, uok := arm64.LDUR64(inst.Raw)
		if !uok {
			return -1
		}
		base, off = b, o
	}
	hi, tracked := poolBase[base]
	if !tracked {
		return -1
	}
	idx, ok := disasm.ARM64PoolIndex(int(hi + int64(off)))
	if !ok {
		return -1
	}
	return idx
}

// isARM64PoolLoad recognizes "ldr/ldur xD, [x27, #imm]" (or w-register
// variants) -- a load from the object pool register.
func isARM64PoolLoad(operands string) bool {
	lower := strings.ToLower(operands)
	return strings.Contains(lower, "["+sdk.ARM64PoolRegStr) || strings.Contains(lower, "[ "+sdk.ARM64PoolRegStr)
}

// arm64PoolIndex extracts the #imm offset from a "[x27, #imm]" operand
// and converts it to a pool slot index via disasm.ARM64PoolIndex, which
// carries the SDK layout constants (elements start at +16, 8 bytes each,
// PP untagged on ARM64).
func arm64PoolIndex(operands string) int {
	i := strings.Index(operands, "#")
	if i < 0 {
		return -1
	}
	rest := operands[i+1:]
	end := strings.IndexAny(rest, "] \t")
	if end >= 0 {
		rest = rest[:end]
	}
	rest = strings.TrimSuffix(rest, "]")
	var v int64
	var err error
	if strings.HasPrefix(rest, "0x") {
		v, err = strconv.ParseInt(rest[2:], 16, 64)
	} else {
		v, err = strconv.ParseInt(rest, 10, 64)
	}
	if err != nil || v < 0 {
		return -1
	}
	idx, ok := disasm.ARM64PoolIndex(int(v))
	if !ok {
		return -1
	}
	return idx
}

// applyOtherARM64 handles ARM64-only mnemonics in ApplyOther's switch.
// Returns (line, hasLine, handled=true) if the mnemonic was consumed,
// (handled=false) if it should fall through to the shared/x86 cases.
// Mnemonics are arch-disjoint: an ARM64 mnemonic never appears in an
// x86 binary and vice versa, so the handled flag is sufficient.
func applyOtherARM64(fir *FuncIR, s *LiftState, mnemonic string, ops []string) (line string, hasLine, handled bool) {
	switch mnemonic {
	case "movk":
		// MOVK (ARM64 move-keep) inserts a 16-bit immediate at a shifted
		// position while preserving other bits. Unlike mov/movz which
		// overwrite the full register, movk merges with the existing value.
		// Format: movk dst, #imm, lsl #shift
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			imm := operandExpr(fir, s, ops[1])
			shift := "0"
			if len(ops) >= 3 {
				// ops[2] is like "lsl #16" — extract the shift amount.
				shiftSpec := strings.TrimSpace(ops[2])
				if idx := strings.Index(shiftSpec, "#"); idx >= 0 {
					shift = strings.TrimSpace(shiftSpec[idx+1:])
				}
			}
			old := s.lookupReg(dst)
			s.setReg(dst, fmt.Sprintf("(%s | (%s << %s))", old, imm, shift))
		}
		return "", false, true
	case "ubfx":
		if len(ops) >= 4 {
			dst := strings.ToLower(ops[0])
			src := operandExpr(fir, s, ops[1])
			pos, ok1 := parseImm(ops[2])
			width, ok2 := parseImm(ops[3])
			expr := fmt.Sprintf("bitField(%s, %s, %s)", src, cleanImmPrefix(ops[2]), cleanImmPrefix(ops[3]))
			// The well-known Dart object class-id bitfield idiom
			// (lsb=12 / 0xc, width=20 / 0x14 on ARM64) renders directly as
			// classId(...) instead of the generic bitField(...) form.
			if ok1 && ok2 && pos == sdk.ClassIdTagPosV3 && width == sdk.ClassIdTagSizeV3 {
				expr = fmt.Sprintf("classId(%s)", strings.TrimSuffix(src, "._tag"))
			}
			s.setReg(dst, expr)
		}
		return "", false, true
	case "ldr", "ldur":
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			if fir.ThreadStubOffsets != nil {
				if memOp := parseOperand(ops[1]); memOp.isMem && memOp.hasDisp && strings.ToLower(memOp.memBase) == fir.ThreadReg {
					if name, ok := fir.ThreadStubOffsets[memOp.memDisp]; ok {
						s.setReg(dst, thrStubSentinelPrefix+name)
						return "", false, true
					}
				}
			}
			s.setReg(dst, operandExpr(fir, s, ops[1]))
			propagateLoadedFieldClass(fir, s, dst, ops[1])
		}
		return "", false, true
	case "cmn":
		// Flags come from rn + o, so equality means rn == -o. Sharing the
		// cmp path, as this used to, reported the wrong sign.
		if len(ops) >= 2 {
			rhs, ok := shiftedOperand(fir, s, ops, 1)
			s.LastCmp = [2]string{operandExpr(fir, s, ops[0]), negateExpr(rhs)}
			s.HasCmp = ok
		}
		return "", false, true
	case "str", "stur":
		if len(ops) >= 2 {
			line, hasLine := applyStore(fir, s, ops[1], ops[0])
			return line, hasLine, true
		}
		return "", false, true
	case "adr", "adrp":
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.setReg(dst, operandExpr(fir, s, ops[1]))
		}
		return "", false, true
	case "ldp":
		if len(ops) >= 3 {
			dst1 := strings.ToLower(strings.TrimSpace(ops[0]))
			dst2 := strings.ToLower(strings.TrimSpace(ops[1]))
			if (dst1 == "x29" || dst1 == "fp" || dst1 == sdk.ARM64FrameRegStr) &&
				(dst2 == "x30" || dst2 == "lr" || dst2 == sdk.ARM64LinkRegStr) {
				memOp := parseOperand(ops[2])
				if memOp.isMem && (memOp.memBase == sdk.ARM64StackRegStr || memOp.memBase == "sp" || memOp.memBase == "csp") {
					// Epilogue frame restore — elide in high-level pseudocode
					return "", false, true
				}
			}
			s.setReg(dst1, operandExpr(fir, s, ops[2]))
			// Second register gets the next memory location (base+8).
			if op := parseOperand(ops[2]); op.isMem {
				memPlus8 := fmt.Sprintf("[%s, #%d]", op.memBase, op.memDisp+8)
				s.setReg(dst2, operandExpr(fir, s, memPlus8))
			} else {
				s.setReg(dst2, fmt.Sprintf("*(%s + 8)", operandExpr(fir, s, ops[2])))
			}
		}
		return "", false, true
	case "stp":
		if len(ops) >= 3 {
			src1 := strings.ToLower(strings.TrimSpace(ops[0]))
			src2 := strings.ToLower(strings.TrimSpace(ops[1]))
			if (src1 == "x29" || src1 == "fp" || src1 == sdk.ARM64FrameRegStr) &&
				(src2 == "x30" || src2 == "lr" || src2 == sdk.ARM64LinkRegStr) {
				memOp := parseOperand(ops[2])
				if memOp.isMem && (memOp.memBase == sdk.ARM64StackRegStr || memOp.memBase == "sp" || memOp.memBase == "csp") {
					// Prologue frame pointer & link register save — elide in high-level pseudocode
					return "", false, true
				}
			}
			// Store pair: stp src1, src2, [mem] — emit as two stores.
			line1, handled := applyStore(fir, s, ops[2], ops[0])
			op := parseOperand(ops[2])
			if op.isMem {
				memPlus8 := fmt.Sprintf("[%s, #%d]", op.memBase, op.memDisp+8)
				line2, _ := applyStore(fir, s, memPlus8, ops[1])
				if line2 != "" {
					if line1 != "" {
						return line1 + "\n" + line2, true, true
					}
					return line2, true, true
				}
			}
			return line1, handled, true
		}
		return "", false, true
	case "csel", "csinc", "csinv", "csneg":
		if len(ops) >= 4 {
			dst := strings.ToLower(ops[0])
			src1 := operandExpr(fir, s, ops[1])
			src2 := operandExpr(fir, s, ops[2])
			condOp := arm64CondOp(strings.ToLower(strings.TrimSpace(ops[3])))
			condStr := fmt.Sprintf("/* %s */", strings.ToLower(ops[3]))
			if s.HasCmp && condOp != "?" {
				condStr = fmt.Sprintf("%s %s %s", s.LastCmp[0], condOp, s.LastCmp[1])
			}
			var elseExpr string
			switch mnemonic {
			case "csel":
				elseExpr = src2
			case "csinc":
				elseExpr = fmt.Sprintf("(%s + 1)", src2)
			case "csinv":
				elseExpr = fmt.Sprintf("(~%s)", src2)
			case "csneg":
				elseExpr = fmt.Sprintf("(-%s)", src2)
			}
			s.setReg(dst, fmt.Sprintf("(%s ? %s : %s)", condStr, src1, elseExpr))
		}
		return "", false, true
	case "cset", "csetm":
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			condOp := arm64CondOp(strings.ToLower(strings.TrimSpace(ops[1])))
			condStr := fmt.Sprintf("/* %s */", strings.ToLower(ops[1]))
			if s.HasCmp && condOp != "?" {
				condStr = fmt.Sprintf("%s %s %s", s.LastCmp[0], condOp, s.LastCmp[1])
			}
			if mnemonic == "cset" {
				s.setReg(dst, fmt.Sprintf("(%s ? 1 : 0)", condStr))
			} else {
				s.setReg(dst, fmt.Sprintf("(%s ? -1 : 0)", condStr))
			}
		}
		return "", false, true
	case "fadd", "fsub", "fmul", "fdiv", "fmov", "fneg", "fsqrt", "fabs":
		// ARM64 FPU arithmetic. These operate on Dn/Sn/Qn registers.
		// fmov is a register-to-register copy (like mov for GPR).
		// The others are binary ops: fadd Dd, Dn, Dm → Dd = Dn + Dm.
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			if mnemonic == "fmov" && len(ops) >= 2 {
				s.setReg(dst, operandExpr(fir, s, ops[1]))
			} else if len(ops) >= 3 {
				src1 := operandExpr(fir, s, ops[1])
				src2 := operandExpr(fir, s, ops[2])
				var op string
				switch mnemonic {
				case "fadd":
					op = "+"
				case "fsub":
					op = "-"
				case "fmul":
					op = "*"
				case "fdiv":
					op = "/"
				case "fneg":
					s.setReg(dst, fmt.Sprintf("-(%s)", src1))
					return "", false, true
				case "fsqrt":
					s.setReg(dst, fmt.Sprintf("sqrt(%s)", src1))
					return "", false, true
				case "fabs":
					s.setReg(dst, fmt.Sprintf("abs(%s)", src1))
					return "", false, true
				}
				s.setReg(dst, fmt.Sprintf("(%s %s %s)", src1, op, src2))
			}
		}
		return "", false, true
	case "fcmp":
		// FPU compare: fcmp Dn, Dm — sets flags like cmp but for doubles.
		if len(ops) >= 2 {
			s.LastCmp = [2]string{operandExpr(fir, s, ops[0]), operandExpr(fir, s, ops[1])}
			s.HasCmp = true
		}
		return "", false, true
	case "fcvt":
		// FCVT converts between FP precisions: fcvt Dd, Sn (single→double).
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.setReg(dst, operandExpr(fir, s, ops[1]))
		}
		return "", false, true
	case "scvtf", "ucvtf":
		// SCVTF/UCVTF: integer to FP conversion.
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.setReg(dst, fmt.Sprintf("(%s).toDouble()", operandExpr(fir, s, ops[1])))
		}
		return "", false, true
	case "fcvtzs", "fcvtzu":
		// FCVTZS/FCVTZU: FP to integer conversion (truncate toward zero).
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.setReg(dst, fmt.Sprintf("(%s).toInt()", operandExpr(fir, s, ops[1])))
		}
		return "", false, true
	}
	return "", false, false
}
