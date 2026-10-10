package decompiler

import (
	"fmt"
	"strings"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
	"aotopsy/internal/snapshot"
)

// ARM64 Dart AOT reserved-register roles are now defined in internal/sdk,
// verified against runtime/vm/constants_arm64.h @3.12.2. This file wires
// them into the FuncIR; the constants themselves are shared with disasm,
// typetrack, and signal.

// BuildARM64IR lifts a disassembled ARM64 function (as produced by
// aotopsy's existing internal/disasm.Disassemble+BuildCFG) into the
// arch-neutral FuncIR the pseudocode emitter consumes. cc is deliberately a
// per-function input: a global SDK register table does not prove that this
// particular Function uses it.
func BuildARM64IR(name, dartVersion string, compressedPointers bool, insts []disasm.Inst, cc sdk.RegisterCallingConvention) *FuncIR {
	if len(insts) == 0 {
		fir := newFuncIR(name, 0)
		fir.DartVersion = dartVersion
		return fir
	}
	cfg := disasm.BuildCFG(name, insts)
	poolLoadsByPC := make(map[uint64][]disasm.ARM64PoolAccess)
	for _, access := range disasm.ExtractARM64PoolAccesses(insts, nil) {
		if access.Kind != disasm.ARM64PoolAccessLoad || access.RegClass != disasm.ARM64PoolRegGPR {
			continue
		}
		poolLoadsByPC[access.PC] = append(poolLoadsByPC[access.PC], access)
	}
	fir := newFuncIR(name, insts[0].Addr)
	fir.DartVersion = dartVersion
	fir.ArgRegs = append([]string(nil), cc.GPRNames...)
	fir.FrameReg = sdk.ARM64FrameRegStr
	fir.ReturnReg = sdk.ARM64ReturnRegStr
	fir.LinkReg = sdk.ARM64LinkRegStr
	fir.PoolReg = sdk.ARM64PoolRegStr
	// PP is untagged on ARM64, so the displacement is a plain 16+8*index.
	fir.PoolIndexOf = func(disp int64) (int, bool) { return disasm.ARM64PoolIndex(int(disp)) }
	fir.ThreadReg = sdk.ARM64ThreadRegStr
	fir.NullReg = sdk.ARM64NullRegStr
	fir.HeapBitsReg, fir.HeapBaseReg, fir.BarrierMaskReg = sdk.ARM64HeapRegisterRoles(dartVersion, compressedPointers)
	fir.StackReg = sdk.ARM64StackRegStr
	fir.CodeReg = sdk.ARM64CodeRegStr
	fir.ArgsDescReg = sdk.ARM64ArgsDescStr
	fir.ICDataReg = sdk.ARM64ICDataStr
	fir.FpuArgRegs = append([]string(nil), cc.FPUName...)
	fir.FpuReturnReg = cc.FPUReturn
	fir.TypeTestABIRegs = sdk.TypeTestRegNames(dartVersion, true)

	for _, bb := range cfg.Blocks {
		blk := Block{ID: bb.ID, IsTerm: bb.IsTerm}
		if bb.Start < len(insts) {
			blk.StartVA = insts[bb.Start].Addr
		}
		for i := bb.Start; i < bb.End && i < len(insts); i++ {
			var scalarPoolLoad *disasm.ARM64PoolAccess
			loads := poolLoadsByPC[insts[i].Addr]
			// FuncIR has one Op/Target per machine instruction. A scalar LDR
			// therefore maps exactly; an LDP has two independent destinations
			// and remains OpOther until the IR grows a multi-result operation.
			if len(loads) == 1 {
				scalarPoolLoad = &loads[0]
			}
			lifted := liftARM64Instr(insts[i], scalarPoolLoad)
			if len(loads) == 2 && strings.EqualFold(insts[i].Mnemonic, "ldp") {
				for _, l := range loads {
					lifted.PoolLoads = append(lifted.PoolLoads, PoolLoad{Reg: sdk.ARM64RegName(l.Reg), Index: l.PoolIndex})
				}
			}
			blk.Instrs = append(blk.Instrs, lifted)
		}
		for _, s := range bb.Succs {
			blk.Succs = append(blk.Succs, Succ{BlockID: s.BlockID, Cond: s.Cond})
		}
		fir.addBlock(blk)
	}
	return fir
}

// liftARM64Instr lifts one instruction. scalarPoolLoad is supplied by the same
// canonical SDK-shape extractor used by disassembly/dataflow and strxref, so
// pool provenance cannot drift between those consumers.
func liftARM64Instr(inst disasm.Inst, scalarPoolLoad *disasm.ARM64PoolAccess) Instr {
	mnemonic := strings.ToLower(inst.Mnemonic)
	src := strings.ToLower(inst.Text)
	ir := Instr{Addr: inst.Addr, Src: src, PoolIndex: -1}
	for _, reg := range arm64.DstRegsOfInst(inst.Raw) {
		if name := sdk.ARM64RegName(reg); name != "" {
			ir.DefRegs = append(ir.DefRegs, name)
		}
	}

	if scalarPoolLoad != nil {
		ir.Op = OpLoadPool
		ir.PoolIndex = scalarPoolLoad.PoolIndex
		ir.Target = sdk.ARM64RegName(scalarPoolLoad.Reg)
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
		cc := strings.ToLower(firstOperandToken(inst.Operands))
		ir.CondOp = arm64CondOp(cc)
		ir.CondUnsigned = arm64CondUnsigned(cc)
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

func arm64CondUnsigned(cc string) bool {
	switch cc {
	case "lo", "cc", "ls", "hi", "hs", "cs":
		return true
	}
	return false
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
			expr := fmt.Sprintf("((%s & ~(0xffff << %s)) | ((%s & 0xffff) << %s))", old, shift, imm, shift)
			// A W-register write zero-extends into the corresponding X register.
			if strings.HasPrefix(dst, "w") {
				expr = fmt.Sprintf("(%s & 0xffffffff)", expr)
			}
			s.setReg(dst, expr)
		}
		return "", false, true
	case "sbfx", "sbfiz":
		// Signed bitfield extract / insert-in-zeros. The two shapes the compiler
		// emits for compressed Smis (kSmiTagSize = 1):
		//   SBFX  Xd, Xn, #1, #w  : SmiUntag with sign extension  -> Xn >> 1
		//   SBFIZ Xd, Xn, #1, #31 : SmiTag of a 31-bit value       -> Xn << 1
		// Anything else is a different bitfield operation: its destination is
		// left unknown (the generic default drops it) rather than guessed.
		if len(ops) >= 4 {
			dst := strings.ToLower(ops[0])
			src := operandExpr(fir, s, ops[1])
			lsb, ok1 := parseImm(ops[2])
			width, ok2 := parseImm(ops[3])
			if ok1 && ok2 && lsb == 1 && width >= 31 {
				if mnemonic == "sbfx" {
					s.setReg(dst, fmt.Sprintf("(%s >> 1)", src))
					return "", false, true
				}
				s.setReg(dst, fmt.Sprintf("(%s << 1)", src))
				return "", false, true
			}
			delete(s.Regs, canonReg(dst))
			return "", false, true
		}
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
			classIDPos, classIDSize, layoutOK := snapshot.ClassIdTagLayout(fir.DartVersion)
			if ok1 && ok2 && layoutOK && pos == int64(classIDPos) && width == int64(classIDSize) {
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
			s.CmpBits = cmpBitWidthFromOperand(ops[0])
		}
		return "", false, true
	case "str", "stur":
		if len(ops) >= 2 && isArm64PreIndexSPPush(fir, ops[1]) {
			v := operandExpr(fir, s, ops[0])
			s.Pushed = append(s.Pushed, v)
			return fmt.Sprintf("push(%s);", v), true, true
		}
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
			if isArm64PreIndexSPPush(fir, ops[2]) {
				a, b := operandExpr(fir, s, ops[0]), operandExpr(fir, s, ops[1])
				pushed := pushedByStp(a, b)
				s.Pushed = append(s.Pushed, pushed...)
				return fmt.Sprintf("push(%s);\npush(%s);", pushed[0], pushed[1]), true, true
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
			cc := strings.ToLower(strings.TrimSpace(ops[3]))
			condOp := arm64CondOp(cc)
			condStr := fmt.Sprintf("/* %s */", strings.ToLower(ops[3]))
			if rendered, ok := rememberedCmpCondition(s, condOp, arm64CondUnsigned(cc)); ok {
				condStr = rendered
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
			cc := strings.ToLower(strings.TrimSpace(ops[1]))
			condOp := arm64CondOp(cc)
			condStr := fmt.Sprintf("/* %s */", strings.ToLower(ops[1]))
			if rendered, ok := rememberedCmpCondition(s, condOp, arm64CondUnsigned(cc)); ok {
				condStr = rendered
			}
			if mnemonic == "cset" {
				s.setReg(dst, fmt.Sprintf("(%s ? 1 : 0)", condStr))
			} else {
				s.setReg(dst, fmt.Sprintf("(%s ? -1 : 0)", condStr))
			}
		}
		return "", false, true
		// SIMD&FP mnemonics are handled by applyFloat, shared with x86_64.
	}
	return "", false, false
}
