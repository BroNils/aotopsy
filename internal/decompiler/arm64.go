package decompiler

import (
	"fmt"
	"strconv"
	"strings"

	"aotopsy/internal/arm64dec"
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

	for _, bb := range cfg.Blocks {
		blk := Block{ID: bb.ID, IsTerm: bb.IsTerm}
		if bb.Start < len(insts) {
			blk.StartVA = insts[bb.Start].Addr
		}
		for i := bb.Start; i < bb.End && i < len(insts); i++ {
			blk.Instrs = append(blk.Instrs, liftARM64Instr(insts[i]))
		}
		for _, s := range bb.Succs {
			blk.Succs = append(blk.Succs, Succ{BlockID: s.BlockID, Cond: s.Cond})
		}
		fir.addBlock(blk)
	}
	return fir
}

func liftARM64Instr(inst disasm.Inst) Instr {
	mnemonic := strings.ToLower(inst.Mnemonic)
	src := strings.ToLower(inst.Text)
	ir := Instr{Addr: inst.Addr, Src: src, PoolIndex: -1}

	switch {
	case mnemonic == "ret":
		ir.Op = OpReturn
	case mnemonic == "bl":
		ir.Op = OpCall
		if target, ok := decodeARM64BLTarget(inst.Raw, inst.Addr); ok {
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

// decodeARM64BLTarget delegates to arm64dec.BL (shared single source).
func decodeARM64BLTarget(raw uint32, pc uint64) (uint64, bool) {
	return arm64dec.BL(raw, pc)
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
