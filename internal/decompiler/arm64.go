package decompiler

import (
	"fmt"
	"strconv"
	"strings"

	"aotopsy/internal/disasm"
)

// ARM64 Dart AOT reserved-register convention, verified directly against
// dart-lang/sdk's runtime/vm/constants_arm64.h (fetched this session, not
// assumed from memory): CODE_REG=x24, THR=x26 (Thread*), PP=x27 (object
// pool pointer), HEAP_BITS=x28 (write_barrier_mask/heap_base -- NOT the
// thread register, easy to confuse with x28 by analogy to x86_64's
// r14=THR), FPREG=x29, LR=x30. Used for naming/classification only, not
// decoding.
const (
	arm64PoolReg   = "x27"
	arm64ThreadReg = "x26"
	arm64FrameReg  = "x29"
	arm64LinkReg   = "x30"
	arm64ReturnReg = "x0"
)

// arm64ArgRegs is a DISPLAY convention (arg0..arg7 = x0..x7), not a
// verified claim about Dart's real AOT calling convention. Checked
// against dart-lang/sdk's flow_graph_compiler_arm64.cc this session:
// Dart's OWN calling convention for a checked/generic entry loads
// parameters off the Dart stack (e.g. "LoadFromOffset(R0, SP, ...)"),
// not fixed argument registers the way a C ABI does -- only the
// "unchecked entry" fast path for a small fixed positional-arg count
// uses registers directly, and x0-x7 (matching AAPCS64's own C-ABI
// argument registers) is the plausible, but not exhaustively re-verified
// in this porting session, register set for that path. Treat x0..x7 as
// a readable label, not ground truth -- same caveat x86.go's ArgRegs
// documents for x86_64.
var arm64ArgRegs = []string{"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"}

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
	fir.FrameReg = arm64FrameReg
	fir.ReturnReg = arm64ReturnReg
	fir.LinkReg = arm64LinkReg
	fir.PoolReg = arm64PoolReg
	fir.ThreadReg = arm64ThreadReg

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

// decodeARM64BLTarget mirrors internal/symbolmap's decodeARM64BL (kept
// duplicated here rather than shared, to keep this package independent of
// symbolmap's ELF-scan-specific concerns).
func decodeARM64BLTarget(raw uint32, pc uint64) (uint64, bool) {
	if raw&0xFC000000 != 0x94000000 {
		return 0, false
	}
	imm26 := raw & 0x03FFFFFF
	sign := uint32(1) << 25
	mask := sign - 1
	var offset int32
	if imm26&sign != 0 {
		offset = int32(imm26|^mask) * 4 //nolint:gosec // imm26 is a 26-bit field; result fits in int32
	} else {
		offset = int32(imm26&mask) * 4 //nolint:gosec // imm26 is a 26-bit field; result fits in int32
	}
	return uint64(int64(pc) + int64(offset)), true //nolint:gosec // signed branch offset re-added to a real VA; result is a valid address by construction
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
	case "al", "nv":
		return "true"
	}
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
	return strings.Contains(lower, "["+arm64PoolReg) || strings.Contains(lower, "[ "+arm64PoolReg)
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
