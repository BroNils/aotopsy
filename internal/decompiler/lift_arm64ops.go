package decompiler

import (
	"fmt"
	"strings"
)

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
			s.Regs[dst] = fmt.Sprintf("(%s | (%s << %s))", old, imm, shift)
		}
		return "", false, true
	case "ubfx":
		if len(ops) >= 4 {
			dst := strings.ToLower(ops[0])
			src := operandExpr(fir, s, ops[1])
			expr := fmt.Sprintf("bitField(%s, %s, %s)", src, cleanImmPrefix(ops[2]), cleanImmPrefix(ops[3]))
			// The well-known Dart object class-id bitfield idiom
			// (lsb=0xc, width=0x14 on ARM64) renders directly as
			// classId(...) instead of the generic bitField(...) form.
			if strings.TrimPrefix(ops[2], "#") == "0xc" && strings.TrimPrefix(ops[3], "#") == "0x14" {
				expr = fmt.Sprintf("classId(%s)", strings.TrimSuffix(src, "._tag"))
			}
			s.Regs[dst] = expr
		}
		return "", false, true
	case "ldr", "ldur":
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			if fir.ThreadStubOffsets != nil {
				if memOp := parseOperand(ops[1]); memOp.isMem && memOp.hasDisp && strings.ToLower(memOp.memBase) == fir.ThreadReg {
					if name, ok := fir.ThreadStubOffsets[memOp.memDisp]; ok {
						s.Regs[dst] = thrStubSentinelPrefix + name
						return "", false, true
					}
				}
			}
			s.Regs[dst] = operandExpr(fir, s, ops[1])
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
			s.Regs[dst] = operandExpr(fir, s, ops[1])
		}
		return "", false, true
	case "ldp":
		if len(ops) >= 3 {
			dst1 := strings.ToLower(ops[0])
			s.Regs[dst1] = operandExpr(fir, s, ops[2])
			// Second register gets the next memory location (base+8).
			dst2 := strings.ToLower(ops[1])
			if op := parseOperand(ops[2]); op.isMem {
				memPlus8 := fmt.Sprintf("[%s, #%d]", op.memBase, op.memDisp+8)
				s.Regs[dst2] = operandExpr(fir, s, memPlus8)
			} else {
				s.Regs[dst2] = fmt.Sprintf("*(%s + 8)", operandExpr(fir, s, ops[2]))
			}
		}
		return "", false, true
	case "stp":
		if len(ops) >= 3 {
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
	}
	return "", false, false
}
