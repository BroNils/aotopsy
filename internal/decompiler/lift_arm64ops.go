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
			if ok1 && ok2 && pos == 12 && width == 20 {
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
						s.setReg(dst, thrStubSentinelPrefix + name)
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
			if (dst1 == "x29" || dst1 == "fp" || dst1 == arm64FrameReg) &&
				(dst2 == "x30" || dst2 == "lr" || dst2 == arm64LinkReg) {
				memOp := parseOperand(ops[2])
				if memOp.isMem && (memOp.memBase == "x15" || memOp.memBase == "sp" || memOp.memBase == "csp") {
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
			if (src1 == "x29" || src1 == "fp" || src1 == arm64FrameReg) &&
				(src2 == "x30" || src2 == "lr" || src2 == arm64LinkReg) {
				memOp := parseOperand(ops[2])
				if memOp.isMem && (memOp.memBase == "x15" || memOp.memBase == "sp" || memOp.memBase == "csp") {
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
	}
	return "", false, false
}
