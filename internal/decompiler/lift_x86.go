package decompiler

import (
	"fmt"
	"strings"
)

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
	}
	return "", false, false
}
