package decompiler

import (
	"fmt"
	"strings"
)

// Object-pool operands outside a plain load.
//
// A load through the pool register becomes OpLoadPool and the emitter
// resolves it (emitLoadPool). Every other instruction that names a pool slot
// used to fall through operandExpr's memory path and render as the literal
// `pool[?]` -- an honest placeholder, but one that discards an index the
// displacement already carries.
//
// This is not evenly distributed across architectures, and the reason is the
// instruction sets rather than anything about the snapshot:
//
//	x86_64   cmp eax, [r15+0x3f]     reads a pool entry with no load
//	ARM64    ldr x0, [x27, #...]     must load first -- so it is OpLoadPool
//	         cmp x0, x1
//
// So the placeholder was structurally impossible on ARM64 and common on
// x86_64. It was found by counting placeholders across a widened corpus:
// 2059 lines on a Dart 3.10.7 x64 build against 0 on either ARM64 build. The
// first reading of that gap was that 3.10 had a different pool format --
// wrong. Both x64 builds have the shape; 3.10 merely uses it more often
// (311 compare-against-pool sites versus 84 on 3.12).
func poolOperandExpr(fir *FuncIR, s *LiftState, op operand) string {
	if !op.hasDisp || fir.PoolIndexOf == nil {
		return "pool[?]"
	}
	return poolOperandDispExpr(fir, s, op.memDisp)
}

// poolOperandDispExpr resolves a pool slot by its byte displacement off the pool register.
func poolOperandDispExpr(fir *FuncIR, s *LiftState, disp int64) string {
	if fir.PoolIndexOf == nil {
		return "pool[?]"
	}
	idx, ok := fir.PoolIndexOf(disp)
	if !ok {
		// A displacement that cannot name an element: not element-aligned,
		// or below the first one. Reporting a wrong index would be worse
		// than reporting none, since every pool-derived fact is keyed on it.
		return "pool[?]"
	}
	if s != nil && s.Pool != nil {
		if display, found := s.Pool(idx); found {
			return display
		}
	}
	return fmt.Sprintf("pool[%d]", idx)
}

// parsePPOffset extracts the byte offset from a "(PP + N)", "(x27 + N)", or "PP+N" expression.
func parsePPOffset(fir *FuncIR, expr string) (int64, bool) {
	expr = strings.TrimSpace(expr)
	expr = strings.Trim(expr, "()")
	parts := strings.Split(expr, "+")
	if len(parts) != 2 {
		return 0, false
	}
	base := strings.ToLower(strings.TrimSpace(parts[0]))
	if base != "pp" && base != strings.ToLower(fir.PoolReg) {
		return 0, false
	}
	v, ok := parseImm(strings.TrimSpace(parts[1]))
	return v, ok
}
