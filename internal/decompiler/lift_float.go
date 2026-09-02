package decompiler

import "strings"

// applyFloat lifts SIMD&FP instructions for both architectures.
//
// This replaces two near-identical implementations, one in
// applyOtherARM64 and one in applyOtherX86, which between them spent
// ~130 lines saying the same things twice: the same four arithmetic
// operators, the same flag-setting compare, the same toDouble/toInt
// conversions, differing only in mnemonic spelling and operand count.
// The semantics are identical -- `fmul d0, d1, d2` and `mulsd xmm0,
// xmm1` differ in form, not in meaning -- so the expression building,
// which is the part worth getting right, is now written once.
//
// Consolidating also exposed what neither copy covered: FP MOVES. On the
// 3.12.2 x64 sample the three most common FP instructions are
// MOVSD_XMM (11,875), MOVUPS (2,483) and MOVAPS (1,106), and not one of
// them was lifted. An unlifted instruction leaves its destination
// register holding nothing, so every later read printed the register
// name -- which is exactly where the d0/d1/q0/q1 and xmm tokens in the
// pseudocode came from.
//
// Operand-count convention, and why it matters here:
//
//	ARM64  three-operand, non-destructive:  fmul d0, d1, d2   -> d0 = d1 * d2
//	x86_64 two-operand, destructive:        mulsd xmm0, xmm1  -> xmm0 = xmm0 * xmm1
//
// Reading the x86 form as if it were the ARM64 form (dst = op0 * op1)
// would drop the accumulator and state an arithmetic the binary does not
// perform.
func applyFloat(fir *FuncIR, s *LiftState, mnemonic string, ops []string) (line string, hasLine, handled bool) {
	if op, ok := floatBinOp(mnemonic); ok {
		switch {
		case isARM64FloatMnemonic(mnemonic) && len(ops) >= 3:
			dst := strings.ToLower(ops[0])
			s.setReg(dst, "("+operandExpr(fir, s, ops[1])+" "+op+" "+operandExpr(fir, s, ops[2])+")")
			return "", false, true
		case len(ops) >= 2:
			dst := strings.ToLower(ops[0])
			s.setReg(dst, "("+s.lookupReg(dst)+" "+op+" "+operandExpr(fir, s, ops[1])+")")
			return "", false, true
		}
		return "", false, true
	}

	switch mnemonic {
	// --- moves -------------------------------------------------------
	//
	// fmov also transfers between a GPR and an FP register in both
	// directions, and takes an immediate form (`fmov d1, #2.0`). All of
	// them are a plain value copy at this level; operandExpr already
	// renders an immediate as a literal and a register as its tracked
	// value.
	// Mnemonic spellings are x86asm's, verified against its tables.go and
	// against the corpus: the SSE double move is MOVSD_XMM (bare MOVSD is
	// the string instruction and is deliberately NOT matched here), while
	// the single-precision move is plain MOVSS, which has no string-
	// instruction namesake to disambiguate against.
	case "fmov", "movsd_xmm", "movss", "movapd", "movaps", "movupd", "movups", "movq", "movd":
		if len(ops) >= 2 {
			// x86 uses the same mnemonic for stores to memory, exactly as
			// the integer `mov` case does; route those through applyStore
			// rather than inventing a register named "[rbp-0x30]".
			if strings.HasPrefix(strings.TrimSpace(ops[0]), "[") {
				l, h := applyStore(fir, s, ops[0], ops[1])
				return l, h, true
			}
			s.setReg(strings.ToLower(ops[0]), operandExpr(fir, s, ops[1]))
		}
		return "", false, true

	// --- unary -------------------------------------------------------
	case "fneg":
		if len(ops) >= 2 {
			s.setReg(strings.ToLower(ops[0]), "-("+operandExpr(fir, s, ops[1])+")")
		}
		return "", false, true
	case "fsqrt", "sqrtsd", "sqrtss":
		if len(ops) >= 2 {
			s.setReg(strings.ToLower(ops[0]), "sqrt("+operandExpr(fir, s, ops[1])+")")
		}
		return "", false, true
	case "fabs":
		// `.abs()`, not the `abs(x)` the ARM64 copy emitted: abs() is not
		// a Dart function, so that line did not name anything real.
		if len(ops) >= 2 {
			s.setReg(strings.ToLower(ops[0]), "("+operandExpr(fir, s, ops[1])+").abs()")
		}
		return "", false, true

	// --- min/max -----------------------------------------------------
	case "fmax", "fmin", "maxsd", "minsd", "maxss", "minss":
		fn := "max"
		if strings.Contains(mnemonic, "min") {
			fn = "min"
		}
		switch {
		case len(ops) >= 3:
			s.setReg(strings.ToLower(ops[0]), fn+"("+operandExpr(fir, s, ops[1])+", "+operandExpr(fir, s, ops[2])+")")
		case len(ops) >= 2:
			dst := strings.ToLower(ops[0])
			s.setReg(dst, fn+"("+s.lookupReg(dst)+", "+operandExpr(fir, s, ops[1])+")")
		}
		return "", false, true

	// --- comparison --------------------------------------------------
	//
	// These set the flags a following B.cc / Jcc reads, so they feed
	// LastCmp exactly like the integer cmp case in lift.go. Without this
	// an FP comparison produced `if (/* cond */)` -- the placeholder seen
	// throughout x86_64 pseudocode for Rect/Offset geometry code.
	case "fcmp", "fcmpe", "comisd", "comiss", "ucomisd", "ucomiss":
		if len(ops) >= 2 {
			s.LastCmp = [2]string{operandExpr(fir, s, ops[0]), operandExpr(fir, s, ops[1])}
			s.HasCmp = true
		} else if len(ops) == 1 {
			// ARM64 `fcmp d0, #0.0` renders with the zero folded away.
			s.LastCmp = [2]string{operandExpr(fir, s, ops[0]), "0.0"}
			s.HasCmp = true
		}
		return "", false, true

	// --- conversions -------------------------------------------------
	//
	// Named rather than silently dropped: `cvttsd2si` truncates toward
	// zero and `scvtf` reinterprets a signed integer as a double, and an
	// analyst reading a rounding bug needs to see which one ran.
	case "scvtf", "ucvtf", "cvtsi2sd", "cvtsi2ss":
		if len(ops) >= 2 {
			s.setReg(strings.ToLower(ops[0]), "("+operandExpr(fir, s, ops[1])+").toDouble()")
		}
		return "", false, true
	case "fcvtzs", "fcvtzu", "cvttsd2si", "cvttss2si":
		if len(ops) >= 2 {
			s.setReg(strings.ToLower(ops[0]), "("+operandExpr(fir, s, ops[1])+").toInt()")
		}
		return "", false, true
	case "cvtsd2si", "cvtss2si", "frinti", "frintn":
		if len(ops) >= 2 {
			s.setReg(strings.ToLower(ops[0]), "("+operandExpr(fir, s, ops[1])+").round()")
		}
		return "", false, true
	case "fcvt", "cvtsd2ss", "cvtss2sd":
		// A width change between float formats; the VALUE is unchanged, so
		// carrying it through is more useful than naming the conversion.
		if len(ops) >= 2 {
			s.setReg(strings.ToLower(ops[0]), operandExpr(fir, s, ops[1]))
		}
		return "", false, true
	}
	return "", false, false
}

// floatBinOp maps an FP arithmetic mnemonic to its Dart operator.
func floatBinOp(mnemonic string) (string, bool) {
	switch mnemonic {
	case "fadd", "addsd", "addss":
		return "+", true
	case "fsub", "subsd", "subss":
		return "-", true
	case "fmul", "mulsd", "mulss":
		return "*", true
	case "fdiv", "divsd", "divss":
		return "/", true
	}
	return "", false
}

// isARM64FloatMnemonic reports whether the mnemonic uses ARM64's
// three-operand non-destructive form.
func isARM64FloatMnemonic(mnemonic string) bool {
	switch mnemonic {
	case "fadd", "fsub", "fmul", "fdiv":
		return true
	}
	return false
}
