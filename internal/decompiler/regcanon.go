package decompiler

import (
	"fmt"
	"strings"
)

// canonReg maps a register token to the canonical key of its underlying
// PHYSICAL register, collapsing width sub-register aliases so that a single
// value slot backs every width view of the same hardware register. This is the
// foundation of the value-graph model: because w0 and x0 are the same physical
// register on ARM64 (and eax/ax/al are the same as rax on x86-64), writing one
// width MUST be observable through every other width. The previous flat model
// keyed each width separately, so a w-write left a stale x-alias (and vice
// versa); routing every read and write through canonReg makes that class of bug
// structurally impossible instead of patched per-mnemonic.
//
// Canonicalization is architecture-disjoint ONLY because the x86 lifter now
// normalizes SSE register names before they get here. It was not disjoint
// before: x86asm.Inst.String() spells XMM registers "X0".."X15", which
// lowercases to exactly the ARM64 tokens x0..x15, so this function's ARM64
// branch claimed every x86 floating-point register as a general-purpose one.
// See x86.InstText, which renames them to xmm<n> at the single point where
// instruction text is produced. Unknown tokens (THR, PP, sp, named
// pseudo-regs) pass through lowercased unchanged.
//
// Width semantics: a 32-bit write zero-extends the upper bits on both
// architectures, so treating the narrow and wide views as the same symbolic
// value is the correct approximation for an expression-level lifter that does
// not model bit widths. It is strictly better than keeping divergent stale
// aliases, which corrupts values (verified against dart-3.9.2 ground truth:
// `cmp w0, w16` where a prior pool-load rewrote x16 but not w16).
func canonReg(tok string) string {
	tok = strings.ToLower(strings.TrimSpace(tok))
	if tok == "" {
		return tok
	}
	// ARM64: w<n> and x<n> are the low-32 and full-64 views of GPR n.
	if (tok[0] == 'w' || tok[0] == 'x') && len(tok) > 1 && isAllDigits(tok[1:]) {
		return "x" + tok[1:]
	}
	// ARM64: b<n>/h<n>/s<n>/d<n>/q<n>/v<n> are the 8/16/32/64/128-bit and
	// vector views of SIMD&FP register n -- the same physical register, for
	// exactly the reason w<n> and x<n> are. Without collapsing them a
	// 64-bit write through d0 left a stale q0 alias (and vice versa), the
	// same corruption the w/x merge above was written to make impossible.
	// The corpus reaches this: 5,245 FP instructions on the 3.9.2 ARM64
	// sample, and FCMP/FMOV/FMUL freely mix d<n> and q<n> views.
	if len(tok) > 1 && isAllDigits(tok[1:]) {
		switch tok[0] {
		case 'b', 'h', 's', 'd', 'q', 'v':
			return "v" + tok[1:]
		}
	}
	// x86-64 extended registers r8..r15 with optional width suffix d/w/b.
	if tok[0] == 'r' && len(tok) > 1 {
		body := tok[1:]
		if n := len(body); n >= 1 {
			// strip a trailing width suffix, then require r<8..15>.
			core := body
			switch body[n-1] {
			case 'd', 'w', 'b':
				core = body[:n-1]
			}
			if isAllDigits(core) {
				switch core {
				case "8", "9", "10", "11", "12", "13", "14", "15":
					return "r" + core
				}
			}
		}
	}
	// x86-64 legacy registers: collapse every width view onto the 64-bit name.
	if canon, ok := x86RegCanon[tok]; ok {
		return canon
	}
	return tok
}

// x86RegCanon maps every width view of a legacy x86-64 GPR onto its 64-bit
// name. Bare "sp"/"bp" 16-bit forms are intentionally omitted: "sp" collides
// with the ARM64 stack-pointer token, and value tracking never needs the 16-bit
// stack/base-pointer view. The 32-bit (esp/ebp) and 8-bit (spl/bpl) forms are
// unambiguous and included.
var x86RegCanon = map[string]string{
	"rax": "rax", "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
	"rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
	"rcx": "rcx", "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
	"rdx": "rdx", "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
	"rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
	"rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
	"rbp": "rbp", "ebp": "rbp", "bpl": "rbp",
	"rsp": "rsp", "esp": "rsp", "spl": "rsp",
}

// stackComputedSlot recognises a symbolic value that is a computed SP-relative
// address -- "SP", "(SP - k)", or "(SP + k)" -- and renders it as the same
// [SP±k] stack-slot notation stackSlotExpr produces for direct base+disp
// accesses. The seeds in EmitPseudocode name SPREG "SP", so a `sub xN, SP, #k`
// followed by a store/load through xN surfaces here instead of leaking the raw
// stack-pointer register. Returns ok=false for anything that is not an SP
// address, leaving the caller's existing rendering untouched.
func stackComputedSlot(expr string) (string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "SP" {
		return "stack_sp", true
	}
	if !strings.HasPrefix(expr, "(SP ") || !strings.HasSuffix(expr, ")") {
		return "", false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(expr, "(SP "), ")")
	// inner is "- k" or "+ k".
	if len(inner) < 3 || (inner[0] != '-' && inner[0] != '+') || inner[1] != ' ' {
		return "", false
	}
	num := strings.TrimSpace(inner[2:])
	if !isAllDigits(num) {
		return "", false
	}
	// Valid Dart identifier (a stack slot), not `[SP±k]` which does not parse as
	// an lvalue/expression. "m" = minus, "p" = plus, mirroring localName.
	sign := "p"
	if inner[0] == '-' {
		sign = "m"
	}
	return "stack_" + sign + num, true
}

// maxForwardedExprLen bounds the length of a value expression carried in a
// register before it is materialized into a named temporary instead.
//
// Register values are held as expression TEXT, and arithmetic emits no
// statement of its own -- `add x0, x1, x2` is represented purely by storing
// "(a + b)" as x0's value. So an expression that reads a register twice
// doubles, and one that reads it three times triples. Dart's own
// `_SystemHash.combine` does exactly that:
//
//	hash = 0x1fffffff & (hash + value);
//	hash = 0x1fffffff & (hash + ((0x0007ffff & hash) << 10));
//	return hash ^ (hash >> 6);
//
// `SystemHash.hash20` chains twenty of them. Measured on dart-3.12.2-x64
// before this bound: a TWO-BLOCK, 896-byte function emitted ~570 MB of source
// and took the process out of memory at 5.2 GB. maxStepsPerEmitter cannot see
// it -- the step count is tiny; the blowup is in string length.
//
// 240 chars is well past anything a person reads as one expression, so the
// bound costs no real readability.
const maxForwardedExprLen = 240

// setReg writes val as the symbolic value of register dst, keyed by the
// canonical physical register so every width view observes it. This is the
// single write path for the register value-graph; all lifters route through it.
//
// When val exceeds maxForwardedExprLen the expression is spilled to a named
// temporary and dst carries the NAME instead, which turns exponential growth
// into linear. The alternative -- dropping the value -- was rejected: since
// arithmetic emits no statement, dropping would delete the computation from
// the output with nothing saying so, and silently losing code is the failure
// mode this tool exists to avoid.
//
// Spilling needs somewhere to put the declaration, so it happens only when a
// sink is attached (the emitter). The pre-emission fixpoint runs the same
// instructions repeatedly and discards its lines; inventing a name there would
// seed the emitter with an identifier that is never declared. Without a sink
// the over-long value is dropped instead, which is what the fixpoint already
// does whenever predecessors disagree.
func (s *LiftState) setReg(dst, val string) {
	if len(val) > maxForwardedExprLen {
		if s.spillSeq == nil {
			delete(s.Regs, canonReg(dst))
			return
		}
		*s.spillSeq++
		name := fmt.Sprintf("_t%d", *s.spillSeq)
		s.Spills = append(s.Spills, fmt.Sprintf("var %s = %s;", name, val))
		s.Regs[canonReg(dst)] = name
		return
	}
	s.Regs[canonReg(dst)] = val
}
