package decompiler

import "strings"

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
// Canonicalization is architecture-disjoint: an ARM64 token (w/x + digits)
// never appears in an x86 binary and vice versa, so a single function can
// serve both without an explicit arch flag. Unknown tokens (THR, PP, sp, named
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

// setReg writes val as the symbolic value of register dst, keyed by the
// canonical physical register so every width view observes it. This is the
// single write path for the register value-graph; all lifters route through it.
func (s *LiftState) setReg(dst, val string) {
	s.Regs[canonReg(dst)] = val
}
