package x86

import (
	"regexp"

	"golang.org/x/arch/x86/x86asm"
)

// xmmTokenRe matches x86asm's own name for an SSE register.
//
// x86asm.Inst.String() renders XMM registers as "X0".."X15" (see its
// regNames table; only IntelSyntax/GNUSyntax spell them "xmm0"/"%xmm0").
// Lowercased, that produces exactly the ARM64 general-purpose register
// tokens x0..x15 -- so x86_64 disassembly listings and pseudocode showed
// `x3 == x4` for a COMISD of XMM3 and XMM4, and regcanon.go's stated
// invariant that "an ARM64 token (w/x + digits) never appears in an x86
// binary" was false for every one of the 19,949 FP/SIMD instructions on
// the 3.12.2 x64 sample.
//
// No other operand x86asm prints matches this shape: GPRs are spelled
// RAX/R13, memory operands are bracketed, immediates are hex.
var xmmTokenRe = regexp.MustCompile(`\bX(\d{1,2})\b`)

// InstText renders one decoded instruction the way every layer of this
// project should read it: x86asm's default syntax, but with SSE
// registers named xmm<n> instead of X<n>.
//
// Used by BOTH the disassembly listing writer and the pseudocode lifter,
// so the two never disagree about what a register is called.
func InstText(inst x86asm.Inst) string {
	return xmmTokenRe.ReplaceAllString(inst.String(), "xmm$1")
}

// Decoded is one step of a linear x86-64 decode sweep: the decoded
// instruction, its virtual address, and its encoded length. Bad marks a byte
// the decoder could not turn into an instruction (Len is then 1, Inst zero).
//
// Every analysis layer that walks x86 code needs exactly these three facts plus
// the bad-byte flag; they previously each declared their own near-identical
// struct (disasm.x86DecodedInst, decompiler.x86Inst)
// and their own copy of the decode loop below. Those structs still exist where a
// layer wants richer per-instruction state, but they are now built by adapting
// this one canonical sweep instead of re-implementing it.
type Decoded struct {
	Inst x86asm.Inst
	VA   uint64
	Len  int
	Bad  bool
}

// Walk linearly decodes code starting at baseVA, invoking fn for each
// instruction in address order. On a byte the decoder rejects it invokes fn with
// Bad=true and Len=1. Decoding stops when the code is exhausted or fn returns
// false -- the latter lets a caller halt at the first bad byte (the decompiler's
// end-of-function convention) or after finding what it wanted.
//
// This is the single x86 instruction-iteration primitive: the recovery policy
// (advance one byte past an undecodable position, never get stuck) lived in a
// dozen copies, each free to drift.
func Walk(code []byte, baseVA uint64, fn func(Decoded) bool) {
	for off := 0; off < len(code); {
		va := baseVA + uint64(off)
		inst, err := x86asm.Decode(code[off:], 64)
		if err != nil || inst.Len <= 0 {
			if !fn(Decoded{VA: va, Len: 1, Bad: true}) {
				return
			}
			off++
			continue
		}
		if !fn(Decoded{Inst: inst, VA: va, Len: inst.Len}) {
			return
		}
		off += inst.Len
	}
}

// Decode collects the whole linear sweep of code, including a slot for each
// bad byte (Bad=true, Len=1) so addresses stay contiguous. Built on Walk.
func Decode(code []byte, baseVA uint64) []Decoded {
	var out []Decoded
	Walk(code, baseVA, func(d Decoded) bool {
		out = append(out, d)
		return true
	})
	return out
}

// DecodeUntilBad collects instructions until the first undecodable byte (the
// bad byte itself is not included) or the code ends. This is the decompiler's
// "a decode failure marks the end of the real function body / start of padding"
// convention, kept distinct from Decode's decode-past-errors sweep.
func DecodeUntilBad(code []byte, baseVA uint64) []Decoded {
	var out []Decoded
	Walk(code, baseVA, func(d Decoded) bool {
		if d.Bad {
			return false
		}
		out = append(out, d)
		return true
	})
	return out
}
