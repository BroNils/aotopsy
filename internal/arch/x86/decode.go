package x86

import "golang.org/x/arch/x86/x86asm"

// Decoded is one step of a linear x86-64 decode sweep: the decoded
// instruction, its virtual address, and its encoded length. Bad marks a byte
// the decoder could not turn into an instruction (Len is then 1, Inst zero).
//
// Every analysis layer that walks x86 code needs exactly these three facts plus
// the bad-byte flag; they previously each declared their own near-identical
// struct (disasm.x86DecodedInst, typetrack.X86DecodedInst, decompiler.x86Inst)
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
