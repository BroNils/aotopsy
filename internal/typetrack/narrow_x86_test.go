package typetrack

import (
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// The class-check sequence the x86_64 backend emits, taken verbatim from
// IterableExtensions|elementAtOrNull at 0x213d6d in the sample_312 x86_64
// build:
//
//	0x213d6d: MOV R9L, [RAX-0x1]    ; header load (kHeapObjectTag)
//	0x213d71: SHR R9L, 0xc          ; kClassIdTagPos
//	0x213d75: CMP R9, 0x8ca         ; compare against a class id
//	0x213d7c: JE  ...
//
// This is the chain that has to work for a dispatch call to resolve: the
// header load yields Bottom, the shift preserves it, and the equality edge
// of the branch turns it into a real class. Every stage was measured firing
// on the real binary while narrowing still saw an untyped register, so this
// pins the sequence down in isolation.
func x86Inst(addr uint64, op x86asm.Op, args ...x86asm.Arg) X86DecodedInst {
	in := x86asm.Inst{Op: op}
	copy(in.Args[:], args)
	return X86DecodedInst{Addr: addr, Inst: in, Len: 4}
}

func TestX86ClassCheckSequenceTypesTheComparedRegister(t *testing.T) {
	// Both branch edges must resolve for narrowing to apply: the taken edge
	// is only known to be successor 0 when the fall-through is present too.
	// Addresses are 4 bytes apart so the JE at 0x10c falls through to 0x110
	// and its Rel(4) target is 0x114.
	insts := []X86DecodedInst{
		x86Inst(0x100, x86asm.MOV, x86asm.R9L, x86asm.Mem{Base: x86asm.RAX, Disp: -1}),
		x86Inst(0x104, x86asm.SHR, x86asm.R9L, x86asm.Imm(0xc)),
		x86Inst(0x108, x86asm.CMP, x86asm.R9, x86asm.Imm(0x8ca)),
		x86Inst(0x10c, x86asm.JE, x86asm.Rel(4)),
		x86Inst(0x110, x86asm.MOV, x86asm.RDX, x86asm.RDX), // fall-through
		x86Inst(0x114, x86asm.RET),                         // branch target
	}
	ctx := &TypeContext{}
	var entry [31]TypeLattice
	for i := range entry {
		entry[i] = Top()
	}
	AnalyzeFunctionX86(insts, ctx, entry, nil)

	if ctx.HeaderHits == 0 {
		t.Error("the header load produced no type at all")
	}
	if ctx.UBFXHits == 0 {
		t.Error("the class-id extract did not recognise the header load before it")
	}
	if ctx.NarrowShape == 0 {
		t.Fatalf("the narrowing never saw this shape: CMP against an immediate "+
			"terminated by JE (HeaderHits=%d UBFXHits=%d)", ctx.HeaderHits, ctx.UBFXHits)
	}
	if ctx.NarrowNoType > 0 {
		t.Errorf("the compared register was untyped at the branch "+
			"(HeaderHits=%d UBFXHits=%d NarrowShape=%d NarrowNoType=%d) -- "+
			"the class id is lost between the SHR and the CMP",
			ctx.HeaderHits, ctx.UBFXHits, ctx.NarrowShape, ctx.NarrowNoType)
	}
	if ctx.NarrowHits == 0 {
		t.Errorf("no narrowing applied (HeaderHits=%d UBFXHits=%d NarrowShape=%d)",
			ctx.HeaderHits, ctx.UBFXHits, ctx.NarrowShape)
	}
}
