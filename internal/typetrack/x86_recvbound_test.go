package typetrack

import (
	"testing"

	"aotopsy/internal/arch/x86"
)

// Real bytes of the >= 2.19 LoadClassId lowering on x86_64:
//
//	8b 48 ff     mov ecx, [rax-1]     ; header (FieldAddress tags_offset)
//	c1 e9 0c     shr ecx, 12          ; kClassIdTagPos
//
// The class-id register must remember the object it was read from, so the
// dispatch call can ask what that object is known to be.
func x86CidState(t *testing.T) ([31]TypeLattice, *TypeContext) {
	t.Helper()
	insts := decodeX86Seq(t, []byte{0x8b, 0x48, 0xff}, []byte{0xc1, 0xe9, 0x0c})
	ctx := &TypeContext{}
	ctx.SetClassIDTagLayout(12, 20)
	var state [31]TypeLattice
	for i := range state {
		state[i] = Top()
	}
	state[0] = ClassBound(77) // RAX: an instance of class 77 or a subtype
	var prev *x86.Decoded
	for i := range insts {
		transferInstructionX86(&state, insts[i], prev, ctx, &IntraResult{}, nil, map[int]TypeLattice{})
		dropWrittenSrcLinksX86(&state, insts[i].Inst)
		prev = &insts[i]
	}
	return state, ctx
}

func TestX86ClassIDLinksToItsObjectAndYieldsTheReceiverBound(t *testing.T) {
	state, ctx := x86CidState(t)
	rcx := state[1]
	if rcx.Kind != LatticeUnknownClassID || rcx.SrcReg != 1 { // SrcReg is 1+RAX(0)
		t.Fatalf("RCX = %+v, want UnknownClassID linked to RAX", rcx)
	}
	tc := &transferCtxX86{state: &state, ctx: ctx}
	if got := x86ReceiverBound(tc, 1); got != 77 {
		t.Fatalf("receiver bound = %d, want 77", got)
	}
}

// Rewriting the object register invalidates the link: the class id then belongs
// to an object that is no longer in that register.
func TestX86SourceLinkDiesWhenTheObjectRegisterIsRewritten(t *testing.T) {
	state, ctx := x86CidState(t)
	rewrite := decodeX86Seq(t, []byte{0x48, 0x89, 0xd8}) // mov rax, rbx
	transferInstructionX86(&state, rewrite[0], nil, ctx, &IntraResult{}, nil, map[int]TypeLattice{})
	dropWrittenSrcLinksX86(&state, rewrite[0].Inst)
	if state[1].SrcReg != 0 {
		t.Fatalf("link survived a rewrite of its object: %+v", state[1])
	}
	tc := &transferCtxX86{state: &state, ctx: ctx}
	if got := x86ReceiverBound(tc, 1); got != 0 {
		t.Fatalf("bound = %d after the object was rewritten, want 0", got)
	}
}
