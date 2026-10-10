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
	copies := map[int]int{}
	for i := range insts {
		transferInstructionX86(&state, insts[i], prev, ctx, &IntraResult{}, nil, map[int]TypeLattice{})
		updateSrcLinksX86(&state, insts[i].Inst, copies)
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
	updateSrcLinksX86(&state, rewrite[0].Inst, map[int]int{})
	if state[1].SrcReg != 0 {
		t.Fatalf("link survived a rewrite of its object: %+v", state[1])
	}
	tc := &transferCtxX86{state: &state, ctx: ctx}
	if got := x86ReceiverBound(tc, 1); got != 0 {
		t.Fatalf("bound = %d after the object was rewritten, want 0", got)
	}
}

// The dispatch sequence overwrites the object's register with the dispatch table
// before it consumes the class id (`mov rax,[r14+DT]`), and the 2.x form pushes
// the receiver instead of copying it. The bound stamped when the header was read
// must survive that: the class id is still the class id of that object.
func TestX86ReceiverBoundSurvivesTheObjectRegisterBeingOverwritten(t *testing.T) {
	insts := decodeX86Seq(t,
		[]byte{0x8b, 0x48, 0xff},       // mov ecx, [rax-1]
		[]byte{0xc1, 0xe9, 0x0c},       // shr ecx, 12
		[]byte{0x50},                   // push rax
		[]byte{0x49, 0x8b, 0x46, 0x70}) // mov rax, [r14+0x70]   (dispatch table)
	ctx := &TypeContext{}
	ctx.SetClassIDTagLayout(12, 20)
	var state [31]TypeLattice
	for i := range state {
		state[i] = Top()
	}
	state[0] = ClassBound(77)
	var prev *x86.Decoded
	copies := map[int]int{}
	for i := range insts {
		transferInstructionX86(&state, insts[i], prev, ctx, &IntraResult{}, nil, map[int]TypeLattice{})
		stampReceiverBounds(&state)
		updateSrcLinksX86(&state, insts[i].Inst, copies)
		prev = &insts[i]
	}
	if state[1].SrcReg != 0 {
		t.Fatalf("the link must be gone once RAX is overwritten: %+v", state[1])
	}
	tc := &transferCtxX86{state: &state, ctx: ctx}
	if got := x86ReceiverBound(tc, 1); got != 77 {
		t.Fatalf("bound after RAX was overwritten = %d, want the stamped 77", got)
	}
}

// A 64-bit register copy inherits the link when the original is overwritten:
// `mov rdi, rax; mov rax, [r14+DT]`.
func TestX86SourceLinkMovesToAnIntactCopy(t *testing.T) {
	state, ctx := x86CidState(t)
	copies := map[int]int{}
	for _, b := range [][]byte{{0x48, 0x89, 0xc7}, {0x49, 0x8b, 0x46, 0x70}} { // mov rdi,rax ; mov rax,[r14+0x70]
		d := decodeX86Seq(t, b)[0]
		transferInstructionX86(&state, d, nil, ctx, &IntraResult{}, nil, map[int]TypeLattice{})
		updateSrcLinksX86(&state, d.Inst, copies)
	}
	if got := state[1].SrcReg; got != 7+1 { // RDI = 7
		t.Fatalf("link = %d, want it moved to RDI (8)", got)
	}
}

// LoadClassIdMayBeSmi: `test al,1; mov ecx,kSmiCid; je` -- on the Smi path the
// register is the class id of RAX. Only the snapshot's own Smi cid counts.
func TestX86SmiPathOfLoadClassIdMayBeSmiIsLinkedToItsObject(t *testing.T) {
	run := func(smiName string, imm byte) [31]TypeLattice {
		insts := decodeX86Seq(t,
			[]byte{0xa8, 0x01},                  // test al, 1
			[]byte{0xb9, imm, 0x00, 0x00, 0x00}) // mov ecx, imm
		ctx := &TypeContext{ClassIDToName: map[int]string{60: smiName}}
		var state [31]TypeLattice
		for i := range state {
			state[i] = Top()
		}
		var prev *x86.Decoded
		for i := range insts {
			transferInstructionX86(&state, insts[i], prev, ctx, &IntraResult{}, nil, map[int]TypeLattice{})
			prev = &insts[i]
		}
		return state
	}
	if got := run("_Smi@0150898", 60)[1]; got.Kind != LatticeExactClassID || got.ClassID != 60 || got.SrcReg != 1 {
		t.Fatalf("Smi path = %+v, want ExactClassID(60) linked to RAX", got)
	}
	// An immediate that is not the Smi cid is just a constant.
	if got := run("_Smi@0150898", 61)[1]; got.Kind == LatticeExactClassID {
		t.Fatalf("an unrelated immediate became a class id: %+v", got)
	}
	// No `_Smi` class in the table: nothing to compare against, nothing claimed.
	if got := run("Foo", 60)[1]; got.Kind == LatticeExactClassID {
		t.Fatalf("class id claimed without a known Smi cid: %+v", got)
	}
}
