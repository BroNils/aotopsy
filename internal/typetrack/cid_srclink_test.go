package typetrack

import (
	"testing"

	"aotopsy/internal/disasm"
)

// Real 3.9.2 ladder shape (EmitTestAndCallCheckCid + LoadTaggedClassIdMayBeSmi):
//
//	LDUR X1,[X2,#-1]; UBFX X1,X1,#12,#20; LSL X1,X1,#1; CMP W1,#0xbc; B.NE
const (
	rawLDURHdr  = 0xF85FF041 // LDUR X1,[X2,#-1]
	rawUBFXCid  = 0xD34C7C21 // UBFX X1,X1,#12,#20
	rawLSLTag   = 0xD37FF821 // LSL X1,X1,#1
	rawMovX2X3  = 0xAA0303E2 // MOV X2,X3
	rawCmpW1BC  = 0x7102F03F // CMP W1,#0xbc
	rawCmpW1Odd = 0x7102EC3F // CMP W1,#0xbb (odd: cannot be a tagged cid)
)

func srcLinkState(t *testing.T, raws ...uint32) [31]TypeLattice {
	t.Helper()
	var state [31]TypeLattice
	for i := range state {
		state[i] = Top()
	}
	stack := make(map[int]TypeLattice)
	shadow := shadowSPState{}
	ctx := &TypeContext{ClassIDTagPos: 12, ClassIDTagSize: 20}
	result := &IntraResult{}
	for i, raw := range raws {
		inst := disasm.Inst{Addr: 0x1000 + uint64(i)*4, Raw: raw, Size: 4}
		transferInstruction(&state, inst, 0, ctx, result, nil, stack, &shadow)
		dropWrittenSrcLinks(&state, raw)
	}
	return state
}

func TestTaggedCidCompareNarrowsSourceObject(t *testing.T) {
	state := srcLinkState(t, rawLDURHdr, rawUBFXCid, rawLSLTag)
	if state[1].Kind != LatticeTaggedClassID || state[1].SrcReg != 3 {
		t.Fatalf("X1 = %+v, want TaggedClassID linked to X2", state[1])
	}
	ctx := &TypeContext{}
	narrowed := state
	narrowByClassIDCompare(&narrowed, 1, 0xbc, ctx, 0x2000)
	if narrowed[2].Kind != LatticeExactClass || narrowed[2].ClassID != 0xbc>>1 {
		t.Fatalf("X2 = %+v, want ExactClass(%d)", narrowed[2], 0xbc>>1)
	}
	// The not-equal edge learns nothing: the original state is untouched.
	if state[2].Kind != LatticeTop {
		t.Fatalf("source state mutated: %+v", state[2])
	}
	// An odd immediate cannot be a Smi-tagged cid.
	odd := state
	narrowByClassIDCompare(&odd, 1, 0xbb, ctx, 0x2004)
	if odd[2].Kind != LatticeTop {
		t.Fatalf("odd compare narrowed source: %+v", odd[2])
	}
}

func TestUntaggedCidCompareNarrowsSourceObject(t *testing.T) {
	state := srcLinkState(t, rawLDURHdr, rawUBFXCid)
	narrowed := state
	narrowByClassIDCompare(&narrowed, 1, 0x5e, &TypeContext{}, 0x2000)
	if narrowed[2].Kind != LatticeExactClass || narrowed[2].ClassID != 0x5e {
		t.Fatalf("X2 = %+v, want ExactClass(0x5e)", narrowed[2])
	}
	if narrowed[1].Kind != LatticeExactClassID || narrowed[1].ClassID != 0x5e {
		t.Fatalf("X1 = %+v, want ExactClassID(0x5e)", narrowed[1])
	}
}

func TestSourceRewriteDropsLink(t *testing.T) {
	state := srcLinkState(t, rawLDURHdr, rawUBFXCid, rawLSLTag, rawMovX2X3)
	if state[1].SrcReg != 0 {
		t.Fatalf("link survived a rewrite of its source: %+v", state[1])
	}
	narrowed := state
	narrowByClassIDCompare(&narrowed, 1, 0xbc, &TypeContext{}, 0x2000)
	if narrowed[2].Kind != LatticeTop {
		t.Fatalf("rewritten X2 narrowed through a stale link: %+v", narrowed[2])
	}
}

func TestSrcLinkJoinKeepsOnlyAgreement(t *testing.T) {
	a := UnknownClassID()
	a.SrcReg = 3
	b := UnknownClassID()
	b.SrcReg = 4
	if got := joinType(a, b, nil); got.SrcReg != 0 || got.Kind != LatticeUnknownClassID {
		t.Fatalf("join(links differ) = %+v", got)
	}
	if got := joinType(a, a, nil); got.SrcReg != 3 {
		t.Fatalf("join(same link) = %+v", got)
	}
	if a.Equal(b) {
		t.Fatal("values with different source links compared equal")
	}
}

// armCidLadder builds `LDUR X1,[X2,#-1]; UBFX X1,X1,#12,#20; CMP W1,#0x5e; <mid>; B.EQ +8; NOP; RET`.
func armCidLadder(mid ...uint32) []disasm.Inst {
	raws := append([]uint32{rawLDURHdr, rawUBFXCid, 0x7101783F}, mid...)
	raws = append(raws, 0x54000040, 0xD503201F, 0xD65F03C0)
	insts := make([]disasm.Inst, len(raws))
	for i, r := range raws {
		insts[i] = disasm.Inst{Addr: 0x1000 + uint64(i)*4, Raw: r, Size: 4}
	}
	return insts
}

func TestArm64CmpThenBeqNarrowsSourceObject(t *testing.T) {
	ctx := minimalTypeContext()
	ctx.SetClassIDTagLayout(12, 20)
	AnalyzeFunction(armCidLadder(), ctx, [31]TypeLattice{}, nil)
	if ctx.NarrowHits != 1 || ctx.NarrowSrcHits != 1 {
		t.Fatalf("CMP; B.EQ: NarrowHits=%d NarrowSrcHits=%d, want 1/1", ctx.NarrowHits, ctx.NarrowSrcHits)
	}
}

// A flag-preserving instruction that REWRITES the compared register between
// the CMP and the branch makes the equality fact about the old value; it must
// not be attributed to the new one (here a different class id, X3).
func TestArm64RewriteOfComparedRegisterBetweenCmpAndBranchDoesNotNarrow(t *testing.T) {
	ctx := minimalTypeContext()
	ctx.SetClassIDTagLayout(12, 20)
	var entry [31]TypeLattice
	entry[3] = UnknownClassID()
	AnalyzeFunction(armCidLadder(rawMovX1X3), ctx, entry, nil)
	if ctx.NarrowHits != 0 || ctx.NarrowSrcHits != 0 {
		t.Fatalf("stale CMP narrowed a rewritten register: NarrowHits=%d NarrowSrcHits=%d", ctx.NarrowHits, ctx.NarrowSrcHits)
	}
}

const rawMovX1X3 = 0xAA0303E1 // MOV X1, X3
