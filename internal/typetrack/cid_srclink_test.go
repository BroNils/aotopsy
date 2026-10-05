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
