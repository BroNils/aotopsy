package typetrack

import (
	"testing"

	"aotopsy/internal/arch/x86"
	"aotopsy/internal/disasm"

	"golang.org/x/arch/x86/x86asm"
)

// Real encodings from the 3.9.2 corpus sample (dyn:call site):
//
//	ADD X16, X27, #0x298        0x910A6370
//	LDP X5, X30, [X16]          0xA9407A05   (<= 3.9.2 pair order)
//	LDP X30, X5, [X16]          0xA940161E   (>= 3.10.7 pair order)
//	BLR X30                     0xD63F03C0
//
// and the two-ADD form LoadDoubleWordFromPoolIndex uses past the LDP range:
//
//	ADD X16, X27, #0x4, LSL #12 0x91401370
//	ADD X16, X16, #0x2d0        0x910B4210
const (
	rawAddPP298   = 0x910A6370
	rawLdpIC30    = 0xA9407A05
	rawLdp30IC    = 0xA940161E
	rawBlrX30     = 0xD63F03C0
	rawAddPPHi4   = 0x91401370
	rawAddX16d0x2 = 0x910B4210
)

func switchableCtx(poolIdx int, name string) *TypeContext {
	return &TypeContext{
		PoolUnlinkedCallNames:    map[int]string{poolIdx: name},
		MethodNameToSelectorImms: map[string][]int{name: {5}},
		SelectorMonomorphic:      map[int]string{5: "Foo.foo"},
		SelectorCache:            map[int][]string{},
	}
}

func runPairSeq(t *testing.T, ctx *TypeContext, raws ...uint32) *IntraResult {
	t.Helper()
	var state [31]TypeLattice
	for i := range state {
		state[i] = Top()
	}
	stack := make(map[int]TypeLattice)
	shadow := shadowSPState{}
	result := &IntraResult{}
	for i, raw := range raws {
		inst := disasm.Inst{Addr: 0x1000 + uint64(i)*4, Raw: raw, Size: 4}
		transferInstruction(&state, inst, 0, ctx, result, nil, stack, &shadow)
	}
	return result
}

// The BLR through LR after `LDP R5, LR, [pool]` resolves by the UnlinkedCall's
// selector -- not to whatever the stub slot happens to display as.
func TestPoolPairLoadResolvesSwitchableCallBySelector(t *testing.T) {
	// ADD X16 = PP+0x298 -> pool index (0x298-16)/8 = 81 for R5; the stub is 82.
	res := runPairSeq(t, switchableCtx(81, "foo"), rawAddPP298, rawLdpIC30, rawBlrX30)
	if len(res.BLRResolutions) != 1 {
		t.Fatalf("BLR resolutions = %+v, want one", res.BLRResolutions)
	}
	r := res.BLRResolutions[0]
	if r.Derivation != DerivationUnlinkedCall || r.TargetName != "Foo.foo" {
		t.Fatalf("resolution = %+v, want unlinked_call -> Foo.foo", r)
	}
}

// >= 3.10.7 loads {stub -> LR, UnlinkedCall -> R5}: the UnlinkedCall is the
// SECOND pool word, so it sits at index 82.
func TestPoolPairLoadHonoursThe3107PairOrder(t *testing.T) {
	res := runPairSeq(t, switchableCtx(82, "foo"), rawAddPP298, rawLdp30IC, rawBlrX30)
	if len(res.BLRResolutions) != 1 || res.BLRResolutions[0].Derivation != DerivationUnlinkedCall {
		t.Fatalf("resolutions = %+v, want one unlinked_call", res.BLRResolutions)
	}
}

// ADD X16,PP,#hi,LSL#12 ; ADD X16,X16,#lo accumulates into one pool offset
// (0x4000 + 0x2d0 = 0x42d0 -> index (0x42d0-16)/8 = 2136).
func TestTwoAddPoolBaseAccumulates(t *testing.T) {
	res := runPairSeq(t, switchableCtx(2136, "foo"), rawAddPPHi4, rawAddX16d0x2, rawLdpIC30, rawBlrX30)
	if len(res.BLRResolutions) != 1 || res.BLRResolutions[0].Derivation != DerivationUnlinkedCall {
		t.Fatalf("resolutions = %+v, want one unlinked_call", res.BLRResolutions)
	}
}

// A pair whose R5 slot is not a call site must not be named: the BLR stays
// unresolved instead of inheriting a stub display name.
func TestPoolPairLoadOfANonCallSiteStaysUnresolved(t *testing.T) {
	res := runPairSeq(t, switchableCtx(500, "foo"), rawAddPP298, rawLdpIC30, rawBlrX30)
	for _, r := range res.BLRResolutions {
		if r.Derivation == DerivationUnlinkedCall {
			t.Fatalf("resolved a non call-site pair: %+v", r)
		}
	}
}

func decodeX86Seq(t *testing.T, code ...[]byte) []x86.Decoded {
	t.Helper()
	var out []x86.Decoded
	va := uint64(0x1000)
	for _, b := range code {
		in, err := x86asm.Decode(b, 64)
		if err != nil {
			t.Fatalf("decode % x: %v", b, err)
		}
		out = append(out, x86.Decoded{VA: va, Inst: in, Len: in.Len})
		va += uint64(in.Len)
	}
	return out
}

// x86_64 EmitInstanceCallAOT: the stub goes to RCX, the UnlinkedCall to RBX, then
// `call RCX`. Real bytes (3.9.2 shape; pool slots 5 and 6):
//
//	49 8b 4f 37   mov rcx, [r15+0x37]
//	49 8b 5f 3f   mov rbx, [r15+0x3f]
//	ff d1         call rcx
func TestX86SwitchableCallResolvesBySelector(t *testing.T) {
	insts := decodeX86Seq(t,
		[]byte{0x49, 0x8b, 0x4f, 0x37},
		[]byte{0x49, 0x8b, 0x5f, 0x3f},
		[]byte{0xff, 0xd1})
	ctx := switchableCtx(6, "foo")
	var state [31]TypeLattice
	for i := range state {
		state[i] = Top()
	}
	result := &IntraResult{}
	var prev *x86.Decoded
	for i := range insts {
		transferInstructionX86(&state, insts[i], prev, ctx, result, nil, map[int]TypeLattice{})
		prev = &insts[i]
	}
	if len(result.BLRResolutions) != 1 || result.BLRResolutions[0].Derivation != DerivationUnlinkedCall ||
		result.BLRResolutions[0].TargetName != "Foo.foo" {
		t.Fatalf("resolutions = %+v, want one unlinked_call -> Foo.foo", result.BLRResolutions)
	}
}

// `dyn:foo` is the dynamic-invocation forwarder name of `foo`; the resolver
// demangles it before the lookup, so the candidates are those of `foo`.
func TestDynPrefixedUnlinkedCallResolvesByTheDemangledSelector(t *testing.T) {
	ctx := switchableCtx(81, "foo") // selector table and candidates are keyed by `foo`
	ctx.PoolUnlinkedCallNames[81] = "dyn:foo"
	res := runPairSeq(t, ctx, rawAddPP298, rawLdpIC30, rawBlrX30)
	if len(res.BLRResolutions) != 1 || res.BLRResolutions[0].TargetName != "Foo.foo" {
		t.Fatalf("resolutions = %+v, want Foo.foo via the demangled selector", res.BLRResolutions)
	}
}
