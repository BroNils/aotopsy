package decompiler

import (
	"testing"

	"aotopsy/internal/disasm"
)

// Dart's LoadWordFromPoolIndex emits a single `ldr xD, [PP, #imm]` only
// while the displacement fits the 12-bit unsigned-offset field. Past that
// it emits `add xT, PP, #hi` then `ldr xD, [xT, #lo]`.
//
// The lifter recognised the one-instruction form only, so on a real
// production binary 60% of pool loads produced no OpLoadPool -- and every
// string, class and stub reference behind them was invisible to the
// pseudocode and to strxref. Recognising the pair took string
// cross-references on dart-3.9.2-arm64 from 716 to 1154.

func inst(addr uint64, raw uint32, mnem, ops string) disasm.Inst {
	return disasm.Inst{Addr: addr, Raw: raw, Size: 4, Mnemonic: mnem, Operands: ops,
		Text: mnem + " " + ops}
}

const (
	// add x2, x27, #4, lsl #12   (x27 = PP, so x2 = PP + 0x4000)
	rawAddPoolBase = 0x91401362
	// ldr x3, [x2, #0x10]
	rawLdrViaBase = 0xF9400843
	// ldr x4, [x27, #0x18]       (the one-instruction form)
	rawLdrDirect = 0xF9400F64
)

func TestLiftPoolLoadViaAddBase(t *testing.T) {
	insts := []disasm.Inst{
		inst(0x1000, rawAddPoolBase, "add", "x2, x27, #0x4000"),
		inst(0x1004, rawLdrViaBase, "ldr", "x3, [x2, #0x10]"),
		inst(0x1008, 0xD65F03C0, "ret", ""),
	}
	fir := BuildARM64IR("f", insts)

	var got *Instr
	for i := range fir.Blocks {
		for j := range fir.Blocks[i].Instrs {
			if fir.Blocks[i].Instrs[j].Addr == 0x1004 {
				got = &fir.Blocks[i].Instrs[j]
			}
		}
	}
	if got == nil {
		t.Fatal("the ldr was not lifted at all")
	}
	if got.Op != OpLoadPool {
		t.Fatalf("Op = %v, want OpLoadPool: the two-instruction pool form was not recognised", got.Op)
	}
	// PP is untagged: elements start at +16, 8 bytes each.
	// (0x4000 + 0x10 - 16) / 8 = 2048.
	if got.PoolIndex != 2048 {
		t.Errorf("PoolIndex = %d, want 2048", got.PoolIndex)
	}
	if got.Target != "x3" {
		t.Errorf("Target = %q, want %q", got.Target, "x3")
	}
}

// A base whose register is overwritten before the load must not resolve:
// the address it named no longer exists, and resolving it anyway would
// point at an arbitrary pool slot.
func TestLiftPoolBaseInvalidatedByRedefine(t *testing.T) {
	insts := []disasm.Inst{
		inst(0x1000, rawAddPoolBase, "add", "x2, x27, #0x4000"),
		// ldr x2, [x27, #0x18] -- redefines x2 from the pool directly
		inst(0x1004, 0xF9400F62, "ldr", "x2, [x27, #0x18]"),
		inst(0x1008, rawLdrViaBase, "ldr", "x3, [x2, #0x10]"),
		inst(0x100c, 0xD65F03C0, "ret", ""),
	}
	fir := BuildARM64IR("f", insts)
	for i := range fir.Blocks {
		for _, in := range fir.Blocks[i].Instrs {
			if in.Addr == 0x1008 && in.Op == OpLoadPool {
				t.Errorf("load at 0x1008 resolved to pool[%d] through a base whose register was overwritten",
					in.PoolIndex)
			}
		}
	}
}

// The one-instruction form must keep working unchanged.
func TestLiftPoolLoadDirect(t *testing.T) {
	insts := []disasm.Inst{
		inst(0x1000, rawLdrDirect, "ldr", "x4, [x27, #0x18]"),
		inst(0x1004, 0xD65F03C0, "ret", ""),
	}
	fir := BuildARM64IR("f", insts)
	found := false
	for i := range fir.Blocks {
		for _, in := range fir.Blocks[i].Instrs {
			if in.Addr == 0x1000 {
				found = true
				if in.Op != OpLoadPool {
					t.Fatalf("Op = %v, want OpLoadPool", in.Op)
				}
				if in.PoolIndex != 1 { // (0x18 - 16) / 8
					t.Errorf("PoolIndex = %d, want 1", in.PoolIndex)
				}
			}
		}
	}
	if !found {
		t.Fatal("instruction not lifted")
	}
}
