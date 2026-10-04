package decompiler

import (
	"testing"

	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
)

// Dart's LoadWordFromPoolIndex emits a single `ldr xD, [PP, #imm]` only
// while the displacement fits the 12-bit unsigned-offset field. Past that
// it emits `add xT, PP, #hi` then `ldr xD, [xT, #lo]`.
//
// Pool-load provenance is recovered by disasm.ExtractARM64PoolAccesses, shared
// with analysis and strxref; these tests pin the lifter's consumption of that
// canonical result rather than a second local address tracker.

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
	fir := BuildARM64IR("f", "3.12.2", false, insts, sdk.RegisterCallingConvention{})

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
	fir := BuildARM64IR("f", "3.12.2", false, insts, sdk.RegisterCallingConvention{})
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
	fir := BuildARM64IR("f", "3.12.2", false, insts, sdk.RegisterCallingConvention{})
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

func TestLiftPoolLoadLargeMOVZMOVKFallback(t *testing.T) {
	// Exact SDK fallback for offset 0x01000010 / pool[0x200000]. This shape
	// used to be understood by disasm but not by the decompiler's local tracker.
	movz := uint32(0xD2800000 | (0x10 << 5) | 16)
	movk := uint32(0xF2800000 | (1 << 21) | (0x100 << 5) | 16)
	ldr := uint32(0xF8606800 | (16 << 16) | (27 << 5) | 16)
	insts := []disasm.Inst{
		inst(0x2000, movz, "movz", "x16, #0x10"),
		inst(0x2004, movk, "movk", "x16, #0x100, lsl #16"),
		inst(0x2008, ldr, "ldr", "x16, [x27, x16]"),
		inst(0x200c, 0xD65F03C0, "ret", ""),
	}
	fir := BuildARM64IR("f", "3.13.0", false, insts, sdk.RegisterCallingConvention{})
	for i := range fir.Blocks {
		for _, in := range fir.Blocks[i].Instrs {
			if in.Addr != 0x2008 {
				continue
			}
			if in.Op != OpLoadPool || in.PoolIndex != 0x200000 || in.Target != "x16" {
				t.Fatalf("large fallback lift = %+v, want OpLoadPool pool[0x200000] -> x16", in)
			}
			return
		}
	}
	t.Fatal("large fallback LDR not found in lifted IR")
}

func TestLiftPoolLoadDoesNotCrossJoin(t *testing.T) {
	bEqToLdr := uint32(0x54000000 | (2 << 5))
	addX0PP := uint32(0x91000000 | (1 << 22) | (4 << 10) | (27 << 5))
	ldrX16X0 := uint32(0xF9400010)
	insts := []disasm.Inst{
		inst(0x3000, bEqToLdr, "b", "eq, .+0x8"),
		inst(0x3004, addX0PP, "add", "x0, x27, #0x4000"),
		inst(0x3008, ldrX16X0, "ldr", "x16, [x0]"),
		inst(0x300c, 0xD65F03C0, "ret", ""),
	}
	fir := BuildARM64IR("f", "3.13.0", false, insts, sdk.RegisterCallingConvention{})
	for i := range fir.Blocks {
		for _, in := range fir.Blocks[i].Instrs {
			if in.Addr == 0x3008 && in.Op == OpLoadPool {
				t.Fatalf("join-bypassed ADD fabricated OpLoadPool: %+v", in)
			}
		}
	}
}

func TestLiftPoolStoreIsNotLoadProvenance(t *testing.T) {
	// StoreWordToPoolIndex is a pool xref, but it writes the slot; it must not
	// become OpLoadPool or claim that x3 now contains the pool value.
	insts := []disasm.Inst{
		inst(0x4000, 0xF9000F63, "str", "x3, [x27, #0x18]"),
		inst(0x4004, 0xD65F03C0, "ret", ""),
	}
	fir := BuildARM64IR("f", "3.13.0", false, insts, sdk.RegisterCallingConvention{})
	for i := range fir.Blocks {
		for _, in := range fir.Blocks[i].Instrs {
			if in.Addr == 0x4000 && in.Op == OpLoadPool {
				t.Fatalf("pool store was lifted as a load: %+v", in)
			}
		}
	}
}

func TestLiftFPPoolLoadIsNotGPRPoolLoad(t *testing.T) {
	insts := []disasm.Inst{
		inst(0x4100, 0x3DC00762, "ldr", "q2, [x27, #0x10]"),
		inst(0x4104, 0xD65F03C0, "ret", ""),
	}
	fir := BuildARM64IR("f", "3.13.0", false, insts, sdk.RegisterCallingConvention{})
	for i := range fir.Blocks {
		for _, in := range fir.Blocks[i].Instrs {
			if in.Addr == 0x4100 && in.Op == OpLoadPool {
				t.Fatalf("FP/SIMD immediate load was lifted as GPR pool object load: %+v", in)
			}
		}
	}
}
