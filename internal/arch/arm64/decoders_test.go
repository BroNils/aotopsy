package arm64

import (
	"math"
	"testing"
)

func TestBL(t *testing.T) {
	raw := uint32(0x94000000 | (0x100 / 4))
	target, ok := BL(raw, 0x1000)
	if !ok || target != 0x1100 {
		t.Fatalf("BL() = (0x%x, %v), want (0x1100, true)", target, ok)
	}

	if _, ok := BL(0x14000000, 0x1000); ok {
		t.Fatalf("BL() on B instruction returned true")
	}
}

func TestB(t *testing.T) {
	off := int32(-0x100 / 4)
	imm26 := uint32(off) & 0x03FFFFFF
	raw := uint32(0x14000000 | imm26)
	target, ok := B(raw, 0x2000)
	if !ok || target != 0x1F00 {
		t.Fatalf("B() = (0x%x, %v), want (0x1F00, true)", target, ok)
	}
}

func TestBranchEncodingIdentitySurvivesTargetOverflow(t *testing.T) {
	if !IsBLEncoding(0x94000001) || !IsBEncoding(0x14000001) {
		t.Fatal("direct branch encoding identity was not recognized")
	}
	if !IsConditionalBranchEncoding(0x54000040) || !IsConditionalBranchEncoding(0x34000040) || !IsConditionalBranchEncoding(0x36000040) {
		t.Fatal("conditional branch encoding identity was not recognized")
	}
	if IsConditionalBranchEncoding(0x5400004E) || IsConditionalBranchEncoding(0x5400004F) {
		t.Fatal("B.AL/B.NV were misclassified as conditional")
	}
	if _, ok := BL(0x94000001, math.MaxUint64-3); ok {
		t.Fatal("overflowing BL produced a target")
	}
	if _, ok := B(0x14000001, math.MaxUint64-3); ok {
		t.Fatal("overflowing B produced a target")
	}
}

func TestBLR(t *testing.T) {
	raw := uint32(0xD63F0000 | (30 << 5))
	rn, ok := BLR(raw)
	if !ok || rn != 30 {
		t.Fatalf("BLR() = (%d, %v), want (30, true)", rn, ok)
	}
}

func TestIsRet(t *testing.T) {
	if !IsRet(0xD65F03C0) {
		t.Fatalf("IsRet(0xD65F03C0) = false, want true")
	}
	if !IsRet(0xD65F0000) {
		t.Fatalf("IsRet(0xD65F0000) = false, want true")
	}
	if IsRet(0x14000000) {
		t.Fatalf("IsRet on B returned true")
	}
}

func TestIsBR(t *testing.T) {
	raw := uint32(0xD61F0000 | (16 << 5))
	rn, ok := IsBR(raw)
	if !ok || rn != 16 {
		t.Fatalf("IsBR() = (%d, %v), want (16, true)", rn, ok)
	}
}

func TestCondBranch(t *testing.T) {
	rawBEQ := uint32(0x54000000 | (8 << 5))
	if target, ok := CondBranch(rawBEQ, 0x1000); !ok || target != 0x1020 {
		t.Fatalf("CondBranch(B.EQ) = (0x%x, %v), want (0x1020, true)", target, ok)
	}

	rawBAL := uint32(0x54000000 | (8 << 5) | 14)
	if _, ok := CondBranch(rawBAL, 0x1000); ok {
		t.Fatalf("CondBranch(B.AL) = true, want false")
	}

	rawCBZ := uint32(0x34000000 | (16 << 5))
	if target, ok := CondBranch(rawCBZ, 0x1000); !ok || target != 0x1040 {
		t.Fatalf("CondBranch(CBZ) = (0x%x, %v), want (0x1040, true)", target, ok)
	}

	rawCBNZ := uint32(0x35000000 | (16 << 5) | 1)
	if target, ok := CondBranch(rawCBNZ, 0x1000); !ok || target != 0x1040 {
		t.Fatalf("CondBranch(CBNZ) = (0x%x, %v), want (0x1040, true)", target, ok)
	}

	rawTBZ := uint32(0x36000000 | (8 << 5))
	if target, ok := CondBranch(rawTBZ, 0x1000); !ok || target != 0x1020 {
		t.Fatalf("CondBranch(TBZ) = (0x%x, %v), want (0x1020, true)", target, ok)
	}

	rawTBNZ := uint32(0x37000000 | (8 << 5))
	if target, ok := CondBranch(rawTBNZ, 0x1000); !ok || target != 0x1020 {
		t.Fatalf("CondBranch(TBNZ) = (0x%x, %v), want (0x1020, true)", target, ok)
	}
}

func TestBCondClassDistinguishesHistoricalALFromReservedNV(t *testing.T) {
	if cond, kind, ok := BCondClass(0x5400004E); !ok || cond != 14 || kind != BCondAlways {
		t.Fatalf("B.AL class = (%d,%d,%v), want (14,always,true)", cond, kind, ok)
	}
	if target, cond, kind, ok := BCond(0x5400004E, 0x1000); !ok || target != 0x1008 || cond != 14 || kind != BCondAlways {
		t.Fatalf("B.AL decode = (%#x,%d,%d,%v), want (0x1008,14,always,true)", target, cond, kind, ok)
	}
	if cond, kind, ok := BCondClass(0x5400004F); !ok || cond != 15 || kind != BCondReserved {
		t.Fatalf("B.NV class = (%d,%d,%v), want (15,reserved,true)", cond, kind, ok)
	}
	if target, _, kind, ok := BCond(0x5400004F, 0x1000); !ok || target != 0 || kind != BCondReserved {
		t.Fatalf("B.NV decode = (%#x,%d,%v), want reserved/no target", target, kind, ok)
	}
	// Classification is preserved even if the target arithmetic cannot be
	// represented in uint64; CFG consumers still need to terminate the block.
	if _, kind, ok := BCondClass(0x5400002E); !ok || kind != BCondAlways {
		t.Fatalf("overflowing B.AL lost opcode classification: kind=%d ok=%v", kind, ok)
	}
	if _, _, _, ok := BCond(0x5400002E, math.MaxUint64-3); ok {
		t.Fatal("overflowing B.AL returned a representable target")
	}
}

func TestImmediateAndPairAddressModes(t *testing.T) {
	if m, ok := Store64Immediate(0xF81F8DE1); !ok || m.BaseReg != 15 || m.Reg != 1 || m.ByteOffset != -8 || m.Mode != AddressPreIndex {
		t.Fatalf("STR pre-index decode = %+v ok=%v", m, ok)
	}
	if m, ok := Load64Immediate(0xF84085E0); !ok || m.BaseReg != 15 || m.Reg != 0 || m.ByteOffset != 8 || m.Mode != AddressPostIndex {
		t.Fatalf("LDR post-index decode = %+v ok=%v", m, ok)
	}
	if m, ok := Load64Immediate(0xF8427002); !ok || m.BaseReg != 0 || m.Reg != 2 || m.ByteOffset != 39 || m.Mode != AddressOffset {
		t.Fatalf("LDUR decode = %+v ok=%v", m, ok)
	}
	if m, ok := Load64Immediate(0xF9400BA0); !ok || m.BaseReg != 29 || m.Reg != 0 || m.ByteOffset != 16 || m.Mode != AddressOffset {
		t.Fatalf("LDR unsigned-offset decode = %+v ok=%v", m, ok)
	}

	if p, ok := StorePair64(0xA9BF79FD); !ok || p.BaseReg != 15 || p.Reg1 != 29 || p.Reg2 != 30 || p.ByteOffset != -16 || p.Mode != PairPreIndex {
		t.Fatalf("STP pre-index decode = %+v ok=%v", p, ok)
	}
	if p, ok := LoadPair64(0xA8C179FD); !ok || p.BaseReg != 15 || p.Reg1 != 29 || p.Reg2 != 30 || p.ByteOffset != 16 || p.Mode != PairPostIndex {
		t.Fatalf("LDP post-index decode = %+v ok=%v", p, ok)
	}
	// STNP is non-temporal/no-writeback, not the post-index STP class.
	if p, ok := StorePair64(0xA8000440); !ok || p.BaseReg != 2 || p.Reg1 != 0 || p.Reg2 != 1 || p.ByteOffset != 0 || p.Mode != PairNonTemporal {
		t.Fatalf("STNP decode = %+v ok=%v", p, ok)
	}
}

func TestBranchTargetsRejectAddressWraparound(t *testing.T) {
	if target, ok := BL(0x94000001, math.MaxUint64-1); ok {
		t.Fatalf("overflowing BL target resolved to %#x", target)
	}
	// B #-4: imm26 is all ones.
	if target, ok := B(0x17FFFFFF, 0); ok {
		t.Fatalf("underflowing B target resolved to %#x", target)
	}
	// B.EQ #+4 at the top of the address space.
	if target, ok := CondBranch(0x54000020, math.MaxUint64-1); ok {
		t.Fatalf("overflowing B.cond target resolved to %#x", target)
	}
	if target, ok := PCRelativeTarget(0, math.MinInt64); ok {
		t.Fatalf("MinInt64 underflow resolved to %#x", target)
	}
}

func TestDstRegOfInst(t *testing.T) {
	rawLDR := uint32(0xF9400000 | (1 << 10) | (27 << 5))
	if rd := DstRegOfInst(rawLDR); rd != 0 {
		t.Fatalf("DstRegOfInst(LDR) = %d, want 0", rd)
	}

	rawMOV := uint32(0xAA0203E1)
	if rd := DstRegOfInst(rawMOV); rd != 1 {
		t.Fatalf("DstRegOfInst(MOV) = %d, want 1", rd)
	}

	// LDP X0, X1, [X26, #80] -> 0xA9450740
	rawLDP := uint32(0xA9400000 | (10 << 15) | (1 << 10) | (26 << 5))
	regs := DstRegsOfInst(rawLDP)
	if len(regs) != 2 || regs[0] != 0 || regs[1] != 1 {
		t.Fatalf("DstRegsOfInst(LDP) = %v, want [0, 1]", regs)
	}

	base, r1, r2, off, ok := LDP64UnsignedOffset(rawLDP)
	if !ok || base != 26 || r1 != 0 || r2 != 1 || off != 80 {
		t.Fatalf("LDP64UnsignedOffset = (%d, %d, %d, %d, %v), want (26, 0, 1, 80, true)", base, r1, r2, off, ok)
	}

	// CMP X0, #0 (SUBS XZR, X0, #0) -> no destination register (discards to XZR)
	rawCMP := uint32(0xF100001F)
	if cmpRegs := DstRegsOfInst(rawCMP); len(cmpRegs) != 0 {
		t.Fatalf("DstRegsOfInst(CMP) = %v, want empty", cmpRegs)
	}

	// CSEL X0, X1, X2, EQ -> 0x9A820020
	rawCSEL := uint32(0x9A820020)
	if cselRegs := DstRegsOfInst(rawCSEL); len(cselRegs) != 1 || cselRegs[0] != 0 {
		t.Fatalf("DstRegsOfInst(CSEL) = %v, want [0]", cselRegs)
	}
}

// TestSUBS32ImmediateIgnores64Bit pins the deliberate asymmetry: the
// class-id narrowing that consumes this decoder must not see 64-bit
// comparisons, because a CMP on an X register is comparing a tagged value
// and narrowing it to KnownClass(imm) is wrong. See the comment above
// MOVZ64 for the measurement that settled it.
func TestSUBS32ImmediateIgnores64Bit(t *testing.T) {
	// CMP W3, #1  ->  SUBS WZR, W3, #1
	if rd, rn, imm, ok := SUBS32Immediate(0x7100047F); !ok || rd != 31 || rn != 3 || imm != 1 {
		t.Errorf("SUBS32Immediate(CMP W3,#1) = (%d,%d,%d,%v), want (31,3,1,true)", rd, rn, imm, ok)
	}
	// CMP X2, #7  ->  SUBS XZR, X2, #7 must NOT match.
	if _, _, _, ok := SUBS32Immediate(0xF1001C5F); ok {
		t.Error("SUBS32Immediate matched a 64-bit CMP; class-id narrowing would fire on tagged values")
	}
	// Plain SUB (no flags) must not match either.
	if _, _, _, ok := SUBS32Immediate(0x51001C41); ok {
		t.Error("SUBS32Immediate matched SUB, which does not set flags")
	}
}

func TestLargePoolFallbackInstructionDecoders(t *testing.T) {
	// Exact shape used by Assembler::LoadWordFromPoolIndex when a byte offset
	// cannot be encoded by the direct LDR or ADD+LDR cases:
	//   movz x16,#0x10
	//   movk x16,#0x100,lsl #16
	//   ldr  x16,[x27,x16]
	movz := uint32(0xD2800000 | (0x10 << 5) | 16)
	movk := uint32(0xF2800000 | (1 << 21) | (0x100 << 5) | 16)
	ldr := uint32(0xF8606800 | (16 << 16) | (27 << 5) | 16)

	if rd, imm, ok := MOVZ64(movz); !ok || rd != 16 || imm != 0x10 {
		t.Fatalf("MOVZ64 = (%d,%#x,%v), want (16,0x10,true)", rd, imm, ok)
	}
	if rd, imm, shift, ok := MOVK64(movk); !ok || rd != 16 || imm != 0x100 || shift != 16 {
		t.Fatalf("MOVK64 = (%d,%#x,%d,%v), want (16,0x100,16,true)", rd, imm, shift, ok)
	}
	base, rm, rt, scaled, ok := LDR64RegisterOffset(ldr)
	if !ok || base != 27 || rm != 16 || rt != 16 || scaled {
		t.Fatalf("LDR64RegisterOffset = (%d,%d,%d,%v,%v), want (27,16,16,false,true)", base, rm, rt, scaled, ok)
	}
	if _, _, _, ok := LDRRegExtended(ldr); ok {
		t.Fatal("scaled dispatch-table decoder accepted unscaled pool-offset LDR")
	}
	scaledLDR := ldr | (1 << 12)
	if base, rm, rt, ok := LDRRegExtended(scaledLDR); !ok || base != 27 || rm != 16 || rt != 16 {
		t.Fatalf("LDRRegExtended(scaled) = (%d,%d,%d,%v)", base, rm, rt, ok)
	}

	// Exact StoreWordToPoolIndex large-offset form, assembled as
	// `str x3, [x27, x16]` -> 0xf8306b63.
	store := uint32(0xF8306B63)
	if base, rm, rt, scaled, ok := STR64RegisterOffset(store); !ok || base != 27 || rm != 16 || rt != 3 || scaled {
		t.Fatalf("STR64RegisterOffset = (%d,%d,%d,%v,%v), want (27,16,3,false,true)", base, rm, rt, scaled, ok)
	}
	if _, _, _, _, ok := STR64RegisterOffset(store &^ (1 << 13)); ok {
		t.Fatal("STR64RegisterOffset accepted an unrelated option encoding")
	}
}

func TestFPPoolLoadInstructionDecoders(t *testing.T) {
	// Replay-assembled exact instructions from LoadS/D/QImmediate lowering.
	unsigned := []struct {
		name             string
		raw              uint32
		wantReg, wantOff int
		wantWidth        int
	}{
		{"S", 0xBD401360, 0, 16, 4},
		{"D", 0xFD400B61, 1, 16, 8},
		{"Q", 0x3DC00762, 2, 16, 16},
	}
	for _, tc := range unsigned {
		base, reg, off, width, ok := FPLoadUnsignedOffset(tc.raw)
		if !ok || base != 27 || reg != tc.wantReg || off != tc.wantOff || width != tc.wantWidth {
			t.Errorf("%s unsigned FP load = (%d,%d,%d,%d,%v)", tc.name, base, reg, off, width, ok)
		}
	}

	regoff := []struct {
		name      string
		raw       uint32
		wantReg   int
		wantWidth int
	}{
		{"S", 0xBC706B66, 6, 4},
		{"D", 0xFC706B67, 7, 8},
		{"Q", 0x3CF06B68, 8, 16},
	}
	for _, tc := range regoff {
		base, rm, reg, width, scaled, ok := FPLoadRegisterOffset(tc.raw)
		if !ok || base != 27 || rm != 16 || reg != tc.wantReg || width != tc.wantWidth || scaled {
			t.Errorf("%s register FP load = (%d,%d,%d,%d,%v,%v)", tc.name, base, rm, reg, width, scaled, ok)
		}
	}
}

func TestPoolOffsetImmediateMaterializationDecoders(t *testing.T) {
	// Replay-assembled forms selected by Assembler::LoadImmediate.
	if rd, imm, ok := ORR64ImmediateFromZR(0xB27003F0); !ok || rd != 16 || imm != 0x10000 {
		t.Fatalf("ORR64ImmediateFromZR = (%d,%#x,%v), want (16,0x10000,true)", rd, imm, ok)
	}
	if rd, imm, shift, ok := MOVZ64Shifted(0xD2A00031); !ok || rd != 17 || imm != 1 || shift != 16 {
		t.Fatalf("MOVZ64Shifted = (%d,%#x,%d,%v), want (17,1,16,true)", rd, imm, shift, ok)
	}
	if _, _, ok := MOVZ64(0xD2A00031); ok {
		t.Fatal("narrow MOVZ64 accepted shifted MOVZ")
	}
}

// TestDstRegsOfInstStoresDefineNothing pins the load/store split.
//
// transferInstruction uses DstRegsOfInst to invalidate a register's
// tracked type, so a store misread as a define erases type information
// that is still live. The unscaled and unsigned-immediate masks used to
// omit bits 23:22 -- the opc field that says load or store -- so STUR Wt,
// STURB, STURH and STR Wt all reported Rt as a destination. On ARM64 that
// collapsed intra-procedural inference: dart-2.12.0 lost 36632
// add_class_hits and gained 4967 blr_at_top.
func TestDstRegsOfInstStoresDefineNothing(t *testing.T) {
	stores := []struct {
		name string
		raw  uint32
	}{
		{"STR Wt, [Xn,#imm]", 0xB9000001},
		{"STR Xt, [Xn,#imm]", 0xF9000001},
		{"STRB Wt, [Xn,#imm]", 0x39000001},
		{"STRH Wt, [Xn,#imm]", 0x79000001},
		{"STUR Xt, [Xn,#imm]", 0xF8000001},
		{"STUR Wt, [Xn,#imm]", 0xB8000001},
		{"STURB Wt, [Xn,#imm]", 0x38000001},
		{"STURH Wt, [Xn,#imm]", 0x78000001},
	}
	for _, s := range stores {
		if regs := DstRegsOfInst(s.raw); len(regs) != 0 {
			t.Errorf("DstRegsOfInst(%s = %#08x) = %v, want none: a store does not define its source register",
				s.name, s.raw, regs)
		}
	}
}

// TestDstRegsOfInstLoadModes covers every addressing mode of the
// unscaled group. All four write Rt; only LDUR used to be recognised, so
// the `ldr x19,[sp],#8` that restores a callee-saved register in an
// epilogue looked like it defined nothing.
func TestDstRegsOfInstLoadModes(t *testing.T) {
	loads := []struct {
		name string
		raw  uint32
	}{
		{"LDUR X1, [X0,#8]", 0xF8408001},
		{"LDR X1, [X0],#8 (post-index)", 0xF8408401},
		{"LDR X1, [X0,#8]! (pre-index)", 0xF8408C01},
		{"LDTR X1, [X0,#8] (unprivileged)", 0xF8408801},
		{"LDURB W1, [X0,#8]", 0x38408001},
		{"LDURH W1, [X0,#8]", 0x78408001},
		{"LDURSW X1, [X0,#8]", 0xB8808001},
	}
	for _, l := range loads {
		regs := DstRegsOfInst(l.raw)
		want := []int{1}
		if l.raw == 0xF8408401 || l.raw == 0xF8408C01 {
			want = []int{1, 0}
		}
		if len(regs) != len(want) {
			t.Errorf("DstRegsOfInst(%s = %#08x) = %v, want %v", l.name, l.raw, regs, want)
			continue
		}
		for i := range want {
			if regs[i] != want[i] {
				t.Errorf("DstRegsOfInst(%s = %#08x) = %v, want %v", l.name, l.raw, regs, want)
				break
			}
		}
	}
}

func TestDstRegsOfInstWritebackExclusiveAndFMOV(t *testing.T) {
	tests := []struct {
		name string
		raw  uint32
		want []int
	}{
		{"LDR X0, [X1],#8", 0xF8408420, []int{0, 1}},
		{"STR X4, [X5],#8", 0xF80084A4, []int{5}},
		{"LDXR X12,[X13]", 0xC85F7DAC, []int{12}},
		{"STXR W4,X2,[X3]", 0xC8047C62, []int{4}},
		{"FMOV X0,D1", 0x9E660020, []int{0}},
		{"BL", 0x94000000, []int{30}},
		{"BLR X9", 0xD63F0120, []int{30}},
	}
	for _, tt := range tests {
		got := DstRegsOfInst(tt.raw)
		if len(got) != len(tt.want) {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
			continue
		}
		for i := range tt.want {
			if got[i] != tt.want[i] {
				t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
				break
			}
		}
	}
}

func TestAliasDecodersRejectTransformsAndMTE(t *testing.T) {
	if _, _, _, _, ok := UBFX(0xD374CCA4); ok { // LSL X4,X5,#12
		t.Fatal("UBFX accepted wrapping UBFM/LSL encoding")
	}
	if _, _, ok := MOVOrr(0xAA0307E2); ok { // ORR X2,XZR,X3,LSL #1
		t.Fatal("MOVOrr accepted shifted ORR")
	}
	if _, _, _, ok := ADD64Immediate(0x91800360); ok { // ADDG X0,X27,#0,#0
		t.Fatal("ADD64Immediate accepted MTE ADDG encoding")
	}
	// The exact aliases still match.
	if rd, rm, ok := MOVOrr(0xAA0303E2); !ok || rd != 2 || rm != 3 { // MOV X2,X3
		t.Fatalf("MOVOrr(real MOV) = (%d,%d,%v), want (2,3,true)", rd, rm, ok)
	}
	// UBFX X2,X1,#12,#20 => UBFM X2,X1,#12,#31.
	if rd, rn, lsb, width, ok := UBFX(0xD34C7C22); !ok || rd != 2 || rn != 1 || lsb != 12 || width != 20 {
		t.Fatalf("UBFX(real extract) = (%d,%d,%d,%d,%v), want (2,1,12,20,true)", rd, rn, lsb, width, ok)
	}
}

func TestADD64RegisterPreservesShiftSemantics(t *testing.T) {
	// ADD X0, X0, X28, LSR #7. This exact transformed HEAP_BITS operand used
	// to be indistinguishable from a compressed-pointer decompression.
	if rd, rn, rm, shift, amount, ok := ADD64Register(0x8B5C1C00); !ok ||
		rd != 0 || rn != 0 || rm != 28 || shift != ShiftLSR || amount != 7 {
		t.Fatalf("shifted ADD decode = (%d,%d,%d,%d,%d,%v), want (0,0,28,LSR,7,true)",
			rd, rn, rm, shift, amount, ok)
	}

	// The Dart compressed-pointer shape is ADD X0,X1,X28,LSL #32.
	rawDecompress := uint32(0x8B000000 | (28 << 16) | (32 << 10) | (1 << 5))
	if rd, rn, rm, shift, amount, ok := ADD64Register(rawDecompress); !ok ||
		rd != 0 || rn != 1 || rm != 28 || shift != ShiftLSL || amount != 32 {
		t.Fatalf("decompress ADD decode = (%d,%d,%d,%d,%d,%v), want (0,1,28,LSL,32,true)",
			rd, rn, rm, shift, amount, ok)
	}
}

func TestUBFXRejectsReservedNZeroEncoding(t *testing.T) {
	if _, _, _, _, ok := UBFX(0xD30C7C20); ok {
		t.Fatal("UBFX accepted reserved 64-bit encoding with N=0")
	}
	if _, _, _, _, ok := UBFX(0xD34C7C20); !ok {
		t.Fatal("UBFX rejected valid N=1 encoding")
	}
}

func TestDstRegsOfInstAcquireLoadsAndLiteralClasses(t *testing.T) {
	for _, tt := range []struct {
		name string
		raw  uint32
		want int
	}{
		{"LDAR X0,[X1]", 0xC8DFFC20, 0},
		{"LDAR W0,[X1]", 0x88DFFC20, 0},
		{"LDARB W2,[X3]", 0x08DFFC62, 2},
		{"LDARH W4,[X5]", 0x48DFFCA4, 4},
	} {
		got := DstRegsOfInst(tt.raw)
		if len(got) != 1 || got[0] != tt.want {
			t.Errorf("%s: got %v, want [%d]", tt.name, got, tt.want)
		}
	}

	for _, tt := range []struct {
		name string
		raw  uint32
	}{
		{"PRFM literal", 0xD8000005},
		{"LDR D3 literal", 0x5C000003},
	} {
		if got := DstRegsOfInst(tt.raw); len(got) != 0 {
			t.Errorf("%s: reported GPR writes %v", tt.name, got)
		}
	}
	if got := DstRegsOfInst(0x58000005); len(got) != 1 || got[0] != 5 {
		t.Fatalf("LDR X5 literal: got %v, want [5]", got)
	}
}

func TestDstRegsOfInstDartGPRWriterFamilies(t *testing.T) {
	tests := []struct {
		name string
		raw  uint32
		want int
	}{
		{"LDRSW register offset", 0xB8A07821, 1},
		{"LDRSB register offset", 0x38A56822, 2},
		{"LDRSH register offset", 0x78A26861, 1},
		{"UMOV/VMOVX lane to GPR", 0x4E083C00, 0},
		{"FCVTZS X0,D5", 0x9E7800A0, 0},
		{"FCVTPS X1,D4", 0x9E680081, 1},
		{"FCVTMS X2,D4", 0x9E700082, 2},
		{"ADC X0,X1,X2", 0x9A020020, 0},
		{"ADCS X0,X1,X2", 0xBA020020, 0},
		{"SBC X0,X1,X2", 0xDA020020, 0},
		{"SBCS X0,X1,X2", 0xFA020020, 0},
		{"LDCLR X2,X0,[X1]", 0xF8221020, 0},
		{"LDSET X2,X0,[X1]", 0xF8223020, 0},
	}
	for _, tt := range tests {
		got := DstRegsOfInst(tt.raw)
		if len(got) != 1 || got[0] != tt.want {
			t.Errorf("%s: DstRegsOfInst(%#08x) = %v, want [%d]", tt.name, tt.raw, got, tt.want)
		}
	}
}

func TestDstRegsOfInstCMNDoesNotWriteSP(t *testing.T) {
	tests := []struct {
		name string
		raw  uint32
	}{
		// CMN is the ADDS alias with Rd=31 (WZR/XZR). Register 31 means SP in
		// ordinary ADD/SUB, but flag-setting forms cannot write SP.
		{"CMN X1,#5", 0xB100143F},
		{"CMN W1,#5", 0x3100143F},
		{"CMN X1,X2", 0xAB02003F},
		{"CMN X1,W2,UXTW", 0xAB22403F},
	}
	for _, tt := range tests {
		if got := DstRegsOfInst(tt.raw); len(got) != 0 {
			t.Errorf("%s: DstRegsOfInst(%#08x) = %v, want no GPR destination", tt.name, tt.raw, got)
		}
	}

	// A real ADDS destination still needs invalidation.
	if got := DstRegsOfInst(0xB1001420); len(got) != 1 || got[0] != 0 { // ADDS X0,X1,#5
		t.Fatalf("ADDS X0,X1,#5 writes = %v, want [0]", got)
	}
}

func TestDstRegsOfInstOmitsArchitecturalSPAndZR(t *testing.T) {
	// ADD SP,SP,#16: register encoding 31 means SP in add/sub immediate.
	if got := DstRegsOfInst(0x910043FF); len(got) != 0 {
		t.Fatalf("ADD SP,SP,#16 tracked destinations = %v, want none", got)
	}
	// ADD XZR,X1,X2: the same encoding 31 means ZR in add/sub shifted register.
	if got := DstRegsOfInst(0x8B02003F); len(got) != 0 {
		t.Fatalf("ADD XZR,X1,X2 tracked destinations = %v, want none", got)
	}
}
