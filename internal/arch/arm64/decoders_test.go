package arm64

import "testing"

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
	rawBEQ := uint32(0x54000000 | (8 << 5) | 0)
	if target, ok := CondBranch(rawBEQ, 0x1000); !ok || target != 0x1020 {
		t.Fatalf("CondBranch(B.EQ) = (0x%x, %v), want (0x1020, true)", target, ok)
	}

	rawBAL := uint32(0x54000000 | (8 << 5) | 14)
	if _, ok := CondBranch(rawBAL, 0x1000); ok {
		t.Fatalf("CondBranch(B.AL) = true, want false")
	}

	rawCBZ := uint32(0x34000000 | (16 << 5) | 0)
	if target, ok := CondBranch(rawCBZ, 0x1000); !ok || target != 0x1040 {
		t.Fatalf("CondBranch(CBZ) = (0x%x, %v), want (0x1040, true)", target, ok)
	}

	rawCBNZ := uint32(0x35000000 | (16 << 5) | 1)
	if target, ok := CondBranch(rawCBNZ, 0x1000); !ok || target != 0x1040 {
		t.Fatalf("CondBranch(CBNZ) = (0x%x, %v), want (0x1040, true)", target, ok)
	}

	rawTBZ := uint32(0x36000000 | (8 << 5) | 0)
	if target, ok := CondBranch(rawTBZ, 0x1000); !ok || target != 0x1020 {
		t.Fatalf("CondBranch(TBZ) = (0x%x, %v), want (0x1020, true)", target, ok)
	}

	rawTBNZ := uint32(0x37000000 | (8 << 5) | 0)
	if target, ok := CondBranch(rawTBNZ, 0x1000); !ok || target != 0x1020 {
		t.Fatalf("CondBranch(TBNZ) = (0x%x, %v), want (0x1020, true)", target, ok)
	}
}

func TestDstRegOfInst(t *testing.T) {
	rawLDR := uint32(0xF9400000 | (1 << 10) | (27 << 5) | 0)
	if rd := DstRegOfInst(rawLDR); rd != 0 {
		t.Fatalf("DstRegOfInst(LDR) = %d, want 0", rd)
	}

	rawMOV := uint32(0xAA0203E1)
	if rd := DstRegOfInst(rawMOV); rd != 1 {
		t.Fatalf("DstRegOfInst(MOV) = %d, want 1", rd)
	}

	// LDP X0, X1, [X26, #80] -> 0xA9450740
	rawLDP := uint32(0xA9400000 | (10 << 15) | (1 << 10) | (26 << 5) | 0)
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
		if len(regs) != 1 || regs[0] != 1 {
			t.Errorf("DstRegsOfInst(%s = %#08x) = %v, want [1]", l.name, l.raw, regs)
		}
	}
}
