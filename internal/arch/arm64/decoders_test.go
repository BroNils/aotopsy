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
}
