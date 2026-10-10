package disasm

import "testing"

func TestDecodeBranch_RET(t *testing.T) {
	// RET (X30) = 0xD65F03C0
	bi := DecodeBranch(0xD65F03C0, 0x1000)
	if bi == nil {
		t.Fatal("expected RET")
	}
	if !bi.IsRet {
		t.Error("expected IsRet=true")
	}
}

func TestDecodeBranch_B(t *testing.T) {
	// B #0x100 at PC=0x1000 → target=0x1100
	// imm26 = 0x100/4 = 0x40
	raw := uint32(0x14000000 | 0x40)
	bi := DecodeBranch(raw, 0x1000)
	if bi == nil {
		t.Fatal("expected B")
	}
	if bi.Target != 0x1100 {
		t.Errorf("target = 0x%x, want 0x1100", bi.Target)
	}
	if bi.Cond {
		t.Error("B should not be conditional")
	}
}

func TestDecodeBranch_B_Negative(t *testing.T) {
	// B #-0x10 at PC=0x1000 → target=0xFF0
	// imm26 = -4 (offset = -0x10 / 4 = -4), encoded as 0x03FFFFFC
	raw := uint32(0x14000000 | (0x03FFFFFF - 3)) // -4 in 26-bit two's complement
	bi := DecodeBranch(raw, 0x1000)
	if bi == nil {
		t.Fatal("expected B")
	}
	if bi.Target != 0x0FF0 {
		t.Errorf("target = 0x%x, want 0xFF0", bi.Target)
	}
}

func TestDecodeBranch_Bcond(t *testing.T) {
	// B.EQ #0x20 at PC=0x2000 → target=0x2020
	// imm19 = 0x20/4 = 8, cond = 0 (EQ)
	raw := uint32(0x54000000 | (8 << 5)) // B.EQ
	bi := DecodeBranch(raw, 0x2000)
	if bi == nil {
		t.Fatal("expected B.cond")
	}
	if bi.Target != 0x2020 {
		t.Errorf("target = 0x%x, want 0x2020", bi.Target)
	}
	if !bi.Cond {
		t.Error("B.cond should be conditional")
	}
}

func TestDecodeBranch_CBZ(t *testing.T) {
	// CBZ X0, #0x40 at PC=0x3000 → target=0x3040
	// imm19 = 0x40/4 = 0x10, sf=1 (64-bit), Rt=0
	raw := uint32(0xB4000000 | (0x10 << 5)) // CBZ X0
	bi := DecodeBranch(raw, 0x3000)
	if bi == nil {
		t.Fatal("expected CBZ")
	}
	if bi.Target != 0x3040 {
		t.Errorf("target = 0x%x, want 0x3040", bi.Target)
	}
	if !bi.Cond {
		t.Error("CBZ should be conditional")
	}
}

func TestDecodeBranch_TBZ(t *testing.T) {
	// TBZ W0, #0, #0x10 at PC=0x4000 → target=0x4010
	// imm14 = 0x10/4 = 4
	raw := uint32(0x36000000 | (4 << 5)) // TBZ
	bi := DecodeBranch(raw, 0x4000)
	if bi == nil {
		t.Fatal("expected TBZ")
	}
	if bi.Target != 0x4010 {
		t.Errorf("target = 0x%x, want 0x4010", bi.Target)
	}
	if !bi.Cond {
		t.Error("TBZ should be conditional")
	}
}

func TestDecodeBranch_NotBranch(t *testing.T) {
	// ADD X0, X1, X2 = 0x8B020020
	bi := DecodeBranch(0x8B020020, 0x1000)
	if bi != nil {
		t.Error("ADD should not be a branch")
	}

	// BL is NOT a basic-block terminator (it's a call)
	bl := uint32(0x94000000 | 0x100)
	bi = DecodeBranch(bl, 0x1000)
	if bi != nil {
		t.Error("BL should not be detected as branch terminator")
	}
}

// B.AL used the B.cond encoding in Dart <=2.14 but is unconditional. NV is
// not a valid emitted branch: older Dart used it only as a far-branch sentinel
// rewritten to NOP, and >=2.15 asserts against it.
//
// Reporting them as conditional gave the CFG a fallthrough edge that cannot
// be taken, and made the decompiler render the branch with the literal
// string "true" as its comparison operator -- `if ((x15 - 16) true THR.f64)`,
// which is not valid Dart. That shape appeared 28148 times in the Dart 2.12
// sample. The encoding below, 0x5400004e, is one such instruction taken from
// it verbatim: `B AL, .+0x8`.
func TestDecodeBranchTreatsALAsUnconditionalAndRejectsNV(t *testing.T) {
	bi := DecodeBranch(0x5400004e, 0x1000) // real Dart 2.12 B.AL +8
	if bi == nil || bi.Cond || bi.Target != 0x1008 {
		t.Fatalf("B.AL decode = %+v, want unconditional target 0x1008", bi)
	}
	if bi := DecodeBranch(0x5400004f, 0x1000); bi != nil {
		t.Fatalf("reserved B.NV decoded as executable branch: %+v", bi)
	}
	// Every other condition code stays conditional.
	for cond := uint32(0); cond < 14; cond++ {
		bi := DecodeBranch(0x54000040|cond, 0x1000)
		if bi == nil || !bi.Cond {
			t.Errorf("cond %d should still be conditional, got %+v", cond, bi)
		}
	}
}
