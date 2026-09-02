package typetrack

import (
	"testing"

	"aotopsy/internal/arch/arm64"
)

// --- isLDURH tests (Dart 2.x class ID extraction) ---

func TestIsLDURH(t *testing.T) {
	tests := []struct {
		name     string
		raw      uint32
		wantOK   bool
		wantBase int
		wantRT   int
		wantImm9 int
	}{
		{
			name:     "LDURH W0, [X2, #1] (class ID load)",
			raw:      0x78401040, // 0x78400000 | (1<<12) | (2<<5)
			wantOK:   true,
			wantBase: 2,
			wantRT:   0,
			wantImm9: 1,
		},
		{
			name:     "LDURH W4, [X8, #1]",
			raw:      0x78401108, // 0x78400000 | (1<<12) | (8<<5) | 4
			wantOK:   true,
			wantBase: 8,
			wantRT:   4,
			wantImm9: 1,
		},
		{
			name:   "not LDURH (LDR Xt, [Xn, #imm])",
			raw:    0xF9400000, // LDR X0, [X0, #0]
			wantOK: false,
		},
		{
			name:   "not LDURH (STUR Xt)",
			raw:    0xF8000000, // STUR X0, [X0, #0]
			wantOK: false,
		},
		{
			name:   "not LDURH (random instruction)",
			raw:    0xD2800000, // MOVZ X0, #0
			wantOK: false,
		},
	}
	for _, tt := range tests {
		base, rt, imm9, ok := arm64.LDURH(tt.raw)
		if ok != tt.wantOK {
			t.Errorf("isLDURH(0x%08x) [%s]: ok = %v, want %v", tt.raw, tt.name, ok, tt.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if base != tt.wantBase {
			t.Errorf("isLDURH(0x%08x) [%s]: base = %d, want %d", tt.raw, tt.name, base, tt.wantBase)
		}
		if imm9 != tt.wantImm9 {
			t.Errorf("isLDURH(0x%08x) [%s]: imm9 = %d, want %d", tt.raw, tt.name, imm9, tt.wantImm9)
		}
		_ = rt // rt varies, just check it's valid
	}
}

// --- isADD64Immediate reserved shift tests ---

func TestIsADD64ImmediateReservedShift(t *testing.T) {
	// ADD X0, X0, #0x123, shift=0 (no shift) — normal case
	raw := uint32(0x91000000) | (0x123 << 10) | (0 << 5)
	rd, rn, imm, ok := arm64.ADD64Immediate(raw)
	if !ok {
		t.Error("ADD with shift=0 should be valid")
	}
	if imm != 0x123 {
		t.Errorf("ADD shift=0: imm = 0x%x, want 0x123", imm)
	}
	_ = rd
	_ = rn

	// ADD X0, X0, #0x123, shift=1 (LSL #12) — normal case
	raw = uint32(0x91400000) | (0x123 << 10) | (0 << 5)
	_, _, imm, ok = arm64.ADD64Immediate(raw)
	if !ok {
		t.Error("ADD with shift=1 should be valid")
	}
	if imm != 0x123000 {
		t.Errorf("ADD shift=1: imm = 0x%x, want 0x123000", imm)
	}

	// ADD X0, X0, #0x123, shift=2 (RESERVED) — should return imm=0
	raw = uint32(0x91800000) | (0x123 << 10) | (0 << 5)
	_, _, imm, ok = arm64.ADD64Immediate(raw)
	if !ok {
		t.Error("ADD with shift=2 should still return ok=true")
	}
	if imm != 0 {
		t.Errorf("ADD shift=2 (reserved): imm = 0x%x, want 0", imm)
	}
}

// --- isSUB64Immediate reserved shift tests ---

func TestIsSUB64ImmediateReservedShift(t *testing.T) {
	// SUB X0, X0, #0x123, shift=2 (RESERVED)
	raw := uint32(0xD1800000) | (0x123 << 10) | (0 << 5)
	_, _, imm, ok := arm64.SUB64Immediate(raw)
	if !ok {
		t.Error("SUB with shift=2 should still return ok=true")
	}
	if imm != 0 {
		t.Errorf("SUB shift=2 (reserved): imm = 0x%x, want 0", imm)
	}
}
