package sdk

import "testing"

// A trivial x86-64 sequence: NOP (0x90), INC ECX (0xFF 0xC1), RET (0xC3).
func TestDecodeX86Basic(t *testing.T) {
	code := []byte{0x90, 0xff, 0xc1, 0xc3}
	got := DecodeX86(code, 0x1000)
	if len(got) != 3 {
		t.Fatalf("want 3 instructions, got %d: %+v", len(got), got)
	}
	wantVA := []uint64{0x1000, 0x1001, 0x1003}
	wantLen := []int{1, 2, 1}
	for i, d := range got {
		if d.Bad {
			t.Errorf("inst %d unexpectedly Bad", i)
		}
		if d.VA != wantVA[i] || d.Len != wantLen[i] {
			t.Errorf("inst %d: VA=0x%x Len=%d, want VA=0x%x Len=%d", i, d.VA, d.Len, wantVA[i], wantLen[i])
		}
	}
}

// A bad leading byte is reported as Bad with Len 1, and the sweep continues.
func TestDecodeX86BadByteRecovery(t *testing.T) {
	// 0x06 is invalid in 64-bit mode; 0xc3 (RET) follows.
	code := []byte{0x06, 0xc3}
	got := DecodeX86(code, 0x2000)
	if len(got) != 2 {
		t.Fatalf("want 2 slots, got %d", len(got))
	}
	if !got[0].Bad || got[0].Len != 1 || got[0].VA != 0x2000 {
		t.Errorf("slot 0 should be a bad byte at 0x2000 len 1, got %+v", got[0])
	}
	if got[1].Bad || got[1].VA != 0x2001 {
		t.Errorf("slot 1 should decode at 0x2001, got %+v", got[1])
	}
}

// DecodeX86UntilBad stops at the first undecodable byte, excluding it.
func TestDecodeX86UntilBad(t *testing.T) {
	code := []byte{0x90, 0x06, 0xc3}
	got := DecodeX86UntilBad(code, 0x3000)
	if len(got) != 1 || got[0].VA != 0x3000 {
		t.Fatalf("want only the NOP before the bad byte, got %+v", got)
	}
}

// WalkX86 halts early when the callback returns false.
func TestWalkX86EarlyStop(t *testing.T) {
	code := []byte{0x90, 0x90, 0x90, 0xc3}
	n := 0
	WalkX86(code, 0x4000, func(d X86Decoded) bool {
		n++
		return n < 2
	})
	if n != 2 {
		t.Errorf("callback should have run exactly twice, ran %d", n)
	}
}
