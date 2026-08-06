package disasm

import (
	"encoding/binary"
	"testing"
)

func TestIsLDR64UnsignedOffset(t *testing.T) {
	tests := []struct {
		name       string
		raw        uint32
		wantBase   int
		wantOffset int
		wantOK     bool
	}{
		// LDR X0, [X27, #0x120] → base=27, offset=0x120, idx=36
		// Encoding: 0xF9400000 | (imm12 << 10) | (Rn << 5) | Rt
		// imm12 = 0x120/8 = 0x24, Rn=27, Rt=0
		{"PP_load_0x120", 0xF9400000 | (0x24 << 10) | (27 << 5) | 0, 27, 0x120, true},

		// LDR X16, [X26, #72] → base=26, offset=72
		// imm12 = 72/8 = 9, Rn=26, Rt=16
		{"THR_load_72", 0xF9400000 | (9 << 10) | (26 << 5) | 16, 26, 72, true},

		// LDR X0, [X29, #64] → base=29 (frame pointer, not PP/THR)
		{"FP_load", 0xF9400000 | (8 << 10) | (29 << 5) | 0, 29, 64, true},

		// Not an LDR (STR instruction)
		{"not_LDR", 0xF9000000, 0, 0, false},

		// ADD instruction
		{"ADD_not_LDR", 0x91000000, 0, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, off, ok := isLDR64UnsignedOffset(tt.raw)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if base != tt.wantBase {
				t.Errorf("base = %d, want %d", base, tt.wantBase)
			}
			if off != tt.wantOffset {
				t.Errorf("offset = %d, want %d", off, tt.wantOffset)
			}
		})
	}
}

func TestIsADD64Immediate(t *testing.T) {
	tests := []struct {
		name    string
		raw     uint32
		wantRd  int
		wantRn  int
		wantImm int
		wantOK  bool
	}{
		// ADD X0, X27, #0x1000 (shift=1, imm12=1)
		// Encoding: 0x91000000 | (1<<22) | (1<<10) | (27<<5) | 0
		{"ADD_PP_shift12", 0x91000000 | (1 << 22) | (1 << 10) | (27 << 5) | 0, 0, 27, 0x1000, true},

		// ADD X5, X27, #0x10 (shift=0, imm12=0x10)
		{"ADD_PP_noshift", 0x91000000 | (0x10 << 10) | (27 << 5) | 5, 5, 27, 0x10, true},

		// SUB instruction (not ADD)
		{"SUB_not_ADD", 0xD1000000, 0, 0, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rd, rn, imm, ok := isADD64Immediate(tt.raw)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if rd != tt.wantRd {
				t.Errorf("rd = %d, want %d", rd, tt.wantRd)
			}
			if rn != tt.wantRn {
				t.Errorf("rn = %d, want %d", rn, tt.wantRn)
			}
			if imm != tt.wantImm {
				t.Errorf("imm = 0x%x, want 0x%x", imm, tt.wantImm)
			}
		})
	}
}

func TestPPAnnotator(t *testing.T) {
	pool := map[int]string{
		36: `"hello world"`,
	}
	ann := PPAnnotator(pool)

	// LDR X0, [X27, #0x120] → PP[36] "hello world"
	raw := uint32(0xF9400000 | (0x24 << 10) | (27 << 5) | 0)
	got := ann(Inst{Raw: raw})
	want := `PP[36] "hello world"`
	if got != want {
		t.Errorf("PPAnnotator = %q, want %q", got, want)
	}

	// LDR X0, [X27, #0x128] → PP[37] (unknown index)
	raw2 := uint32(0xF9400000 | (0x25 << 10) | (27 << 5) | 0)
	got2 := ann(Inst{Raw: raw2})
	if got2 != "PP[37]" {
		t.Errorf("PPAnnotator unknown = %q, want %q", got2, "PP[37]")
	}

	// LDR from non-PP register → empty
	rawFP := uint32(0xF9400000 | (8 << 10) | (29 << 5) | 0)
	if got := ann(Inst{Raw: rawFP}); got != "" {
		t.Errorf("PPAnnotator non-PP = %q, want empty", got)
	}
}

func TestTHRAnnotator(t *testing.T) {
	ann := THRAnnotator(nil)

	// LDR X16, [X26, #72] → THR+0x48
	raw := uint32(0xF9400000 | (9 << 10) | (26 << 5) | 16)
	got := ann(Inst{Raw: raw})
	if got != "THR+0x48" {
		t.Errorf("THRAnnotator = %q, want %q", got, "THR+0x48")
	}

	// With field map.
	fields := map[int]string{0x48: "stack_limit"}
	annFields := THRAnnotator(fields)
	got = annFields(Inst{Raw: raw})
	if got != "THR.stack_limit" {
		t.Errorf("THRAnnotator with fields = %q, want %q", got, "THR.stack_limit")
	}
}

func TestPeepholeState(t *testing.T) {
	pool := map[int]string{
		0x800: `"large pool string"`,
	}
	ps := NewPeepholeState(pool)

	// ADD X0, X27, #0x4000 (shift=1, imm12=4)
	addRaw := uint32(0x91000000 | (1 << 22) | (4 << 10) | (27 << 5) | 0)
	got := ps.Annotate(Inst{Raw: addRaw})
	if got != "" {
		t.Errorf("ADD alone should not annotate, got %q", got)
	}

	// LDR X1, [X0, #0] → combined offset = 0x4000, idx = 0x800
	ldrRaw := uint32(0xF9400000 | (0 << 10) | (0 << 5) | 1)
	got = ps.Annotate(Inst{Raw: ldrRaw})
	want := `PP[2048] "large pool string"`
	if got != want {
		t.Errorf("peephole = %q, want %q", got, want)
	}
}

// TestPPAnnotator_RealBytes tests on actual ARM64 machine code bytes
// (little-endian encoding as it would appear in a binary).
func TestPPAnnotator_RealBytes(t *testing.T) {
	pool := map[int]string{9: "stack_limit"}

	// LDR X16, [X26, #72] = 0xF9402750 in LE: 50 27 40 f9
	var buf [4]byte
	buf[0], buf[1], buf[2], buf[3] = 0x50, 0x27, 0x40, 0xf9
	raw := binary.LittleEndian.Uint32(buf[:])

	thr := THRAnnotator(nil)
	got := thr(Inst{Raw: raw})
	if got != "THR+0x48" {
		t.Errorf("THR from real bytes = %q, want %q", got, "THR+0x48")
	}

	pp := PPAnnotator(pool)
	got = pp(Inst{Raw: raw})
	if got != "" {
		t.Errorf("PP from THR load should be empty, got %q", got)
	}
}
