package disasm

import (
	"encoding/binary"
	"testing"

	"aotopsy/internal/arch/arm64"
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
		{"PP_load_0x120", 0xF9400000 | (0x24 << 10) | (27 << 5), 27, 0x120, true},

		// LDR X16, [X26, #72] → base=26, offset=72
		// imm12 = 72/8 = 9, Rn=26, Rt=16
		{"THR_load_72", 0xF9400000 | (9 << 10) | (26 << 5) | 16, 26, 72, true},

		// LDR X0, [X29, #64] → base=29 (frame pointer, not PP/THR)
		{"FP_load", 0xF9400000 | (8 << 10) | (29 << 5), 29, 64, true},

		// Not an LDR (STR instruction)
		{"not_LDR", 0xF9000000, 0, 0, false},

		// ADD instruction
		{"ADD_not_LDR", 0x91000000, 0, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, off, ok := arm64.LDR64UnsignedOffset(tt.raw)
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
		// Encoding: 0x91000000 | (1<<22) | (1<<10) | (27<<5)
		{"ADD_PP_shift12", 0x91000000 | (1 << 22) | (1 << 10) | (27 << 5), 0, 27, 0x1000, true},

		// ADD X5, X27, #0x10 (shift=0, imm12=0x10)
		{"ADD_PP_noshift", 0x91000000 | (0x10 << 10) | (27 << 5) | 5, 5, 27, 0x10, true},

		// SUB instruction (not ADD)
		{"SUB_not_ADD", 0xD1000000, 0, 0, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rd, rn, imm, ok := arm64.ADD64Immediate(tt.raw)
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
	// Displacement -> index uses the SDK layout: elements start at +16 and
	// are 8 bytes each, PP untagged on ARM64 (see disasm.ARM64PoolIndex).
	// So #0x120 (288) is index (288-16)/8 = 34, not 36.
	pool := map[int]string{
		34: `"hello world"`,
	}
	ann := PPAnnotator(pool)

	// LDR X0, [X27, #0x120] → PP[34] "hello world"
	raw := uint32(0xF9400000 | (0x24 << 10) | (27 << 5))
	got := ann(Inst{Raw: raw})
	want := `PP[34] "hello world"`
	if got != want {
		t.Errorf("PPAnnotator = %q, want %q", got, want)
	}

	// LDR X0, [X27, #0x128] → PP[35] (unknown index)
	raw2 := uint32(0xF9400000 | (0x25 << 10) | (27 << 5))
	got2 := ann(Inst{Raw: raw2})
	if got2 != "PP[35]" {
		t.Errorf("PPAnnotator unknown = %q, want %q", got2, "PP[35]")
	}

	// A displacement below the first element cannot name a pool entry.
	rawLow := uint32(0xF9400000 | (1 << 10) | (27 << 5)) // #8
	if got := ann(Inst{Raw: rawLow}); got != "" {
		t.Errorf("PPAnnotator below first element = %q, want empty", got)
	}

	// LDR from non-PP register → empty
	rawFP := uint32(0xF9400000 | (8 << 10) | (29 << 5))
	if got := ann(Inst{Raw: rawFP}); got != "" {
		t.Errorf("PPAnnotator non-PP = %q, want empty", got)
	}
}

func TestTHRContextAnnotator(t *testing.T) {
	// LDR X16, [X26, #72] → THR+0x48
	raw := uint32(0xF9400000 | (9 << 10) | (26 << 5) | 16)
	insts := []Inst{{Addr: 0x1000, Raw: raw}}

	ann := THRContextAnnotator(insts, nil)
	got := ann(insts[0])
	if got != "THR+0x48 LDR[UNKNOWN]" {
		t.Errorf("THRContextAnnotator = %q, want %q", got, "THR+0x48 LDR[UNKNOWN]")
	}

	// With field map.
	fields := map[int]string{0x48: "stack_limit"}
	annFields := THRContextAnnotator(insts, fields)
	got = annFields(insts[0])
	if got != "THR.stack_limit" {
		t.Errorf("THRContextAnnotator with fields = %q, want %q", got, "THR.stack_limit")
	}
}

func TestPeepholeState(t *testing.T) {
	pool := map[int]string{
		2046: `"large pool string"`,
	}
	ps := NewPeepholeState(pool)

	// ADD X0, X27, #0x4000 (shift=1, imm12=4)
	addRaw := uint32(0x91000000 | (1 << 22) | (4 << 10) | (27 << 5))
	got := ps.Annotate(Inst{Raw: addRaw})
	if got != "" {
		t.Errorf("ADD alone should not annotate, got %q", got)
	}

	// LDR X1, [X0, #0] → combined offset = 0x4000, idx = (0x4000-16)/8 = 2046
	ldrRaw := uint32(0xF9400000 | (0 << 10) | (0 << 5) | 1)
	got = ps.Annotate(Inst{Raw: ldrRaw})
	want := `PP[2046] "large pool string"`
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

	thr := THRContextAnnotator([]Inst{{Addr: 0x1000, Raw: raw}}, nil)
	got := thr(Inst{Addr: 0x1000, Raw: raw})
	if got != "THR+0x48 LDR[UNKNOWN]" {
		t.Errorf("THR from real bytes = %q, want %q", got, "THR+0x48 LDR[UNKNOWN]")
	}

	pp := PPAnnotator(pool)
	got = pp(Inst{Raw: raw})
	if got != "" {
		t.Errorf("PP from THR load should be empty, got %q", got)
	}
}
