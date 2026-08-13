package disasm

import "testing"

// The layout constants come from dart-lang/sdk (see poolindex.go). These
// tests pin the two conversions against hand-computed values so a future
// "simplification" back to displacement/8 fails loudly: that error shifted
// every pool-derived fact by two slots, which is invisible in aggregate
// counts and wrong in every single line of output.
func TestARM64PoolIndex(t *testing.T) {
	tests := []struct {
		disp      int
		wantIndex int
		wantOK    bool
	}{
		{16, 0, true},       // first element
		{24, 1, true},       // second
		{288, 34, true},     // 0x120
		{40272, 5032, true}, // add x, x27, #0x9000 + ldr [x, #3408]
		{0, 0, false},       // the tags word, not an element
		{8, 0, false},       // the length word
		{20, 0, false},      // not element-aligned
		{-8, 0, false},
	}
	for _, tt := range tests {
		idx, ok := ARM64PoolIndex(tt.disp)
		if ok != tt.wantOK {
			t.Errorf("ARM64PoolIndex(%d) ok = %v, want %v", tt.disp, ok, tt.wantOK)
			continue
		}
		if ok && idx != tt.wantIndex {
			t.Errorf("ARM64PoolIndex(%d) = %d, want %d", tt.disp, idx, tt.wantIndex)
		}
	}
}

func TestX64PoolIndex(t *testing.T) {
	// PP is tagged on x64, so displacements are 16 + 8*index - 1, i.e. always
	// congruent to 7 mod 8 -- confirmed by histogramming every [r15+disp]
	// operand of a real x86_64 libapp.so (19683 of 19693 were ≡7).
	tests := []struct {
		disp      int64
		wantIndex int
		wantOK    bool
	}{
		{15, 0, true},
		{23, 1, true},
		{40271, 5032, true},
		{16, 0, false}, // ARM64-shaped displacement is not valid here
		{0, 0, false},
		{-1, 0, false},
	}
	for _, tt := range tests {
		idx, ok := X64PoolIndex(tt.disp)
		if ok != tt.wantOK {
			t.Errorf("X64PoolIndex(%d) ok = %v, want %v", tt.disp, ok, tt.wantOK)
			continue
		}
		if ok && idx != tt.wantIndex {
			t.Errorf("X64PoolIndex(%d) = %d, want %d", tt.disp, idx, tt.wantIndex)
		}
	}
}
