package disasm

import "testing"

// TestInferCallArgCountLocal_RealSample uses the exact instruction sequence
// found at VA 0x1b78f4-0x1b7904 in a real compiled Dart 3.9.2 sample
// (compare_sample, arm64-v8a) -- the call site `factorial(6)` in
// _CompareHomePageState._runAll, verified by disassembling the raw bytes
// directly and cross-checking against the Dart source (MathTools.factorial
// takes exactly 1 parameter). `MOVZ X1, #0x6` is the sole instruction
// setting up the call, immediately preceding the `bl`; the three earlier
// instructions (pool-address computation, a field store) are unrelated
// register traffic and must NOT be counted as argument setup.
func TestInferCallArgCountLocal_RealSample(t *testing.T) {
	insts := []Inst{
		{Addr: 0x1b78f4, Raw: 0x91402770}, // ADD X16, X27, #0x9, LSL #12 (pool address, unrelated)
		{Addr: 0x1b78f8, Raw: 0xf9469a10}, // LDR X16, [X16,#3376] (pool load, unrelated)
		{Addr: 0x1b78fc, Raw: 0xb800f010}, // STUR W16, [X0,#15] (field store, unrelated)
		{Addr: 0x1b7900, Raw: 0xd28000c1}, // MOVZ X1, #0x6 -- the real argument setup
		{Addr: 0x1b7904, Raw: 0x94000154}, // BL MathTools.factorial
	}
	if got := inferCallArgCountLocal(insts, 4); got != 1 {
		t.Errorf("inferCallArgCountLocal() = %d, want 1", got)
	}
}
