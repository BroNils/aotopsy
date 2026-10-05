package typetrack

import (
	"testing"

	"aotopsy/internal/disasm"
)

// TestLargeSelectorDispatchRecordedOnEverySDK pins the TMP2 form of
// EmitDispatchTableCall: AddImmediate(cid_reg, ..., offset) materialises offset
// with LoadImmediate(TMP2, offset) + register ADD whenever it fits neither
// ADD/SUB imm12 nor imm12<<12 (SDK @3.12.2 assembler_arm64.cc AddImmediate,
// assembler_arm64.h CanHold; same shape @2.12.0). The pre-scan used to be gated
// to 2.10/2.12 and silently dropped these sites on every newer SDK.
func TestLargeSelectorDispatchRecordedOnEverySDK(t *testing.T) {
	const (
		movzX17Imm1388 = 0xD2827111 // movz x17, #0x1388
		blrX30         = 0xD63F03C0 // blr x30
		retInst        = 0xD65F03C0 // ret
	)
	cases := []struct {
		version string
		add     uint32 // add xD, xM, x17
		ldr     uint32 // ldr x30, [x21, xD, lsl #3]
	}{
		{"3.12.2", 0x8B11001E, 0xF87E7ABE}, // add x30, x0, x17 ; ldr x30, [x21, x30, lsl #3]
		{"3.9.2", 0x8B11001E, 0xF87E7ABE},
		{"2.12.0", 0x8B110000, 0xF8607ABE}, // add x0, x0, x17 ; ldr x30, [x21, x0, lsl #3]
	}
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			ctx := minimalTypeContext()
			ctx.DartVersion = tc.version
			raws := []uint32{movzX17Imm1388, tc.add, tc.ldr, blrX30, retInst}
			insts := make([]disasm.Inst, len(raws))
			for i, raw := range raws {
				insts[i] = disasm.Inst{Addr: 0x1000 + uint64(i)*4, Raw: raw}
			}
			AnalyzeFunction(insts, ctx, [31]TypeLattice{}, nil)
			got, ok := ctx.SelectorOffsets[insts[3].Addr]
			if !ok || got != 0x1388 {
				t.Fatalf("SelectorOffsets[blr] = %d, recorded=%v; want 0x1388", got, ok)
			}
		})
	}
}
