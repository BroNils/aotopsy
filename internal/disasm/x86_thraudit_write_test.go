package disasm

import (
	"testing"

	"aotopsy/internal/thraudit"

	"golang.org/x/arch/x86/x86asm"
)

func TestX86THRPopIsStore(t *testing.T) {
	// 41 8f 46 48 = pop qword ptr [r14+0x48].
	got := ExtractX86THRAccesses([]byte{0x41, 0x8f, 0x46, 0x48}, 0x5000, nil)
	if len(got) != 1 {
		t.Fatalf("POP THR access count = %d, want 1: %+v", len(got), got)
	}
	if got[0].Access != thraudit.AccessWrite {
		t.Fatalf("POP THR access mode = %s, want write: %+v", got[0].Access, got[0])
	}
}

func TestX86THRSIMDStoresAreStores(t *testing.T) {
	tests := []struct {
		name string
		code []byte
	}{
		{name: "movsd", code: []byte{0xf2, 0x41, 0x0f, 0x11, 0x46, 0x48}},
		{name: "movups", code: []byte{0x41, 0x0f, 0x11, 0x46, 0x48}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractX86THRAccesses(tt.code, 0x6000, nil)
			if len(got) != 1 {
				t.Fatalf("THR access count = %d, want 1: %+v", len(got), got)
			}
			if got[0].Access != thraudit.AccessWrite {
				t.Fatalf("THR SIMD store mode = %s, want write: %+v", got[0].Access, got[0])
			}
			if got[0].SrcReg != nil {
				t.Fatalf("THR SIMD store fabricated a GPR source index: %+v", got[0])
			}
		})
	}
}

func TestX86THRSignedOffsetAndDirectMemoryCall(t *testing.T) {
	// 49 8b 46 f8 = mov rax,qword ptr [r14-8]. The displacement is signed
	// architectural data and must not be wrapped into a huge positive offset.
	neg := ExtractX86THRAccesses([]byte{0x49, 0x8b, 0x46, 0xf8}, 0x7000, nil)
	if len(neg) != 1 || neg[0].THROffset != -8 || neg[0].Access != thraudit.AccessRead || neg[0].DstReg == nil || *neg[0].DstReg != 0 {
		t.Fatalf("negative THR load = %+v", neg)
	}

	// 41 ff 96 40 02 00 00 = call qword ptr [r14+0x240]. CALL reads the
	// function pointer directly from Thread; it neither writes Thread nor has a
	// GPR destination.
	call := ExtractX86THRAccesses([]byte{0x41, 0xff, 0x96, 0x40, 0x02, 0x00, 0x00}, 0x7100,
		map[int]string{0x240: "stack_overflow_shared_without_fpu_regs_entry_point"})
	if len(call) != 1 || call[0].THROffset != 0x240 || call[0].Access != thraudit.AccessRead || call[0].Width != 8 || call[0].DstReg != nil || !call[0].Resolved {
		t.Fatalf("direct THR CALL access = %+v", call)
	}
}

func TestX86THRComparisonDoesNotFabricateLoadDestination(t *testing.T) {
	// 49 3b 46 48 = cmp rax,qword ptr [r14+0x48]. RAX consumes the memory
	// operand but does not become equal to it. Recording RAX as dst_reg would let
	// a following CALL RAX falsely look like a call through the Thread field.
	got := ExtractX86THRAccesses([]byte{0x49, 0x3b, 0x46, 0x48}, 0x7200, nil)
	if len(got) != 1 || got[0].Access != thraudit.AccessRead || got[0].DstReg != nil {
		t.Fatalf("CMP fabricated THR load destination: %+v", got)
	}
}

func TestX86THRReadWriteRegisterRoles(t *testing.T) {
	xadd := x86asm.Inst{Op: x86asm.XADD, Args: [4]x86asm.Arg{
		x86asm.Mem{Base: x86asm.R14, Disp: 0x48}, x86asm.RBX,
	}}
	if got := x86ReadWriteResultGPR(xadd, 0); got == nil || *got != 3 {
		t.Fatalf("XADD old-value destination = %v, want RBX canonical index 3", got)
	}
	cmpxchg := x86asm.Inst{Op: x86asm.CMPXCHG, Args: [4]x86asm.Arg{
		x86asm.Mem{Base: x86asm.R14, Disp: 0x48}, x86asm.R11,
	}}
	if got := x86ReadWriteResultGPR(cmpxchg, 0); got == nil || *got != 0 {
		t.Fatalf("CMPXCHG old-value destination = %v, want RAX canonical index 0", got)
	}
}
