package disasm

import (
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestFormatX86MemoryTargetPreservesSignedDisplacement(t *testing.T) {
	for _, tc := range []struct {
		mem  x86asm.Mem
		want string
	}{
		{x86asm.Mem{Base: x86asm.RAX, Disp: 0x20}, "[RAX+0x20]"},
		{x86asm.Mem{Base: x86asm.RAX, Index: x86asm.RCX, Scale: 8, Disp: -0x20}, "[RAX+RCX*8-0x20]"},
		{x86asm.Mem{Base: x86asm.RAX, Disp: -1 << 63}, "[RAX-0x8000000000000000]"},
	} {
		if got := formatX86MemoryTarget(tc.mem); got != tc.want {
			t.Errorf("formatX86MemoryTarget(%+v) = %q, want %q", tc.mem, got, tc.want)
		}
	}
}
