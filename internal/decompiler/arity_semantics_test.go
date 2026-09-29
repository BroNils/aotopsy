package decompiler

import (
	"reflect"
	"testing"
)

func TestLiveInArgIndicesRespectsInstructionOperandSemantics(t *testing.T) {
	tests := []struct {
		name    string
		argRegs []string
		src     string
		want    []int
	}{
		{
			name:    "arm64 movk reads preserved destination bits",
			argRegs: []string{"x0"},
			src:     "movk x0, #0x1234, lsl #16",
			want:    []int{0},
		},
		{
			name:    "arm64 sub does not read destination",
			argRegs: []string{"x0", "x1"},
			src:     "sub x0, x1, #1",
			want:    []int{1},
		},
		{
			name:    "x86 add reads and writes destination",
			argRegs: []string{"rdx", "rcx"},
			src:     "add rdx, rcx",
			want:    []int{0, 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fir := newFuncIR(tt.name, 0x1000)
			fir.ArgRegs = tt.argRegs
			fir.addBlock(Block{
				ID:      0,
				StartVA: 0x1000,
				Instrs:  []Instr{{Op: OpOther, Src: tt.src}},
			})
			if got := LiveInArgIndices(fir); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("LiveInArgIndices(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}
