package disasm

import "testing"

func TestX86THRPopIsStore(t *testing.T) {
	// 41 8f 46 48 = pop qword ptr [r14+0x48].
	got := ExtractX86THRAccesses([]byte{0x41, 0x8f, 0x46, 0x48}, 0x5000, nil)
	if len(got) != 1 {
		t.Fatalf("POP THR access count = %d, want 1: %+v", len(got), got)
	}
	if !got[0].IsStore {
		t.Fatalf("POP THR access classified as read-only: %+v", got[0])
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
			if !got[0].IsStore {
				t.Fatalf("THR SIMD store classified as read-only: %+v", got[0])
			}
			if got[0].SrcReg < 0 {
				t.Fatalf("THR SIMD store fabricated a GPR source index: %+v", got[0])
			}
		})
	}
}
