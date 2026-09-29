package disasm

import "testing"

func TestExtractTHRAccessesLDPTopEndPair(t *testing.T) {
	// a9 46 07 40 = ldp x0, x1, [x26,#0x60]. Dart's ARM64 inline
	// allocator emits this exact pair load because Thread.top and Thread.end
	// are adjacent words.
	insts := []Inst{{
		Addr: 0x7000,
		Raw:  0xa9460740,
		Text: "LDP X0, X1, [X26,#96]",
	}}
	fields := map[int]string{0x60: "top", 0x68: "end"}

	got := ExtractTHRAccesses(insts, fields)
	if len(got) != 2 {
		t.Fatalf("LDP THR access count = %d, want 2: %+v", len(got), got)
	}
	if got[0].THROffset != 0x60 || got[0].DstReg != 0 || got[0].Width != 8 || !got[0].Resolved {
		t.Fatalf("first LDP access = %+v, want top at 0x60 -> X0", got[0])
	}
	if got[1].THROffset != 0x68 || got[1].DstReg != 1 || got[1].Width != 8 || !got[1].Resolved {
		t.Fatalf("second LDP access = %+v, want end at 0x68 -> X1", got[1])
	}
}
