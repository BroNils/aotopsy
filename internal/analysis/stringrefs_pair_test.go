package analysis

import (
	"testing"

	"aotopsy/internal/disasm"
)

func TestExtractStringRefsPreservesBothPairPoolSlots(t *testing.T) {
	// ldp x5,x24,[x27,#0x10] reads pool indices 0 and 1 at one PC.
	insts := []disasm.Inst{{
		Addr: 0x6000,
		Raw:  0xA9400000 | (2 << 15) | (24 << 10) | (27 << 5) | 5,
		Text: "ldp x5, x24, [x27, #0x10]",
	}}
	pool := map[int]string{0: `"first"`, 1: `"second"`}
	got := ExtractStringRefs(insts, pool, "pair")
	if len(got) != 2 {
		t.Fatalf("string refs = %+v, want two records", got)
	}
	if got[0].PoolIdx != 0 || got[0].Value != "first" || got[1].PoolIdx != 1 || got[1].Value != "second" {
		t.Fatalf("pair string refs = %+v", got)
	}
	if got[0].PC != got[1].PC || got[0].Kind != "PP" || got[1].Kind != "PP" {
		t.Fatalf("pair string-ref metadata = %+v", got)
	}
}
