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

func TestExtractStringRefsIgnoresPoolStore(t *testing.T) {
	// StoreWordToPoolIndex is a machine-code xref to the pool slot, but it does
	// not load the string value into a register and therefore must not enter the
	// load-derived string_refs artifact.
	insts := []disasm.Inst{{
		Addr: 0x6100,
		Raw:  0xF9000F63, // str x3, [x27, #0x18] -> pool[1]
		Text: "str x3, [x27, #0x18]",
	}}
	if got := ExtractStringRefs(insts, map[int]string{1: `"stored"`}, "store"); len(got) != 0 {
		t.Fatalf("pool store became string load evidence: %+v", got)
	}
}

func TestExtractStringRefsMarksMaterializedRegisterOffsetAsPeephole(t *testing.T) {
	// Exact large LoadWordFromPoolIndex fallback for byte offset 0x01000010.
	// PP remains the final memory base, but the offset was materialized by two
	// preceding instructions, so this is not the direct one-instruction PP form.
	movz := uint32(0xD2800000 | (0x10 << 5) | 16)
	movk := uint32(0xF2800000 | (1 << 21) | (0x100 << 5) | 16)
	ldr := uint32(0xF8606800 | (16 << 16) | (27 << 5) | 16)
	insts := []disasm.Inst{
		{Addr: 0x6200, Raw: movz, Text: "movz x16, #0x10"},
		{Addr: 0x6204, Raw: movk, Text: "movk x16, #0x100, lsl #16"},
		{Addr: 0x6208, Raw: ldr, Text: "ldr x16, [x27, x16]"},
	}
	got := ExtractStringRefs(insts, map[int]string{0x200000: `"large"`}, "large")
	if len(got) != 1 || got[0].PoolIdx != 0x200000 || got[0].Kind != "PP_peep" || got[0].Value != "large" {
		t.Fatalf("materialized register-offset string ref = %+v, want PP_peep pool[0x200000]", got)
	}
}

func TestExtractStringRefsIgnoresFPPoolImmediate(t *testing.T) {
	insts := []disasm.Inst{{
		Addr: 0x6300,
		Raw:  0x3DC00762, // ldr q2,[x27,#0x10] -> pool[0], pool[1]
		Text: "ldr q2, [x27, #0x10]",
	}}
	pool := map[int]string{0: `"not-an-object-load"`, 1: `"also-not"`}
	if got := ExtractStringRefs(insts, pool, "fp"); len(got) != 0 {
		t.Fatalf("FP immediate pool bytes became String object load evidence: %+v", got)
	}
}
