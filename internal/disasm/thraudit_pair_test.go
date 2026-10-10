package disasm

import (
	"testing"

	"aotopsy/internal/thraudit"
)

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
	if got[0].THROffset != 0x60 || got[0].DstReg == nil || *got[0].DstReg != 0 || got[0].Width != 8 || got[0].Access != thraudit.AccessRead || !got[0].Resolved || got[0].FieldName != "top" {
		t.Fatalf("first LDP access = %+v, want top at 0x60 -> X0", got[0])
	}
	if got[1].THROffset != 0x68 || got[1].DstReg == nil || *got[1].DstReg != 1 || got[1].Width != 8 || got[1].Access != thraudit.AccessRead || !got[1].Resolved || got[1].FieldName != "end" {
		t.Fatalf("second LDP access = %+v, want end at 0x68 -> X1", got[1])
	}
}

func TestExtractTHRAccessesSignedUnscaledARM64(t *testing.T) {
	// LDUR X3, [X26,#-8] and STUR W4, [X26,#-4]. Signed imm9 offsets are
	// legitimate architectural displacements and must remain negative in the
	// audit record rather than being dropped or wrapped.
	ldur := uint32(0xF8400000 | (0x1f8 << 12) | (26 << 5) | 3)
	stur := uint32(0xB8000000 | (0x1fc << 12) | (26 << 5) | 4)
	insts := []Inst{
		{Addr: 0x7100, Raw: ldur, Text: "LDUR X3, [X26,#-8]"},
		{Addr: 0x7104, Raw: stur, Text: "STUR W4, [X26,#-4]"},
	}
	got := ExtractTHRAccesses(insts, nil)
	if len(got) != 2 {
		t.Fatalf("signed THR access count = %d, want 2: %+v", len(got), got)
	}
	if got[0].THROffset != -8 || got[0].Access != thraudit.AccessRead || got[0].Width != 8 || got[0].DstReg == nil || *got[0].DstReg != 3 {
		t.Fatalf("LDUR THR access = %+v", got[0])
	}
	if got[1].THROffset != -4 || got[1].Access != thraudit.AccessWrite || got[1].Width != 4 || got[1].SrcReg == nil || *got[1].SrcReg != 4 {
		t.Fatalf("STUR THR access = %+v", got[1])
	}
}

func TestExtractTHRAccessesSTPPairPreservesBothStores(t *testing.T) {
	// STP X5, X6, [X26,#0x10]. One machine instruction writes two distinct
	// Thread slots; collapsing it to one store loses half of the mutation.
	raw := uint32(0xA9000000 | (2 << 15) | (6 << 10) | (26 << 5) | 5)
	insts := []Inst{{Addr: 0x7200, Raw: raw, Text: "STP X5, X6, [X26,#16]"}}
	fields := map[int]string{0x10: "field_a", 0x18: "field_b"}
	got := ExtractTHRAccesses(insts, fields)
	if len(got) != 2 {
		t.Fatalf("STP THR access count = %d, want 2: %+v", len(got), got)
	}
	for i, want := range []struct {
		off  int64
		reg  int
		name string
	}{{0x10, 5, "field_a"}, {0x18, 6, "field_b"}} {
		if got[i].THROffset != want.off || got[i].Access != thraudit.AccessWrite || got[i].Width != 8 || got[i].SrcReg == nil || *got[i].SrcReg != want.reg || !got[i].Resolved || got[i].FieldName != want.name {
			t.Fatalf("STP THR access %d = %+v", i, got[i])
		}
	}
}

func TestExtractTHRAccessesRejectsTHRWritebackAddressing(t *testing.T) {
	// LDR X0, [X26,#8]! updates X26. A stateless scan cannot continue treating
	// X26 as the canonical Thread base after this instruction, so fail closed
	// rather than emitting a plausible THR record with poisoned provenance.
	raw := uint32(0xF8400000 | (8 << 12) | (3 << 10) | (26 << 5))
	if got := ExtractTHRAccesses([]Inst{{Addr: 0x7300, Raw: raw, Text: "LDR X0, [X26,#8]!"}}, nil); len(got) != 0 {
		t.Fatalf("writeback X26 access was treated as stable THR provenance: %+v", got)
	}
}

func TestExtractTHRAccessesARM64ZeroRegisterHasNoGPRProvenance(t *testing.T) {
	ldrZR := uint32(0xF9400000 | (26 << 5) | 31)
	strZR := uint32(0xF9000000 | (1 << 10) | (26 << 5) | 31) // [X26,#8]
	got := ExtractTHRAccesses([]Inst{
		{Addr: 0x7400, Raw: ldrZR, Text: "LDR XZR, [X26]"},
		{Addr: 0x7404, Raw: strZR, Text: "STR XZR, [X26,#8]"},
	}, nil)
	if len(got) != 2 {
		t.Fatalf("ZR THR access count = %d, want 2: %+v", len(got), got)
	}
	if got[0].Access != thraudit.AccessRead || got[0].DstReg != nil {
		t.Fatalf("LDR XZR fabricated GPR destination: %+v", got[0])
	}
	if got[1].Access != thraudit.AccessWrite || got[1].SrcReg != nil {
		t.Fatalf("STR XZR fabricated GPR source: %+v", got[1])
	}
}
