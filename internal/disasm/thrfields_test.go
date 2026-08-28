package disasm

import (
	"fmt"
	"testing"

	"aotopsy/internal/vmtables"
)

func TestRuntimeEntryMerge(t *testing.T) {
	fields := vmtables.THRFields("3.10.7", true)

	// Check a few runtime entry offsets. The suffix is "_entry_point", the
	// same spelling runtime_offsets_extracted.h uses for the entry-point
	// fields it exports -- see mergeRuntimeEntries for why the old "_ep"
	// abbreviation was dropped.
	checks := []struct {
		off  int
		want string
	}{
		{0x2e8, "AllocateArray_entry_point"},
		{0x2f0, "AllocateMint_entry_point"},
		{0x2f8, "AllocateDouble_entry_point"},
		{0x468, "ArgumentErrorUnboxedInt64_entry_point"},
		{0x470, "IntegerDivisionByZeroException_entry_point"},
		{0x478, "ReThrow_entry_point"},
		{0x568, "InitializeSharedField_entry_point"},
	}
	for _, c := range checks {
		t.Run(fmt.Sprintf("0x%x", c.off), func(t *testing.T) {
			got, ok := fields[c.off]
			if !ok {
				t.Fatalf("offset 0x%x not in map", c.off)
			}
			if got != c.want {
				t.Errorf("0x%x = %q, want %q", c.off, got, c.want)
			}
		})
	}

	// Verify static entries not overwritten.
	if got := fields[0x48]; got != "stack_limit" {
		t.Errorf("stack_limit = %q", got)
	}

	t.Logf("Total v3.10.7 entries: %d", len(fields))
}

func TestRuntimeEntryV217Merge(t *testing.T) {
	fields := vmtables.THRFields("2.17.6", true)

	// v2.17.6 base 0x2d8 = AllocateArray
	checks := []struct {
		off  int
		want string
	}{
		{0x2d8, "AllocateArray_entry_point"},
		{0x2e0, "AllocateMint_entry_point"},
		{0x488, "NotLoaded_entry_point"},
		// LEAF entries
		{0x490, "DeoptimizeCopyFrame_entry_point"},
		{0x580, "TsanStoreRelease_entry_point"},
	}
	for _, c := range checks {
		t.Run(fmt.Sprintf("0x%x", c.off), func(t *testing.T) {
			got, ok := fields[c.off]
			if !ok {
				t.Fatalf("offset 0x%x not in map", c.off)
			}
			if got != c.want {
				t.Errorf("0x%x = %q, want %q", c.off, got, c.want)
			}
		})
	}

	t.Logf("Total v2.17.6 entries: %d", len(fields))
}

func TestTHRContextAnnotator_RuntimeEntry(t *testing.T) {
	fields := vmtables.THRFields("3.10.7", true)

	// LDR X5, [X26,#1128] → 0x468 → ArgumentErrorUnboxedInt64_entry_point
	// Raw encoding: 45 37 42 f9 = 0xf9423745
	raw := uint32(0xf9423745)

	insts := []Inst{
		{Addr: 0x1000, Raw: 0xd503201f, Text: "NOP"}, // padding
		{Addr: 0x1004, Raw: raw, Text: "LDR X5, [X26,#1128]"},
		{Addr: 0x1008, Raw: 0xd503201f, Text: "NOP"}, // padding
	}

	ann := THRContextAnnotator(insts, fields)
	got := ann(insts[1])
	want := "THR.ArgumentErrorUnboxedInt64_entry_point"
	if got != want {
		t.Errorf("THRContextAnnotator(0x468) = %q, want %q", got, want)
	}
}
