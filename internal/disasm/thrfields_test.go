package disasm

import (
	"fmt"
	"testing"
)

func TestRuntimeEntryMerge(t *testing.T) {
	fields := THRFields("3.10.7", true)

	// Check a few runtime entry offsets.
	checks := []struct {
		off  int
		want string
	}{
		{0x2e8, "AllocateArray_ep"},
		{0x2f0, "AllocateMint_ep"},
		{0x2f8, "AllocateDouble_ep"},
		{0x468, "ArgumentErrorUnboxedInt64_ep"},
		{0x470, "IntegerDivisionByZeroException_ep"},
		{0x478, "ReThrow_ep"},
		{0x568, "InitializeSharedField_ep"},
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
	fields := THRFields("2.17.6", true)

	// v2.17.6 base 0x2d8 = AllocateArray
	checks := []struct {
		off  int
		want string
	}{
		{0x2d8, "AllocateArray_ep"},
		{0x2e0, "AllocateMint_ep"},
		{0x488, "NotLoaded_ep"},
		// LEAF entries
		{0x490, "DeoptimizeCopyFrame_ep"},
		{0x580, "TsanStoreRelease_ep"},
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
	fields := THRFields("3.10.7", true)

	// LDR X5, [X26,#1128] → 0x468 → ArgumentErrorUnboxedInt64_ep
	// Raw encoding: 45 37 42 f9 = 0xf9423745
	raw := uint32(0xf9423745)

	insts := []Inst{
		{Addr: 0x1000, Raw: 0xd503201f, Text: "NOP"}, // padding
		{Addr: 0x1004, Raw: raw, Text: "LDR X5, [X26,#1128]"},
		{Addr: 0x1008, Raw: 0xd503201f, Text: "NOP"}, // padding
	}

	ann := THRContextAnnotator(insts, fields)
	got := ann(insts[1])
	want := "THR.ArgumentErrorUnboxedInt64_ep"
	if got != want {
		t.Errorf("THRContextAnnotator(0x468) = %q, want %q", got, want)
	}
}
