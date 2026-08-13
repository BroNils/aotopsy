package disasm

import (
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func decodeOne(t *testing.T, b []byte) x86asm.Inst {
	t.Helper()
	inst, err := x86asm.Decode(b, 64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return inst
}

// A THR-relative call with no index register is a stub entry point, not a
// dispatch-table call. Both shapes used to be labelled `dispatch_table`, so
// 6348 sites on the 3.12.2 x86_64 sample carried a claim about the dispatch
// table that was simply false, and resolved to nothing -- 5979 of them the
// stack-overflow check in the function prologue.
func TestX86THRCallIsAStubNotADispatchTableCall(t *testing.T) {
	// 41 ff 96 40 02 00 00   call qword ptr [r14+0x240]
	inst := decodeOne(t, []byte{0x41, 0xff, 0x96, 0x40, 0x02, 0x00, 0x00})
	thrFields := map[int]string{0x240: "stack_overflow_shared_without_fpu_regs_entry_point"}

	e := classifyX86Call(inst, 0x136289, inst.Len, nil, &x86RegTracker{}, nil, thrFields)
	if want := "THR.stack_overflow_shared_without_fpu_regs_entry_point"; e.Via != want {
		t.Errorf("Via = %q, want %q", e.Via, want)
	}
}

// An offset the Thread table does not cover must report the slot, not fall
// back to a category the code never established. Claiming `dispatch_table`
// for an unknown Thread offset is what produced the 6348 false labels.
func TestX86THRCallWithUnknownOffsetNamesNoCategory(t *testing.T) {
	inst := decodeOne(t, []byte{0x41, 0xff, 0x96, 0x40, 0x02, 0x00, 0x00})

	e := classifyX86Call(inst, 0x136289, inst.Len, nil, &x86RegTracker{}, nil, map[int]string{})
	if e.Via == "dispatch_table" {
		t.Error("an unknown Thread offset must not be claimed as the dispatch table")
	}
	if want := "THR+0x240"; e.Via != want {
		t.Errorf("Via = %q, want %q", e.Via, want)
	}
}

// The real dispatch call indexes a register the table was loaded INTO, so its
// base is never THR. This pins the shape the SDK actually emits:
//
//	MOV  RAX, [R14+0x70]        ; THR.dispatch_table_array
//	CALL [RAX+8*RCX+0xd700]
//
// All 3371 dispatch calls on the 3.12.2 x86_64 sample have it, and all of
// them resolve -- so this path must keep working unchanged.
func TestX86DispatchCallIndexesTheLoadedTable(t *testing.T) {
	// ff 94 c8 00 d7 00 00   call qword ptr [rax+rcx*8+0xd700]
	inst := decodeOne(t, []byte{0xff, 0x94, 0xc8, 0x00, 0xd7, 0x00, 0x00})
	rt := &x86RegTracker{}
	rt.defs[0] = x86RegProvenance{note: "THR.dispatch_table_array"} // RAX

	e := classifyX86Call(inst, 0x13626c, inst.Len, nil, rt, nil, nil)
	if e.Via != "THR.dispatch_table_array" {
		t.Errorf("Via = %q; the dispatch call must keep the provenance of the loaded table", e.Via)
	}
}
