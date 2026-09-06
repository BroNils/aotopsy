package naming

import (
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/vmtables"
)

// BuildIsolateStubSymbols names the isolate stubs, keyed by the ref of the
// Code that implements each one.
//
// These are the only Codes in an AOT snapshot with no owner at all. The SDK
// sets `code.set_owner(...)` to a Function, a Class (allocation stub) or an
// AbstractType (type-testing stub); an isolate stub gets none, so the owner
// walk and buildTypeNames both come up empty and every one of them
// renders as `sub_<pcOffset>`. Measured on dart-3.9.2-gt-arm64: 85 of 8049
// ranges unnamed, all 85 spelled `_iso_stub_*` by the ELF symbol table, and
// called often enough to be 639 of the 840 `unresolvedCall` tokens in the
// fidelity census.
//
// Their names survive one place only: the isolate roots section writes the
// ObjectStore's fields in order, and 74-89 of those are
// `RW(Code, <name>_stub)`. Zipping the committed per-version field table
// against Result.ObjectStoreRefs recovers the name.
//
// Returns nil when the version has no verified field table or the roots were
// not read -- an unnamed stub is the honest outcome, a guessed one is not.
func BuildIsolateStubSymbols(result *cluster.Result, dartVersion string) map[int]string {
	fields := vmtables.ObjectStoreStubFields(dartVersion)
	if len(fields) == 0 || len(result.ObjectStoreRefs) == 0 {
		return nil
	}
	// Only a ref that really is a Code may be named: the roots also hold
	// null and non-Code objects, and a mis-indexed table must produce
	// nothing rather than a plausible wrong label.
	isCode := make(map[int]bool, len(result.Codes))
	for i := range result.Codes {
		isCode[result.Codes[i].RefID] = true
	}
	out := make(map[int]string, len(fields))
	for _, f := range fields {
		if f.Index < 0 || f.Index >= len(result.ObjectStoreRefs) {
			continue
		}
		ref := result.ObjectStoreRefs[f.Index]
		if ref <= 0 || !isCode[ref] {
			continue
		}
		// Two Code-typed fields can share one Code (e.g. the with/without
		// FPU-regs pair collapsing on a target with no FPU spill). First
		// name wins, so the output is stable rather than map-order.
		if _, taken := out[ref]; !taken {
			out[ref] = isolateStubDisplayName(f.Name)
		}
	}
	return out
}

// isolateStubDisplayName turns an object-store field name into the spelling
// this project already uses for VM stubs: `array_write_barrier_stub` becomes
// `ArrayWriteBarrier`, matching vmtables.VMStubNames and therefore
// BuildVMStubSymbols' output.
//
// Three spellings exist for the same stub and none of them is wrong:
//
//	object_store.h   array_write_barrier_stub
//	stub_code_list.h ArrayWriteBarrier          <- what we emit
//	ELF symtab       _iso_stub_ArrayWriteBarrierStub
//
// Emitting the middle one keeps every stub in this tool spelled one way,
// whichever table it came from. The ELF's prefix and suffix are folded away in
// the comparison rather than here; see NormalizeSymbolName.
func isolateStubDisplayName(field string) string {
	s := strings.TrimSuffix(field, "_stub")
	if s == "" {
		return field
	}
	var b strings.Builder
	b.Grow(len(s))
	upper := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' {
			upper = true
			continue
		}
		if upper && c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		upper = false
		b.WriteByte(c)
	}
	return b.String()
}
