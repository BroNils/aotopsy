package elfx

import "debug/elf"

// Function symbols from the static symbol table.
//
// A Flutter build's libapp.so often keeps a `.symtab` describing every code
// range it contains -- 8346 FUNC symbols on the 3.12.2 sample against 8173
// Code objects in the snapshot -- while `.dynsym` holds only the five
// snapshot blobs. Nothing in this project read `.symtab`.
//
// This is deliberately a LAST RESORT and must stay one. Recovering names from
// the snapshot is the entire point of the tool, and a production app is
// usually stripped: the gopay corpus samples are. A name that comes from the
// symbol table proves nothing about whether the snapshot-derived naming
// works, so it must never silently stand in for it. It is used only where the
// snapshot yields no name at all -- Codes with a null owner, which are VM and
// isolate stubs; 86 of them on the 3.12.2 x86_64 sample, all of which the
// symbol table names exactly.
//
// The names are Dart-side and human-written, spaces and all
// ("stub CheckIsolateFieldAccess", "assert type is HitTestTarget",
// "new Duration"), so callers must not assume identifier syntax.

// FuncSymbols returns virtual address -> symbol name for every STT_FUNC
// symbol in `.symtab`. Returns nil when the binary is stripped, which is the
// normal case for a production build and is not an error.
func (f *File) FuncSymbols() map[uint64]string {
	syms, err := f.ELF.Symbols()
	if err != nil {
		return nil // no .symtab: stripped
	}
	out := make(map[uint64]string, len(syms))
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Name == "" || s.Value == 0 {
			continue
		}
		// Two symbols on one address would make the choice arbitrary; keep
		// the first and do not overwrite, so the result is deterministic.
		if _, exists := out[s.Value]; !exists {
			out[s.Value] = s.Name
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
