package elfx

import (
	"debug/elf"
	"fmt"
)

// Function symbols from the static symbol table.
//
// A Flutter build's libapp.so often keeps a `.symtab` describing every code
// range it contains -- 8346 FUNC symbols on the 3.12.2 sample against 8173
// Code objects in the snapshot -- while `.dynsym` holds only the five
// snapshot blobs. Nothing in this project read `.symtab`.
//
// This is deliberately a LAST RESORT and must stay one. Recovering names from
// the snapshot is the entire point of the tool, and a production app is
// usually stripped: the realapp2 corpus samples are. A name that comes from the
// symbol table proves nothing about whether the snapshot-derived naming
// works, so it must never silently stand in for it. It is used only where the
// snapshot yields no name at all -- Codes with a null owner, which are VM and
// isolate stubs; 86 of them on the 3.12.2 x86_64 sample, all of which the
// symbol table names exactly.
//
// The names are Dart-side and human-written, spaces and all
// ("stub CheckIsolateFieldAccess", "assert type is HitTestTarget",
// "new Duration"), so callers must not assume identifier syntax.

// FuncSymbols returns virtual address -> symbol name for every STT_FUNC symbol
// in `.symtab`. A genuinely stripped binary returns (nil,nil); malformed symbol
// tables are errors and must never be disguised as "stripped", because callers
// use this API as an external naming ground-truth gate.
func (f *File) FuncSymbols() (map[uint64]string, error) {
	syms, err := f.Symbols()
	if err != nil {
		return nil, err
	}
	if len(syms) == 0 {
		return nil, nil
	}
	out := make(map[uint64]string, len(syms))
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Name == "" || s.Value == 0 || s.Section == elf.SHN_UNDEF {
			continue
		}
		// Values in the reserved section-index range are not indexes into
		// f.ELF.Sections. SHN_ABS and SHN_COMMON are valid ELF values, while
		// SHN_XINDEX means the real index lives in SHT_SYMTAB_SHNDX (which
		// debug/elf does not resolve for symbols). None identifies an executable
		// section we can safely use as function ground truth, so skip them.
		if s.Section >= elf.SHN_LORESERVE {
			continue
		}
		sectionIndex := int(s.Section)
		if sectionIndex < 0 || sectionIndex >= len(f.ELF.Sections) {
			return nil, fmt.Errorf("elfx: function symbol %q has invalid section index %d", s.Name, s.Section)
		}
		sec := f.ELF.Sections[sectionIndex]
		if sec == nil || sec.Flags&elf.SHF_EXECINSTR == 0 {
			continue
		}
		// A STT_FUNC tag alone is not proof that the symbol points into the
		// section it names. Malformed/legacy tables can carry container symbols
		// or out-of-range values; never expose those as callable addresses.
		if s.Value < sec.Addr {
			continue
		}
		rel := s.Value - sec.Addr
		if rel >= sec.Size {
			continue
		}
		if s.Size > 0 && s.Size > sec.Size-rel {
			continue
		}
		// Two symbols on one address would make the choice arbitrary; keep
		// the first and do not overwrite, so the result is deterministic.
		if _, exists := out[s.Value]; !exists {
			out[s.Value] = s.Name
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
