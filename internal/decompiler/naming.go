package decompiler

import (
	"strings"

	"aotopsy/internal/decompiler/stmt"
	"aotopsy/internal/strutil"
)

// applyNamingPass replaces raw ABI register tokens that leaked through
// into the emitted pseudocode (frame pointer / link register, mainly --
// most other registers are already replaced with symbolic expressions by
// the lifter) with friendlier names. It never invents a role for a temp:
// the usage-count re-classification (result/flag/counter/accumulator) was
// removed because it asserted roles the binary does not have and was not
// stable across unrelated edits (AUDIT-2026-10 section 7.2).
func applyNamingPass(source string, fir *FuncIR) string {
	if fir.FrameReg != "" {
		source = stmt.ReplaceIdent(source, fir.FrameReg, "framePointer")
	}
	if fir.LinkReg != "" {
		source = stmt.ReplaceIdent(source, fir.LinkReg, "returnAddress")
	}
	return source
}

// cleanCalleeName simplifies callee symbol names for pseudocode display:
//  1. Strips the library-disambiguation hash @NNNNNN (_Set@3099033 -> _Set).
//  2. D7: Strips PCOffset hex disambiguation suffixes (_564794, _233d64, _14b90).
//  3. Compacts a mixin-application owner to `base&….member` (see compactMixinOwner).
//
// It deliberately does NOT fold a mixin-application chain to its LAST component.
// Folding `_Set&…&_LinkedHashSetMixin.add` to `_LinkedHashSetMixin.add` asserts
// the DEFINING class, which is wrong ~23% of the time (the method is often on a
// superclass of the mixin) -- this is why foldMixinOwner in symtabdiff.go is
// comparison-only (audit A6). Instead we keep the base class and mark the mixins
// with `&…`, which is compact AND honest: it asserts only the base type (`_Set`)
// -- true by construction -- and signals a mixin composite without naming a
// definer. Measured: the full chains were ~85k tokens of noise per 400 functions.
func cleanCalleeName(name string) string {
	if name == "" {
		return name
	}
	// Exact SDK private-key scrub: only @ followed by decimal digits is VM
	// mangling. A nonnumeric '@' is not proven to be removable and is preserved.
	name = strutil.ScrubDartPrivateKeys(name)
	name = compactMixinOwner(name)
	// D7: Strip trailing PCOffset hex suffix (_564794, _14b90, _233d64)
	if lastUnder := strings.LastIndex(name, "_"); lastUnder > 0 {
		suffix := name[lastUnder+1:]
		if isHexOffset(suffix) && !strings.HasPrefix(name, "sub_") && !strings.HasPrefix(name, "block_") && !strings.HasPrefix(name, "local_") && !strings.HasPrefix(name, "local_m") {
			name = name[:lastUnder]
		}
	}
	return name
}

// compactMixinOwner rewrites a mixin-application owner `A & B & … & Z.member`
// (or the unspaced `A&B&…&Z.member`) to `A&….member`, keeping the base class A
// and marking the applied mixins with `&…`. It asserts only the base type, so it
// never claims a wrong defining class (unlike a last-component fold). Names with
// no `&` are returned unchanged.
func compactMixinOwner(name string) string {
	if !strings.Contains(name, "&") {
		return name
	}
	owner, member := name, ""
	if dot := strings.LastIndex(name, "."); dot >= 0 {
		owner, member = name[:dot], name[dot:]
	}
	amp := strings.IndexByte(owner, '&')
	if amp < 0 {
		return name
	}
	base := strings.TrimSpace(owner[:amp])
	if base == "" {
		return name
	}
	return base + "&…" + member
}

func isHexOffset(s string) bool {
	if len(s) < 4 || len(s) > 8 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
