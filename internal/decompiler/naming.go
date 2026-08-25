package decompiler

import "strings"

// applyNamingPass replaces raw ABI register tokens that leaked through
// into the emitted pseudocode (frame pointer / link register, mainly --
// most other registers are already replaced with symbolic expressions by
// the lifter) with friendlier names. Mirrors the register-alias half of
// flutterdec's passes/naming.rs apply_name_and_type_hints (the
// arg0..arg7 semantic-renaming half is not ported: this project's
// pseudocode already names call results/locals descriptively enough via
// the lifter's own local/temp naming, and a full IdentStats-based
// re-classification pass is a documented future extension).
func applyNamingPass(source string, fir *FuncIR) string {
	if fir.FrameReg != "" {
		source = replaceIdentToken(source, fir.FrameReg, "framePointer")
	}
	if fir.LinkReg != "" {
		source = replaceIdentToken(source, fir.LinkReg, "returnAddress")
	}
	return source
}

// replaceIdentToken replaces every whole-token occurrence of old with
// new in text, where "whole token" means not adjacent to another
// identifier character (matching flutterdec's replace_identifier_token
// word-boundary-aware byte scanner).
func replaceIdentToken(text, old, newName string) string {
	if old == "" {
		return text
	}
	var b strings.Builder
	i := 0
	for {
		idx := strings.Index(text[i:], old)
		if idx < 0 {
			b.WriteString(text[i:])
			break
		}
		start := i + idx
		end := start + len(old)
		beforeOK := start == 0 || !isIdentChar(text[start-1])
		afterOK := end == len(text) || !isIdentChar(text[end])
		b.WriteString(text[i:start])
		if beforeOK && afterOK {
			b.WriteString(newName)
		} else {
			b.WriteString(old)
		}
		i = end
	}
	return b.String()
}

func isIdentChar(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
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
	// Strip library hash: ClassName@123456.method -> ClassName.method or ClassName@123456 -> ClassName
	if atIdx := strings.Index(name, "@"); atIdx >= 0 {
		rest := name[atIdx+1:]
		end := strings.IndexAny(rest, "._ \t")
		if end >= 0 {
			name = name[:atIdx] + rest[end:]
		} else {
			name = name[:atIdx]
		}
	}
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
