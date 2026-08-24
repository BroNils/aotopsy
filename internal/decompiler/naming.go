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
// 1. D4: Simplifies compound mixin chain (__A & _B & _C.method -> _C.method)
// 2. D7: Strips PCOffset hex disambiguation suffixes (_564794, _233d64, _14b90)
// 3. Strips library hash @NNNNNN from class names (_Set@3099033 -> _Set)
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
	// D4: Compound mixin chain simplification (both "A & B" and "A&B")
	if strings.Contains(name, "&") {
		parts := strings.Split(name, "&")
		name = strings.TrimSpace(parts[len(parts)-1])
	}
	// D7: Strip trailing PCOffset hex suffix (_564794, _14b90, _233d64)
	if lastUnder := strings.LastIndex(name, "_"); lastUnder > 0 {
		suffix := name[lastUnder+1:]
		if isHexOffset(suffix) && !strings.HasPrefix(name, "sub_") && !strings.HasPrefix(name, "block_") && !strings.HasPrefix(name, "local_") && !strings.HasPrefix(name, "local_m") {
			name = name[:lastUnder]
		}
	}
	return name
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
