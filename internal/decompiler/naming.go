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
