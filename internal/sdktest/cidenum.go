package sdktest

import (
	"fmt"
	"regexp"
	"strings"

	"aotopsy/internal/cmacro"
)

// CIDEnumAtTag reproduces runtime/vm/class_id.h's ClassId enum ordering for
// one exact Dart release tag. Snapshot drift gates share this because the enum
// mixes literal entries with X-macro expansions whose per-entry templates
// change across releases (notably CLASS_LIST_TYPED_DATA).
func CIDEnumAtTag(tag string) (map[string]int, int, error) {
	src, err := SDKFileAtTag("runtime/vm/class_id.h", tag)
	if err != nil {
		return nil, 0, err
	}
	macros, err := cmacro.ParseMacros(src)
	if err != nil {
		return nil, 0, err
	}

	body, err := classIDEnumBody(src)
	if err != nil {
		return nil, 0, err
	}
	typedDataStride := 0

	out := map[string]int{}
	next := 0
	add := func(name string) {
		if _, dup := out[name]; !dup {
			out[name] = next
		}
		next++
	}

	// Per-entry templates must be tracked positionally: older ClassId enums
	// redefine DEFINE_OBJECT_KIND several times, while ParseMacros intentionally
	// exposes only the file-wide macro definition catalog.
	templates := map[string]string{}

	var walk func(text string, depth int) error
	walk = func(text string, depth int) error {
		if depth > 8 {
			return fmt.Errorf("sdktest: class_id macro nesting too deep at %s", tag)
		}
		for i := 0; i < len(text); {
			d := classIDInlineDefineRe.FindStringSubmatchIndex(text[i:])
			loc := classIDTokenRe.FindStringSubmatchIndex(text[i:])
			if d != nil && (loc == nil || d[0] <= loc[0]) {
				templates[text[i+d[2]:i+d[3]]] = text[i+d[8] : i+d[9]]
				i += d[1]
				continue
			}
			if loc == nil {
				return nil
			}
			tok := text[i+loc[0] : i+loc[1]]
			i += loc[1]

			if strings.HasPrefix(tok, "k") && strings.HasSuffix(tok, ",") {
				if m := classIDEnumEntryRe.FindStringSubmatch(tok); m != nil {
					add(m[1])
				}
				continue
			}
			name, arg, isCall := classIDSplitCall(tok)
			if !isCall {
				if macro, ok := macros[name]; ok && strings.Contains(macro.Body, "(") {
					if err := walk(macro.Body, depth+1); err != nil {
						return err
					}
				}
				continue
			}
			if tmpl, ok := templates[name]; ok {
				if err := walk(classIDSubstParam(tmpl, arg), depth+1); err != nil {
					return err
				}
				continue
			}
			if _, ok := macros[name]; ok && strings.HasPrefix(name, "CLASS_LIST") {
				tmpl, ok := templates[arg]
				if !ok {
					if macro, found := macros[arg]; found {
						tmpl, ok = macro.Body, true
					}
				}
				if !ok {
					return fmt.Errorf("sdktest: no template %s for %s at %s", arg, name, tag)
				}
				classes, err := cmacro.Expand(macros, name)
				if err != nil {
					return err
				}
				if name == "CLASS_LIST_TYPED_DATA" {
					before := next
					if err := walk(classIDSubstParam(tmpl, "Probe"), depth+1); err != nil {
						return err
					}
					typedDataStride = next - before
					next = before
					for k, v := range out {
						if v >= before {
							delete(out, k)
						}
					}
				}
				for _, c := range classes {
					if err := walk(classIDSubstParam(tmpl, c), depth+1); err != nil {
						return err
					}
				}
				continue
			}
		}
		return nil
	}

	if err := walk(body, 0); err != nil {
		return nil, 0, err
	}
	if len(out) < 50 {
		return nil, 0, fmt.Errorf("sdktest: class_id.h@%s yielded too few ids to be the ClassId enum", tag)
	}
	if typedDataStride == 0 {
		return nil, 0, fmt.Errorf("sdktest: CLASS_LIST_TYPED_DATA not expanded at %s", tag)
	}
	return out, typedDataStride, nil
}

func classIDSplitCall(tok string) (name, arg string, ok bool) {
	open := strings.IndexByte(tok, '(')
	if open < 0 || !strings.HasSuffix(tok, ")") {
		return strings.TrimSuffix(tok, ","), "", false
	}
	return tok[:open], strings.TrimSpace(tok[open+1 : len(tok)-1]), true
}

func classIDSubstParam(tmpl, arg string) string {
	t := strings.ReplaceAll(tmpl, "##", "\x00")
	for _, p := range []string{"clazz", "cid", "class"} {
		t = regexp.MustCompile(`\b`+p+`\b`).ReplaceAllString(t, arg)
	}
	return strings.ReplaceAll(t, "\x00", "")
}

var (
	classIDEnumOpenRe     = regexp.MustCompile(`enum\s+ClassId[^{]*\{`)
	classIDInlineDefineRe = regexp.MustCompile(`#define\s+(\w+)(\(\s*(\w+)\s*\))?([^\n]*)`)
	classIDTokenRe        = regexp.MustCompile(`(\w+\([^()]*\))|(k\w+\s*(?:=\s*\d+\s*)?,)|(\w+)`)
	classIDEnumEntryRe    = regexp.MustCompile(`\bk(\w+?)(?:Cid)?\s*(?:=\s*\d+\s*)?,`)
	classIDBlockCmtRe     = regexp.MustCompile(`(?s)/\*.*?\*/`)
	classIDLineCmtRe      = regexp.MustCompile(`//[^\n]*`)
)

func classIDEnumBody(src string) (string, error) {
	loc := classIDEnumOpenRe.FindStringIndex(src)
	if loc == nil {
		return "", fmt.Errorf("sdktest: enum ClassId not found")
	}
	rest := src[loc[1]:]
	end := strings.Index(rest, "};")
	if end < 0 {
		return "", fmt.Errorf("sdktest: unterminated enum ClassId")
	}
	body := rest[:end]
	body = strings.ReplaceAll(body, "\\\r\n", "")
	body = strings.ReplaceAll(body, "\\\n", "")
	body = classIDBlockCmtRe.ReplaceAllString(body, "")
	body = classIDLineCmtRe.ReplaceAllString(body, "")
	return body, nil
}
