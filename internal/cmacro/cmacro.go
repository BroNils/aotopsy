// Package cmacro expands the C preprocessor X-macro lists that the Dart
// SDK uses to declare almost every table this project mirrors.
//
// The lists look like `#define SOME_LIST(V) V(A) V(B) ...`, they nest
// (VM_STUB_CODE_LIST expands PROBE_POINT_STUBS_LIST and
// VM_TYPE_TESTING_STUB_CODE_LIST inline), and several carry multiple
// arguments per entry, including initialiser expressions with their own
// parentheses:
//
//	V(uword, deoptimize_entry_, StubCode::Deoptimize().EntryPoint(), 0)
//
// A `V\((\w+)\)` scan silently drops the nested lists and every
// multi-argument entry. That does not fail -- it produces a shorter list,
// which downstream reads as a narrower mask or a table missing rows, i.e.
// exactly the silent drift the SDK gates exist to catch. So there is one
// expander, used by the gates and by tools/extract_thr.go alike.
package cmacro

import (
	"regexp"
	"strings"
)

var (
	// Both function-like (`#define NAME(args) body`) and object-like
	// (`#define NAME body`) macros. Dart 3.13.0 moved the ClassId enum from
	// a set of parameterised CLASS_LIST_* invocations to a single object-like
	// CLASS_ID_LIST, so a parser that only knows the parameterised form reads
	// that header as having no list at all.
	macroDefRe   = regexp.MustCompile(`(?m)^#define\s+(\w+)(\([^)]*\))?(.*)$`)
	blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineComment  = regexp.MustCompile(`//[^\n]*`)
	identRe      = regexp.MustCompile(`\w+`)
)

// ParseMacros returns every `#define NAME ...` body in a C header, with
// line continuations joined and comments stripped. Both function-like and
// object-like macros are included, keyed by name.
//
// A name defined more than once keeps the LAST definition, which is what
// the preprocessor would see at the end of the file but not necessarily
// at a given point in it. Callers that walk a region containing its own
// `#define` (the pre-3.13 ClassId enum redefines DEFINE_OBJECT_KIND three
// times) must track those positionally instead.
func ParseMacros(src string) map[string]string {
	src = strings.ReplaceAll(src, "\\\r\n", "")
	src = strings.ReplaceAll(src, "\\\n", "")
	src = blockComment.ReplaceAllString(src, "")
	src = lineComment.ReplaceAllString(src, "")
	out := map[string]string{}
	for _, m := range macroDefRe.FindAllStringSubmatch(src, -1) {
		out[m[1]] = m[3]
	}
	return out
}

// ExpandRaw expands one list macro, recursing into nested list macros,
// and returns each entry's arguments split and trimmed.
//
// `V(Name)` yields ["Name"]; `V(Type, name, expr, default)` yields all
// four. Use this when the position of an argument matters.
func ExpandRaw(macros map[string]string, name string) ([][]string, error) {
	body, ok := macros[name]
	if !ok {
		return nil, Error("macro " + name + " not found")
	}
	return expandBody(macros, body, map[string]bool{name: true})
}

// Expand expands one list macro and returns the first argument of each
// entry, which for the single-argument lists is the whole entry.
func Expand(macros map[string]string, name string) ([]string, error) {
	return Column(macros, name, 0)
}

// Column expands a list macro and returns argument i of each entry.
// Entries with fewer arguments are skipped.
func Column(macros map[string]string, name string, i int) ([]string, error) {
	rows, err := ExpandRaw(macros, name)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if i < len(r) {
			out = append(out, r[i])
		}
	}
	return out, nil
}

// expandBody walks `IDENT( ... )` calls with a paren-depth scan rather
// than a regex, because entries carry initialiser expressions and a
// regex that stops at the first ')' truncates the row while one that
// forbids nested parens drops it entirely. Both read as a short list.
func expandBody(macros map[string]string, body string, seen map[string]bool) ([][]string, error) {
	var out [][]string
	for i := 0; i < len(body); {
		loc := identRe.FindStringIndex(body[i:])
		if loc == nil {
			break
		}
		name := body[i+loc[0] : i+loc[1]]
		j := i + loc[1]
		if j >= len(body) || body[j] != '(' {
			i += loc[1]
			continue
		}
		inner, end, ok := balanced(body, j)
		if !ok {
			break
		}
		i = end

		if name != "V" {
			// A nested list is invoked as NAME(V); anything else with
			// arguments is an ordinary call, not part of the list.
			if strings.TrimSpace(inner) != "V" || seen[name] {
				continue
			}
			sub, ok := macros[name]
			if !ok {
				return nil, Error("nested macro " + name + " not found")
			}
			seen[name] = true
			vals, err := expandBody(macros, sub, seen)
			delete(seen, name)
			if err != nil {
				return nil, err
			}
			out = append(out, vals...)
			continue
		}

		args := SplitTopLevel(inner)
		// V() with an empty body is a list terminator in some headers,
		// not an entry.
		if len(args) == 1 && args[0] == "" {
			continue
		}
		out = append(out, args)
	}
	return out, nil
}

// balanced returns the contents between body[open] == '(' and its
// matching ')', plus the index just past that ')'.
func balanced(body string, open int) (string, int, bool) {
	depth := 0
	for k := open; k < len(body); k++ {
		switch body[k] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return body[open+1 : k], k + 1, true
			}
		}
	}
	return "", 0, false
}

// SplitTopLevel splits on commas that are not inside parentheses or
// angle brackets, so `Array<int, int>` and `f(a, b)` stay one argument.
func SplitTopLevel(s string) []string {
	var out []string
	depth, start := 0, 0
	for k := 0; k < len(s); k++ {
		switch s[k] {
		case '(', '<':
			depth++
		case ')', '>':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:k]))
				start = k + 1
			}
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

// Error is a macro expansion failure.
type Error string

func (e Error) Error() string { return string(e) }
