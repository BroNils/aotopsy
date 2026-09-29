// Package cmacro expands the C/C++ preprocessor X-macro lists used by the
// Dart SDK to declare VM tables mirrored by aotopsy.
package cmacro

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var macroDefRe = regexp.MustCompile(`(?m)^[\t ]*#[\t ]*define[\t ]+([A-Za-z_]\w*)(\([^)]*\))?(.*)$`)

const (
	maxExpansionDepth = 256
	maxExpansionSteps = 100000
	maxExpansionRows  = 100000
	// Source headers are capped at 8 MiB by the SDK drift loader, but macro
	// substitution can amplify one argument many times in a single expansion.
	// Keep the expanded work bounded as well so a small definition cannot turn
	// into an unbounded allocation before the step/depth limits get a chance to
	// fire. The SDK list macros are orders of magnitude smaller than this.
	maxExpansionBytes = 16 << 20
)

type expansionState struct {
	steps int
	rows  int
	bytes int
}

// Macro is one parsed #define. Keeping formal parameter names is essential:
// Dart headers compose lists as LIST(V) -> SUBLIST(V), and some use F/X/etc.
// Dropping the formals makes correct nested substitution impossible.
type Macro struct {
	Params       []string
	Body         string
	FunctionLike bool
}

// Macros is the parsed macro table keyed by definition name.
type Macros map[string]Macro

// ParseMacros returns every #define body in a C/C++ header. Line
// continuations are joined and comments are removed without treating comment
// markers inside string/character literals as comments. The last textual
// definition of a name wins. This is intentionally a definition catalog rather
// than a full preprocessor: conditional directives and #undef do not remove
// definitions, because SDK drift checks also inspect list macros after their
// declaration site has been undefined.
func ParseMacros(src string) Macros {
	src = strings.ReplaceAll(src, "\\\r\n", "")
	src = strings.ReplaceAll(src, "\\\n", "")
	src = stripComments(src)
	out := Macros{}
	for _, m := range macroDefRe.FindAllStringSubmatch(src, -1) {
		var params []string
		if m[2] != "" {
			inside := strings.TrimSpace(m[2][1 : len(m[2])-1])
			if inside != "" {
				for _, p := range strings.Split(inside, ",") {
					p = strings.TrimSpace(p)
					if p != "" {
						params = append(params, p)
					}
				}
			}
		}
		out[m[1]] = Macro{Params: params, Body: m[3], FunctionLike: m[2] != ""}
	}
	return out
}

// ExpandRaw expands one list macro recursively and returns every entry's
// top-level arguments. The list callback is the root macro's first formal
// parameter (V/F/X/etc.); object-like lists default to the conventional V.
func ExpandRaw(macros Macros, name string) ([][]string, error) {
	m, ok := macros[name]
	if !ok {
		return nil, Error("macro " + name + " not found")
	}
	callback := "V"
	if len(m.Params) > 0 {
		callback = m.Params[0]
	}
	state := &expansionState{}
	if err := chargeExpansionBytes(state, len(m.Body)); err != nil {
		return nil, err
	}
	return expandBody(macros, m.Body, callback, map[string]bool{name: true}, state, 0)
}

// Expand returns the first column of an expanded list.
func Expand(macros Macros, name string) ([]string, error) {
	return Column(macros, name, 0)
}

// Column expands a list and returns argument i from every entry. A malformed
// short row is an error, never a silently skipped row: SDK drift gates must fail
// loudly rather than comparing a shorter, shifted table.
func Column(macros Macros, name string, i int) ([]string, error) {
	if i < 0 {
		return nil, Error(fmt.Sprintf("column index %d is negative", i))
	}
	rows, err := ExpandRaw(macros, name)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for row, r := range rows {
		if i >= len(r) {
			return nil, Error(fmt.Sprintf("macro %s row %d has %d columns; need column %d", name, row, len(r), i))
		}
		out = append(out, r[i])
	}
	return out, nil
}

// expandBody walks identifier/call tokens in one instantiated macro body.
// callback is the entry macro visible in this expansion (usually V).
func expandBody(macros Macros, body, callback string, seen map[string]bool, state *expansionState, depth int) ([][]string, error) {
	if depth > maxExpansionDepth {
		return nil, Error(fmt.Sprintf("macro expansion exceeds depth limit %d", maxExpansionDepth))
	}
	var out [][]string
	for i := 0; i < len(body); {
		if body[i] == '\'' || body[i] == '"' {
			end, ok := quotedLiteralEnd(body, i)
			if !ok {
				return nil, Error("unterminated quoted literal in macro body")
			}
			i = end
			continue
		}
		if !isIdentStart(body[i]) {
			i++
			continue
		}
		start := i
		i++
		for i < len(body) && isIdentContinue(body[i]) {
			i++
		}
		name := body[start:i]
		j := i
		for j < len(body) && unicode.IsSpace(rune(body[j])) {
			j++
		}

		if j < len(body) && body[j] == '(' {
			inner, end, ok := balanced(body, j)
			if !ok {
				return nil, Error("unterminated macro invocation " + name)
			}
			i = end
			args := SplitTopLevel(inner)
			if name == callback {
				if len(args) == 1 && args[0] == "" {
					continue
				}
				state.rows++
				if state.rows > maxExpansionRows {
					return nil, Error(fmt.Sprintf("macro expansion exceeds row limit %d", maxExpansionRows))
				}
				out = append(out, args)
				continue
			}

			sub, exists := macros[name]
			if !exists {
				// The scanner advances over callback invocations as one balanced
				// token, so calls inside an entry expression are never visited here.
				// An unknown call at this level is therefore a missing nested-list
				// macro and must fail loudly instead of truncating an SDK table.
				return nil, Error("macro " + name + " not found while expanding list")
			}
			if seen[name] {
				return nil, Error("recursive macro expansion at " + name)
			}
			if !sub.FunctionLike {
				// C expands an object-like macro even when the next token happens
				// to be '('. Treat `OBJ()` as object expansion followed by an
				// unrelated parenthesized token sequence; consuming the balanced
				// suffix is fine for this list extractor, but silently skipping OBJ
				// loses every callback row in its replacement list.
				state.steps++
				if state.steps > maxExpansionSteps {
					return nil, Error(fmt.Sprintf("macro expansion exceeds step limit %d", maxExpansionSteps))
				}
				if err := chargeExpansionBytes(state, len(sub.Body)); err != nil {
					return nil, err
				}
				seen[name] = true
				vals, err := expandBody(macros, sub.Body, callback, seen, state, depth+1)
				delete(seen, name)
				if err != nil {
					return nil, err
				}
				out = append(out, vals...)
				continue
			}
			if strings.TrimSpace(inner) == "" {
				args = nil
			}
			if len(sub.Params) != len(args) {
				// Not an invocation of this macro in the parsed form (e.g. a name
				// collision with an overloaded-looking C call). Only fail when it
				// clearly participates in the list by mentioning the callback.
				if containsIdent(inner, callback) {
					return nil, Error(fmt.Sprintf("macro %s expects %d args, got %d", name, len(sub.Params), len(args)))
				}
				continue
			}
			state.steps++
			if state.steps > maxExpansionSteps {
				return nil, Error(fmt.Sprintf("macro expansion exceeds step limit %d", maxExpansionSteps))
			}
			remaining := maxExpansionBytes - state.bytes
			instantiated, err := substituteIdentifiers(sub.Body, sub.Params, args, remaining)
			if err != nil {
				return nil, err
			}
			if err := chargeExpansionBytes(state, len(instantiated)); err != nil {
				return nil, err
			}
			seen[name] = true
			vals, err := expandBody(macros, instantiated, callback, seen, state, depth+1)
			delete(seen, name)
			if err != nil {
				return nil, err
			}
			out = append(out, vals...)
			continue
		}

		// Object-like nested list macro.
		if sub, exists := macros[name]; exists && !sub.FunctionLike {
			if seen[name] {
				return nil, Error("recursive macro expansion at " + name)
			}
			state.steps++
			if state.steps > maxExpansionSteps {
				return nil, Error(fmt.Sprintf("macro expansion exceeds step limit %d", maxExpansionSteps))
			}
			if err := chargeExpansionBytes(state, len(sub.Body)); err != nil {
				return nil, err
			}
			seen[name] = true
			vals, err := expandBody(macros, sub.Body, callback, seen, state, depth+1)
			delete(seen, name)
			if err != nil {
				return nil, err
			}
			out = append(out, vals...)
		}
	}
	return out, nil
}

func quotedLiteralEnd(s string, start int) (int, bool) {
	if start < 0 || start >= len(s) || (s[start] != '\'' && s[start] != '"') {
		return start, false
	}
	quote := s[start]
	escaped := false
	for i := start + 1; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == quote {
			return i + 1, true
		}
	}
	return len(s), false
}

// balanced returns the contents of a parenthesized expression. Quotes and
// escapes are honoured so `V(Name, "x)y")` is not truncated at the `)` inside
// the literal.
func balanced(body string, open int) (string, int, bool) {
	depth := 0
	var quote byte
	escaped := false
	for k := open; k < len(body); k++ {
		c := body[k]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		switch c {
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

// SplitTopLevel splits an argument list on commas outside (), [], {}, string
// literals and C++ template angle brackets. Angle brackets are treated as a
// template only in the common lexical form `Type<...>` (no whitespace before
// '<'), so shift/comparison expressions such as `kOne >> 1` and `a < b` do not
// corrupt the nesting depth.
func SplitTopLevel(s string) []string {
	var out []string
	paren, bracket, brace, angle := 0, 0, 0, 0
	start := 0
	var quote byte
	escaped := false
	for k := 0; k < len(s); k++ {
		c := s[k]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		switch c {
		case '(':
			paren++
		case ')':
			if paren > 0 {
				paren--
			}
		case '[':
			bracket++
		case ']':
			if bracket > 0 {
				bracket--
			}
		case '{':
			brace++
		case '}':
			if brace > 0 {
				brace--
			}
		case '<':
			if looksLikeTemplateOpen(s, k) {
				angle++
			}
		case '>':
			if angle > 0 {
				angle--
				// `>>` closes two nested templates when two are open.
				if k+1 < len(s) && s[k+1] == '>' && angle > 0 {
					angle--
					k++
				}
			}
		case ',':
			if paren == 0 && bracket == 0 && brace == 0 && angle == 0 {
				out = append(out, strings.TrimSpace(s[start:k]))
				start = k + 1
			}
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

func looksLikeTemplateOpen(s string, i int) bool {
	if i == 0 || unicode.IsSpace(rune(s[i-1])) {
		return false
	}
	prev := s[i-1]
	if !(isIdentContinue(prev) || prev == '>' || prev == ':') {
		return false
	}
	if i+1 >= len(s) || s[i+1] == '<' || s[i+1] == '=' {
		return false
	}
	// A compact comparison such as `a<b` is lexically indistinguishable from
	// a template-id if all we inspect is the '<'. Dart's C++ type/template names
	// in these X-macro tables are class-style identifiers (contain an uppercase
	// rune), namespace-qualified (`std::...`), or continue a nested template.
	// Require one of those positive signals instead of letting a lowercase
	// expression consume every comma until some unrelated later '>'.
	if prev != '>' {
		start := i - 1
		for start > 0 && (isIdentContinue(s[start-1]) || s[start-1] == ':') {
			start--
		}
		qualifier := s[start:i]
		strong := strings.Contains(qualifier, "::")
		for j := 0; !strong && j < len(qualifier); j++ {
			strong = qualifier[j] >= 'A' && qualifier[j] <= 'Z'
		}
		if !strong {
			return false
		}
	}
	return hasPlausibleTemplateClose(s, i+1)
}

// hasPlausibleTemplateClose rejects the important ambiguous case `a<b, next`:
// without a closing '>' the '<' cannot delimit a template argument list, and
// treating it as one hides the following top-level comma. When a close exists,
// require its immediate lexical continuation to look like a type/template use
// rather than the right operand of another compact comparison (`a<b,c>d`).
func hasPlausibleTemplateClose(s string, start int) bool {
	for i := start; i < len(s); i++ {
		if s[i] != '>' || (i+1 < len(s) && s[i+1] == '=') {
			continue
		}
		j := i + 1
		hadSpace := false
		for j < len(s) && unicode.IsSpace(rune(s[j])) {
			hadSpace = true
			j++
		}
		if j == len(s) {
			return true
		}
		switch s[j] {
		case ',', ')', ']', '}', ':', '*', '&', '>', '(':
			return true
		}
		if hadSpace && isIdentStart(s[j]) {
			return true
		}
		return false
	}
	return false
}

func chargeExpansionBytes(state *expansionState, n int) error {
	if n < 0 || state.bytes > maxExpansionBytes-n {
		return Error(fmt.Sprintf("macro expansion exceeds byte limit %d", maxExpansionBytes))
	}
	state.bytes += n
	return nil
}

func substituteIdentifiers(s string, params, args []string, maxBytes int) (string, error) {
	if maxBytes < 0 {
		return "", Error(fmt.Sprintf("macro expansion exceeds byte limit %d", maxExpansionBytes))
	}
	replacements := make(map[string]string, len(params))
	for i, param := range params {
		if param != "" && i < len(args) {
			replacements[param] = args[i]
		}
	}
	if len(replacements) == 0 {
		if len(s) > maxBytes {
			return "", Error(fmt.Sprintf("macro expansion exceeds byte limit %d", maxExpansionBytes))
		}
		return s, nil
	}
	var b strings.Builder
	written := 0
	write := func(part string) error {
		if len(part) > maxBytes-written {
			return Error(fmt.Sprintf("macro expansion exceeds byte limit %d", maxExpansionBytes))
		}
		b.WriteString(part)
		written += len(part)
		return nil
	}
	for i := 0; i < len(s); {
		if s[i] == '\'' || s[i] == '"' {
			start := i
			end, ok := quotedLiteralEnd(s, i)
			if !ok {
				if err := write(s[start:]); err != nil {
					return "", err
				}
				break
			}
			i = end
			if err := write(s[start:end]); err != nil {
				return "", err
			}
			continue
		}
		if isIdentStart(s[i]) {
			start := i
			i++
			for i < len(s) && isIdentContinue(s[i]) {
				i++
			}
			tok := s[start:i]
			if replacement, ok := replacements[tok]; ok {
				if err := write(replacement); err != nil {
					return "", err
				}
			} else {
				if err := write(tok); err != nil {
					return "", err
				}
			}
			continue
		}
		if written >= maxBytes {
			return "", Error(fmt.Sprintf("macro expansion exceeds byte limit %d", maxExpansionBytes))
		}
		b.WriteByte(s[i])
		written++
		i++
	}
	return b.String(), nil
}

func containsIdent(s, ident string) bool {
	for i := 0; i < len(s); {
		if !isIdentStart(s[i]) {
			i++
			continue
		}
		start := i
		i++
		for i < len(s) && isIdentContinue(s[i]) {
			i++
		}
		if s[start:i] == ident {
			return true
		}
	}
	return false
}

func stripComments(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\'' || s[i] == '"' {
			q := s[i]
			start := i
			i++
			escaped := false
			for i < len(s) {
				c := s[i]
				i++
				if escaped {
					escaped = false
					continue
				}
				if c == '\\' {
					escaped = true
					continue
				}
				if c == q {
					break
				}
			}
			b.WriteString(s[start:i])
			continue
		}
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '/' {
			b.WriteByte(' ')
			i += 2
			for i < len(s) && s[i] != '\n' {
				i++
			}
			continue
		}
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			b.WriteByte(' ')
			i += 2
			for i+1 < len(s) && !(s[i] == '*' && s[i+1] == '/') {
				i++
			}
			if i+1 < len(s) {
				i += 2
			}
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func isIdentContinue(c byte) bool {
	return isIdentStart(c) || c >= '0' && c <= '9'
}

// Error is a macro expansion failure.
type Error string

func (e Error) Error() string { return string(e) }
