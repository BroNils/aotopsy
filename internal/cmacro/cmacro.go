// Package cmacro expands the C/C++ preprocessor X-macro lists used by the
// Dart SDK to declare VM tables mirrored by aotopsy.
package cmacro

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var macroDefRe = regexp.MustCompile(`^[\t ]*#[\t ]*define[\t ]+([A-Za-z_]\w*)(.*)$`)
var defineDirectiveRe = regexp.MustCompile(`^[\t ]*#[\t ]*define(?:[\t ]|$)`)
var undefDirectiveRe = regexp.MustCompile(`^[\t ]*#[\t ]*undef(?:[\t ]|$)`)
var macroUndefRe = regexp.MustCompile(`^[\t ]*#[\t ]*undef[\t ]+([A-Za-z_]\w*)[\t ]*$`)
var conditionalDirectiveRe = regexp.MustCompile(`^[\t ]*#[\t ]*(if|ifdef|ifndef|elif|else|endif)(?:[\t ]|$)`)

const (
	maxSourceBytes    = 8 << 20
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
	Params            []string
	Body              string
	FunctionLike      bool
	Ambiguous         bool
	UnsupportedParams bool
}

// Macros is the parsed macro table keyed by definition name.
type Macros map[string]Macro

// ParseMacros returns every #define body in a C/C++ header. Line
// continuations are joined and comments are removed without treating comment
// markers inside string/character literals as comments. This is intentionally a
// definition catalog rather than a full preprocessor: conditional directives
// and #undef do not select an active branch. Identical redefinitions are safe;
// different redefinitions are recorded as ambiguous and fail if a caller tries
// to expand that name without preprocessing context.
func ParseMacros(src string) (Macros, error) {
	if len(src) > maxSourceBytes {
		return nil, Error(fmt.Sprintf("macro source exceeds byte limit %d", maxSourceBytes))
	}
	src = strings.ReplaceAll(src, "\\\r\n", "")
	src = strings.ReplaceAll(src, "\\\n", "")
	var err error
	src, err = stripComments(src)
	if err != nil {
		return nil, err
	}
	out := Macros{}
	type conditionalFrame struct {
		id     int
		branch int
	}
	var conditionalStack []conditionalFrame
	nextConditionalID := 0
	contextKey := func() string {
		if len(conditionalStack) == 0 {
			return ""
		}
		var b strings.Builder
		for _, f := range conditionalStack {
			fmt.Fprintf(&b, "%d:%d/", f.id, f.branch)
		}
		return b.String()
	}
	lastDefinitionContext := map[string]string{}
	lastUndefContext := map[string]string{}
	for lineNo, line := range strings.Split(src, "\n") {
		if m := conditionalDirectiveRe.FindStringSubmatch(line); m != nil {
			switch m[1] {
			case "if", "ifdef", "ifndef":
				nextConditionalID++
				conditionalStack = append(conditionalStack, conditionalFrame{id: nextConditionalID})
			case "elif", "else":
				if len(conditionalStack) == 0 {
					return nil, Error(fmt.Sprintf("unmatched #%s at line %d", m[1], lineNo+1))
				}
				conditionalStack[len(conditionalStack)-1].branch++
			case "endif":
				if len(conditionalStack) == 0 {
					return nil, Error(fmt.Sprintf("unmatched #endif at line %d", lineNo+1))
				}
				conditionalStack = conditionalStack[:len(conditionalStack)-1]
			}
			continue
		}
		if undefDirectiveRe.MatchString(line) {
			m := macroUndefRe.FindStringSubmatch(line)
			if m == nil {
				return nil, Error(fmt.Sprintf("malformed #undef at line %d", lineNo+1))
			}
			lastUndefContext[m[1]] = contextKey()
			continue
		}
		if !defineDirectiveRe.MatchString(line) {
			continue
		}
		m := macroDefRe.FindStringSubmatch(line)
		if m == nil {
			return nil, Error(fmt.Sprintf("malformed #define at line %d", lineNo+1))
		}
		name, rest := m[1], m[2]
		functionLike := strings.HasPrefix(rest, "(")
		body := rest
		var params []string
		unsupportedParams := false
		if functionLike {
			close := strings.IndexByte(rest, ')')
			if close < 0 {
				return nil, Error(fmt.Sprintf("unterminated formal parameter list for macro %s at line %d", name, lineNo+1))
			}
			inside := strings.TrimSpace(rest[1:close])
			body = rest[close+1:]
			if inside != "" {
				seenParam := map[string]bool{}
				for _, raw := range strings.Split(inside, ",") {
					p := strings.TrimSpace(raw)
					if p == "" || !validMacroParam(p) || seenParam[p] {
						unsupportedParams = true
					}
					if p != "" {
						params = append(params, p)
						seenParam[p] = true
					}
				}
			}
		}
		next := Macro{
			Params:            params,
			Body:              body,
			FunctionLike:      functionLike,
			UnsupportedParams: unsupportedParams,
		}
		ctx := contextKey()
		if prev, exists := out[name]; exists {
			resetByUndef := lastUndefContext[name] == ctx && lastDefinitionContext[name] == ctx
			if !resetByUndef {
				next.Ambiguous = prev.Ambiguous || !sameMacroDefinition(prev, next)
			}
		}
		out[name] = next
		lastDefinitionContext[name] = ctx
		delete(lastUndefContext, name)
	}
	if len(conditionalStack) != 0 {
		return nil, Error(fmt.Sprintf("unterminated conditional directive depth %d", len(conditionalStack)))
	}
	return out, nil
}

// ExpandRaw expands one list macro recursively and returns every entry's
// top-level arguments. The list callback is the root macro's first formal
// parameter (V/F/X/etc.); object-like lists default to the conventional V.
func ExpandRaw(macros Macros, name string) ([][]string, error) {
	m, err := expansionMacro(macros, name)
	if err != nil {
		return nil, err
	}
	callback := "V"
	if len(m.Params) > 0 {
		callback = m.Params[0]
	}
	callbacks := map[string]bool{callback: true}
	state := &expansionState{}
	if err := chargeExpansionBytes(state, len(m.Body)); err != nil {
		return nil, err
	}
	var out [][]string
	if err := expandBody(macros, m.Body, callbacks, map[string]bool{name: true}, state, 0, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ExpandRawAllCallbacks expands a list whose root macro has more than one row
// callback formal. Calls to any root formal are returned in exact source order.
// This matches Dart's OBJECT_STORE_FIELD_LIST shape, where R_, RW, ARW_* and
// LAZY_* are all field-row callbacks.
func ExpandRawAllCallbacks(macros Macros, name string) ([][]string, error) {
	m, err := expansionMacro(macros, name)
	if err != nil {
		return nil, err
	}
	if len(m.Params) == 0 {
		return nil, Error("macro " + name + " has no callback formals")
	}
	callbacks := make(map[string]bool, len(m.Params))
	for _, p := range m.Params {
		callbacks[p] = true
	}
	state := &expansionState{}
	if err := chargeExpansionBytes(state, len(m.Body)); err != nil {
		return nil, err
	}
	var out [][]string
	if err := expandBody(macros, m.Body, callbacks, map[string]bool{name: true}, state, 0, &out); err != nil {
		return nil, err
	}
	return out, nil
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
// callbacks contains the row callback identifiers visible in this expansion.
// All recursion appends into one accumulator so a deep nested-list chain does
// not repeatedly copy the complete row set on its way back to the root.
func expandBody(macros Macros, body string, callbacks map[string]bool, seen map[string]bool, state *expansionState, depth int, out *[][]string) error {
	if depth > maxExpansionDepth {
		return Error(fmt.Sprintf("macro expansion exceeds depth limit %d", maxExpansionDepth))
	}
	for i := 0; i < len(body); {
		if body[i] == '\'' || body[i] == '"' {
			end, ok := quotedLiteralEnd(body, i)
			if !ok {
				return Error("unterminated quoted literal in macro body")
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
				return Error("unterminated macro invocation " + name)
			}
			i = end
			args, err := SplitTopLevel(inner)
			if err != nil {
				return Error(fmt.Sprintf("malformed arguments to %s: %v", name, err))
			}
			if callbacks[name] {
				if len(args) == 1 && args[0] == "" {
					return Error("empty callback row for " + name)
				}
				state.rows++
				if state.rows > maxExpansionRows {
					return Error(fmt.Sprintf("macro expansion exceeds row limit %d", maxExpansionRows))
				}
				*out = append(*out, args)
				continue
			}

			sub, exists := macros[name]
			if !exists {
				// The scanner advances over callback invocations as one balanced
				// token, so calls inside an entry expression are never visited here.
				// An unknown call at this level is therefore a missing nested-list
				// macro and must fail loudly instead of truncating an SDK table.
				return Error("macro " + name + " not found while expanding list")
			}
			if seen[name] {
				return Error("recursive macro expansion at " + name)
			}
			if err := validateExpansionMacro(name, sub); err != nil {
				return err
			}
			if !sub.FunctionLike {
				// C expands an object-like macro even when the next token happens
				// to be '('. Treat `OBJ()` as object expansion followed by an
				// unrelated parenthesized token sequence; consuming the balanced
				// suffix is fine for this list extractor, but silently skipping OBJ
				// loses every callback row in its replacement list.
				state.steps++
				if state.steps > maxExpansionSteps {
					return Error(fmt.Sprintf("macro expansion exceeds step limit %d", maxExpansionSteps))
				}
				if err := chargeExpansionBytes(state, len(sub.Body)); err != nil {
					return err
				}
				seen[name] = true
				err := expandBody(macros, sub.Body, callbacks, seen, state, depth+1, out)
				delete(seen, name)
				if err != nil {
					return err
				}
				continue
			}
			if strings.TrimSpace(inner) == "" {
				args = nil
			}
			if len(sub.Params) != len(args) {
				// Not an invocation of this macro in the parsed form (e.g. a name
				// collision with an overloaded-looking C call). Only fail when it
				// clearly participates in the list by mentioning the callback.
				if containsAnyIdent(inner, callbacks) {
					return Error(fmt.Sprintf("macro %s expects %d args, got %d", name, len(sub.Params), len(args)))
				}
				continue
			}
			state.steps++
			if state.steps > maxExpansionSteps {
				return Error(fmt.Sprintf("macro expansion exceeds step limit %d", maxExpansionSteps))
			}
			remaining := maxExpansionBytes - state.bytes
			instantiated, err := substituteIdentifiers(sub.Body, sub.Params, args, remaining)
			if err != nil {
				return err
			}
			if err := chargeExpansionBytes(state, len(instantiated)); err != nil {
				return err
			}
			seen[name] = true
			err = expandBody(macros, instantiated, callbacks, seen, state, depth+1, out)
			delete(seen, name)
			if err != nil {
				return err
			}
			continue
		}

		// Object-like nested list macro.
		if sub, exists := macros[name]; exists && !sub.FunctionLike {
			if err := validateExpansionMacro(name, sub); err != nil {
				return err
			}
			if seen[name] {
				return Error("recursive macro expansion at " + name)
			}
			state.steps++
			if state.steps > maxExpansionSteps {
				return Error(fmt.Sprintf("macro expansion exceeds step limit %d", maxExpansionSteps))
			}
			if err := chargeExpansionBytes(state, len(sub.Body)); err != nil {
				return err
			}
			seen[name] = true
			err := expandBody(macros, sub.Body, callbacks, seen, state, depth+1, out)
			delete(seen, name)
			if err != nil {
				return err
			}
		}
	}
	return nil
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
// corrupt the nesting depth. Unbalanced delimiters fail loudly instead of
// returning a plausible shorter row.
func SplitTopLevel(s string) ([]string, error) {
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
			if paren == 0 {
				return nil, Error("unmatched ')' in macro arguments")
			}
			paren--
		case '[':
			bracket++
		case ']':
			if bracket == 0 {
				return nil, Error("unmatched ']' in macro arguments")
			}
			bracket--
		case '{':
			brace++
		case '}':
			if brace == 0 {
				return nil, Error("unmatched '}' in macro arguments")
			}
			brace--
		case '<':
			if looksLikeTemplateOpen(s, k) {
				angle++
			} else if looksLikeTemplatePrefix(s, k) && !hasPlausibleTemplateClose(s, k+1) {
				return nil, Error("unterminated C++ template argument list")
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
	if quote != 0 {
		return nil, Error("unterminated quoted literal in macro arguments")
	}
	if paren != 0 || bracket != 0 || brace != 0 || angle != 0 {
		return nil, Error(fmt.Sprintf("unbalanced macro arguments: paren=%d bracket=%d brace=%d angle=%d", paren, bracket, brace, angle))
	}
	return append(out, strings.TrimSpace(s[start:])), nil
}

func looksLikeTemplateOpen(s string, i int) bool {
	return looksLikeTemplatePrefix(s, i) && hasPlausibleTemplateClose(s, i+1)
}

func looksLikeTemplatePrefix(s string, i int) bool {
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
	return true
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

func containsAnyIdent(s string, idents map[string]bool) bool {
	for ident := range idents {
		if containsIdent(s, ident) {
			return true
		}
	}
	return false
}

func stripComments(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\'' || s[i] == '"' {
			q := s[i]
			start := i
			i++
			escaped := false
			closed := false
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
					closed = true
					break
				}
			}
			if !closed {
				return "", Error("unterminated quoted literal in macro source")
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
			closed := false
			for i < len(s) {
				if i+1 < len(s) && s[i] == '*' && s[i+1] == '/' {
					i += 2
					closed = true
					break
				}
				// C preprocessing replaces a block comment with whitespace while
				// preserving physical newlines. Keeping them also prevents a
				// following #define from being merged into the previous line.
				if s[i] == '\n' {
					b.WriteByte('\n')
				}
				i++
			}
			if !closed {
				return "", Error("unterminated block comment in macro source")
			}
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String(), nil
}

func validMacroParam(p string) bool {
	if p == "" || !isIdentStart(p[0]) {
		return false
	}
	for i := 1; i < len(p); i++ {
		if !isIdentContinue(p[i]) {
			return false
		}
	}
	return true
}

func sameMacroDefinition(a, b Macro) bool {
	if a.Body != b.Body || a.FunctionLike != b.FunctionLike ||
		a.UnsupportedParams != b.UnsupportedParams || len(a.Params) != len(b.Params) {
		return false
	}
	for i := range a.Params {
		if a.Params[i] != b.Params[i] {
			return false
		}
	}
	return true
}

func expansionMacro(macros Macros, name string) (Macro, error) {
	m, ok := macros[name]
	if !ok {
		return Macro{}, Error("macro " + name + " not found")
	}
	if err := validateExpansionMacro(name, m); err != nil {
		return Macro{}, err
	}
	return m, nil
}

func validateExpansionMacro(name string, m Macro) error {
	if m.Ambiguous {
		return Error("macro " + name + " has multiple different definitions; conditional preprocessing context is required")
	}
	if m.UnsupportedParams {
		return Error("macro " + name + " has unsupported formal parameters")
	}
	return nil
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
