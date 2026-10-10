package stmt

import (
	"regexp"
	"strings"
	"sync"
)

// IsIdentChar reports whether c is an identifier character.
func IsIdentChar(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// identRegexCache caches compiled regexes for ReplaceIdent, keyed by the
// identifier being replaced. regex.MustCompile is too expensive to call
// per-line per-rename inside nested loops.
var identRegexCache sync.Map

// ReplaceIdent replaces whole-word identifiers in Dart code, including live
// interpolation expressions inside strings, while preserving literal string
// data. A complex replacement for `$ident` is upgraded to `${expr}` so the
// replacement remains one interpolation expression.
func ReplaceIdent(line, old, new string) string {
	var re *regexp.Regexp
	if cached, ok := identRegexCache.Load(old); ok {
		re = cached.(*regexp.Regexp)
	} else {
		re = regexp.MustCompile(`\b` + regexp.QuoteMeta(old) + `\b`)
		identRegexCache.Store(old, re)
	}
	return rewriteDartCode(line, func(code string) string {
		return re.ReplaceAllString(code, new)
	})
}

// SimpleAssignRe matches a whole-line simple assignment `name = expr;`.
var SimpleAssignRe = regexp.MustCompile(`^(\w+)\s*=\s*(.+);$`)

// HasSideEffect reports whether an assignment's right-hand side may do more
// than compute a value. Anything containing a call (`(`) or an assignment is
// treated as effectful, so its store is never eliminated.
func HasSideEffect(expr string) bool {
	return strings.ContainsAny(expr, "()") || strings.Contains(expr, "=")
}

// ReferencesIdent reports whether expr mentions ident as a whole word.
func ReferencesIdent(expr, ident string) bool {
	var re *regexp.Regexp
	if cached, ok := identRegexCache.Load(ident); ok {
		re = cached.(*regexp.Regexp)
	} else {
		re = regexp.MustCompile(`\b` + regexp.QuoteMeta(ident) + `\b`)
		identRegexCache.Store(ident, re)
	}
	return re.MatchString(CodeOutsideStrings(expr))
}

// AnyAssignRe matches any assignment target at the start of a statement,
// including `final x = ...` declarations, for any identifier (not just tN).
var AnyAssignRe = regexp.MustCompile(`^(?:final\s+)?([A-Za-z_]\w*)\s*=[^=]`)

// ReplaceExactSubstring replaces old with new in s, but only when old appears
// as a complete token (not part of a larger identifier).
func ReplaceExactSubstring(s, old, new string) string {
	idx := 0
	for {
		if idx >= len(s) {
			break
		}
		pos := strings.Index(s[idx:], old)
		if pos < 0 {
			break
		}
		absPos := idx + pos
		// If a quote starts before this candidate, skip that literal verbatim.
		// CSE expressions are code; matching the same bytes inside a Dart string
		// literal must never rewrite the literal's data.
		if q := strings.IndexAny(s[idx:absPos], "\"'"); q >= 0 {
			idx = skipQuotedLiteral(s, idx+q)
			continue
		}
		// Check character before
		if absPos > 0 {
			c := s[absPos-1]
			if IsIdentChar(c) || c == '.' {
				idx = absPos + len(old)
				continue
			}
		}
		// Check character after
		afterPos := absPos + len(old)
		if afterPos < len(s) {
			c := s[afterPos]
			if IsIdentChar(c) || c == '.' {
				idx = afterPos
				continue
			}
		}
		// Replace
		s = s[:absPos] + new + s[afterPos:]
		idx = absPos + len(new)
	}
	return s
}

// CodeOutsideStrings returns the executable code portions of a Dart source
// line. Literal string data and trailing comments are omitted, but `$ident`
// and `${expr}` interpolation code is retained.
func CodeOutsideStrings(s string) string {
	var b strings.Builder
	codeStart := 0
	for i := 0; i < len(s); {
		if s[i] == '\'' || s[i] == '"' {
			b.WriteString(s[codeStart:i])
			i = appendInterpolationCode(&b, s, i)
			b.WriteByte(' ')
			codeStart = i
			continue
		}
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '/' {
			b.WriteString(s[codeStart:i])
			break
		}
		i++
		if i == len(s) {
			b.WriteString(s[codeStart:])
		}
	}
	return b.String()
}

func rewriteDartCode(s string, rewrite func(string) string) string {
	var b strings.Builder
	codeStart := 0
	for i := 0; i < len(s); {
		if s[i] == '\'' || s[i] == '"' {
			b.WriteString(rewrite(s[codeStart:i]))
			i = rewriteQuotedDartString(&b, s, i, rewrite)
			codeStart = i
			continue
		}
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '/' {
			b.WriteString(rewrite(s[codeStart:i]))
			b.WriteString(s[i:])
			return b.String()
		}
		i++
	}
	if codeStart < len(s) {
		b.WriteString(rewrite(s[codeStart:]))
	}
	return b.String()
}

func rewriteQuotedDartString(b *strings.Builder, s string, start int, rewrite func(string) string) int {
	quote := s[start]
	b.WriteByte(quote)
	literalStart := start + 1
	for i := literalStart; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if s[i] == quote {
			b.WriteString(s[literalStart:i])
			b.WriteByte(quote)
			return i + 1
		}
		if s[i] == '$' && i+1 < len(s) {
			if s[i+1] == '{' {
				if end := interpolationBraceEnd(s, i+2); end >= 0 {
					b.WriteString(s[literalStart : i+2])
					b.WriteString(rewriteDartCode(s[i+2:end], rewrite))
					b.WriteByte('}')
					i = end + 1
					literalStart = i
					continue
				}
			} else if isIdentStart(s[i+1]) {
				j := i + 2
				for j < len(s) && IsIdentChar(s[j]) {
					j++
				}
				ident := s[i+1 : j]
				rewritten := rewrite(ident)
				b.WriteString(s[literalStart:i])
				if rewritten == ident || isSimpleDartIdent(rewritten) {
					b.WriteByte('$')
					b.WriteString(rewritten)
				} else {
					b.WriteString("${")
					b.WriteString(rewritten)
					b.WriteByte('}')
				}
				i = j
				literalStart = i
				continue
			}
		}
		i++
	}
	b.WriteString(s[literalStart:])
	return len(s)
}

func appendInterpolationCode(b *strings.Builder, s string, start int) int {
	quote := s[start]
	for i := start + 1; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if s[i] == quote {
			return i + 1
		}
		if s[i] == '$' && i+1 < len(s) {
			if s[i+1] == '{' {
				if end := interpolationBraceEnd(s, i+2); end >= 0 {
					b.WriteByte(' ')
					b.WriteString(CodeOutsideStrings(s[i+2 : end]))
					b.WriteByte(' ')
					i = end + 1
					continue
				}
			} else if isIdentStart(s[i+1]) {
				j := i + 2
				for j < len(s) && IsIdentChar(s[j]) {
					j++
				}
				b.WriteByte(' ')
				b.WriteString(s[i+1 : j])
				b.WriteByte(' ')
				i = j
				continue
			}
		}
		i++
	}
	return len(s)
}

func interpolationBraceEnd(s string, start int) int {
	depth := 1
	for i := start; i < len(s); i++ {
		if s[i] == '\'' || s[i] == '"' {
			i = skipQuotedLiteral(s, i) - 1
			continue
		}
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isSimpleDartIdent(s string) bool {
	if s == "" || !isIdentStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !IsIdentChar(s[i]) {
			return false
		}
	}
	return true
}

func skipQuotedLiteral(s string, start int) int {
	if start >= len(s) || (s[start] != '\'' && s[start] != '"') {
		return start
	}
	quote := s[start]
	for i := start + 1; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			continue
		}
		if s[i] == quote {
			return i + 1
		}
	}
	return len(s)
}

// replaceRegexpMatchesOutsideStrings applies rewrite only to matches that
// begin in code. The match itself may contain quoted arguments (for example
// _interpolate(["hello", name])), so splitting the line into quote-free
// segments before running the regexp would incorrectly hide legitimate calls.
func replaceRegexpMatchesOutsideStrings(text string, re *regexp.Regexp, rewrite func(string) string) string {
	var b strings.Builder
	pos := 0
	for pos < len(text) {
		loc := re.FindStringIndex(text[pos:])
		if loc == nil {
			b.WriteString(text[pos:])
			break
		}
		start, end := pos+loc[0], pos+loc[1]
		b.WriteString(text[pos:start])
		if end == start {
			// An empty match would leave pos where it was and loop forever.
			// Copy one byte through unchanged and move on.
			if start < len(text) {
				b.WriteByte(text[start])
			}
			pos = start + 1
			continue
		}
		match := text[start:end]
		if isCodePosition(text, start) {
			b.WriteString(rewrite(match))
		} else {
			b.WriteString(match)
		}
		pos = end
	}
	return b.String()
}

func isCodePosition(s string, pos int) bool {
	for i := 0; i < len(s) && i < pos; {
		if s[i] == '\'' || s[i] == '"' {
			end := skipQuotedLiteral(s, i)
			if pos < end {
				return false
			}
			i = end
			continue
		}
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '/' {
			return false
		}
		i++
	}
	return true
}

// ExtractIterVarFromCond extracts the iterator variable name from a condition
// like "local_8 < 10" or "local_m8 != arg0".
func ExtractIterVarFromCond(cond string) string {
	for _, op := range []string{" < ", " <= ", " != ", " > ", " >= ", " == "} {
		idx := strings.Index(cond, op)
		if idx > 0 {
			left := strings.TrimSpace(cond[:idx])
			if strings.HasPrefix(left, "local_") {
				return left
			}
		}
	}
	return ""
}
