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

// ReplaceIdent replaces whole-word identifiers, not substrings.
// It skips matches inside string literals (between unescaped quotes) to avoid
// corrupting string constants like print("arg0").
func ReplaceIdent(line, old, new string) string {
	var re *regexp.Regexp
	if cached, ok := identRegexCache.Load(old); ok {
		re = cached.(*regexp.Regexp)
	} else {
		re = regexp.MustCompile(`\b` + regexp.QuoteMeta(old) + `\b`)
		identRegexCache.Store(old, re)
	}
	// Split on string literals, only replace in non-literal segments.
	// Handles both "..." and '...' quoting.
	var result strings.Builder
	i := 0
	for i < len(line) {
		// Find next quote.
		quoteIdx := strings.IndexAny(line[i:], "\"'")
		if quoteIdx < 0 {
			// No more strings — replace in the rest.
			result.WriteString(re.ReplaceAllString(line[i:], new))
			break
		}
		quotePos := i + quoteIdx
		quote := line[quotePos]
		// Replace in the segment before the quote.
		result.WriteString(re.ReplaceAllString(line[i:quotePos], new))
		// Copy the string literal verbatim (including the closing quote).
		result.WriteByte(quote)
		j := quotePos + 1
		for j < len(line) {
			if line[j] == '\\' && j+1 < len(line) {
				// Escaped char — copy both bytes.
				result.WriteByte(line[j])
				result.WriteByte(line[j+1])
				j += 2
				continue
			}
			if line[j] == quote {
				result.WriteByte(line[j])
				j++
				break
			}
			result.WriteByte(line[j])
			j++
		}
		i = j
	}
	return result.String()
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
	return re.MatchString(expr)
}

// AnyAssignRe matches any assignment target at the start of a statement,
// including `final x = ...` declarations, for any identifier (not just tN).
var AnyAssignRe = regexp.MustCompile(`^(?:final\s+)?([A-Za-z_]\w*)\s*=[^=]`)

// ReplaceExactSubstring replaces old with new in s, but only when old appears
// as a complete token (not part of a larger identifier).
func ReplaceExactSubstring(s, old, new string) string {
	idx := 0
	for {
		pos := strings.Index(s[idx:], old)
		if pos < 0 {
			break
		}
		absPos := idx + pos
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
