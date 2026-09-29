package strutil

import (
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strings"
)

// SanitizeLibraryPath turns a Dart library URL into a safe relative file path.
func SanitizeLibraryPath(url string) string {
	url = strings.TrimPrefix(url, "package:")
	url = strings.TrimPrefix(url, "dart:")
	url = strings.TrimPrefix(url, "file:///")
	// Library URLs are snapshot-controlled input. Normalize both slash styles
	// before cleaning so a Windows build cannot interpret a backslash traversal
	// that a Unix build would treat as an ordinary character.
	url = strings.ReplaceAll(url, "\\", "/")
	url = strings.ReplaceAll(url, ":", "/")

	// Prefixing with '/' anchors path.Clean at a synthetic root. Any leading or
	// embedded '..' components therefore collapse at that root instead of
	// surviving as a relative traversal. Strip the synthetic root afterwards.
	clean := strings.TrimPrefix(pathpkg.Clean("/"+url), "/")
	if clean == "" || clean == "." {
		clean = "library"
	}
	if !strings.HasSuffix(clean, ".dart") {
		clean += ".dart"
	}

	parts := strings.Split(clean, "/")
	for i, part := range parts {
		parts[i] = SanitizeFilename(part)
		if parts[i] == "" {
			parts[i] = "_"
		}
	}
	return filepath.FromSlash(strings.Join(parts, "/"))
}

// DartReservedWords are keywords that cannot appear as a bare identifier in a
// declaration. Recovered names that collide with one are prefixed so the emitted
// Dart parses.
var DartReservedWords = map[string]bool{
	"new": true, "class": true, "return": true, "if": true, "else": true, "for": true,
	"while": true, "do": true, "switch": true, "case": true, "default": true, "break": true,
	"continue": true, "var": true, "final": true, "const": true, "void": true, "null": true,
	"true": true, "false": true, "this": true, "super": true, "is": true, "as": true,
	"in": true, "assert": true, "async": true, "await": true, "yield": true, "try": true,
	"catch": true, "finally": true, "throw": true, "rethrow": true, "with": true,
	"extends": true, "implements": true, "abstract": true, "static": true, "operator": true,
	"typedef": true, "enum": true, "mixin": true, "extension": true, "factory": true,
	"external": true, "part": true, "import": true, "export": true, "library": true,
	"deferred": true, "covariant": true, "late": true, "required": true,
}

// SanitizeDartIdent turns a recovered function/class name into a valid Dart
// identifier for a declaration: it drops the `new ` constructor-marker prefix,
// replaces every non-identifier rune with `_`, avoids a leading digit, and
// prefixes reserved words. Without this the exported .dart does not parse.
func SanitizeDartIdent(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "new ")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '_' || r == '$' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" {
		return "_anon"
	}
	if out[0] >= '0' && out[0] <= '9' {
		out = "_" + out
	}
	if DartReservedWords[out] {
		out = "_" + out
	}
	return out
}

// placeholderReDart matches a standalone honest placeholder like `<TypeArguments>` or
// `<Instance_2300>` (a value the decompiler could not resolve), but NOT a real
// generic `List<int>` (which is preceded by an identifier).
var placeholderReDart = regexp.MustCompile(`(^|[^\w])<([A-Za-z][^>]*)>`)

// mixinChainReDart matches a compacted mixin-application owner rendered by
// compactMixinOwner, e.g. `__Map & …` or `A & B & …` — a chain of `&`-joined
// tokens that CONTAINS the ellipsis. The ellipsis is what distinguishes it from a
// real bitwise-and expression (`x17 & mask`), which must be left untouched.
var mixinChainReDart = regexp.MustCompile(`[\w$]+(?:\s*&\s*[\w$\x{2026}]+)+`)

// atHashReDart matches a `@<digits>` PC-offset disambiguator suffix that recovered
// callee names carry (`method@3099033`); `@` is not valid in a Dart identifier.
var atHashReDart = regexp.MustCompile(`@\d+`)

// opMethodReplacerDart rewrites operator-method call syntax that does not parse
// (`x.[]=(...)`, `x.[](...)`) into valid (but undefined) identifier method calls,
// preserving the operation name honestly.
var opMethodReplacerDart = strings.NewReplacer(
	".[]=(", ".op_index_set(",
	".[](", ".op_index(",
	".[]=", ".op_index_set",
	".[]", ".op_index",
)

// SanitizeDartBody makes an emitted pseudocode body parse as Dart without
// changing its meaning: standalone `<X>` placeholders become a valid (but
// undefined) `unresolved_X` identifier — an honest "unknown value" that the
// analyzer flags as undefined rather than a hard syntax error — and an
// empty named-constructor call `Name.(` becomes `Name(`.
func SanitizeDartBody(body string) string {
	var out strings.Builder
	out.Grow(len(body))
	codeStart := 0
	flushCode := func(end int) {
		if codeStart < end {
			out.WriteString(sanitizeDartCode(body[codeStart:end]))
		}
	}

	for i := 0; i < len(body); {
		if body[i] == '/' && i+1 < len(body) && body[i+1] == '/' {
			flushCode(i)
			end := strings.IndexByte(body[i+2:], '\n')
			if end < 0 {
				out.WriteString(body[i:])
				return out.String()
			}
			end += i + 2
			out.WriteString(body[i:end])
			i = end
			codeStart = i
			continue
		}

		if body[i] == '/' && i+1 < len(body) && body[i+1] == '*' {
			flushCode(i)
			endRel := strings.Index(body[i+2:], "*/")
			if endRel < 0 {
				out.WriteString(body[i:])
				return out.String()
			}
			end := i + 2 + endRel + 2
			comment := body[i:end]
			if comment == "/* cond */" {
				out.WriteString("unresolved_cond")
			} else {
				out.WriteString(comment)
			}
			i = end
			codeStart = i
			continue
		}

		if isDartQuote(body[i]) {
			flushCode(i)
			end := dartStringEnd(body, i, false)
			out.WriteString(body[i:end])
			i = end
			codeStart = i
			continue
		}
		if (body[i] == 'r' || body[i] == 'R') && i+1 < len(body) && isDartQuote(body[i+1]) && dartRawPrefixBoundary(body, i) {
			flushCode(i)
			end := dartStringEnd(body, i+1, true)
			out.WriteString(body[i:end])
			i = end
			codeStart = i
			continue
		}
		i++
	}
	flushCode(len(body))
	return out.String()
}

func sanitizeDartCode(body string) string {
	body = placeholderReDart.ReplaceAllStringFunc(body, func(m string) string {
		sub := placeholderReDart.FindStringSubmatch(m)
		prefix, inner := sub[1], sub[2]
		var b strings.Builder
		b.WriteString(prefix)
		b.WriteString("unresolved_")
		for _, r := range inner {
			switch {
			case r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
				b.WriteRune(r)
			default:
				b.WriteRune('_')
			}
		}
		return b.String()
	})
	// Collapse a compacted mixin owner to its base class (the first token), but
	// only when the ellipsis marks it as a mixin chain — never a bitwise `&`.
	body = mixinChainReDart.ReplaceAllStringFunc(body, func(m string) string {
		if !strings.Contains(m, "…") {
			return m // real bitwise expression, leave it
		}
		base := m
		if i := strings.IndexByte(m, '&'); i >= 0 {
			base = strings.TrimSpace(m[:i])
		}
		return base
	})
	body = opMethodReplacerDart.Replace(body)
	body = atHashReDart.ReplaceAllString(body, "")
	body = strings.ReplaceAll(body, ".(", "(")
	return body
}

func isDartQuote(b byte) bool { return b == '\'' || b == '"' }

func dartRawPrefixBoundary(body string, i int) bool {
	if i == 0 {
		return true
	}
	prev := body[i-1]
	return !((prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') ||
		(prev >= '0' && prev <= '9') || prev == '_' || prev == '$')
}

// dartStringEnd returns the byte just after a Dart single-, double-, or
// triple-quoted string. Unterminated strings consume the remainder so malformed
// pseudocode is preserved instead of treating literal data as code.
func dartStringEnd(body string, quoteStart int, raw bool) int {
	quote := body[quoteStart]
	delimLen := 1
	if quoteStart+2 < len(body) && body[quoteStart+1] == quote && body[quoteStart+2] == quote {
		delimLen = 3
	}
	for i := quoteStart + delimLen; i < len(body); {
		if !raw && body[i] == '\\' {
			if i+1 < len(body) {
				i += 2
				continue
			}
			return len(body)
		}
		if body[i] == quote {
			if delimLen == 1 {
				return i + 1
			}
			if i+2 < len(body) && body[i+1] == quote && body[i+2] == quote {
				return i + 3
			}
		}
		i++
	}
	return len(body)
}
