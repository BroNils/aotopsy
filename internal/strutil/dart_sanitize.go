package strutil

import (
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strings"
)

// SanitizeLibraryPath turns a Dart library URL into a safe relative file path.
func SanitizeLibraryPath(url string) string {
	rawURL := url
	// Library URLs are snapshot-controlled input. Normalize both slash styles
	// before cleaning so a Windows build cannot interpret a backslash traversal
	// that a Unix build would treat as an ordinary character.
	url = strings.ReplaceAll(url, "\\", "/")

	// Keep the URL scheme as part of the artifact identity. The old code stripped
	// package:/dart:/file:/// before sanitizing, so `dart:core` and
	// `package:core` both became core.dart. Clean the remainder under the scheme
	// namespace so `package:../../x` cannot escape into the unschemed namespace.
	scheme := ""
	if colon := strings.IndexByte(url, ':'); colon > 0 && isLibraryURLScheme(url[:colon]) {
		scheme = strings.ToLower(url[:colon])
		url = strings.TrimLeft(url[colon+1:], "/")
	} else {
		url = strings.ReplaceAll(url, ":", "/")
	}

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
	}
	if scheme != "" {
		parts = append([]string{SanitizeFilename(scheme)}, parts...)
	}
	// path.Clean intentionally removes traversal/dot components. Bind the leaf
	// artifact to the complete raw URL as well, so two distinct recovered URLs
	// cannot overwrite each other merely because normalization reaches the same
	// cleaned path (for example package:a/../b.dart vs package:b.dart).
	parts[len(parts)-1] = addFilenameIdentitySuffix(parts[len(parts)-1], rawURL)
	return filepath.FromSlash(strings.Join(parts, "/"))
}

func isLibraryURLScheme(s string) bool {
	if s == "" || !((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z')) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// dartKeywords is the union of the frontend scanner's Keyword declarations for
// every exact Dart release supported by this repository. The exact local SDK
// census is 69 entries in 2.10.0-2.16.0, +augment in 2.17.6, +when in 2.19.0,
// and +base/+sealed in 3.0.5, with no later removals through 3.13.0.
//
// Source of truth: pkg/_fe_analyzer_shared/lib/src/scanner/token.dart at each
// supported exact release. We conservatively avoid every reserved, built-in and
// pseudo keyword because this helper emits identifiers into several declaration
// contexts where those contextual distinctions differ.
var dartKeywords = map[string]struct{}{
	"abstract": {}, "as": {}, "assert": {}, "async": {}, "augment": {}, "await": {},
	"base": {}, "break": {}, "case": {}, "catch": {}, "class": {}, "const": {},
	"continue": {}, "covariant": {}, "default": {}, "deferred": {}, "do": {},
	"dynamic": {}, "else": {}, "enum": {}, "export": {}, "extends": {}, "extension": {},
	"external": {}, "factory": {}, "false": {}, "final": {}, "finally": {}, "for": {},
	"Function": {}, "get": {}, "hide": {}, "if": {}, "implements": {}, "import": {},
	"in": {}, "inout": {}, "interface": {}, "is": {}, "late": {}, "library": {},
	"mixin": {}, "native": {}, "new": {}, "null": {}, "of": {}, "on": {},
	"operator": {}, "out": {}, "part": {}, "patch": {}, "required": {}, "rethrow": {},
	"return": {}, "sealed": {}, "set": {}, "show": {}, "source": {}, "static": {},
	"super": {}, "switch": {}, "sync": {}, "this": {}, "throw": {}, "true": {},
	"try": {}, "typedef": {}, "var": {}, "void": {}, "when": {}, "while": {},
	"with": {}, "yield": {},
}

// SanitizeDartIdent turns a recovered function/class name into a valid Dart
// identifier for a declaration. Exact frontend scanner source at Dart 2.10.0
// and 3.13.0 accepts only ASCII [A-Za-z0-9_$] identifier characters; the same
// predicate was checked across the supported range. This helper therefore does
// not invent Unicode identifier support the Dart scanner does not have.
//
// Any lossy rewrite gets a stable raw-name hash suffix, so distinct semantic
// names such as `a-b` and `a_b`, or keyword `class` and raw `_class`, cannot
// collapse to the same emitted declaration.
func SanitizeDartIdent(s string) string {
	raw := s
	changed := hasGeneratedIdentitySuffix(raw)
	trimmed := strings.TrimSpace(s)
	if trimmed != s {
		changed = true
	}
	s = trimmed
	if strings.HasPrefix(s, "new ") {
		s = strings.TrimPrefix(s, "new ")
		changed = true
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '_' || r == '$' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		default:
			b.WriteRune('_')
			changed = true
		}
	}
	out := b.String()
	if out == "" {
		out = "_anon"
		changed = true
	}
	if out[0] >= '0' && out[0] <= '9' {
		out = "_" + out
		changed = true
	}
	if _, keyword := dartKeywords[out]; keyword {
		out = "_" + out
		changed = true
	}
	if changed {
		out += "_" + shortIdentityHash(raw)
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
		return prefix + "unresolved_" + SanitizeDartIdent(inner)
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
	// VM private-name mangling is a library-scoped identity suffix, not a PC
	// offset. Source-level rendering removes it exactly as String::ScrubName does:
	// only '@' immediately followed by one or more decimal digits is stripped.
	body = ScrubDartPrivateKeys(body)
	body = strings.ReplaceAll(body, ".(", "(")
	return body
}

// ScrubDartPrivateKeys removes Dart VM private-library key suffixes while
// leaving every other '@' untouched. This is the private-key portion of
// String::ScrubName, verified in exact local SDK runtime/vm/object.cc at both
// 2.10.0 and 3.13.0: an '@' is mangling only when the next byte is a decimal
// digit, and all following decimal digits are skipped. Multiple keys in one
// generated name are removed independently.
func ScrubDartPrivateKeys(name string) string {
	first := -1
	for i := 0; i+1 < len(name); i++ {
		if name[i] == '@' && name[i+1] >= '0' && name[i+1] <= '9' {
			first = i
			break
		}
	}
	if first < 0 {
		return name
	}
	var b strings.Builder
	b.Grow(len(name))
	b.WriteString(name[:first])
	for i := first; i < len(name); {
		if name[i] == '@' && i+1 < len(name) && name[i+1] >= '0' && name[i+1] <= '9' {
			i += 2
			for i < len(name) && name[i] >= '0' && name[i] <= '9' {
				i++
			}
			continue
		}
		b.WriteByte(name[i])
		i++
	}
	return b.String()
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
