package strutil

import (
	"path/filepath"
	"regexp"
	"strings"
)

// SanitizeLibraryPath turns a Dart library URL into a safe relative file path.
func SanitizeLibraryPath(url string) string {
	url = strings.TrimPrefix(url, "package:")
	url = strings.TrimPrefix(url, "dart:")
	url = strings.TrimPrefix(url, "file:///")
	url = strings.ReplaceAll(url, ":", "/")

	if !strings.HasSuffix(url, ".dart") {
		url += ".dart"
	}
	return filepath.Clean(url)
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
	// An unrecoverable branch condition is rendered `/* cond */` (a comment, not an
	// expression). Make it a valid, honestly-undefined identifier so the `if`
	// parses; the semantics stay "unknown", not fabricated.
	body = strings.ReplaceAll(body, "/* cond */", "unresolved_cond")
	body = atHashReDart.ReplaceAllString(body, "")
	body = strings.ReplaceAll(body, ".(", "(")
	return body
}
