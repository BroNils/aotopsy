package decompiler

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// setConstructorRe matches `final s = new _Set();` or `final s = new _LinkedHashSet();`.
	setConstructorRe = regexp.MustCompile(`^(?:final\s+)?(\w+)\s*=\s*new\s+(_LinkedHashSet|_Set)(?:\(\))?;$`)

	// listConstructorRe matches `final l = new _GrowableList();` or `final l = new _List();`.
	listConstructorRe = regexp.MustCompile(`^(?:final\s+)?(\w+)\s*=\s*new\s+(_GrowableList|_List)(?:\(\))?;$`)

	// addCallRe matches `s.add(arg);` or `_LinkedHashSetMixin.add(arg);` or `_Set.add(arg);`.
	addCallRe = regexp.MustCompile(`^(?:(?:\w+|_LinkedHashSetMixin|_Set|_GrowableList)\.)?add\((.+)\);$`)
)

// collectionIdiomsStmt collapses constructor + `.add()` sequences into clean collection literals:
//
//	final t0 = new _LinkedHashSet();
//	t0.add("a");
//	t0.add("b");
//	->
//	final t0 = {"a", "b"};
//
// And:
//
//	final t0 = new _GrowableList();
//	t0.add(1);
//	t0.add(2);
//	->
//	final t0 = [1, 2];
func collectionIdiomsStmt(stmts []Stmt) ([]Stmt, bool) {
	anyChanged := false

	var walk func([]Stmt) ([]Stmt, bool)
	walk = func(body []Stmt) ([]Stmt, bool) {
		bodyChanged := false
		for i := 0; i < len(body); i++ {
			line := asLine(body[i])
			if line == nil {
				if c := asConstruct(body[i]); c != nil {
					for ci := range c.Clauses {
						var cChanged bool
						c.Clauses[ci].Body, cChanged = walk(c.Clauses[ci].Body)
						bodyChanged = bodyChanged || cChanged
					}
				}
				continue
			}

			isSet := false
			isList := false
			var varName string

			if m := setConstructorRe.FindStringSubmatch(line.Text); m != nil {
				isSet = true
				varName = m[1]
			} else if m := listConstructorRe.FindStringSubmatch(line.Text); m != nil {
				isList = true
				varName = m[1]
			}

			if !isSet && !isList {
				continue
			}

			// Scan subsequent lines for .add(...) calls on varName
			var elements []string
			k := i + 1
			for k < len(body) {
				subLine := asLine(body[k])
				if subLine == nil {
					break
				}
				// Check if this line is varName.add(...) or has addCallRe
				t := strings.TrimSpace(subLine.Text)
				if strings.HasPrefix(t, varName+".add(") || strings.HasPrefix(t, "_LinkedHashSetMixin.add(") || strings.HasPrefix(t, "_Set.add(") || strings.HasPrefix(t, "_GrowableList.add(") {
					if m := addCallRe.FindStringSubmatch(t); m != nil {
						elem := strings.TrimSpace(m[1])
						// If the first argument is varName in static form: _LinkedHashSetMixin.add(s, elem)
						if strings.HasPrefix(t, "_") && strings.Contains(elem, ",") {
							parts := strings.SplitN(elem, ",", 2)
							if strings.TrimSpace(parts[0]) == varName {
								elem = strings.TrimSpace(parts[1])
							}
						}
						elements = append(elements, elem)
						k++
						continue
					}
				}
				break
			}

			// If we found .add calls or empty constructor
			var literal string
			isFinal := strings.HasPrefix(line.Text, "final ")
			declPrefix := ""
			if isFinal {
				declPrefix = "final "
			}

			if isSet {
				if len(elements) == 0 {
					literal = fmt.Sprintf("%s%s = <dynamic>{};", declPrefix, varName)
				} else {
					literal = fmt.Sprintf("%s%s = {%s};", declPrefix, varName, strings.Join(elements, ", "))
				}
			} else if isList {
				literal = fmt.Sprintf("%s%s = [%s];", declPrefix, varName, strings.Join(elements, ", "))
			}

			// Replace lines i .. k-1 with literal
			newLine := &Line{Ind: line.Ind, Text: literal}
			body = append(body[:i], append([]Stmt{newLine}, body[k:]...)...)
			bodyChanged = true
			anyChanged = true
		}
		return body, bodyChanged
	}

	res, changed := walk(stmts)
	return res, changed || anyChanged
}

var (
	// interpolateCallRe matches `_StringBase._interpolate(...)`, `_interpolate(...)`, or `_StringBase.concat(...)`.
	interpolateCallRe = regexp.MustCompile(`(?:_StringBase\._interpolate|_interpolate|_StringBase\.concat)\((.+)\)`)
)

// stringInterpolationIdiomStmt rewrites runtime string interpolation calls to clean Dart template literals:
//
//	final t0 = _StringBase._interpolate(["Hello, ", name, "!"]);
//	->
//	final t0 = "Hello, $name!";
//
// And:
//
//	final t0 = _StringBase.concat(a, b);
//	->
//	final t0 = "$a$b";
func stringInterpolationIdiomStmt(stmts []Stmt) ([]Stmt, bool) {
	anyChanged := false

	var walk func([]Stmt) ([]Stmt, bool)
	walk = func(body []Stmt) ([]Stmt, bool) {
		bodyChanged := false
		for i := 0; i < len(body); i++ {
			line := asLine(body[i])
			if line == nil {
				if c := asConstruct(body[i]); c != nil {
					for ci := range c.Clauses {
						var cChanged bool
						c.Clauses[ci].Body, cChanged = walk(c.Clauses[ci].Body)
						bodyChanged = bodyChanged || cChanged
					}
				}
				continue
			}

			if interpolateCallRe.MatchString(line.Text) {
				newText := interpolateCallRe.ReplaceAllStringFunc(line.Text, func(match string) string {
					m := interpolateCallRe.FindStringSubmatch(match)
					if len(m) < 2 {
						return match
					}
					return formatStringInterpolation(m[1])
				})
				if newText != line.Text {
					line.Text = newText
					bodyChanged = true
					anyChanged = true
				}
			}
		}
		return body, bodyChanged
	}

	res, changed := walk(stmts)
	return res, changed || anyChanged
}

// formatStringInterpolation formats a slice of interpolation arguments into a Dart template string.
func formatStringInterpolation(argsText string) string {
	argsText = strings.TrimSpace(argsText)
	if strings.HasPrefix(argsText, "[") && strings.HasSuffix(argsText, "]") {
		argsText = strings.TrimPrefix(argsText, "[")
		argsText = strings.TrimSuffix(argsText, "]")
	}
	parts := splitInterpolationParts(argsText)
	if len(parts) == 0 {
		return `""`
	}
	var sb strings.Builder
	sb.WriteByte('"')
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if len(p) >= 2 && strings.HasPrefix(p, `"`) && strings.HasSuffix(p, `"`) {
			inner := p[1 : len(p)-1]
			sb.WriteString(inner)
		} else if len(p) >= 2 && strings.HasPrefix(p, `'`) && strings.HasSuffix(p, `'`) {
			inner := p[1 : len(p)-1]
			sb.WriteString(inner)
		} else if isSimpleIdent(p) {
			sb.WriteString("$")
			sb.WriteString(p)
		} else {
			sb.WriteString("${")
			sb.WriteString(p)
			sb.WriteString("}")
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

func splitInterpolationParts(s string) []string {
	var parts []string
	depth := 0
	start := 0
	inQuote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote != 0 {
			if c == inQuote && (i == 0 || s[i-1] != '\\') {
				inQuote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			inQuote = c
			continue
		}
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if start < len(s) {
		trimmed := strings.TrimSpace(s[start:])
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

func isSimpleIdent(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}
