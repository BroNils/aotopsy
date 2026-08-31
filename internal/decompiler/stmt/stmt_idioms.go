package stmt

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
func CollectionIdiomsStmt(stmts []Stmt) ([]Stmt, bool) {
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
				// Only the INSTANCE form `varName.add(x)` with EXACTLY ONE argument
				// is collapsed. The static/mixin form `_LinkedHashSetMixin.add(recv,
				// elem, …)` on real output carries the receiver plus selector-hint
				// registers (8-arg dumps), and guessing which token is the element
				// produced garbage literals like `{"<Array>", x0, (PP+..).fNN, …}`
				// (audit B1). If the add has more than one top-level argument, we do
				// not know the element, so we stop collecting rather than fabricate.
				t := strings.TrimSpace(subLine.Text)
				if strings.HasPrefix(t, varName+".add(") {
					if m := addCallRe.FindStringSubmatch(t); m != nil {
						elem := strings.TrimSpace(m[1])
						if topLevelCommaCount(elem) == 0 {
							elements = append(elements, elem)
							k++
							continue
						}
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
func StringInterpolationIdiomStmt(stmts []Stmt) ([]Stmt, bool) {
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

// topLevelCommaCount counts commas that are not nested inside brackets or
// quotes -- i.e. how many arguments a comma-separated list has, minus one.
func topLevelCommaCount(s string) int {
	n := 0
	depth := 0
	inQuote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote != 0 {
			if c == inQuote && (i == 0 || s[i-1] != '\\') {
				inQuote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inQuote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				n++
			}
		}
	}
	return n
}

// bracketsBalanced reports whether (), [] and {} are balanced in s (ignoring
// quoted content). Used to reject regex captures that split a nested expression.
func bracketsBalanced(s string) bool {
	depth := 0
	inQuote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote != 0 {
			if c == inQuote && (i == 0 || s[i-1] != '\\') {
				inQuote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inQuote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
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

var (
	// ternaryNotNullRe matches `(a != null) ? thenExpr : elseExpr`
	ternaryNotNullRe = regexp.MustCompile(`\(([A-Za-z_]\w*)\s*!=\s*null\)\s*\?\s*([^?:]+?)\s*:\s*([^;]+)`)
	// ternaryEqualsNullRe matches `(a == null) ? thenExpr : elseExpr`
	ternaryEqualsNullRe = regexp.MustCompile(`\(([A-Za-z_]\w*)\s*==\s*null\)\s*\?\s*([^?:]+?)\s*:\s*([^;]+)`)

	// nullAssignRe matches `if (x == null) { x = val; }`
	nullAssignRe = regexp.MustCompile(`^([A-Za-z_]\w*)\s*=\s*(.+);$`)
)

// nullAwareIdiomStmt folds null check ternaries and guards into `?.`, `??`, `??=`.
func NullAwareIdiomStmt(stmts []Stmt) ([]Stmt, bool) {
	anyChanged := false

	var walk func([]Stmt) ([]Stmt, bool)
	walk = func(body []Stmt) ([]Stmt, bool) {
		bodyChanged := false
		for i := 0; i < len(body); i++ {
			// Check construct: if (x == null) { x = val; } -> x ??= val;
			if c := asConstruct(body[i]); c != nil {
				if c.isIf() && len(c.Clauses) == 1 {
					cond := strings.TrimSpace(c.cond())
					varName := ""
					if strings.HasSuffix(cond, " == null") {
						varName = strings.TrimSpace(strings.TrimSuffix(cond, " == null"))
					}
					if varName != "" && len(c.body()) == 1 {
						if l := asLine(c.body()[0]); l != nil {
							if m := nullAssignRe.FindStringSubmatch(strings.TrimSpace(l.Text)); m != nil && m[1] == varName {
								val := strings.TrimSpace(m[2])
								newLine := &Line{Ind: c.Ind, Text: fmt.Sprintf("%s ??= %s;", varName, val)}
								body[i] = newLine
								bodyChanged = true
								anyChanged = true
								continue
							}
						}
					}
				}

				for ci := range c.Clauses {
					var cChanged bool
					c.Clauses[ci].Body, cChanged = walk(c.Clauses[ci].Body)
					bodyChanged = bodyChanged || cChanged
				}
				continue
			}

			line := asLine(body[i])
			if line == nil {
				continue
			}

			text := line.Text
			if strings.Contains(text, "?") && strings.Contains(text, "null") {
				text = ternaryNotNullRe.ReplaceAllStringFunc(text, func(match string) string {
					m := ternaryNotNullRe.FindStringSubmatch(match)
					if len(m) < 4 {
						return match
					}
					varName := strings.TrimSpace(m[1])
					thenExpr := strings.TrimSpace(m[2])
					elseExpr := strings.TrimSpace(m[3])

					// Audit B3: the `[^?:]+?`/`[^;]+` capture is not bracket-aware,
					// so a nested call/collection can be mis-split. Only rewrite
					// when both arms are self-contained (balanced brackets).
					if !bracketsBalanced(thenExpr) || !bracketsBalanced(elseExpr) {
						return match
					}
					// (a != null) ? a : b -> a ?? b
					if thenExpr == varName {
						return fmt.Sprintf("%s ?? %s", varName, elseExpr)
					}
					// (a != null) ? a.foo : null -> a?.foo
					if elseExpr == "null" && strings.HasPrefix(thenExpr, varName+".") {
						return fmt.Sprintf("%s?.%s", varName, strings.TrimPrefix(thenExpr, varName+"."))
					}
					return match
				})

				text = ternaryEqualsNullRe.ReplaceAllStringFunc(text, func(match string) string {
					m := ternaryEqualsNullRe.FindStringSubmatch(match)
					if len(m) < 4 {
						return match
					}
					varName := strings.TrimSpace(m[1])
					thenExpr := strings.TrimSpace(m[2])
					elseExpr := strings.TrimSpace(m[3])

					// Audit B3: see note above -- require balanced arms.
					if !bracketsBalanced(thenExpr) || !bracketsBalanced(elseExpr) {
						return match
					}
					// (a == null) ? b : a -> a ?? b
					if elseExpr == varName {
						return fmt.Sprintf("%s ?? %s", varName, thenExpr)
					}
					// (a == null) ? null : a.foo -> a?.foo
					if thenExpr == "null" && strings.HasPrefix(elseExpr, varName+".") {
						return fmt.Sprintf("%s?.%s", varName, strings.TrimPrefix(elseExpr, varName+"."))
					}
					return match
				})
			}

			if text != line.Text {
				line.Text = text
				bodyChanged = true
				anyChanged = true
			}
		}
		return body, bodyChanged
	}

	res, changed := walk(stmts)
	return res, changed || anyChanged
}

var (
	// newInstanceRe matches `final p = new Paint();` or `final p = Paint();`.
	// The constructor call PARENS are required (audit B2): without them a bare
	// capitalized constant like `final p = Colors;` was matched and turned into
	// `Colors()..`, fabricating a constructor call on a constant.
	newInstanceRe = regexp.MustCompile(`^(?:final\s+)?([A-Za-z_]\w*)\s*=\s*(?:new\s+)?([A-Z]\w*\([^)]*\));$`)
)

// cascadeIdiomStmt collapses sequence of method/setter calls on a new instance into cascade notation `..`:
//
//	final p = new Paint();
//	p.color = red;
//	p.strokeWidth = 2;
//	return p;
//	->
//	return Paint()..color = red..strokeWidth = 2;
func CascadeIdiomStmt(stmts []Stmt) ([]Stmt, bool) {
	anyChanged := false

	var walk func([]Stmt) ([]Stmt, bool)
	walk = func(body []Stmt) ([]Stmt, bool) {
		bodyChanged := false
		for i := 0; i < len(body); i++ {
			if c := asConstruct(body[i]); c != nil {
				for ci := range c.Clauses {
					var cChanged bool
					c.Clauses[ci].Body, cChanged = walk(c.Clauses[ci].Body)
					bodyChanged = bodyChanged || cChanged
				}
				continue
			}

			line := asLine(body[i])
			if line == nil {
				continue
			}

			m := newInstanceRe.FindStringSubmatch(strings.TrimSpace(line.Text))
			if m == nil {
				continue
			}

			varName := m[1]
			instExpr := m[2]
			if !strings.HasSuffix(instExpr, ")") {
				instExpr += "()"
			}

			var cascades []string
			k := i + 1
			for k < len(body) {
				subLine := asLine(body[k])
				if subLine == nil {
					break
				}
				t := strings.TrimSpace(subLine.Text)
				// Check if this line is varName.foo = bar; or varName.method(...);
				if strings.HasPrefix(t, varName+".") && strings.HasSuffix(t, ";") {
					rest := strings.TrimSuffix(strings.TrimPrefix(t, varName+"."), ";")
					cascades = append(cascades, ".."+rest)
					k++
					continue
				}
				break
			}

			if len(cascades) == 0 {
				continue
			}

			cascadeStr := instExpr + strings.Join(cascades, "")

			// Check if next line is return varName;
			if k < len(body) {
				retLine := asLine(body[k])
				if retLine != nil && strings.TrimSpace(retLine.Text) == "return "+varName+";" {
					newLine := &Line{Ind: line.Ind, Text: "return " + cascadeStr + ";"}
					body = append(body[:i], append([]Stmt{newLine}, body[k+1:]...)...)
					bodyChanged = true
					anyChanged = true
					break
				}
			}

			// Otherwise declare final varName = cascadeStr;
			isFinal := strings.HasPrefix(line.Text, "final ")
			declPrefix := ""
			if isFinal {
				declPrefix = "final "
			}
			newLine := &Line{Ind: line.Ind, Text: fmt.Sprintf("%s%s = %s;", declPrefix, varName, cascadeStr)}
			body = append(body[:i], append([]Stmt{newLine}, body[k:]...)...)
			bodyChanged = true
			anyChanged = true
			break
		}
		return body, bodyChanged
	}

	res, changed := walk(stmts)
	return res, changed || anyChanged
}
