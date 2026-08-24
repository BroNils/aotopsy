package decompiler

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// allocateClosureRe matches `final t0 = AllocateClosure(fn, ctx);`, `final t0 = _Closure(fn, ctx);`, `final t0 = new _Closure(fn, ctx);`.
	allocateClosureRe = regexp.MustCompile(`^(?:final\s+)?([A-Za-z_]\w*)\s*=\s*(?:new\s+)?(?:_?AllocateClosure\d*|_?Closure)\(([^,)]+)(?:,\s*([^)]*))?\);?$`)

	// anonClosureRefRe matches `SomeClass.someMethod.<anonymous closure>` or `someFunc.<anonymous closure>`.
	anonClosureRefRe = regexp.MustCompile(`^(?:[\w&@.]+\.)?<anonymous closure>$`)

	// higherOrderCallRe matches `target.higherOrderMethod(arg)`
	higherOrderCallRe = regexp.MustCompile(`^(.+)\.(map|where|forEach|then|catchError|whenComplete|firstWhere|lastWhere|singleWhere|any|every|fold|reduce|expand|takeWhile|skipWhile|sort|removeWhere|retainWhere|putIfAbsent|update|listen)\((.+)\)$`)
)

// closureInliningStmt inlines closure allocations and anonymous callback references directly into call-sites:
//
//	final t0 = AllocateClosure(print, null);
//	items.forEach(t0);
//	->
//	items.forEach(print);
//
// And:
//
//	final t0 = AllocateClosure(User.getName, null);
//	final t1 = users.map(t0);
//	->
//	final t1 = users.map(User.getName);
//
// And:
//
//	final t0 = items.map(process.<anonymous closure>);
//	->
//	final t0 = items.map((x) => process(x));
func closureInliningStmt(stmts []Stmt) ([]Stmt, bool) {
	anyChanged := false

	var walk func([]Stmt) ([]Stmt, bool)
	walk = func(body []Stmt) ([]Stmt, bool) {
		bodyChanged := false
		for i := 0; i < len(body); i++ {
			// Recurse into nested constructs
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

			// Pattern 1: Inline AllocateClosure temporary into immediate subsequent call
			mAlloc := allocateClosureRe.FindStringSubmatch(strings.TrimSpace(line.Text))
			if mAlloc != nil {
				tmpVar := mAlloc[1]
				fnTarget := strings.TrimSpace(mAlloc[2])

				// If fnTarget is an anonymous closure like Foo.bar.<anonymous closure>, clean it
				cleanFn := cleanClosureTarget(fnTarget)

				// Look ahead for single-use call-site that consumes tmpVar
				if i+1 < len(body) {
					nextLine := asLine(body[i+1])
					if nextLine != nil && isSingleIdentifierUse(nextLine.Text, tmpVar) {
						// Replace tmpVar in next line with cleanFn
						newText := replaceIdent(nextLine.Text, tmpVar, cleanFn)
						if newText != nextLine.Text {
							nextLine.Text = newText
							// Drop the AllocateClosure allocation line
							body = append(body[:i], body[i+1:]...)
							bodyChanged = true
							anyChanged = true
							i--
							continue
						}
					}
				}
			}

			// Pattern 2: Rewrite direct anonymous closure in higher-order method call arguments
			t := line.Text
			if strings.Contains(t, "<anonymous closure>") {
				newText := rewriteAnonClosureInCall(t)
				if newText != t {
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

func cleanClosureTarget(fn string) string {
	fn = strings.TrimSpace(fn)
	if fn == "" {
		return "()"
	}
	if anonClosureRefRe.MatchString(fn) {
		prefix := strings.TrimSuffix(fn, ".<anonymous closure>")
		prefix = strings.TrimSuffix(prefix, "<anonymous closure>")
		if prefix != "" {
			parts := strings.Split(prefix, ".")
			shortName := parts[len(parts)-1]
			return fmt.Sprintf("(item) => %s(item)", shortName)
		}
		return "(item) => item"
	}
	return fn
}

func rewriteAnonClosureInCall(text string) string {
	// If text contains a call to .map(Foo.<anonymous closure>) etc.
	idx := strings.Index(text, "<anonymous closure>")
	if idx < 0 {
		return text
	}

	// Extract the closure expression surrounding the index
	start := idx
	for start > 0 && (text[start-1] == '.' || text[start-1] == '_' || text[start-1] == '$' ||
		(text[start-1] >= 'a' && text[start-1] <= 'z') ||
		(text[start-1] >= 'A' && text[start-1] <= 'Z') ||
		(text[start-1] >= '0' && text[start-1] <= '9') ||
		text[start-1] == '@' || text[start-1] == '&') {
		start--
	}
	end := idx + len("<anonymous closure>")
	fullTarget := text[start:end]

	cleaned := cleanClosureTarget(fullTarget)
	return text[:start] + cleaned + text[end:]
}

func isSingleIdentifierUse(text, ident string) bool {
	matches := regexp.MustCompile(`\b` + regexp.QuoteMeta(ident) + `\b`).FindAllString(text, -1)
	return len(matches) == 1
}
