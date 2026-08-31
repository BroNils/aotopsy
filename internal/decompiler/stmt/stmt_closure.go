package stmt

import (
	"regexp"
	"strings"
)

var (
	// allocateClosureRe matches `final t0 = AllocateClosure(fn, ctx);`,
	// `final t0 = _Closure(fn, ctx);`, `final t0 = new _Closure(fn, ctx);`.
	// Group 2 is the function/target, group 3 (optional) the captured context.
	allocateClosureRe = regexp.MustCompile(`^(?:final\s+)?([A-Za-z_]\w*)\s*=\s*(?:new\s+)?(?:_?AllocateClosure\d*|_?Closure)\(([^,)]+)(?:,\s*([^)]*))?\);?$`)
)

// closureInliningStmt inlines a closure ALLOCATION temporary into its immediate
// single use, but ONLY when doing so cannot change meaning:
//
//	final t0 = AllocateClosure(print, null);   // no captured context
//	items.forEach(t0);
//	->
//	items.forEach(print);
//
// Two hard rules keep this from fabricating (audit sections A3/A4):
//
//  1. It only fires when the captured context (group 3) is absent or `null`.
//     `AllocateClosure(fn, ctx)` binds `ctx` into the closure; reducing it to
//     the bare tear-off `fn` would silently DROP that binding, so a closure
//     with a real context is left exactly as emitted.
//
//  2. It NEVER synthesizes a lambda body. The body of an `<anonymous closure>`
//     lives in a separate function that is not examined here, so inventing
//     `(item) => fn(item)` would be a guess. The closure reference is moved
//     verbatim; an anonymous-closure reference stays an honest
//     `Owner.method.<anonymous closure>`.
func ClosureInliningStmt(stmts []Stmt) ([]Stmt, bool) {
	anyChanged := false

	var walk func([]Stmt) ([]Stmt, bool)
	walk = func(body []Stmt) ([]Stmt, bool) {
		bodyChanged := false
		for i := 0; i < len(body); i++ {
			// Recurse into nested constructs.
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

			mAlloc := allocateClosureRe.FindStringSubmatch(strings.TrimSpace(line.Text))
			if mAlloc == nil {
				continue
			}
			tmpVar := mAlloc[1]
			fnTarget := strings.TrimSpace(mAlloc[2])
			ctx := strings.TrimSpace(mAlloc[3])

			// Rule 1: a captured context cannot be dropped.
			if ctx != "" && ctx != "null" {
				continue
			}
			if fnTarget == "" {
				continue
			}

			// Inline into the immediately following single use, verbatim.
			if i+1 < len(body) {
				nextLine := asLine(body[i+1])
				if nextLine != nil && isSingleIdentifierUse(nextLine.Text, tmpVar) {
					newText := ReplaceIdent(nextLine.Text, tmpVar, fnTarget)
					if newText != nextLine.Text {
						nextLine.Text = newText
						body = append(body[:i], body[i+1:]...)
						bodyChanged = true
						anyChanged = true
						i--
						continue
					}
				}
			}
		}
		return body, bodyChanged
	}

	res, changed := walk(stmts)
	return res, changed || anyChanged
}

func isSingleIdentifierUse(text, ident string) bool {
	matches := regexp.MustCompile(`\b`+regexp.QuoteMeta(ident)+`\b`).FindAllString(text, -1)
	return len(matches) == 1
}
