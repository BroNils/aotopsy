package stmt

import (
	"regexp"
	"strings"
)

var (
	// singleUseDeclRe matches `final tN = rhs;` or `tN = rhs;` where tN is a temporary.
	singleUseDeclRe = regexp.MustCompile(`^(?:final\s+)?(t\d+|local_m?\d+)\s*=\s*(.+);$`)
)

// inlineSingleUseTempsStmt inlines single-use temporary variables into their use sites:
//
//	final t0 = getTheme();
//	return t0;
//	->
//	return getTheme();
//
// And:
//
//	final t0 = obj.width;
//	final t1 = draw(t0);
//	->
//	final t1 = draw(obj.width);
func InlineSingleUseTempsStmt(stmts []Stmt) ([]Stmt, bool) {
	flat := flattenLines(stmts)
	if len(flat) == 0 {
		return stmts, false
	}

	// Count total whole-word occurrences of each identifier across the function.
	identCounts := map[string]int{}
	for _, r := range flat {
		for _, id := range identRe.FindAllString(r.line.Text, -1) {
			identCounts[id]++
		}
	}

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

			m := singleUseDeclRe.FindStringSubmatch(line.Text)
			if m == nil || !strings.HasPrefix(line.Text, "final ") {
				continue
			}
			temp, rhs := m[1], strings.TrimSpace(m[2])

			// Only inline call results, constructors, or direct property access (not general arithmetic expressions).
			if !strings.Contains(rhs, "(") && !strings.Contains(rhs, ".") {
				continue
			}

			// Must occur exactly twice in the entire function (1 def + 1 use).
			if identCounts[temp] != 2 {
				continue
			}

			// Check if the single use is in the immediately following statement (i+1).
			if i+1 < len(body) {
				nextLine := asLine(body[i+1])
			if nextLine != nil && !nextLine.isLabel() && ReferencesIdent(nextLine.Text, temp) {
					re := identBoundaryRe(temp)
					inlinedText := re.ReplaceAllString(nextLine.Text, rhs)
					nextLine.Text = inlinedText

					// Drop statement i (the declaration).
					body = append(body[:i], body[i+1:]...)
					bodyChanged = true
					anyChanged = true
					i-- // re-process at current index
					continue
				}
			}

			// If rhs is pure (no function calls or state modification), check subsequent siblings.
		if !HasSideEffect(rhs) {
				for j := i + 1; j < len(body); j++ {
					targetLine := asLine(body[j])
					if targetLine == nil || targetLine.isLabel() {
						break // do not cross construct boundaries or labels
					}
				if ReferencesIdent(targetLine.Text, temp) {
						re := identBoundaryRe(temp)
						targetLine.Text = re.ReplaceAllString(targetLine.Text, rhs)

						// Drop statement i.
						body = append(body[:i], body[i+1:]...)
						bodyChanged = true
						anyChanged = true
						i--
						break
					}
					// If targetLine modifies any identifier read by rhs, stop.
					if ids, ok := exprOperands(rhs); ok {
						modified := false
						for _, id := range ids {
							if strings.HasPrefix(targetLine.Text, id+" =") ||
								strings.HasPrefix(targetLine.Text, "final "+id+" =") {
								modified = true
								break
							}
						}
						if modified {
							break
						}
					}
				}
			}
		}
		return body, bodyChanged
	}

	res, changed := walk(stmts)
	return res, changed || anyChanged
}
