package stmt

import (
	"regexp"
	"strings"
)

var (
	// iteratorInitRe matches `final it = <iterable>.iterator;` or `it = <iterable>.iterator;` or `final it = _getIterator(<iterable>);`.
	iteratorInitRe = regexp.MustCompile(`^(?:final\s+)?([A-Za-z_]\w*)\s*=\s*(.+?)(?:\.iterator|\.getIterator\(\)|_getIterator\((.+?)\));?$`)

	// moveNextCondRe matches `it.moveNext()`, `it.moveNext() == true`, or `iterator_moveNext(it)`.
	moveNextCondRe = regexp.MustCompile(`^(?:([A-Za-z_]\w*)\.moveNext\(\)(?:\s*==\s*true)?|_?iterator_moveNext\(([A-Za-z_]\w*)\))$`)

	// currentAssignRe matches `final item = it.current;`, `item = it.current;`, `final item = it.getCurrent();`.
	currentAssignRe = regexp.MustCompile(`^(?:final\s+)?([A-Za-z_]\w*)\s*=\s*(?:([A-Za-z_]\w*)\.current|[A-Za-z_]\w*\.getCurrent\(\)|_?iterator_current\(([A-Za-z_]\w*)\));?$`)
)

// forInLoopRecoveryStmt rewrites lowered iterator loops into clean `for (final x in iterable)` syntax:
//
//	final it = items.iterator;
//	while (it.moveNext()) {
//	  final item = it.current;
//	  print(item);
//	}
//	->
//	for (final item in items) {
//	  print(item);
//	}
func ForInLoopRecoveryStmt(stmts []Stmt) ([]Stmt, bool) {
	anyChanged := false

	var walk func([]Stmt) ([]Stmt, bool)
	walk = func(body []Stmt) ([]Stmt, bool) {
		bodyChanged := false
		for i := 0; i < len(body); i++ {
			// First, recurse into nested constructs
			if c := asConstruct(body[i]); c != nil {
				for ci := range c.Clauses {
					var cChanged bool
					c.Clauses[ci].Body, cChanged = walk(c.Clauses[ci].Body)
					bodyChanged = bodyChanged || cChanged
				}
			}

			c := asConstruct(body[i])
			if c == nil || len(c.Clauses) != 1 {
				continue
			}

			header := c.Clauses[0].Header
			if !strings.HasPrefix(header, "while (") && !strings.HasPrefix(header, "for (;") {
				continue
			}

			cond := c.cond()
			mCond := moveNextCondRe.FindStringSubmatch(strings.TrimSpace(cond))
			if mCond == nil {
				continue
			}
			iterVar := mCond[1]
			if iterVar == "" {
				iterVar = mCond[2]
			}
			if iterVar == "" {
				continue
			}

			// Preceding sibling must be the iterator init
			prevIdx := prevCodeIndex(body, i)
			if prevIdx < 0 {
				continue
			}
			initLine := asLine(body[prevIdx])
			if initLine == nil {
				continue
			}

			mInit := iteratorInitRe.FindStringSubmatch(strings.TrimSpace(initLine.Text))
			if mInit == nil || mInit[1] != iterVar {
				continue
			}

			iterable := mInit[2]
			if iterable == "" {
				iterable = mInit[3]
			}
			iterable = strings.TrimSpace(iterable)
			if iterable == "" {
				continue
			}

			inner := c.body()
			if len(inner) == 0 {
				continue
			}

			firstLine := asLine(firstCode(inner))
			if firstLine == nil {
				continue
			}

			mCurr := currentAssignRe.FindStringSubmatch(strings.TrimSpace(firstLine.Text))
			if mCurr == nil {
				continue
			}
			currIterVar := mCurr[2]
			if currIterVar == "" {
				currIterVar = mCurr[3]
			}
			if currIterVar != "" && currIterVar != iterVar {
				continue
			}

			itemVar := mCurr[1]
			if itemVar == "" {
				continue
			}

			// Drop the first line (current extraction) from loop body
			newInner := make([]Stmt, 0, len(inner)-1)
			firstFound := false
			for _, st := range inner {
				if !firstFound && st == Stmt(firstLine) {
					firstFound = true
					continue
				}
				newInner = append(newInner, st)
			}

			declPrefix := "final "
			if !strings.HasPrefix(firstLine.Text, "final ") && !strings.HasPrefix(firstLine.Text, "var ") {
				declPrefix = ""
			}

			forInLoop := &Construct{
				Ind:     c.Ind,
				Closer:  c.Closer,
				Clauses: []Clause{{Header: "for (" + declPrefix + itemVar + " in " + iterable + ") {", Body: newInner}},
			}

			out := append([]Stmt{}, body[:prevIdx]...)
			out = append(out, body[prevIdx+1:i]...)
			out = append(out, forInLoop)
			out = append(out, body[i+1:]...)

			body = out
			bodyChanged = true
			anyChanged = true
			break
		}
		return body, bodyChanged
	}

	res, changed := walk(stmts)
	return res, changed || anyChanged
}

func firstCode(body []Stmt) Stmt {
	for _, s := range body {
		if isCode(s) {
			return s
		}
	}
	return nil
}
