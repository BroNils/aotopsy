package stmt

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// rawAwaitCallRe matches `await t1(fut); // await` or `await t1(fut);`
	rawAwaitCallRe = regexp.MustCompile(`^await\s+([A-Za-z_]\w*)\((.*)\);\s*(?://.*)?$`)

	// suspendStateAwaitRe matches `_SuspendState._await(fut)` or `_SuspendState._await(state, fut)`
	suspendStateAwaitRe = regexp.MustCompile(`^(?:final\s+([A-Za-z_]\w*)\s*=\s*)?_SuspendState\._await\((.*)\);?$`)

	// suspendStateReturnRe matches `_SuspendState._returnAsync(future, res);` or `_SuspendState._returnAsyncNotFuture(future, res);`
	suspendStateReturnRe = regexp.MustCompile(`^_SuspendState\._returnAsync(?:NotFuture)?\((.*)\);?$`)

	// streamIteratorInitRe matches `final it = new _StreamIterator(stream);` or `it = new _StreamIterator(stream);`
	streamIteratorInitRe = regexp.MustCompile(`^(?:final\s+)?([A-Za-z_]\w*)\s*=\s*new\s+_StreamIterator\((.+?)\);?$`)

	// streamMoveNextCondRe matches `await it.moveNext()` or `await it.moveNext() == true`
	streamMoveNextCondRe = regexp.MustCompile(`^await\s+([A-Za-z_]\w*)\.moveNext\(\)(?:\s*==\s*true)?$`)
)

// LinearizeAsyncStmt rewrites async helper idioms whose source meaning is
// explicit in the emitted text (await helper calls and StreamIterator await-for
// loops). It deliberately does NOT flatten `if (state == 0/1/...)` trees.
//
// Compact SuspendState lowering stores a resume PC, not a small source-level
// state ordinal. More importantly, an async function may contain ordinary user
// branches comparing an integer named `state`; removing those branches changes
// program semantics. Structural control flow is therefore preserved unless a
// separate lowering-specific proof exists.
func LinearizeAsyncStmt(stmts []Stmt) ([]Stmt, bool) {
	anyChanged := false

	var walk func([]Stmt) ([]Stmt, bool)
	walk = func(body []Stmt) ([]Stmt, bool) {
		bodyChanged := false
		for i := 0; i < len(body); i++ {
			// First, rewrite individual raw await/return calls in lines
			if line := asLine(body[i]); line != nil {
				t := strings.TrimSpace(line.Text)
				if m := rawAwaitCallRe.FindStringSubmatch(t); m != nil {
					tmpVar := m[1]
					arg := strings.TrimSpace(m[2])
					if arg != "" {
						line.Text = fmt.Sprintf("final %s = await %s;", tmpVar, arg)
					} else {
						line.Text = fmt.Sprintf("await %s;", tmpVar)
					}
					bodyChanged = true
					anyChanged = true
					continue
				}
				if m := suspendStateAwaitRe.FindStringSubmatch(t); m != nil {
					resVar := m[1]
					arg := strings.TrimSpace(m[2])
					if strings.Contains(arg, ",") {
						parts := strings.Split(arg, ",")
						arg = strings.TrimSpace(parts[len(parts)-1])
					}
					if resVar != "" {
						line.Text = fmt.Sprintf("final %s = await %s;", resVar, arg)
					} else {
						line.Text = fmt.Sprintf("await %s;", arg)
					}
					bodyChanged = true
					anyChanged = true
					continue
				}
				if m := suspendStateReturnRe.FindStringSubmatch(t); m != nil {
					arg := strings.TrimSpace(m[1])
					if strings.Contains(arg, ",") {
						parts := strings.Split(arg, ",")
						arg = strings.TrimSpace(parts[len(parts)-1])
					}
					line.Text = fmt.Sprintf("return %s;", arg)
					bodyChanged = true
					anyChanged = true
					continue
				}
			}

			// Check for Stream `await for` loop pattern
			if c := asConstruct(body[i]); c != nil {
				if len(c.Clauses) == 1 && strings.HasPrefix(c.Clauses[0].Header, "while (") {
					cond := strings.TrimSpace(c.cond())
					if mStream := streamMoveNextCondRe.FindStringSubmatch(cond); mStream != nil {
						iterVar := mStream[1]
						prevIdx := prevCodeIndex(body, i)
						if prevIdx >= 0 {
							if initLine := asLine(body[prevIdx]); initLine != nil {
								if mInit := streamIteratorInitRe.FindStringSubmatch(strings.TrimSpace(initLine.Text)); mInit != nil && mInit[1] == iterVar {
									streamExpr := strings.TrimSpace(mInit[2])
									inner := c.body()
									if len(inner) > 0 {
										if firstLine := asLine(firstCode(inner)); firstLine != nil {
											if mCurr := currentAssignRe.FindStringSubmatch(strings.TrimSpace(firstLine.Text)); mCurr != nil {
												itemVar := mCurr[1]
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
												awaitForLoop := &Construct{
													Ind:     c.Ind,
													Closer:  c.Closer,
													Clauses: []Clause{{Header: "await for (" + declPrefix + itemVar + " in " + streamExpr + ") {", Body: newInner}},
												}
												out := append([]Stmt{}, body[:prevIdx]...)
												out = append(out, body[prevIdx+1:i]...)
												out = append(out, awaitForLoop)
												out = append(out, body[i+1:]...)

												body = out
												bodyChanged = true
												anyChanged = true
												break
											}
										}
									}
								}
							}
						}
					}
				}
			}

			// Recurse into ordinary control-flow constructs, but preserve their
			// structure. Async evidence elsewhere in the function is not proof that
			// this particular branch is compiler suspension machinery.
			if c := asConstruct(body[i]); c != nil {
				for ci := range c.Clauses {
					var cChanged bool
					c.Clauses[ci].Body, cChanged = walk(c.Clauses[ci].Body)
					bodyChanged = bodyChanged || cChanged
				}
			}
		}
		return body, bodyChanged
	}

	res, changed := walk(stmts)
	return res, changed || anyChanged
}
