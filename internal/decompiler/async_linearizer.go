package decompiler

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	// stateCondRe matches `state == 0`, `t0 == 1`, `(state == 2)`, `s == 0`.
	stateCondRe = regexp.MustCompile(`^(?:\(?\s*([A-Za-z_]\w*)\s*==\s*(\d+)\s*\)?)$`)

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

// linearizeAsyncStmt unwraps Dart AOT async state machine dispatch trees into clean linear Dart code:
//
//	if (state == 0) {
//	  final fut = fetch();
//	  await t1(fut);
//	} else if (state == 1) {
//	  return t1;
//	}
//	->
//	final fut = fetch();
//	final t1 = await fut;
//	return t1;
func linearizeAsyncStmt(stmts []Stmt) ([]Stmt, bool) {
	anyChanged := false

	// The state-machine flatten (below) is only sound inside an async function.
	// A plain `if (x == 0) {} else if (x == 1) {}` on non-async code is NOT a
	// suspend-state dispatch and must not be linearized (audit B4). Gate it on
	// real async evidence anywhere in the tree.
	asyncEvidence := treeHasAsyncEvidence(stmts)

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

			// Check for state machine dispatch construct
			c := asConstruct(body[i])
			if c == nil || !c.isIf() || len(c.Clauses) < 2 {
				if c != nil {
					for ci := range c.Clauses {
						var cChanged bool
						c.Clauses[ci].Body, cChanged = walk(c.Clauses[ci].Body)
						bodyChanged = bodyChanged || cChanged
					}
				}
				continue
			}

			// Check if all clauses match state == N in sequential order (0, 1, 2, ...)
			isStateMachine := true
			var stateVar string
			numStateConds := 0
			for ci := range c.Clauses {
				cond := c.clauseCond(ci)
				if cond == "" {
					if ci == len(c.Clauses)-1 && numStateConds >= 2 {
						// else clause at the end is allowed only if >= 2 states precede it
						break
					}
					isStateMachine = false
					break
				}
				m := stateCondRe.FindStringSubmatch(strings.TrimSpace(cond))
				if m == nil {
					isStateMachine = false
					break
				}
				if stateVar == "" {
					stateVar = m[1]
				} else if m[1] != stateVar {
					isStateMachine = false
					break
				}
				val, err := strconv.Atoi(m[2])
				if err != nil || val != ci {
					isStateMachine = false
					break
				}
				numStateConds++
			}

			if numStateConds < 2 {
				isStateMachine = false
			}

			if !isStateMachine || !asyncEvidence {
				for ci := range c.Clauses {
					var cChanged bool
					c.Clauses[ci].Body, cChanged = walk(c.Clauses[ci].Body)
					bodyChanged = bodyChanged || cChanged
				}
				continue
			}

			// Flatten state machine clauses sequentially
			var flattened []Stmt
			for _, cl := range c.Clauses {
				recBody, _ := walk(cl.Body)
				for _, st := range recBody {
					st.shift(-1) // adjust indentation
					flattened = append(flattened, st)
				}
			}

			out := append([]Stmt{}, body[:i]...)
			out = append(out, flattened...)
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

// treeHasAsyncEvidence reports whether any line in the statement tree carries a
// marker of async lowering (await, _SuspendState, _StreamIterator, _returnAsync).
// Used to gate the state-machine flatten so it never fires on ordinary
// integer-dispatch if/else chains.
func treeHasAsyncEvidence(stmts []Stmt) bool {
	found := false
	var scan func([]Stmt)
	scan = func(body []Stmt) {
		for _, s := range body {
			if found {
				return
			}
			if l := asLine(s); l != nil {
				t := l.Text
				if strings.Contains(t, "await") || strings.Contains(t, "_SuspendState") ||
					strings.Contains(t, "_StreamIterator") || strings.Contains(t, "_returnAsync") {
					found = true
					return
				}
			}
			if c := asConstruct(s); c != nil {
				for ci := range c.Clauses {
					scan(c.Clauses[ci].Body)
				}
			}
		}
	}
	scan(stmts)
	return found
}

// clauseCond extracts the condition string from clause ci.
func (c *Construct) clauseCond(ci int) string {
	if ci < 0 || ci >= len(c.Clauses) {
		return ""
	}
	h := c.Clauses[ci].Header
	if strings.HasPrefix(h, "if (") {
		h = strings.TrimPrefix(h, "if (")
	} else if strings.HasPrefix(h, "} else if (") {
		h = strings.TrimPrefix(h, "} else if (")
	} else {
		return ""
	}
	if idx := strings.LastIndex(h, ") {"); idx >= 0 {
		return h[:idx]
	}
	return ""
}
