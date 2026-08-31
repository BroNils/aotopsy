package stmt

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// untypedFinalDeclRe matches `final varName = rhs;` or `var varName = rhs;`
	untypedFinalDeclRe = regexp.MustCompile(`^(?:final|var)\s+([A-Za-z_]\w*)\s*=\s*(.+);$`)

	// newClassInstanceRe matches `new ClassName(...)` or `ClassName(...)`
	newClassInstanceRe = regexp.MustCompile(`^(?:new\s+)?([A-Z]\w*)(?:\(.*\))?$`)

	// intLiteralRe matches decimal integer literals
	intLiteralRe = regexp.MustCompile(`^-?\d+$`)

	// doubleLiteralRe matches floating point literals
	doubleLiteralRe = regexp.MustCompile(`^-?\d+\.\d+(?:[eE][+-]?\d+)?$`)
)

// typedDeclarationsStmt infers and injects explicit Dart type annotations into variable declarations:
//
//	final t0 = "hello";
//	->
//	final String t0 = "hello";
//
// And:
//
//	final t0 = 42;
//	->
//	final int t0 = 42;
//
// And:
//
//	final t0 = new UserModel();
//	->
//	final UserModel t0 = UserModel();
func TypedDeclarationsStmt(stmts []Stmt) ([]Stmt, bool) {
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

			t := strings.TrimSpace(line.Text)
			m := untypedFinalDeclRe.FindStringSubmatch(t)
			if m == nil {
				continue
			}

			varName := m[1]
			rhs := strings.TrimSpace(m[2])

			// Phi induction locals (phi_bH_<reg>) are declared mutable and are
			// reassigned every loop iteration; promoting them to `final` would
			// produce invalid Dart (assignment to a final). Leave them as `var`.
			if strings.HasPrefix(varName, "phi_b") {
				continue
			}

			inferredType := inferTypeFromRHS(rhs)
			if inferredType == "" {
				continue
			}

			// Clean `new ClassName(...)` to `ClassName(...)` if type is injected
			if strings.HasPrefix(rhs, "new ") {
				rhs = strings.TrimPrefix(rhs, "new ")
			}

			newLineText := fmt.Sprintf("final %s %s = %s;", inferredType, varName, rhs)
			if newLineText != line.Text {
				line.Text = newLineText
				bodyChanged = true
				anyChanged = true
			}
		}
		return body, bodyChanged
	}

	res, changed := walk(stmts)
	return res, changed || anyChanged
}

func inferTypeFromRHS(rhs string) string {
	rhs = strings.TrimSpace(rhs)
	if rhs == "" {
		return ""
	}

	// String literals or string templates
	if (strings.HasPrefix(rhs, `"`) && strings.HasSuffix(rhs, `"`)) ||
		(strings.HasPrefix(rhs, `'`) && strings.HasSuffix(rhs, `'`)) {
		return "String"
	}

	// Boolean literals
	if rhs == "true" || rhs == "false" {
		return "bool"
	}

	// Numeric literals
	if intLiteralRe.MatchString(rhs) {
		return "int"
	}
	if doubleLiteralRe.MatchString(rhs) {
		return "double"
	}

	// List literals
	if strings.HasPrefix(rhs, "[") && strings.HasSuffix(rhs, "]") {
		return "List"
	}

	// Set or Map literals
	if strings.HasPrefix(rhs, "{") && strings.HasSuffix(rhs, "}") {
		if strings.Contains(rhs, ":") {
			return "Map"
		}
		return "Set"
	}

	// Instantiations: new Foo() or Foo()
	if strings.HasPrefix(rhs, "new ") {
		inst := strings.TrimPrefix(rhs, "new ")
		if m := newClassInstanceRe.FindStringSubmatch(inst); m != nil {
			cls := m[1]
			if !strings.HasPrefix(cls, "_") {
				return cls
			}
		}
	}

	return ""
}
