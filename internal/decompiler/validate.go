package decompiler

import (
	"fmt"
	"regexp"
	"strings"
)

// Sanity checks on emitted pseudocode.
//
// The output claims to be Dart. Two of the worst defects found in this
// package were shapes that simply are not:
//
//	if ((x15 - 16) true THR.f64) {      // 28148 sites, from B.AL decoded
//	                                    // as a conditional branch whose
//	                                    // "condition" was the string "true"
//	_StringBase@0150898. + (a, b)       // 1830 sites, a method call the
//	                                    // expression parser re-rendered as
//	                                    // an addition
//
// Neither was caught by anything. The golden gate compares hashes, so it
// notices a change but has no opinion about whether the new text is
// coherent; the unit tests only ever saw hand-written input, which is
// exactly the input these bugs do not occur on.
//
// This is deliberately a list of shapes known to be wrong rather than a Dart
// parser. A parser would reject plenty of things this emitter legitimately
// prints -- `local_m24`, `THR.f88`, `goto block_3;` -- and rejecting those
// would make the check useless. Every rule here corresponds to a defect that
// actually shipped.

// Problem is one suspicious line of emitted source.
type Problem struct {
	Line int    // 1-based
	Text string // the offending line, trimmed
	Rule string // which check fired
}

func (p Problem) String() string {
	return fmt.Sprintf("line %d [%s]: %s", p.Line, p.Rule, p.Text)
}

var (
	// A bare keyword sitting where a binary operator belongs. `B.AL` decoded
	// as a conditional branch produced `(x) true (y)`; there is no Dart
	// operator spelled `true`, `false` or `null`.
	reKeywordAsOperator = regexp.MustCompile(`\)\s+(true|false|null)\s+[\(A-Za-z_0-9]`)
	// A member access whose name is missing, leaving the operator adrift:
	// `X. + (a)`. A real operator method prints as `X.+(a)` with no space.
	reSpacedMemberOperator = regexp.MustCompile(`[A-Za-z_0-9\]\)]\.\s+[-+*/%&|^<>=!~]+\s`)
	// Placeholders that mean "the emitter gave up". They are honest, but a
	// spike in them is a regression, so they are reported for counting
	// rather than treated as malformed.
	rePlaceholder = regexp.MustCompile(`/\* cond \*/|pool\[\?\]`)
)

// ValidateSource reports lines of emitted pseudocode that are known-bad
// shapes. An empty result does not prove the source is valid Dart; a
// non-empty one proves it is not.
func ValidateSource(src string) []Problem {
	var out []Problem
	depth := 0
	for i, line := range strings.Split(src, "\n") {
		_, text, ok := splitIndent(line)
		if !ok {
			text = strings.TrimSpace(line)
		}
		add := func(rule string) {
			out = append(out, Problem{Line: i + 1, Text: text, Rule: rule})
		}
		if reKeywordAsOperator.MatchString(text) {
			add("keyword-as-operator")
		}
		if reSpacedMemberOperator.MatchString(text) {
			add("spaced-member-operator")
		}
		// Brace accounting, ignoring braces inside strings and comments --
		// a `"{"` in a literal is not structure. See braceDelta.
		depth += braceDelta(text)
		if depth < 0 {
			add("brace-depth-negative")
			depth = 0
		}
	}
	if depth != 0 {
		out = append(out, Problem{Line: 0, Rule: "brace-unbalanced",
			Text: fmt.Sprintf("file ends at depth %d", depth)})
	}
	return out
}

// CountPlaceholders returns how many lines carry an "emitter gave up"
// marker. Not a defect on its own; useful as a regression signal.
func CountPlaceholders(src string) int {
	n := 0
	for _, line := range strings.Split(src, "\n") {
		if rePlaceholder.MatchString(line) {
			n++
		}
	}
	return n
}
