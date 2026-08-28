package decompiler

import (
	"strings"

	"aotopsy/internal/decompiler/stmt"
)

// compactLines runs the structural readability passes to a fixed point.
//
// The passes operate on the statement tree (stmt.go), not on lines: the text
// is parsed once, rewritten as a tree, and printed once. Every pass used to
// re-derive nesting for itself by counting braces and dividing leading spaces
// by two, and four defects were measured on that implementation:
//
//   - merging continue-guards deleted the else branch of an if-with-else,
//     leaving the braces balanced so nothing downstream noticed;
//   - copy propagation carried a temp from one branch into a sibling branch,
//     which is a different scope that may never have run;
//   - CSE emitted a reference to a `final` temp declared inside a branch,
//     from a statement after that branch;
//   - a `"{"` in a string literal made the block finder overshoot a loop's
//     closing brace onto the function's, so unwrapping pushed the rest of the
//     function to top level.
//
// Each is recorded next to the pass that had it, in stmt_passes.go and
// stmt_dataflow.go, with the input that reproduced it.
//
// The full ~20-pass flutterdec pipeline (retry-loop synthesis and the rest)
// is still a documented, not-yet-ported subset -- see
// knowledge/SESSION_HANDOFF_2026-07-17_AOTOPSY_UNIVERSAL_RE_PLATFORM.md.
func compactLines(source string) string {
	tree := stmt.ParseStmts(strings.Split(source, "\n"))
	for pass := 0; pass < 16; pass++ {
		var changed bool
		tree, changed = stmt.CompactTree(tree)
		var c0, c4, c5, c6, c7, c8, c9, c10, c11 bool
		tree, c9 = stmt.LinearizeAsyncStmt(tree)
		tree, c6 = stmt.ForInLoopRecoveryStmt(tree)
		tree, c10 = stmt.ClosureInliningStmt(tree)
		tree, c0 = stmt.CollectionIdiomsStmt(tree)
		tree, c5 = stmt.StringInterpolationIdiomStmt(tree)
		tree, c7 = stmt.NullAwareIdiomStmt(tree)
		c1 := stmt.CopyPropagationStmt(tree)
		c2 := stmt.CommonSubexpressionEliminationStmt(tree)
		tree, c4 = stmt.InlineSingleUseTempsStmt(tree)
		tree, c8 = stmt.CascadeIdiomStmt(tree)
		tree, c11 = stmt.TypedDeclarationsStmt(tree)
		c3 := stmt.CleanExprs(tree)
		if !changed && !c0 && !c1 && !c2 && !c3 && !c4 && !c5 && !c6 && !c7 && !c8 && !c9 && !c10 && !c11 {
			break
		}
	}
	return strings.Join(stmt.PrintStmts(tree), "\n")
}

func leadingIndent(line string) int {
	n := 0
	for n < len(line) && line[n] == ' ' {
		n++
	}
	return n / 2
}

func trimmed(line string) string {
	return strings.TrimSpace(line)
}

