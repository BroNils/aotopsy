package stmt

import (
	"regexp"
	"strings"
)

// BoxInt64Instr::EmitNativeCode (il_arm64.cc / il_x64.cc, md5-bucketed and
// diffed over all 23 supported SDK trees) compiles boxing an unboxed int64 as
//
//	if (value fits a Smi)  out = SmiTag(value)           // fast path, falls into `done`
//	else                   out = AllocateMint(); out.value = value   // slow path, then `done`
//
// Both paths end at the same continuation, and they hold the same Dart int. The
// emitter renders it as a diamond whose miss branch is nothing but the Mint
// allocation followed by a `goto` to the label that opens the hit branch:
//
//	if (<fits-smi test>) {
//	  block_N:;
//	  ...rest...
//	} else {
//	  final t = AllocateMintWithoutFpuRegs()..f7 = v;
//	  goto block_N;
//	}
//
// The allocation is machinery, not source, and each such diamond nests the
// rest of the function one level deeper (the x64 nesting is what pushes the
// structured walk to its depth budget). collapseMintBoxDiamondStmt removes the
// diamond: the hit branch's statements replace the whole construct, because
// control reaches them on both paths.
//
// A branch is treated as the Mint slow path ONLY when every statement in it is
// a comment, a label, a call to an `Allocate...Mint...` stub (optionally with
// its `.f7` value store; `Mint::value_offset() - kHeapObjectTag` is 7), and a
// final `goto` to the label that opens the other branch. Any other statement
// makes the construct a real branch and it is left alone.
var (
	mintAllocLineRe = regexp.MustCompile(`^(?:final\s+(?:\w+\s+)?\w+\s*=\s*)?\w*Allocate\w*Mint\w*\(.*\)(?:\.{1,2}f7 = .+)?;$`)
	gotoLabelRe     = regexp.MustCompile(`^goto (block_\d+);$`)
)

// lineOrVerbatimText returns the trimmed text of a leaf, or "" and false for a
// construct.
func lineOrVerbatimText(s Stmt) (string, bool) {
	switch v := s.(type) {
	case *Line:
		return strings.TrimSpace(v.Text), true
	case *Verbatim:
		return strings.TrimSpace(v.Raw), true
	}
	return "", false
}

// openingLabel returns the label that is the first code statement of body.
func openingLabel(body []Stmt) (label string, ok bool) {
	for _, s := range body {
		t, leaf := lineOrVerbatimText(s)
		if !leaf {
			return "", false
		}
		if t == "" || strings.HasPrefix(t, "//") {
			continue
		}
		if m := LabelDeclRe.FindStringSubmatch(t); m != nil {
			return "block_" + m[1], true
		}
		return "", false
	}
	return "", false
}

// isMintSlowPath reports whether body is only the Mint allocation followed by a
// goto to label.
func isMintSlowPath(body []Stmt, label string) bool {
	allocs := 0
	sawGoto := false
	for _, s := range body {
		t, leaf := lineOrVerbatimText(s)
		if !leaf {
			return false
		}
		switch {
		case t == "" || strings.HasPrefix(t, "//"):
			continue
		case sawGoto:
			return false // nothing may follow the goto
		case mintAllocLineRe.MatchString(t):
			allocs++
		case LabelDeclRe.MatchString(t):
			continue
		default:
			m := gotoLabelRe.FindStringSubmatch(t)
			if m == nil || m[1] != label {
				return false
			}
			sawGoto = true
		}
	}
	return allocs > 0 && sawGoto
}

// collapseMintBoxDiamondStmt removes BoxInt64 Smi-or-Mint diamonds (see above).
func collapseMintBoxDiamondStmt(body []Stmt) ([]Stmt, bool) {
	changed := false
	out := make([]Stmt, 0, len(body))
	for _, s := range body {
		c := asConstruct(s)
		if c != nil && c.isIf() && len(c.Clauses) == 2 && c.hasElse() {
			hit, miss := c.Clauses[0].Body, c.Clauses[1].Body
			label, ok := openingLabel(hit)
			if !ok || !isMintSlowPath(miss, label) {
				// Orientation 2: the Mint path is the `if` clause.
				hit, miss = c.Clauses[1].Body, c.Clauses[0].Body
				label, ok = openingLabel(hit)
				if !ok || !isMintSlowPath(miss, label) {
					out = append(out, s)
					continue
				}
			}
			for _, h := range hit {
				h.shift(-1)
				out = append(out, h)
			}
			changed = true
			continue
		}
		out = append(out, s)
	}
	return out, changed
}
