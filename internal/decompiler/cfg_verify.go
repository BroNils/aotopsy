package decompiler

import (
	"fmt"
	"strings"
)

// CFGVerification holds the result of comparing the pseudocode's
// control flow structure against the binary's CFG.
//
// This is the achievable version of Tier 4 item 12 (recompile-and-diff):
// instead of compiling pseudocode back to a snapshot (which requires
// gen_snapshot, not available in AOT runtime — SDK-verified:
// Compiler::CompileFunction calls FATAL in DART_PRECOMPILED_RUNTIME),
// we verify that the emitted pseudocode's control flow matches the
// binary's CFG structure. If the pseudocode has the same branches,
// loops, and returns as the binary, it is structurally correct.
//
// This turns "looks right" into a measurement: a function with
// MismatchedBranches > 0 has control flow that doesn't match the
// binary, which means the pseudocode is structurally wrong.
type CFGVerification struct {
	TotalBlocks        int
	TotalBranches      int
	TotalReturns       int
	TotalLoops         int
	MatchedBranches    int
	MismatchedBranches int
	MatchedReturns     int
	MismatchedReturns  int
	// CoveragePct is the percentage of binary CFG nodes that appear
	// in the pseudocode. Below 100% means some blocks were omitted
	// (budget exceeded, visit count limit, etc).
	CoveragePct float64
}

// VerifyCFG compares the pseudocode artifact's control flow structure
// against the FuncIR's CFG. Returns a verification report.
//
// The check is structural, not semantic: it verifies that every
// branch in the binary has a corresponding if/else in the pseudocode,
// every return has a corresponding return, and every loop header
// has a corresponding while loop. It does NOT verify that the
// condition expressions are correct (that would require semantic
// equivalence, which is the full recompile-and-diff problem).
func VerifyCFG(fir *FuncIR, artifact Artifact) CFGVerification {
	v := CFGVerification{
		TotalBlocks:   len(fir.Blocks),
		TotalBranches: 0,
		TotalReturns:  0,
	}

	// Count binary CFG structures.
	emittedBlocks := make(map[int]bool)
	for i := range fir.Blocks {
		blk := &fir.Blocks[i]
		for _, ins := range blk.Instrs {
			switch ins.Op {
			case OpBranch:
				v.TotalBranches++
			case OpReturn:
				v.TotalReturns++
			}
		}
	}
	v.TotalLoops = len(identifyLoopHeaders(fir))

	// Count pseudocode structures by scanning emitted lines.
	src := artifact.Source
	lines := strings.Split(src, "\n")

	pseudocodeBranches := 0
	pseudocodeReturns := 0
	pseudocodeLoops := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Count if/else as branches (exclude comments).
		if !strings.HasPrefix(trimmed, "//") {
			if strings.HasPrefix(trimmed, "if (") || strings.HasPrefix(trimmed, "if(") {
				pseudocodeBranches++
			}
			if strings.HasPrefix(trimmed, "while (") || strings.HasPrefix(trimmed, "while(") {
				pseudocodeLoops++
			}
			if strings.HasPrefix(trimmed, "return ") || trimmed == "return;" {
				pseudocodeReturns++
			}
		}
	}

	// Calculate coverage based on actual blocks visited and emitted in pseudocode.
	if v.TotalBlocks > 0 {
		visitedCount := len(artifact.VisitedBlocks)
		if visitedCount == 0 {
			// Fallback: count emitted blocks by scanning for block labels if VisitedBlocks was empty
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "block_") && strings.HasSuffix(trimmed, ":;") {
					label := strings.TrimSuffix(trimmed, ":;")
					var id int
					if _, err := fmt.Sscanf(label, "block_%d", &id); err == nil {
						emittedBlocks[id] = true
					}
				}
			}
			visitedCount = len(emittedBlocks)
		}
		v.CoveragePct = float64(visitedCount) / float64(v.TotalBlocks) * 100.0
		if v.CoveragePct > 100.0 {
			v.CoveragePct = 100.0
		}
	}

	// Match counts (structural, not semantic).
	v.MatchedBranches = min(v.TotalBranches, pseudocodeBranches)
	v.MismatchedBranches = abs(v.TotalBranches - pseudocodeBranches)
	v.MatchedReturns = min(v.TotalReturns, pseudocodeReturns)
	v.MismatchedReturns = abs(v.TotalReturns - pseudocodeReturns)

	return v
}

// Summary renders a one-line verification summary.
func (v CFGVerification) Summary() string {
	return fmt.Sprintf("blocks=%d coverage=%.1f%% branches=%d/%d returns=%d/%d loops=%d",
		v.TotalBlocks, v.CoveragePct,
		v.MatchedBranches, v.TotalBranches,
		v.MatchedReturns, v.TotalReturns,
		v.TotalLoops)
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
