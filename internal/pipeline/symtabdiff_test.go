package pipeline

import (
	"testing"

	"aotopsy/internal/samplecorpus"
)

// Symtab differential: compare recovered names against the ELF symbol table
// on the corpus samples that kept one.
//
// This is the ONLY gate that compares against something other than our own
// previous output. Golden compares hashes of what we produced last time, so it
// notices a change but has no opinion on whether the new text is RIGHT. The
// cross-version differential compares siblings to each other, so a fault
// shared by all of them is invisible to it. The ELF symbol table is ground
// truth from the linker.
//
// That distinction is not academic here. Measured on this corpus: the previous
// resolver reported 2271 monomorphic call sites on 3.12.2 arm64 where the true
// candidate count is a median of 208 and never 1 -- 1517 of them naming
// `build`, Flutter's most common selector. Every counter went UP as it got
// more wrong. Only ground truth catches that shape of error, which is why this
// gate runs by default rather than behind an env var.
//
// It used to be gated on AOTOPSY_VALIDATE_SYMTAB and driven by three hardcoded
// env vars. Of those three samples only ONE (3.12.2 x86_64) actually carries a
// .symtab, so in practice the gate validated a single binary and only when
// someone remembered the variable. It is now driven by samplecorpus, covers
// every sample that has symbols, and grows on its own as the corpus does.
//
// Samples without a .symtab skip: production Flutter builds are stripped, and
// recovering names without symbols is the whole point of the tool. Currently
// the Flutter releases from 3.44 on keep symbols in merged_native_libs, which
// is where the six covered samples come from.
func TestSymtabDifferential(t *testing.T) {
	covered := 0
	for _, s := range samplecorpus.Registry {
		path := samplecorpus.Path(s.FileName())
		if path == "" {
			continue
		}
		name := s.FileName()
		t.Run(name, func(t *testing.T) {
			if runSymtabDifferential(t, path, name) {
				covered++
			}
		})
	}
	if covered == 0 {
		t.Skip("no corpus sample carries a .symtab")
	}
	t.Logf("validated recovered names against .symtab on %d sample(s)", covered)
}

// runSymtabDifferential reports whether the sample actually had symbols to
// compare against, so the caller can tell "all skipped" from "all passed".
func runSymtabDifferential(t *testing.T, libPath, name string) bool {
	ctx, err := LoadContext(libPath)
	if err != nil {
		t.Fatalf("LoadContext: %v", err)
	}
	defer func() { _ = ctx.Close() }()

	elfSyms := ctx.EF.FuncSymbols()
	if len(elfSyms) == 0 {
		t.Skipf("stripped (no .symtab) -- nothing to compare against")
		return false
	}

	// stub_/sub_/SharedStub are not naming claims, they are honest "we don't
	// know" markers. Counting them as disagreements would punish honesty and
	// reward guessing -- the exact failure mode this gate exists to catch.
	recovered := make(map[uint64]string, len(ctx.SymbolNames))
	for va, nm := range ctx.SymbolNames {
		switch {
		case len(nm) > 4 && nm[:4] == "stub",
			len(nm) > 4 && nm[:4] == "sub_",
			len(nm) > 10 && nm[:10] == "SharedStub":
			continue
		}
		recovered[va] = nm
	}
	if len(recovered) == 0 {
		t.Skipf("no recovered names to compare")
		return false
	}

	comp := CompareNamesToSymbols(recovered, elfSyms)
	rate := comp.AgreementRate()
	t.Logf("%d compared, %d agree, %d disagree, rate=%.1f%%",
		comp.Compared, comp.Agree, len(comp.Disagreement), rate*100)

	if len(comp.Disagreement) > 0 {
		limit := min(20, len(comp.Disagreement))
		for _, d := range comp.Disagreement[:limit] {
			t.Logf("  disagree 0x%x: ours=%q elf=%q", d.VA, d.Ours, d.ELF)
		}
		if len(comp.Disagreement) > limit {
			t.Logf("  ... and %d more", len(comp.Disagreement)-limit)
		}
	}

	// Most surviving disagreements are convention differences, not wrong
	// names, which is why the bar is under 100%.
	//
	// Measured 66.9-80.1% across the samples that carry symbols, and the
	// spread is a property of the ELF dialect rather than of the analysis:
	//
	//	>= 2.18   79-80%   AddAssemblerIdentifier keeps '.' and spells
	//	                   operators out, so most structure survives
	//	3.x prose 73-79%   readable names, only conventions differ
	//	2.13-2.17 67-68%   EnsureAssemblerIdentifier turns EVERY separator
	//	                   into '_', so `A.b`, `A_b` and `A&b` arrive
	//	                   indistinguishable and some pairs can never be
	//	                   matched back up
	//
	// The bar sits just under the worst of those. It is a REGRESSION gate: it
	// has to trip when a naming category breaks, not encode how well any one
	// dialect can possibly do.
	//
	// It was 0.50 while the real rate was ~60%, which left room for a
	// category-sized regression to pass unnoticed -- and one was in fact
	// hiding there: every `new X` name disagreed on a space-vs-underscore
	// asymmetry in NormalizeRecoveredName, worth 14.8 points on its own.
	//
	// Raised in two steps as name resolution improved, each just under the new
	// measured floor:
	//   0.65 -> 0.72  PatchClass owner resolution (worst band 66.9% -> 73.2%)
	//   0.72 -> 0.76  closures qualified by their enclosing function, not their
	//                 class (worst band 73.2% -> 76.3%)
	//   0.76 -> 0.77  mixin owner folded to its last component in the prose
	//                 dialect for comparison (worst band 76.3% -> 78.1%)
	//   0.77 -> 0.81  the "::" top-level pseudo-class stripped from real output
	//                 and the init: marker folded in prose (worst band
	//                 78.1% -> 81.3%)
	const minAgreementRate = 0.81
	if rate < minAgreementRate {
		t.Errorf("agreement rate %.1f%% < %.1f%% threshold -- %d disagreements out of %d compared",
			rate*100, minAgreementRate*100, len(comp.Disagreement), comp.Compared)
	}
	return true
}
