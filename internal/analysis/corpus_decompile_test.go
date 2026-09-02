package analysis

import (
	"os"
	"strings"
	"testing"

	"aotopsy/internal/decompiler"
	"aotopsy/internal/samplecorpus"
)

// decompileCorpusFuncs is how many functions per sample this test emits.
// The point is to exercise every registered Dart version and both
// architectures against the emitter, not to decompile a whole binary --
// the pathologies this catches (unbounded recursion, a version whose
// blocks never resolve) show up within the first couple hundred
// functions or not at all.
const decompileCorpusFuncs = 200

// decompileCorpusMinCoverage is the floor for average CFG coverage.
//
// Every sample in the corpus currently sits at 99.9%-100%. The floor is
// set below that rather than at it because coverage legitimately moves a
// fraction when the emitter changes; what it must never do is fall off a
// cliff, which is what a version-specific structuring failure looks like.
const decompileCorpusMinCoverage = 95.0

// TestDecompileCorpus runs every registered sample through the decompiler.
//
// This test exists because nothing did. The golden test covers pipeline
// ARTIFACTS, and pseudocode is not one of them (it is written only under
// --decompile), so the emitter had no corpus-wide coverage at all. A
// switch-case path that bypassed every recursion guard therefore sat in
// the tree while six samples -- Dart 2.14.0, 2.15.0 and 2.16.0 on ARM64,
// every variant -- died with `fatal error: out of memory` at a recursion
// depth around 5,400. Nothing was red. The bug was found by running the
// corpus by hand, which is exactly the thing a test is for.
//
// Each sample runs as a subtest so one failure reports the sample that
// caused it instead of taking the rest of the run with it.
func TestDecompileCorpus(t *testing.T) {
	if testing.Short() {
		t.Skip("corpus decompile sweep is slow; skipped under -short")
	}
	seen := map[string]bool{}
	for _, s := range samplecorpus.Registry {
		name := s.FileName()
		if seen[name] {
			continue
		}
		seen[name] = true

		t.Run(name, func(t *testing.T) {
			path := samplecorpus.Path(name)
			if path == "" {
				t.Skip(samplecorpus.MissingMessage(s))
			}
			ctx, err := LoadContext(path)
			if err != nil {
				t.Fatalf("%s (Dart %s %s): LoadContext: %v", name, s.DartVersion, s.Arch, err)
			}
			defer func() { _ = ctx.Close() }()

			sym := func(va uint64) (string, bool) {
				n, ok := ctx.SymbolNames[va]
				return n, ok && n != ""
			}
			poolLk := func(i int) (string, bool) { n, ok := ctx.PoolDisplay[i]; return n, ok }

			var fns int
			var covSum float64
			var worstName string
			var worstLines int
			for _, cr := range ctx.Ranges {
				if fns >= decompileCorpusFuncs {
					break
				}
				if cr.Size == 0 || cr.RefID < 0 {
					continue
				}
				fir, err := ctx.FuncIRFor(cr)
				if err != nil || fir == nil || len(fir.Blocks) == 0 {
					continue
				}
				fns++
				art := decompiler.EmitPseudocode(fir, sym, poolLk)
				covSum += decompiler.VerifyCFG(fir, art).CoveragePct
				if n := strings.Count(art.Source, "\n"); n > worstLines {
					worstLines, worstName = n, fir.Name
				}
			}
			if fns == 0 {
				t.Fatalf("%s (Dart %s %s): no decompilable functions -- the emitter "+
					"produced nothing for an entire supported version",
					name, s.DartVersion, s.Arch)
			}
			cov := covSum / float64(fns)
			if cov < decompileCorpusMinCoverage {
				t.Errorf("%s (Dart %s %s): average CFG coverage %.1f%% is below %.1f%% "+
					"over %d functions -- blocks are being dropped from the pseudocode",
					name, s.DartVersion, s.Arch, cov, decompileCorpusMinCoverage, fns)
			}
			t.Logf("%s: %d fns, coverage %.1f%%, largest %s at %d lines",
				name, fns, cov, worstName, worstLines)
		})
	}
}

// TestDecompileCorpusRegistryPresent fails when samples/ is populated but
// the registry disagrees with it, so a sample added to disk without a
// registry entry does not silently escape the sweep above.
func TestDecompileCorpusRegistryPresent(t *testing.T) {
	if samplecorpus.Path(samplecorpus.Registry[0].FileName()) == "" {
		t.Skip("samples/ not present")
	}
	for _, s := range samplecorpus.Registry {
		if _, err := os.Stat(samplecorpus.Path(s.FileName())); err != nil {
			t.Errorf("registered sample %s (Dart %s %s) is missing from samples/",
				s.FileName(), s.DartVersion, s.Arch)
		}
	}
}
