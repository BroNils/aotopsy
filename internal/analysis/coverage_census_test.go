package analysis

import (
	"os"
	"testing"

	"aotopsy/internal/samplecorpus"
)

// TestCoverageCensus parses every registered corpus sample present on disk and
// emits a machine-parseable COVROW line per sample, powering the public coverage
// scoreboard (COVERAGE.md via `make coverage`). It is NOT a gate; it is a
// measurement harness, skipped unless AOTOPSY_COVERAGE=1.
//
// The claim it substantiates: aotopsy parses the full Dart AOT snapshot — ELF,
// snapshot region, cluster alloc+fill, instructions table, disassembly — cleanly
// across every modeled Dart version on BOTH architectures, with zero
// unknown-CID / cluster-desync errors. A sample that failed to parse would
// surface as a LoadContext error here.
func TestCoverageCensus(t *testing.T) {
	if os.Getenv("AOTOPSY_COVERAGE") == "" {
		t.Skip("set AOTOPSY_COVERAGE=1 to run the coverage census")
	}
	requireCompleteCorpus(t)
	rows := 0
	for _, s := range samplecorpus.Registry {
		name := s.FileName()
		path := corpusSample(t, name)
		if _, err := samplecorpus.ValidateSample(path, s); err != nil {
			t.Fatalf("%s: corpus identity validation: %v", name, err)
		}
		rows++
		func() {
			ctx, err := LoadContext(path)
			if err != nil {
				// A parse failure is the exact thing coverage must expose.
				t.Errorf("COVROW\t%s\t%s\tFAIL\t0\t0\t%s\t%v", s.DartVersion, s.Arch, name, err)
				return
			}
			defer func() { _ = ctx.Close() }()
			fns := len(ctx.Ranges)
			symtab := 0
			if ctx.EF != nil {
				if syms, err := ctx.EF.FuncSymbols(); err == nil {
					symtab = len(syms)
				} else {
					t.Fatalf("FuncSymbols(%s): %v", name, err)
				}
			}
			t.Logf("COVROW\t%s\t%s\tOK\t%d\t%d\t%s", s.DartVersion, s.Arch, fns, symtab, name)
		}()
	}
	if rows != samplecorpus.ExpectedSampleCount {
		t.Fatalf("coverage census emitted %d rows, want exactly %d", rows, samplecorpus.ExpectedSampleCount)
	}
}
